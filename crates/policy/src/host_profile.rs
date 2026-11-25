//! Validation and application of admin-owned host profiles
//! ([`HostProfile`]) to the local [`EdgeSafetyConfig`].
//!
//! Safety invariant: a profile can only TIGHTEN the built-in edge floor.
//! Caps take `min(builtin, profile)`; `enabled_collectors` intersects the
//! built-in allowlist. `approved_file_roots` is the single additive field,
//! and noncanonical, overly broad, or denied roots are rejected
//! at apply time — the hard denylist itself always stays in force at
//! collection time.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use defsec_protocol::profile::{
    is_valid_host_tag, HostProfile, HostProfileSummary, MAX_EXPECTED_SERVICES, MAX_HOST_TAGS,
    MAX_PROFILE_FILE_ROOTS, HOST_PROFILE_SCHEMA_VERSION,
};
use defsec_protocol::watch::CollectorType;

use crate::edge_floor::{validate_systemd_unit_name, EdgeSafetyConfig};

/// Validate a parsed profile against structural rules and the local floor,
/// then return the tightened effective configuration. Every rejection
/// carries an explicit reason.
pub fn apply_host_profile(
    cfg: &EdgeSafetyConfig,
    profile: &HostProfile,
) -> Result<(EdgeSafetyConfig, HostProfileSummary), String> {
    if profile.schema_version != HOST_PROFILE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported host profile schema_version {} (expected {})",
            profile.schema_version, HOST_PROFILE_SCHEMA_VERSION
        ));
    }

    validate_profile_metadata(&profile.host_tags, &profile.expected_services)?;

    if profile.approved_file_roots.len() > MAX_PROFILE_FILE_ROOTS {
        return Err(format!(
            "host profile declares {} approved_file_roots (max {MAX_PROFILE_FILE_ROOTS})",
            profile.approved_file_roots.len()
        ));
    }
    let mut extra_roots = Vec::with_capacity(profile.approved_file_roots.len());
    for raw in &profile.approved_file_roots {
        extra_roots.push(validate_profile_file_root(raw, cfg)?);
    }

    // Caps only tighten: min(builtin, profile), and a zero cap would make the
    // collector unusable, so it is rejected outright.
    let caps = &profile.collector_caps;
    let max_outbound_flows = match caps.max_outbound_flows {
        None => cfg.max_outbound_flows,
        Some(0) => return Err("collector cap max_outbound_flows must be >= 1".into()),
        Some(cap) => cfg.max_outbound_flows.min(cap),
    };
    let max_packages = match caps.max_packages {
        None => cfg.max_packages,
        Some(0) => return Err("collector cap max_packages must be >= 1".into()),
        Some(cap) => cfg.max_packages.min(cap),
    };
    let max_file_hash_bytes = match caps.max_file_hash_bytes {
        None => cfg.max_file_hash_bytes,
        Some(0) => return Err("collector cap max_file_hash_bytes must be >= 1".into()),
        Some(cap) => cfg.max_file_hash_bytes.min(cap),
    };
    let max_journal_batch_events = match caps.max_journal_batch_events {
        None => cfg.max_journal_batch_events,
        Some(0) => return Err("collector cap max_journal_batch_events must be >= 1".into()),
        Some(cap) => cfg.max_journal_batch_events.min(cap),
    };

    // enabled_collectors intersects the built-in allowlist; it can never
    // add a collector the local floor does not already allow.
    let allowed_collectors: BTreeSet<CollectorType> = match &profile.enabled_collectors {
        None => cfg.allowed_collectors.clone(),
        Some(enabled) => enabled
            .iter()
            .copied()
            .filter(|c| cfg.allowed_collectors.contains(c))
            .collect(),
    };

    let mut effective = cfg.clone();
    effective.max_outbound_flows = max_outbound_flows;
    effective.max_packages = max_packages;
    effective.max_file_hash_bytes = max_file_hash_bytes;
    effective.max_journal_batch_events = max_journal_batch_events;
    effective.allowed_collectors = allowed_collectors;
    // Additive by design, but only after every root passed the denylist
    // checks above; the hard denylist still applies at collection time.
    for root in extra_roots {
        if !effective.approved_file_roots.contains(&root) {
            effective.profile_file_roots.push(root.clone());
            effective.approved_file_roots.push(root);
        }
    }

    let summary = HostProfileSummary {
        host_tags: profile.host_tags.clone(),
        expected_services: profile.expected_services.clone(),
        enabled_collectors: effective.allowed_collectors.iter().copied().collect(),
    };
    Ok((effective, summary))
}

/// Validate the metadata and effective collector set from an agent registration.
pub fn validate_host_profile_summary(summary: &HostProfileSummary) -> Result<(), String> {
    validate_profile_metadata(&summary.host_tags, &summary.expected_services)?;
    let enabled: BTreeSet<_> = summary.enabled_collectors.iter().collect();
    if enabled.len() != summary.enabled_collectors.len() {
        return Err("host profile summary contains duplicate enabled_collectors".into());
    }
    Ok(())
}

fn validate_profile_metadata(host_tags: &[String], expected_services: &[String]) -> Result<(), String> {
    if host_tags.len() > MAX_HOST_TAGS {
        return Err(format!(
            "host profile declares {} host_tags (max {MAX_HOST_TAGS})",
            host_tags.len()
        ));
    }
    for tag in host_tags {
        if tag.len() > 64 {
            return Err("host tag must be at most 64 bytes".into());
        }
        if !is_valid_host_tag(tag) {
            return Err(format!(
                "host tag '{tag}' must match ^[a-z0-9][a-z0-9:._-]{{0,63}}$"
            ));
        }
    }
    if expected_services.len() > MAX_EXPECTED_SERVICES {
        return Err(format!(
            "host profile declares {} expected_services (max {MAX_EXPECTED_SERVICES})",
            expected_services.len()
        ));
    }
    for unit in expected_services {
        validate_systemd_unit_name(unit)?;
    }
    Ok(())
}

/// Require an existing, canonical directory that does not overlap a denied prefix.
fn validate_profile_file_root(
    raw: &str,
    cfg: &EdgeSafetyConfig,
) -> Result<std::path::PathBuf, String> {
    if raw.is_empty() || raw.len() > 512 {
        return Err("approved file root length must be 1..=512 bytes".into());
    }
    if raw.bytes().any(|b| b == 0 || b < 0x20) {
        return Err("approved file root contains control characters or NUL".into());
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(format!("approved file root '{raw}' must be absolute"));
    }
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(format!(
                    "approved file root '{raw}' contains forbidden traversal component"
                ));
            }
        }
    }
    if path.components().count() < 3 {
        return Err(format!("approved file root '{raw}' is too broad"));
    }
    let check_denylist = |path: &Path| {
        for denied in &cfg.denied_path_prefixes {
            if path.starts_with(denied) || denied.starts_with(path) {
                return Err(format!(
                    "approved file root '{raw}' overlaps local sensitive path denylist entry {denied:?}"
                ));
            }
        }
        Ok(())
    };
    check_denylist(path)?;
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("cannot resolve approved file root '{raw}': {e}"))?;
    check_denylist(&canonical)?;
    if canonical.as_os_str() != path.as_os_str() {
        return Err(format!(
            "approved file root '{raw}' must be canonical and contain no symlinks"
        ));
    }
    if !canonical.is_dir() {
        return Err(format!("approved file root '{raw}' is not a directory"));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_json(raw: &str) -> HostProfile {
        serde_json::from_str(raw).expect("valid profile JSON")
    }

    #[test]
    fn valid_profile_tightens_and_summarizes() {
        let cfg = EdgeSafetyConfig::default();
        let profile = profile_json(
            r#"{
                "schema_version": 1,
                "host_tags": ["prod", "dc:eu-west-1"],
                "expected_services": ["sshd.service", "nginx.service"],
                "enabled_collectors": ["sockets.listening", "connections.outbound", "journal.unit_events"],
                "collector_caps": { "max_outbound_flows": 128, "max_file_hash_bytes": 1048576 }
            }"#,
        );
        let (effective, summary) = apply_host_profile(&cfg, &profile).unwrap();

        // Caps tighten only.
        assert_eq!(effective.max_outbound_flows, 128);
        assert_eq!(effective.max_file_hash_bytes, 1_048_576);
        assert_eq!(effective.max_packages, cfg.max_packages);
        assert_eq!(effective.max_journal_batch_events, cfg.max_journal_batch_events);

        assert!(
            effective
                .approved_file_roots
                .contains(&std::path::PathBuf::from("/etc/systemd/system"))
        );

        // Intersected collectors: profile listed 3, all in the built-in set;
        // the summary carries them in BTreeSet (declaration) order.
        assert_eq!(
            summary.enabled_collectors,
            vec![
                CollectorType::SocketsListening,
                CollectorType::JournalUnitEvents,
                CollectorType::ConnectionsOutbound,
            ]
        );
        assert_eq!(summary.host_tags, vec!["prod".to_string(), "dc:eu-west-1".to_string()]);
    }

    #[test]
    fn caps_never_widen_only_clamp() {
        let cfg = EdgeSafetyConfig::default();
        let mut profile = profile_json(r#"{"schema_version": 1}"#);
        profile.collector_caps.max_outbound_flows = Some(100_000);
        profile.collector_caps.max_packages = Some(999_999);
        profile.collector_caps.max_file_hash_bytes = Some(u64::MAX);
        profile.collector_caps.max_journal_batch_events = Some(u32::MAX);
        let (effective, _) = apply_host_profile(&cfg, &profile).unwrap();
        assert_eq!(effective.max_outbound_flows, cfg.max_outbound_flows);
        assert_eq!(effective.max_packages, cfg.max_packages);
        assert_eq!(effective.max_file_hash_bytes, cfg.max_file_hash_bytes);
        assert_eq!(effective.max_journal_batch_events, cfg.max_journal_batch_events);

        let mut zero_caps = profile_json(r#"{"schema_version": 1}"#);
        zero_caps.collector_caps.max_outbound_flows = Some(0);
        assert!(apply_host_profile(&cfg, &zero_caps).unwrap_err().contains("max_outbound_flows"));
        zero_caps.collector_caps.max_outbound_flows = None;
        zero_caps.collector_caps.max_packages = Some(0);
        assert!(apply_host_profile(&cfg, &zero_caps).unwrap_err().contains("max_packages"));
        zero_caps.collector_caps.max_packages = None;
        zero_caps.collector_caps.max_file_hash_bytes = Some(0);
        assert!(apply_host_profile(&cfg, &zero_caps).unwrap_err().contains("max_file_hash_bytes"));
        zero_caps.collector_caps.max_file_hash_bytes = None;
        zero_caps.collector_caps.max_journal_batch_events = Some(0);
        assert!(
            apply_host_profile(&cfg, &zero_caps)
                .unwrap_err()
                .contains("max_journal_batch_events")
        );
    }

    #[test]
    fn denylisted_and_slash_roots_are_rejected() {
        let cfg = EdgeSafetyConfig::default();
        for bad in ["/etc/shadow", "/root", "/home/x", "/", "/proc/self", "etc/app", "/etc/../app"] {
            let mut profile = profile_json(r#"{"schema_version": 1}"#);
            profile.approved_file_roots = vec![bad.to_string()];
            let err = apply_host_profile(&cfg, &profile).unwrap_err();
            assert!(err.contains(bad), "expected rejection of {bad}, got: {err}");
        }
    }

    #[test]
    fn roots_must_be_canonical_narrow_and_outside_the_denylist() {
        let parent = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("defsec-profile-roots-{}", std::process::id()));
        let real = parent.join("real");
        let link = parent.join("link");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut cfg = EdgeSafetyConfig {
            denied_path_prefixes: vec![real.join("private")],
            ..Default::default()
        };
        let mut profile = profile_json(r#"{"schema_version":1}"#);
        for bad in [
            real.as_path(),
            link.as_path(),
            Path::new("/usr"),
            Path::new("/var"),
            Path::new("/etc"),
            Path::new("/home"),
        ] {
            profile.approved_file_roots = vec![bad.to_str().unwrap().into()];
            assert!(apply_host_profile(&cfg, &profile).is_err(), "{bad:?}");
        }
        cfg.denied_path_prefixes.clear();
        profile.approved_file_roots = vec![link.to_str().unwrap().into()];
        assert!(
            apply_host_profile(&cfg, &profile)
                .unwrap_err()
                .contains("symlinks")
        );
        profile.approved_file_roots = vec![real.to_str().unwrap().into()];
        assert!(
            apply_host_profile(&cfg, &profile)
                .unwrap()
                .0
                .approved_file_roots
                .contains(&real)
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn tag_and_service_rules_are_enforced() {
        let cfg = EdgeSafetyConfig::default();

        let mut tags = profile_json(r#"{"schema_version": 1}"#);
        tags.host_tags = vec!["Prod-Env".to_string()];
        assert!(apply_host_profile(&cfg, &tags).unwrap_err().contains("host tag 'Prod-Env'"));

        let mut too_many = profile_json(r#"{"schema_version": 1}"#);
        too_many.host_tags = (0..17).map(|i| format!("tag{i}")).collect();
        assert!(apply_host_profile(&cfg, &too_many).unwrap_err().contains("host_tags"));

        let mut bad_unit = profile_json(r#"{"schema_version": 1}"#);
        bad_unit.expected_services = vec!["sshd.service; rm -rf /".to_string()];
        assert!(apply_host_profile(&cfg, &bad_unit).unwrap_err().contains("systemd unit"));

        let mut too_many_services = profile_json(r#"{"schema_version": 1}"#);
        too_many_services.expected_services =
            (0..65).map(|i| format!("unit{i}.service")).collect();
        assert!(apply_host_profile(&cfg, &too_many_services).unwrap_err().contains("expected_services"));

        let bad_version = profile_json(r#"{"schema_version": 2}"#);
        assert!(apply_host_profile(&cfg, &bad_version).unwrap_err().contains("schema_version"));
    }

    #[test]
    fn enabled_collectors_intersect_and_empty_is_allowed() {
        let cfg = EdgeSafetyConfig::default();
        let mut profile = profile_json(r#"{"schema_version": 1}"#);
        profile.enabled_collectors = Some(vec![CollectorType::SocketsListening]);
        let (effective, summary) = apply_host_profile(&cfg, &profile).unwrap();
        assert_eq!(summary.enabled_collectors, vec![CollectorType::SocketsListening]);
        assert_eq!(effective.allowed_collectors.len(), 1);

        // An unknown-to-the-floor collector cannot be enabled by a profile.
        let mut narrow = cfg.clone();
        narrow.allowed_collectors.remove(&CollectorType::SocketsListening);
        let (effective, summary) = apply_host_profile(&narrow, &profile).unwrap();
        assert!(summary.enabled_collectors.is_empty());
        assert!(effective.allowed_collectors.is_empty());
    }
}
