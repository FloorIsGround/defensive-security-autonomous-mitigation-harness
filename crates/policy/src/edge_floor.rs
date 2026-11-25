//! Edge-local hard safety floor enforced independently by `agent-d`.
//!
//! Even if `control-d` is compromised, signed watch bundles CANNOT loosen
//! these limits. This configuration is owned strictly by local host administration.

use std::collections::{BTreeSet, HashSet};
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use defsec_protocol::watch::{
    CollectorSpec, CollectorType, CompareTarget, TriggerPredicate, WATCH_BUNDLE_SCHEMA_VERSION,
    WatchBundlePayload, WatchClass, WatchSpec,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeSafetyConfig {
    pub expected_policy_version: u32,
    pub min_interval_seconds: u64,
    pub max_timeout_seconds: u64,
    pub max_concurrent_collectors: usize,
    pub max_watches_total: usize,
    pub max_ephemeral_watches: usize,
    pub max_ephemeral_ttl_seconds: u64,
    pub max_ephemeral_runs: u64,
    pub max_paths_per_file_watch: usize,
    pub max_file_hash_bytes: u64,
    pub max_journal_batch_events: u32,
    pub max_journal_message_bytes: usize,
    /// Local ceiling for `connections.outbound` retained flow groups.
    pub max_outbound_flows: u32,
    /// Local ceiling for `packages.inventory` retained package entries.
    pub max_packages: u32,
    pub max_clock_skew_seconds: i64,
    pub allowed_collectors: BTreeSet<CollectorType>,
    pub approved_file_roots: Vec<PathBuf>,
    pub denied_path_prefixes: Vec<PathBuf>,
    pub denied_filename_suffixes: Vec<String>,
    pub denied_exact_filenames: Vec<String>,
}

impl Default for EdgeSafetyConfig {
    fn default() -> Self {
        let mut allowed_collectors = BTreeSet::new();
        allowed_collectors.insert(CollectorType::SocketsListening);
        allowed_collectors.insert(CollectorType::SystemdUnitState);
        allowed_collectors.insert(CollectorType::FilesMetadata);
        allowed_collectors.insert(CollectorType::JournalUnitEvents);
        allowed_collectors.insert(CollectorType::ConnectionsOutbound);
        allowed_collectors.insert(CollectorType::PackagesInventory);

        Self {
            expected_policy_version: 1,
            min_interval_seconds: 15,
            max_timeout_seconds: 30,
            max_concurrent_collectors: 4,
            max_watches_total: 32,
            max_ephemeral_watches: 10,
            max_ephemeral_ttl_seconds: 4 * 3600, // 4 hours
            max_ephemeral_runs: 1000,
            max_paths_per_file_watch: 64,
            max_file_hash_bytes: 10 * 1024 * 1024, // 10 MiB
            max_journal_batch_events: 100,
            max_journal_message_bytes: 512,
            max_outbound_flows: 512,
            max_packages: 16384,
            max_clock_skew_seconds: 300,
            allowed_collectors,
            approved_file_roots: vec![
                PathBuf::from("/etc/systemd/system"),
                PathBuf::from("/etc/ssh"),
                PathBuf::from("/etc/nginx"),
                PathBuf::from("/etc/cron.d"),
                PathBuf::from("/usr/lib/systemd/system"),
            ],
            denied_path_prefixes: vec![
                PathBuf::from("/etc/shadow"),
                PathBuf::from("/etc/gshadow"),
                PathBuf::from("/etc/sudoers"),
                PathBuf::from("/etc/sudoers.d"),
                PathBuf::from("/etc/ssl/private"),
                PathBuf::from("/home"),
                PathBuf::from("/root"),
                PathBuf::from("/proc"),
                PathBuf::from("/sys"),
                PathBuf::from("/dev"),
            ],
            denied_filename_suffixes: vec![
                ".key".into(),
                ".pem".into(),
                ".p12".into(),
                ".pfx".into(),
                "_key".into(),
            ],
            denied_exact_filenames: vec![
                "id_rsa".into(),
                "id_ed25519".into(),
                "id_ecdsa".into(),
                "id_dsa".into(),
                "authorized_keys".into(),
                "shadow".into(),
                "gshadow".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleHighWaterMark {
    pub bundle_version: u64,
    pub payload_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleValidationOutcome {
    AcceptNew,
    IdenticalRetransmission,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EdgeFloorError {
    #[error("unsupported bundle schema version: {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("policy version mismatch: expected {expected}, got {actual}")]
    PolicyVersionMismatch { expected: u32, actual: u32 },
    #[error("bundle target_host_id '{actual}' does not match local host '{expected}'")]
    HostMismatch { expected: String, actual: String },
    #[error("bundle version {incoming} is stale (high-water mark is {current})")]
    StaleBundleVersion { incoming: u64, current: u64 },
    #[error("bundle version {version} reused with different payload digest")]
    ConflictingBundleDigest { version: u64 },
    #[error("bundle issued_at is too far in the future")]
    IssuedInFuture,
    #[error("bundle has expired")]
    BundleExpired,
    #[error("bundle expires_at must be after issued_at")]
    InvalidValidityWindow,
    #[error("total watch count {count} exceeds ceiling {max}")]
    TooManyWatches { count: usize, max: usize },
    #[error("ephemeral watch count {count} exceeds ceiling {max}")]
    TooManyEphemeralWatches { count: usize, max: usize },
    #[error("duplicate watch id '{0}' in bundle")]
    DuplicateWatchId(String),
    #[error("invalid watch '{watch_id}': {reason}")]
    InvalidWatch { watch_id: String, reason: String },
}

/// Validate a verified `WatchBundlePayload` against host binding, monotonic
/// version high-water mark, expiry/clock skew, and every local safety ceiling.
pub fn validate_bundle(
    bundle: &WatchBundlePayload,
    payload_digest: &str,
    local_host_id: &str,
    hwm: Option<&BundleHighWaterMark>,
    cfg: &EdgeSafetyConfig,
    now: DateTime<Utc>,
) -> Result<BundleValidationOutcome, EdgeFloorError> {
    validate_bundle_header(bundle, local_host_id, cfg, now)?;
    if bundle.expires_at + Duration::seconds(cfg.max_clock_skew_seconds) < now {
        return Err(EdgeFloorError::BundleExpired);
    }
    let outcome = if let Some(mark) = hwm {
        if bundle.bundle_version < mark.bundle_version {
            return Err(EdgeFloorError::StaleBundleVersion {
                incoming: bundle.bundle_version,
                current: mark.bundle_version,
            });
        }
        if bundle.bundle_version == mark.bundle_version {
            if payload_digest != mark.payload_digest {
                return Err(EdgeFloorError::ConflictingBundleDigest {
                    version: bundle.bundle_version,
                });
            }
            BundleValidationOutcome::IdenticalRetransmission
        } else {
            BundleValidationOutcome::AcceptNew
        }
    } else {
        BundleValidationOutcome::AcceptNew
    };
    validate_bundle_watches(bundle, cfg, now)?;
    Ok(outcome)
}

/// Revalidate the cached bundle against the current floor. An expired
/// bundle may still supply baseline watches during disconnected operation.
pub fn validate_cached_bundle(
    bundle: &WatchBundlePayload,
    local_host_id: &str,
    cfg: &EdgeSafetyConfig,
    now: DateTime<Utc>,
) -> Result<(), EdgeFloorError> {
    validate_bundle_header(bundle, local_host_id, cfg, now)?;
    validate_bundle_watches(bundle, cfg, now)
}

fn validate_bundle_header(
    bundle: &WatchBundlePayload,
    local_host_id: &str,
    cfg: &EdgeSafetyConfig,
    now: DateTime<Utc>,
) -> Result<(), EdgeFloorError> {
    if bundle.schema_version != WATCH_BUNDLE_SCHEMA_VERSION {
        return Err(EdgeFloorError::UnsupportedSchemaVersion(
            bundle.schema_version,
        ));
    }
    if bundle.policy_version != cfg.expected_policy_version {
        return Err(EdgeFloorError::PolicyVersionMismatch {
            expected: cfg.expected_policy_version,
            actual: bundle.policy_version,
        });
    }
    if bundle.target_host_id != local_host_id {
        return Err(EdgeFloorError::HostMismatch {
            expected: local_host_id.to_string(),
            actual: bundle.target_host_id.clone(),
        });
    }
    if bundle.expires_at <= bundle.issued_at {
        return Err(EdgeFloorError::InvalidValidityWindow);
    }

    let skew = Duration::seconds(cfg.max_clock_skew_seconds);
    if bundle.issued_at > now + skew {
        return Err(EdgeFloorError::IssuedInFuture);
    }
    Ok(())
}

fn validate_bundle_watches(
    bundle: &WatchBundlePayload,
    cfg: &EdgeSafetyConfig,
    now: DateTime<Utc>,
) -> Result<(), EdgeFloorError> {
    let local_host_id = &bundle.target_host_id;
    if bundle.watches.len() > cfg.max_watches_total {
        return Err(EdgeFloorError::TooManyWatches {
            count: bundle.watches.len(),
            max: cfg.max_watches_total,
        });
    }

    let mut seen_ids = HashSet::with_capacity(bundle.watches.len());
    let mut ephemeral_count = 0usize;

    for watch in &bundle.watches {
        if !seen_ids.insert(watch.id.as_str()) {
            return Err(EdgeFloorError::DuplicateWatchId(watch.id.clone()));
        }
        if &watch.host_id != local_host_id {
            return Err(EdgeFloorError::InvalidWatch {
                watch_id: watch.id.clone(),
                reason: format!(
                    "watch host_id '{}' does not match bundle target '{}'",
                    watch.host_id, local_host_id
                ),
            });
        }
        if watch.class == WatchClass::Ephemeral {
            ephemeral_count += 1;
        }
        validate_watch_spec(watch, cfg, now)?;
    }

    if ephemeral_count > cfg.max_ephemeral_watches {
        return Err(EdgeFloorError::TooManyEphemeralWatches {
            count: ephemeral_count,
            max: cfg.max_ephemeral_watches,
        });
    }

    Ok(())
}

/// Validate a single `WatchSpec` against local safety limits.
pub fn validate_watch_spec(
    watch: &WatchSpec,
    cfg: &EdgeSafetyConfig,
    now: DateTime<Utc>,
) -> Result<(), EdgeFloorError> {
    let err = |msg: String| EdgeFloorError::InvalidWatch {
        watch_id: watch.id.clone(),
        reason: msg,
    };

    if !is_valid_identifier(&watch.id) {
        return Err(err("watch id must be 1..=96 chars of [A-Za-z0-9._-]".into()));
    }
    if watch.version == 0 {
        return Err(err("watch version must be >= 1".into()));
    }
    if !cfg
        .allowed_collectors
        .contains(&watch.collector.collector_type())
    {
        return Err(err(format!(
            "collector '{}' is not allowed by local safety floor",
            watch.collector.collector_type().as_str()
        )));
    }

    if watch.schedule.interval_seconds < cfg.min_interval_seconds {
        return Err(err(format!(
            "interval_seconds {} is below local floor {}",
            watch.schedule.interval_seconds, cfg.min_interval_seconds
        )));
    }
    if watch.schedule.timeout_seconds == 0
        || watch.schedule.timeout_seconds > cfg.max_timeout_seconds
    {
        return Err(err(format!(
            "timeout_seconds {} must be within 1..={}",
            watch.schedule.timeout_seconds, cfg.max_timeout_seconds
        )));
    }
    if watch.schedule.timeout_seconds >= watch.schedule.interval_seconds {
        return Err(err(
            "timeout_seconds must be strictly less than interval_seconds".into(),
        ));
    }

    // Ephemeral watches MUST have explicit bounded TTL and max_runs, and cannot
    // require an accepted_baseline (Section 6.1 / 6.3).
    if watch.class == WatchClass::Ephemeral {
        let Some(expires_at) = watch.lifecycle.expires_at else {
            return Err(err("ephemeral watch must declare lifecycle.expires_at".into()));
        };
        let max_expiry = now + Duration::seconds(cfg.max_ephemeral_ttl_seconds as i64 + cfg.max_clock_skew_seconds);
        if expires_at > max_expiry {
            return Err(err(format!(
                "ephemeral watch expires_at exceeds maximum TTL of {}s",
                cfg.max_ephemeral_ttl_seconds
            )));
        }
        let Some(max_runs) = watch.lifecycle.max_runs else {
            return Err(err("ephemeral watch must declare lifecycle.max_runs".into()));
        };
        if max_runs == 0 || max_runs > cfg.max_ephemeral_runs {
            return Err(err(format!(
                "ephemeral watch max_runs {} must be within 1..={}",
                max_runs, cfg.max_ephemeral_runs
            )));
        }
        if matches!(
            &watch.trigger,
            TriggerPredicate::FieldChanged {
                compare_against: CompareTarget::AcceptedBaseline,
                ..
            } | TriggerPredicate::SetDiff {
                compare_against: CompareTarget::AcceptedBaseline,
                ..
            }
        ) {
            return Err(err(
                "ephemeral watch cannot compare against accepted_baseline; use last_observed".into(),
            ));
        }
    }

    validate_collector_params(&watch.collector, cfg).map_err(err)?;
    validate_trigger_predicate(&watch.trigger, &watch.collector).map_err(err)?;

    Ok(())
}

fn validate_collector_params(
    collector: &CollectorSpec,
    cfg: &EdgeSafetyConfig,
) -> Result<(), String> {
    match collector {
        CollectorSpec::SocketsListening(p) => {
            if !p.include_tcp && !p.include_udp {
                return Err("sockets.listening must include at least one of tcp or udp".into());
            }
            Ok(())
        }
        CollectorSpec::SystemdUnitState(p) => validate_systemd_unit_name(&p.unit),
        CollectorSpec::FilesMetadata(p) => {
            if p.paths.is_empty() {
                return Err("files.metadata requires at least one path".into());
            }
            if p.paths.len() > cfg.max_paths_per_file_watch {
                return Err(format!(
                    "files.metadata path count {} exceeds ceiling {}",
                    p.paths.len(),
                    cfg.max_paths_per_file_watch
                ));
            }
            if let Some(max_bytes) = p.max_file_bytes
                && (max_bytes == 0 || max_bytes > cfg.max_file_hash_bytes)
            {
                return Err(format!(
                    "max_file_bytes {} must be within 1..={}",
                    max_bytes, cfg.max_file_hash_bytes
                ));
            }
            for raw_path in &p.paths {
                validate_file_path(raw_path, cfg)?;
            }
            Ok(())
        }
        CollectorSpec::JournalUnitEvents(p) => {
            validate_systemd_unit_name(&p.unit)?;
            if let Some(prio) = p.min_priority
                && prio > 7
            {
                return Err("journal.unit_events min_priority must be 0..=7".into());
            }
            if let Some(max_events) = p.max_events_per_batch
                && (max_events == 0 || max_events > cfg.max_journal_batch_events)
            {
                return Err(format!(
                    "max_events_per_batch {} must be within 1..={}",
                    max_events, cfg.max_journal_batch_events
                ));
            }
            if let Some(max_bytes) = p.max_message_bytes
                && (max_bytes == 0 || max_bytes > cfg.max_journal_message_bytes)
            {
                return Err(format!(
                    "max_message_bytes {} must be within 1..={}",
                    max_bytes, cfg.max_journal_message_bytes
                ));
            }
            Ok(())
        }
        CollectorSpec::ConnectionsOutbound(p) => {
            if !p.include_tcp && !p.include_udp {
                return Err(
                    "connections.outbound must include at least one of tcp or udp".into(),
                );
            }
            if let Some(max_flows) = p.max_flows {
                let ceiling = cfg
                    .max_outbound_flows
                    .min(defsec_protocol::watch::OUTBOUND_FLOWS_HARD_MAX);
                if max_flows == 0 || max_flows > ceiling {
                    return Err(format!(
                        "max_flows {} must be within 1..={ceiling} (hard max {}, local ceiling {})",
                        max_flows,
                        defsec_protocol::watch::OUTBOUND_FLOWS_HARD_MAX,
                        cfg.max_outbound_flows
                    ));
                }
            }
            Ok(())
        }
        CollectorSpec::PackagesInventory(p) => {
            if let Some(max_packages) = p.max_packages {
                let ceiling = cfg
                    .max_packages
                    .min(defsec_protocol::watch::PACKAGES_INVENTORY_HARD_MAX);
                if max_packages == 0 || max_packages > ceiling {
                    return Err(format!(
                        "max_packages {} must be within 1..={ceiling} (hard max {}, local ceiling {})",
                        max_packages,
                        defsec_protocol::watch::PACKAGES_INVENTORY_HARD_MAX,
                        cfg.max_packages
                    ));
                }
            }
            Ok(())
        }
    }
}

fn validate_trigger_predicate(
    predicate: &TriggerPredicate,
    collector: &CollectorSpec,
) -> Result<(), String> {
    match predicate {
        TriggerPredicate::FieldChanged { fields, .. } => {
            if fields.is_empty() || fields.len() > 32 {
                return Err("field_changed must specify 1..=32 fields".into());
            }
            for f in fields {
                if !is_valid_field_name(f) {
                    return Err(format!("invalid field name '{f}'"));
                }
            }
            Ok(())
        }
        TriggerPredicate::SetDiff {
            set_field,
            identity_key,
            ignore_fields,
            ..
        } => {
            if !is_valid_field_name(set_field) || !is_valid_field_name(identity_key) {
                return Err("set_diff field names must be valid identifiers".into());
            }
            if ignore_fields.len() > 8 || ignore_fields.iter().any(|f| !is_valid_field_name(f)) {
                return Err(
                    "set_diff ignore_fields must contain at most 8 valid identifiers".into(),
                );
            }
            Ok(())
        }
        TriggerPredicate::ThresholdSustained {
            field,
            consecutive_samples,
            ..
        } => {
            if !is_valid_field_name(field) {
                return Err(format!("invalid threshold field '{field}'"));
            }
            if *consecutive_samples == 0 || *consecutive_samples > 1000 {
                return Err("consecutive_samples must be within 1..=1000".into());
            }
            if collector.collector_type().is_stream() {
                return Err("threshold_sustained is only valid on snapshot collectors".into());
            }
            Ok(())
        }
        TriggerPredicate::CollectorStaleOrError {
            max_stale_seconds,
            consecutive_errors,
        } => {
            if *max_stale_seconds == 0 || *consecutive_errors == 0 {
                return Err("collector_stale_or_error thresholds must be >= 1".into());
            }
            Ok(())
        }
    }
}

/// Strictly validate a systemd unit name (no shell metacharacters, path
/// separators, whitespace, or arbitrary strings).
pub fn validate_systemd_unit_name(unit: &str) -> Result<(), String> {
    const ALLOWED_SUFFIXES: &[&str] = &[
        ".service", ".socket", ".timer", ".target", ".path", ".mount", ".scope", ".slice",
    ];
    if unit.is_empty() || unit.len() > 128 {
        return Err("systemd unit name must be 1..=128 bytes".into());
    }
    if unit.starts_with('-') || unit.contains("..") {
        return Err(format!("unsafe systemd unit name '{unit}'"));
    }
    if !unit
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b':'))
    {
        return Err(format!(
            "systemd unit name '{unit}' contains forbidden characters"
        ));
    }
    if !ALLOWED_SUFFIXES.iter().any(|s| unit.ends_with(s)) {
        return Err(format!(
            "systemd unit name '{unit}' must end with an allowed unit suffix"
        ));
    }
    Ok(())
}

/// Lexically validate a file path against approved roots and sensitive denylists.
/// Note: `agent-d` additionally enforces kernel-level `openat2` (`RESOLVE_BENEATH`,
/// `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_XDEV`) at collection time.
pub fn validate_file_path(raw: &str, cfg: &EdgeSafetyConfig) -> Result<PathBuf, String> {
    if raw.is_empty() || raw.len() > 512 {
        return Err("file path length must be 1..=512 bytes".into());
    }
    if raw.bytes().any(|b| b == 0 || b < 0x20) {
        return Err("file path contains control characters or NUL".into());
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(format!("file path '{raw}' must be absolute"));
    }

    // Reject any `.` or `..` components outright rather than normalizing away traversal attempts.
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(format!("file path '{raw}' contains forbidden traversal component"));
            }
        }
    }

    // Check sensitive denylist first (defense in depth even if an admin accidentally widens roots).
    for denied in &cfg.denied_path_prefixes {
        if path.starts_with(denied) {
            return Err(format!(
                "file path '{raw}' is blocked by local sensitive path denylist"
            ));
        }
    }

    if let Some(fname) = path.file_name().and_then(|f| f.to_str()) {
        let lower = fname.to_ascii_lowercase();
        if cfg
            .denied_exact_filenames
            .iter()
            .any(|d| lower == d.to_ascii_lowercase())
        {
            return Err(format!(
                "filename '{fname}' is blocked by local sensitive filename denylist"
            ));
        }
        if cfg
            .denied_filename_suffixes
            .iter()
            .any(|s| lower.ends_with(&s.to_ascii_lowercase()))
        {
            return Err(format!(
                "filename '{fname}' matches a denied sensitive suffix"
            ));
        }
    } else {
        return Err(format!("file path '{raw}' must refer to a regular file"));
    }

    // Must fall beneath at least one approved root.
    let under_approved_root = cfg
        .approved_file_roots
        .iter()
        .any(|root| path.starts_with(root) && path != root);
    if !under_approved_root {
        return Err(format!(
            "file path '{raw}' is outside all locally approved file roots"
        ));
    }

    Ok(path.to_path_buf())
}

pub fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub fn is_valid_field_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use defsec_protocol::watch::{
        FilesMetadataParams, SystemdUnitStateParams, WakePolicy, WatchLifecycle, WatchSchedule,
    };

    fn sample_watch(id: &str, host: &str, class: WatchClass, now: DateTime<Utc>) -> WatchSpec {
        WatchSpec {
            id: id.into(),
            version: 1,
            host_id: host.into(),
            class,
            incident_id: (class == WatchClass::Ephemeral).then(|| "inc-1".into()),
            collector: CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
                unit: "sshd.service".into(),
                hash_unit_files: true,
            }),
            schedule: WatchSchedule {
                interval_seconds: 30,
                timeout_seconds: 5,
            },
            trigger: TriggerPredicate::FieldChanged {
                compare_against: CompareTarget::LastObserved,
                fields: vec!["active_state".into()],
            },
            wake_policy: WakePolicy {
                cooldown_seconds: 120,
                max_wakeups_per_hour: 4,
            },
            lifecycle: WatchLifecycle {
                enabled: true,
                expires_at: (class == WatchClass::Ephemeral).then(|| now + Duration::hours(1)),
                max_runs: (class == WatchClass::Ephemeral).then_some(120),
            },
        }
    }

    fn sample_bundle(host: &str, version: u64, watches: Vec<WatchSpec>, now: DateTime<Utc>) -> WatchBundlePayload {
        WatchBundlePayload {
            schema_version: WATCH_BUNDLE_SCHEMA_VERSION,
            bundle_id: format!("bundle-{version}"),
            target_host_id: host.into(),
            bundle_version: version,
            issued_at: now,
            expires_at: now + Duration::hours(12),
            policy_version: 1,
            watches,
        }
    }

    #[test]
    fn identical_retransmission_revalidates_effective_watch_floor() {
        let now = Utc::now();
        let watch = sample_watch("w1", "edge-01", WatchClass::Baseline, now);
        let collector = watch.collector.collector_type();
        let bundle = sample_bundle("edge-01", 5, vec![watch], now);
        let hwm = BundleHighWaterMark {
            bundle_version: 5,
            payload_digest: "digest-a".into(),
        };
        let tightened = EdgeSafetyConfig {
            allowed_collectors: BTreeSet::new(),
            ..Default::default()
        };
        assert!(matches!(
            validate_bundle(&bundle, "digest-a", "edge-01", Some(&hwm), &tightened, now),
            Err(EdgeFloorError::InvalidWatch { watch_id, reason })
                if watch_id == "w1" && reason.contains(collector.as_str())
        ));
    }

    #[test]
    fn accepts_valid_bundle_and_identical_retransmission_but_rejects_replay_or_wrong_host() {
        let now = Utc::now();
        let cfg = EdgeSafetyConfig::default();
        let w = sample_watch("w1", "edge-01", WatchClass::Baseline, now);
        let bundle = sample_bundle("edge-01", 5, vec![w], now);

        assert_eq!(
            validate_bundle(&bundle, "digest-a", "edge-01", None, &cfg, now).unwrap(),
            BundleValidationOutcome::AcceptNew
        );

        let hwm = BundleHighWaterMark {
            bundle_version: 5,
            payload_digest: "digest-a".into(),
        };
        assert_eq!(
            validate_bundle(&bundle, "digest-a", "edge-01", Some(&hwm), &cfg, now).unwrap(),
            BundleValidationOutcome::IdenticalRetransmission
        );
        assert!(matches!(
            validate_bundle(&bundle, "digest-b", "edge-01", Some(&hwm), &cfg, now),
            Err(EdgeFloorError::ConflictingBundleDigest { version: 5 })
        ));

        let stale = sample_bundle("edge-01", 4, vec![], now);
        assert!(matches!(
            validate_bundle(&stale, "digest-c", "edge-01", Some(&hwm), &cfg, now),
            Err(EdgeFloorError::StaleBundleVersion { incoming: 4, current: 5 })
        ));

        assert!(matches!(
            validate_bundle(&bundle, "digest-a", "edge-02", None, &cfg, now),
            Err(EdgeFloorError::HostMismatch { .. })
        ));
    }

    #[test]
    fn blocks_sensitive_paths_traversal_and_shell_units() {
        let cfg = EdgeSafetyConfig::default();
        assert!(validate_file_path("/etc/ssh/sshd_config", &cfg).is_ok());
        assert!(validate_file_path("/etc/shadow", &cfg).is_err());
        assert!(validate_file_path("/etc/ssh/ssh_host_ed25519_key", &cfg).is_err());
        assert!(validate_file_path("/etc/ssh/../shadow", &cfg).is_err());
        assert!(validate_file_path("/home/alice/.ssh/id_rsa", &cfg).is_err());
        assert!(validate_file_path("/var/lib/other/file.txt", &cfg).is_err());

        assert!(validate_systemd_unit_name("sshd.service").is_ok());
        assert!(validate_systemd_unit_name("sshd.service; rm -rf /").is_err());
        assert!(validate_systemd_unit_name("../sshd.service").is_err());
        assert!(validate_systemd_unit_name("-n").is_err());
        assert!(validate_systemd_unit_name("sshd.evil").is_err());
    }

    #[test]
    fn enforces_ephemeral_ttl_max_runs_and_interval_floor() {
        let now = Utc::now();
        let cfg = EdgeSafetyConfig::default();

        let mut fast = sample_watch("w-fast", "edge-01", WatchClass::Ephemeral, now);
        fast.schedule.interval_seconds = 5;
        assert!(validate_watch_spec(&fast, &cfg, now).is_err());

        let mut no_ttl = sample_watch("w-nottl", "edge-01", WatchClass::Ephemeral, now);
        no_ttl.lifecycle.expires_at = None;
        assert!(validate_watch_spec(&no_ttl, &cfg, now).is_err());

        let mut huge_ttl = sample_watch("w-hugettl", "edge-01", WatchClass::Ephemeral, now);
        huge_ttl.lifecycle.expires_at = Some(now + Duration::hours(24));
        assert!(validate_watch_spec(&huge_ttl, &cfg, now).is_err());

        let mut bad_files = sample_watch("w-files", "edge-01", WatchClass::Ephemeral, now);
        bad_files.collector = CollectorSpec::FilesMetadata(FilesMetadataParams {
            paths: vec!["/etc/shadow".into()],
            compute_hash: true,
            max_file_bytes: Some(1024),
        });
        assert!(validate_watch_spec(&bad_files, &cfg, now).is_err());
    }

    #[test]
    fn new_collectors_are_allowed_and_bounds_enforced() {
        use defsec_protocol::watch::{
            ConnectionsOutboundParams, PackagesInventoryParams, OUTBOUND_FLOWS_HARD_MAX,
            PACKAGES_INVENTORY_HARD_MAX,
        };

        let now = Utc::now();
        let cfg = EdgeSafetyConfig::default();
        assert!(cfg.allowed_collectors.contains(&CollectorType::ConnectionsOutbound));
        assert!(cfg.allowed_collectors.contains(&CollectorType::PackagesInventory));
        assert_eq!(cfg.max_outbound_flows, 512);
        assert_eq!(cfg.max_packages, 16384);

        let outbound_watch = |max_flows: Option<u32>| {
            let mut w = sample_watch("w-out", "edge-01", WatchClass::Ephemeral, now);
            w.collector = CollectorSpec::ConnectionsOutbound(ConnectionsOutboundParams {
                include_tcp: true,
                include_udp: true,
                include_ipv6: true,
                resolve_process: false,
                exclude_loopback: true,
                max_flows,
            });
            w
        };
        assert!(validate_watch_spec(&outbound_watch(None), &cfg, now).is_ok());
        assert!(validate_watch_spec(&outbound_watch(Some(256)), &cfg, now).is_ok());
        let zero = validate_watch_spec(&outbound_watch(Some(0)), &cfg, now).unwrap_err();
        assert!(zero.to_string().contains("max_flows 0"));
        let over_local = validate_watch_spec(&outbound_watch(Some(513)), &cfg, now).unwrap_err();
        assert!(over_local.to_string().contains("1..=512"));
        let over_hard = validate_watch_spec(&outbound_watch(Some(10_000)), &cfg, now).unwrap_err();
        assert!(over_hard.to_string().contains("hard max"));

        // A tightened local ceiling tightens the acceptance range.
        let mut tight = cfg.clone();
        tight.max_outbound_flows = 64;
        assert!(validate_watch_spec(&outbound_watch(Some(64)), &tight, now).is_ok());
        let over = validate_watch_spec(&outbound_watch(Some(65)), &tight, now).unwrap_err();
        assert!(over.to_string().contains("1..=64"));

        // Both protocols disabled is rejected.
        let mut none = outbound_watch(None);
        if let CollectorSpec::ConnectionsOutbound(p) = &mut none.collector {
            p.include_tcp = false;
            p.include_udp = false;
        }
        assert!(validate_watch_spec(&none, &cfg, now).is_err());

        let packages_watch = |max_packages: Option<u32>| {
            let mut w = sample_watch("w-pkg", "edge-01", WatchClass::Ephemeral, now);
            w.collector = CollectorSpec::PackagesInventory(PackagesInventoryParams {
                max_packages,
            });
            w
        };
        assert!(validate_watch_spec(&packages_watch(None), &cfg, now).is_ok());
        assert!(validate_watch_spec(&packages_watch(Some(4096)), &cfg, now).is_ok());
        assert!(validate_watch_spec(&packages_watch(Some(0)), &cfg, now).is_err());
        let over = validate_watch_spec(&packages_watch(Some(20_000)), &cfg, now).unwrap_err();
        assert!(over.to_string().contains("1..=16384"));
        assert_eq!(PACKAGES_INVENTORY_HARD_MAX, 16384);
        assert_eq!(OUTBOUND_FLOWS_HARD_MAX, 1024);

        // A collector disabled by a tightened allowlist is rejected.
        let mut restricted = cfg.clone();
        restricted.allowed_collectors.remove(&CollectorType::PackagesInventory);
        let err = validate_watch_spec(&packages_watch(None), &restricted, now).unwrap_err();
        assert!(err.to_string().contains("packages.inventory"));
        assert!(err.to_string().contains("not allowed"));
    }
}
