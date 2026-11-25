//! Admin-owned host profile: per-host customization of what an edge agent
//! collects. Loaded from a local JSON file owned by host administration —
//! never from the signed watch bundle channel.
//!
//! A profile can only TIGHTEN the local edge safety floor: collector caps
//! take `min(builtin, profile)` and `enabled_collectors` intersects the
//! built-in allowlist. `approved_file_roots` is the one additive field, and
//! even then the hard sensitive-path denylist still applies at collection
//! time, and roots beneath a denied prefix are rejected at load.

use serde::{Deserialize, Serialize};

use crate::watch::CollectorType;

/// The only supported host profile schema version.
pub const HOST_PROFILE_SCHEMA_VERSION: u32 = 1;

/// Maximum number of host tags in a profile.
pub const MAX_HOST_TAGS: usize = 16;
/// Maximum number of expected services in a profile.
pub const MAX_EXPECTED_SERVICES: usize = 64;
/// Maximum number of additional approved file roots in a profile.
pub const MAX_PROFILE_FILE_ROOTS: usize = 32;

/// True when `tag` matches `^[a-z0-9][a-z0-9:._-]{0,63}$`.
pub fn is_valid_host_tag(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    if bytes.len() > 64 {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'.' | b'_' | b'-'))
}

/// Per-collector ceiling overrides. Each value can only tighten the built-in
/// edge floor (`min` is applied); a wider value is clamped, never widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CollectorCaps {
    #[serde(default)]
    pub max_outbound_flows: Option<u32>,
    #[serde(default)]
    pub max_packages: Option<u32>,
    #[serde(default)]
    pub max_file_hash_bytes: Option<u64>,
    #[serde(default)]
    pub max_journal_batch_events: Option<u32>,
}

/// Local, admin-owned host profile (see `docs/operations-and-deployment.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfile {
    /// Must be [`HOST_PROFILE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Free-form fleet labels, each matching `^[a-z0-9][a-z0-9:._-]{0,63}$`.
    #[serde(default)]
    pub host_tags: Vec<String>,
    /// Systemd unit names expected to exist on this host.
    #[serde(default)]
    pub expected_services: Vec<String>,
    /// Additional approved file roots. Additive to the built-in roots; the
    /// hard denylist still applies and denied-prefixed roots are rejected.
    #[serde(default)]
    pub approved_file_roots: Vec<String>,
    /// `None` means all built-in allowed collectors stay enabled;
    /// `Some(list)` intersects the built-in allowlist.
    #[serde(default)]
    pub enabled_collectors: Option<Vec<CollectorType>>,
    #[serde(default)]
    pub collector_caps: CollectorCaps,
}

/// Summary of an applied profile reported to the control plane on Register.
/// The control plane treats it as informational in this schema version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfileSummary {
    pub host_tags: Vec<String>,
    pub expected_services: Vec<String>,
    /// Effective enabled collectors after intersecting with the built-in
    /// allowlist (sorted; `None` profile means every built-in collector).
    pub enabled_collectors: Vec<CollectorType>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_tag_rules() {
        assert!(is_valid_host_tag("edge"));
        assert!(is_valid_host_tag("a"));
        assert!(is_valid_host_tag("0dc:prod.eu-west_1"));
        assert!(is_valid_host_tag(&"x".repeat(64)));
        // First char must be [a-z0-9]; body charset and length are enforced.
        assert!(!is_valid_host_tag(""));
        assert!(!is_valid_host_tag("-edge"));
        assert!(!is_valid_host_tag(".edge"));
        assert!(!is_valid_host_tag("Edge"));
        assert!(!is_valid_host_tag("edge labs"));
        assert!(!is_valid_host_tag(&"x".repeat(65)));
    }

    #[test]
    fn profile_serde_rejects_unknown_fields_and_defaults() {
        let raw = r#"{"schema_version": 1}"#;
        let profile: HostProfile = serde_json::from_str(raw).unwrap();
        assert_eq!(profile.schema_version, HOST_PROFILE_SCHEMA_VERSION);
        assert_eq!(profile.host_tags, Vec::<String>::new());
        assert_eq!(profile.expected_services, Vec::<String>::new());
        assert_eq!(profile.approved_file_roots, Vec::<String>::new());
        assert_eq!(profile.enabled_collectors, None);
        assert_eq!(profile.collector_caps, CollectorCaps::default());

        let bad = r#"{"schema_version": 1, "shell_cmd": "id"}"#;
        assert!(serde_json::from_str::<HostProfile>(bad).is_err());

        assert!(serde_json::from_str::<CollectorCaps>(r#"{"max_packages": 100, "extra": 1}"#).is_err());
        let caps: CollectorCaps = serde_json::from_str(r#"{"max_packages": 100}"#).unwrap();
        assert_eq!(caps.max_packages, Some(100));
        assert_eq!(caps.max_outbound_flows, None);
    }
}
