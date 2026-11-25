//! Strongly typed, non-Turing-complete Watch Specification DSL and
//! Signed Watch Bundle payload schemas.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const WATCH_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Baseline watches are admin-owned and immutable to reasoning identities.
/// Ephemeral watches are short-lived, bounded follow-up observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchClass {
    Baseline,
    Ephemeral,
}

/// Closed catalog of built-in MVP collector capability IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CollectorType {
    #[serde(rename = "sockets.listening")]
    SocketsListening,
    #[serde(rename = "systemd.unit_state")]
    SystemdUnitState,
    #[serde(rename = "files.metadata")]
    FilesMetadata,
    #[serde(rename = "journal.unit_events")]
    JournalUnitEvents,
}

impl CollectorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SocketsListening => "sockets.listening",
            Self::SystemdUnitState => "systemd.unit_state",
            Self::FilesMetadata => "files.metadata",
            Self::JournalUnitEvents => "journal.unit_events",
        }
    }

    pub fn is_stream(&self) -> bool {
        matches!(self, Self::JournalUnitEvents)
    }
}

/// Typed collector configuration. No arbitrary shell or script strings exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "parameters", deny_unknown_fields)]
pub enum CollectorSpec {
    #[serde(rename = "sockets.listening")]
    SocketsListening(SocketsListeningParams),
    #[serde(rename = "systemd.unit_state")]
    SystemdUnitState(SystemdUnitStateParams),
    #[serde(rename = "files.metadata")]
    FilesMetadata(FilesMetadataParams),
    #[serde(rename = "journal.unit_events")]
    JournalUnitEvents(JournalUnitEventsParams),
}

impl CollectorSpec {
    pub fn collector_type(&self) -> CollectorType {
        match self {
            Self::SocketsListening(_) => CollectorType::SocketsListening,
            Self::SystemdUnitState(_) => CollectorType::SystemdUnitState,
            Self::FilesMetadata(_) => CollectorType::FilesMetadata,
            Self::JournalUnitEvents(_) => CollectorType::JournalUnitEvents,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketsListeningParams {
    #[serde(default = "default_true")]
    pub include_tcp: bool,
    #[serde(default = "default_true")]
    pub include_udp: bool,
    #[serde(default = "default_true")]
    pub include_ipv6: bool,
    #[serde(default = "default_true")]
    pub resolve_process: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnitStateParams {
    pub unit: String,
    #[serde(default = "default_true")]
    pub hash_unit_files: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesMetadataParams {
    pub paths: Vec<String>,
    #[serde(default = "default_true")]
    pub compute_hash: bool,
    #[serde(default)]
    pub max_file_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalUnitEventsParams {
    pub unit: String,
    /// Syslog priority threshold 0 (emerg) .. 7 (debug). Defaults to 6 (info).
    #[serde(default)]
    pub min_priority: Option<u8>,
    #[serde(default)]
    pub max_events_per_batch: Option<u32>,
    #[serde(default)]
    pub max_message_bytes: Option<usize>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchSchedule {
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompareTarget {
    LastObserved,
    AcceptedBaseline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdOp {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
    Neq,
}

/// Closed tagged union of deterministic trigger predicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TriggerPredicate {
    FieldChanged {
        compare_against: CompareTarget,
        fields: Vec<String>,
    },
    SetDiff {
        compare_against: CompareTarget,
        set_field: String,
        identity_key: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ignore_fields: Vec<String>,
    },
    ThresholdSustained {
        field: String,
        operator: ThresholdOp,
        threshold: i64,
        consecutive_samples: u32,
    },
    CollectorStaleOrError {
        max_stale_seconds: u64,
        consecutive_errors: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakePolicy {
    pub cooldown_seconds: u64,
    pub max_wakeups_per_hour: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchLifecycle {
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub max_runs: Option<u64>,
}

/// Complete declarative watch specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchSpec {
    pub id: String,
    pub version: u32,
    pub host_id: String,
    pub class: WatchClass,
    #[serde(default)]
    pub incident_id: Option<String>,
    pub collector: CollectorSpec,
    pub schedule: WatchSchedule,
    pub trigger: TriggerPredicate,
    pub wake_policy: WakePolicy,
    pub lifecycle: WatchLifecycle,
}

/// Desired-state bundle payload signed by `control-d` and synchronized to `agent-d`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchBundlePayload {
    pub schema_version: u32,
    pub bundle_id: String,
    pub target_host_id: String,
    pub bundle_version: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub policy_version: u32,
    pub watches: Vec<WatchSpec>,
}

/// Capability descriptor advertised to scoped reasoning clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorCapability {
    pub collector_type: CollectorType,
    pub schema_version: u32,
    pub is_stream: bool,
    pub sensitivity: DataClassification,
    pub min_interval_seconds: u64,
    pub description: String,
    pub declared_privileges: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    MetadataLow,
    MetadataSensitive,
    BoundedRedactedText,
    RestrictedLocalOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_set_diff_watch_preserves_signed_canonical_bytes() {
        const LEGACY: &str = concat!(
            r#"{"class":"baseline","collector":{"parameters":{"include_ipv6":true,"include_tcp":true,"include_udp":true,"resolve_process":true},"type":"sockets.listening"},"host_id":"edge-1","id":"sockets","incident_id":null,"#,
            r#""lifecycle":{"enabled":true,"expires_at":null,"max_runs":null},"schedule":{"interval_seconds":30,"timeout_seconds":5},"trigger":{"compare_against":"accepted_baseline","identity_key":"socket_key","set_field":"sockets","type":"set_diff"},"version":1,"wake_policy":{"cooldown_seconds":60,"max_wakeups_per_hour":4}}"#
        );
        let spec: WatchSpec = serde_json::from_str(LEGACY).unwrap();
        assert_eq!(
            crate::canonical::to_canonical_json_bytes(&spec).unwrap(),
            LEGACY.as_bytes()
        );
    }

    #[test]
    fn rejects_unknown_fields_in_watch_spec() {
        let raw = r#"{
            "id": "w1",
            "version": 1,
            "host_id": "edge-1",
            "class": "ephemeral",
            "incident_id": "inc-1",
            "collector": {
                "type": "systemd.unit_state",
                "parameters": {
                    "unit": "sshd.service",
                    "shell_cmd": "cat /etc/shadow"
                }
            },
            "schedule": { "interval_seconds": 30, "timeout_seconds": 5 },
            "trigger": {
                "type": "field_changed",
                "compare_against": "last_observed",
                "fields": ["active_state"]
            },
            "wake_policy": { "cooldown_seconds": 60, "max_wakeups_per_hour": 4 },
            "lifecycle": { "enabled": true }
        }"#;
        let parsed: Result<WatchSpec, _> = serde_json::from_str(raw);
        assert!(parsed.is_err(), "unknown collector parameter must be rejected");
    }

    #[test]
    fn rejects_unknown_collector_type() {
        let raw = r#"{
            "type": "shell.exec",
            "parameters": { "cmd": "id" }
        }"#;
        let parsed: Result<CollectorSpec, _> = serde_json::from_str(raw);
        assert!(parsed.is_err());
    }
}
