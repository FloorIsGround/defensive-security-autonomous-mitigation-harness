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
    #[serde(rename = "connections.outbound")]
    ConnectionsOutbound,
    #[serde(rename = "packages.inventory")]
    PackagesInventory,
}

impl CollectorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SocketsListening => "sockets.listening",
            Self::SystemdUnitState => "systemd.unit_state",
            Self::FilesMetadata => "files.metadata",
            Self::JournalUnitEvents => "journal.unit_events",
            Self::ConnectionsOutbound => "connections.outbound",
            Self::PackagesInventory => "packages.inventory",
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
    #[serde(rename = "connections.outbound")]
    ConnectionsOutbound(ConnectionsOutboundParams),
    #[serde(rename = "packages.inventory")]
    PackagesInventory(PackagesInventoryParams),
}

impl CollectorSpec {
    pub fn collector_type(&self) -> CollectorType {
        match self {
            Self::SocketsListening(_) => CollectorType::SocketsListening,
            Self::SystemdUnitState(_) => CollectorType::SystemdUnitState,
            Self::FilesMetadata(_) => CollectorType::FilesMetadata,
            Self::JournalUnitEvents(_) => CollectorType::JournalUnitEvents,
            Self::ConnectionsOutbound(_) => CollectorType::ConnectionsOutbound,
            Self::PackagesInventory(_) => CollectorType::PackagesInventory,
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

/// Default retained outbound flow groups when `max_flows` is unset.
pub const OUTBOUND_FLOWS_DEFAULT: u32 = 256;
/// Hard ceiling for `max_flows` regardless of local configuration.
pub const OUTBOUND_FLOWS_HARD_MAX: u32 = 1024;

/// Default retained package entries when `max_packages` is unset.
pub const PACKAGES_INVENTORY_DEFAULT: u32 = 4096;
/// Hard ceiling for `max_packages` regardless of local configuration.
pub const PACKAGES_INVENTORY_HARD_MAX: u32 = 16384;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionsOutboundParams {
    #[serde(default = "default_true")]
    pub include_tcp: bool,
    /// Connected UDP sockets only (unconnected rows carry a zero remote).
    #[serde(default)]
    pub include_udp: bool,
    #[serde(default = "default_true")]
    pub include_ipv6: bool,
    #[serde(default = "default_true")]
    pub resolve_process: bool,
    #[serde(default = "default_true")]
    pub exclude_loopback: bool,
    /// Retained flow groups; defaults to [`OUTBOUND_FLOWS_DEFAULT`].
    #[serde(default)]
    pub max_flows: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagesInventoryParams {
    /// Retained package entries; defaults to [`PACKAGES_INVENTORY_DEFAULT`].
    #[serde(default)]
    pub max_packages: Option<u32>,
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

    #[test]
    fn outbound_and_packages_specs_roundtrip_with_defaults() {
        let raw = r#"{"type": "connections.outbound", "parameters": {}}"#;
        let spec: CollectorSpec = serde_json::from_str(raw).unwrap();
        assert_eq!(spec.collector_type(), CollectorType::ConnectionsOutbound);
        assert!(!spec.collector_type().is_stream());
        let CollectorSpec::ConnectionsOutbound(p) = &spec else {
            panic!("wrong variant");
        };
        assert!(p.include_tcp && p.include_ipv6 && p.resolve_process && p.exclude_loopback);
        assert!(!p.include_udp);
        assert_eq!(p.max_flows, None);
        // Round trip is stable and unknown fields are rejected.
        assert_eq!(serde_json::to_value(&spec).unwrap(), serde_json::json!({
            "type": "connections.outbound",
            "parameters": {
                "include_tcp": true, "include_udp": false, "include_ipv6": true,
                "resolve_process": true, "exclude_loopback": true, "max_flows": null
            }
        }));
        assert!(serde_json::from_str::<CollectorSpec>(
            r#"{"type": "connections.outbound", "parameters": {"shell_cmd": "x"}}"#
        )
        .is_err());

        let raw = r#"{"type": "packages.inventory", "parameters": {"max_packages": 10}}"#;
        let spec: CollectorSpec = serde_json::from_str(raw).unwrap();
        assert_eq!(spec.collector_type(), CollectorType::PackagesInventory);
        assert!(!spec.collector_type().is_stream());
        let CollectorSpec::PackagesInventory(p) = &spec else {
            panic!("wrong variant");
        };
        assert_eq!(p.max_packages, Some(10));
        assert!(serde_json::from_str::<CollectorSpec>(
            r#"{"type": "packages.inventory", "parameters": {"path": "/etc/passwd"}}"#
        )
        .is_err());
    }

    #[test]
    fn collector_type_wire_names_are_stable() {
        assert_eq!(CollectorType::ConnectionsOutbound.as_str(), "connections.outbound");
        assert_eq!(
            serde_json::to_value(CollectorType::ConnectionsOutbound).unwrap(),
            serde_json::json!("connections.outbound")
        );
        assert_eq!(CollectorType::PackagesInventory.as_str(), "packages.inventory");
        assert_eq!(
            serde_json::to_value(CollectorType::PackagesInventory).unwrap(),
            serde_json::json!("packages.inventory")
        );
    }
}
