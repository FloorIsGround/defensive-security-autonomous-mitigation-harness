//! Normalized observation payloads, collector schemas, and explicit
//! status/completeness semantics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::watch::{CollectorType, DataClassification};

/// Explicit observation completeness/error status. Errors and partial visibility
/// are first-class states and never masquerade as healthy empty snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Ok,
    Partial,
    PermissionDenied,
    NotFound,
    Timeout,
    TruncatedRejected,
    Error,
}

impl ObservationStatus {
    /// Whether this sample represents a usable state observation for baseline/diffing.
    pub fn is_valid_sample(&self) -> bool {
        matches!(self, Self::Ok | Self::Partial)
    }
}

/// Normalized entry emitted by `sockets.listening`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListeningSocketEntry {
    /// Stable identity key: e.g., `tcp6:[::]:22:uid=0`
    pub socket_key: String,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub uid: u32,
    pub inode: u64,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub pid_start_time_ticks: Option<u64>,
    #[serde(default)]
    pub comm: Option<String>,
    #[serde(default)]
    pub systemd_unit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketsListeningSnapshot {
    pub count: usize,
    pub partial_attribution: bool,
    pub sockets: Vec<ListeningSocketEntry>,
}

/// Normalized hash metadata for a single unit file or drop-in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitFileHashEntry {
    pub path: String,
    pub status: ObservationStatus,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
}

/// Normalized snapshot emitted by `systemd.unit_state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnitSnapshot {
    pub unit: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    #[serde(default)]
    pub unit_file_state: Option<String>,
    #[serde(default)]
    pub main_pid: Option<u32>,
    #[serde(default)]
    pub main_pid_start_time_ticks: Option<u64>,
    #[serde(default)]
    pub exec_start_hash: Option<String>,
    #[serde(default)]
    pub unit_files: Vec<UnitFileHashEntry>,
}

/// Normalized metadata entry emitted by `files.metadata`. No raw file contents.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMetadataEntry {
    pub path: String,
    pub status: ObservationStatus,
    #[serde(default)]
    pub mode_octal: Option<String>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub mtime_unix: Option<i64>,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesMetadataSnapshot {
    pub count: usize,
    pub files: Vec<FileMetadataEntry>,
}

/// Process-attribution completeness for one outbound flow group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowAttribution {
    /// Every socket in the group resolved to a process.
    Full,
    /// Only some sockets in the group resolved to a process.
    Partial,
    /// No socket in the group resolved to a process (or resolution disabled).
    None,
}

/// One normalized outbound flow group emitted by `connections.outbound`.
/// Local ephemeral ports and PIDs are deliberately excluded: they churn and
/// would make the snapshot unstable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundFlowEntry {
    /// Stable identity: `<proto>:<remote_addr>:<remote_port>:<uid>:<comm or '?'>`
    pub flow_key: String,
    /// `tcp` | `tcp6` | `udp` | `udp6`
    pub protocol: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub uid: u32,
    /// Sorted unique `/proc/net` state names for the grouped sockets.
    pub states: Vec<String>,
    /// Number of individual sockets in this group.
    pub count: u32,
    #[serde(default)]
    pub comm: Option<String>,
    #[serde(default)]
    pub systemd_unit: Option<String>,
    pub attribution: FlowAttribution,
}

/// Normalized snapshot emitted by `connections.outbound`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionsOutboundSnapshot {
    pub flows: Vec<OutboundFlowEntry>,
    /// Total flow groups found after filtering, including any omitted groups.
    pub total_flows: u32,
    pub attribution_partial: bool,
    /// Present only when flow groups beyond the cap were omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted_flows: Option<u32>,
}

/// One installed package entry emitted by `packages.inventory`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageInventoryEntry {
    /// Stable identity: `<name>:<arch>`
    pub package_key: String,
    pub name: String,
    pub arch: String,
    pub version: String,
}

/// Normalized snapshot emitted by `packages.inventory`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagesInventorySnapshot {
    pub packages: Vec<PackageInventoryEntry>,
    /// Total installed packages found, including any omitted entries.
    pub total_packages: u32,
    /// SHA-256 of the raw dpkg status file bytes.
    pub status_file_sha256: String,
    /// Stanzas that failed to parse and were skipped.
    #[serde(default)]
    pub malformed_stanzas: u32,
    /// Present only when packages beyond the cap were omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted_packages: Option<u32>,
}

/// Bounded, redacted journal record emitted by `journal.unit_events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEventRecord {
    pub cursor: String,
    pub timestamp_us: i64,
    pub unit: String,
    pub priority: u8,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub uid: Option<u32>,
    pub message_redacted: String,
    pub truncated: bool,
    pub redaction_applied: bool,
    pub classification: DataClassification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationPayload {
    Snapshot {
        data: serde_json::Value,
    },
    Delta {
        base_hash: String,
        data: serde_json::Value,
    },
    StreamBatch {
        events: Vec<JournalEventRecord>,
        #[serde(default)]
        cursor_before: Option<String>,
        #[serde(default)]
        cursor_after: Option<String>,
        gap_detected: bool,
    },
    ErrorDetail {
        code: String,
        message: String,
    },
}

/// Stable observation record transmitted from `agent-d` to `control-d`.
/// Identity tuple is `(host_id, session_id, seq_no)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRecord {
    pub host_id: String,
    pub session_id: String,
    pub seq_no: u64,
    pub watch_id: String,
    pub spec_version: u32,
    pub collector_type: CollectorType,
    pub observed_at: DateTime<Utc>,
    pub status: ObservationStatus,
    pub state_hash: String,
    pub payload: ObservationPayload,
    #[serde(default)]
    pub is_reconciliation: bool,
    #[serde(default)]
    pub sustained_count: Option<u32>,
    #[serde(default)]
    pub sustained_active: Option<bool>,
    #[serde(default)]
    pub partial_reasons: Vec<String>,
}
