//! Collector backend abstraction: one async trait, the real Linux routing,
//! and a deterministic `FakeHost` simulator for tests.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::canonical::{canonical_sha256_hex, sha256_hex};
use defsec_protocol::observation::{
    ConnectionsOutboundSnapshot, FileMetadataEntry, ObservationPayload, ObservationStatus,
    PackagesInventorySnapshot, SocketsListeningSnapshot, SystemdUnitSnapshot,
};
use defsec_protocol::watch::{CollectorSpec, CollectorType, ConnectionsOutboundParams, FilesMetadataParams, JournalUnitEventsParams, PackagesInventoryParams, SocketsListeningParams, SystemdUnitStateParams};
use tokio::sync::OnceCell;

pub mod files;
pub mod journal;
pub mod outbound;
pub mod packages;
pub mod sockets;
pub mod systemd;

// Reserve 512 KiB below the 2 MiB frame limit for the observation envelope.
pub(super) const SNAPSHOT_BYTES: usize = 1536 * 1024;

/// Account exactly for entries and separators, leaving space for snapshot metadata.
pub(super) fn bounded_snapshot_entries<T: serde::Serialize>(
    entries: impl IntoIterator<Item = T>,
    cap: u32,
    metadata_bytes: usize,
) -> Vec<T> {
    let mut retained = Vec::new();
    let mut used = metadata_bytes;
    for entry in entries.into_iter().take(cap as usize) {
        let Ok(bytes) = defsec_protocol::canonical::to_canonical_json_bytes(&entry) else {
            break;
        };
        used += bytes.len() + usize::from(!retained.is_empty());
        if used > SNAPSHOT_BYTES {
            break;
        }
        retained.push(entry);
    }
    retained
}

/// Normalized output of one collector run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorOutput {
    pub status: ObservationStatus,
    pub payload: ObservationPayload,
    pub state_hash: String,
    pub next_cursor: Option<String>,
    pub partial_reasons: Vec<String>,
}

/// Build an explicit error observation.
pub fn error_output(code: &str, message: &str) -> CollectorOutput {
    let payload = ObservationPayload::ErrorDetail {
        code: code.to_string(),
        message: message.to_string(),
    };
    let hash = canonical_sha256_hex(&payload).unwrap_or_default();
    CollectorOutput {
        status: ObservationStatus::Error,
        payload,
        state_hash: hash,
        next_cursor: None,
        partial_reasons: vec![message.to_string()],
    }
}

/// Async collector backend. One method routes every built-in collector type.
///
/// Native `async fn` in trait (Rust 1.75+) used generically by the engine;
/// not dyn-compatible — collect through the generic `AgentEngine<C>`.
#[allow(async_fn_in_trait)]
pub trait CollectorBackend: Send + Sync {
    async fn collect(
        &self,
        spec: &CollectorSpec,
        cfg: &EdgeSafetyConfig,
        cursor: Option<&str>,
    ) -> CollectorOutput;
}

/// Real Linux collectors: `/proc` parsing, system D-Bus via zbus,
/// `openat2`-guarded file hashing, and journalctl streaming.
pub struct RealLinuxCollectors {
    /// Cached system bus connection (created lazily on first systemd query).
    dbus: OnceCell<zbus::Connection>,
}

impl Default for RealLinuxCollectors {
    fn default() -> Self {
        Self::new()
    }
}

impl RealLinuxCollectors {
    pub fn new() -> Self {
        Self {
            dbus: OnceCell::new(),
        }
    }

    async fn system_bus(&self) -> Result<zbus::Connection, zbus::Error> {
        if let Some(conn) = self.dbus.get() {
            return Ok(conn.clone());
        }
        let conn = zbus::Connection::system().await?;
        // Best-effort cache; a concurrent racer setting first is harmless.
        let _ = self.dbus.set(conn.clone());
        Ok(conn)
    }
}

impl CollectorBackend for RealLinuxCollectors {
    async fn collect(
        &self,
        spec: &CollectorSpec,
        cfg: &EdgeSafetyConfig,
        cursor: Option<&str>,
    ) -> CollectorOutput {
        match spec {
            CollectorSpec::SocketsListening(p) => sockets::collect_sockets(p, cfg).await,
            CollectorSpec::SystemdUnitState(p) => match self.system_bus().await {
                Ok(conn) => systemd::collect_systemd(p, cfg, &conn).await,
                Err(e) => error_output(
                    "dbus_unavailable",
                    &format!("system D-Bus unavailable: {e}"),
                ),
            },
            CollectorSpec::FilesMetadata(p) => files::collect_files(p, cfg).await,
            CollectorSpec::JournalUnitEvents(p) => {
                let source = journal::JournalctlSource::new();
                journal::collect_journal(p, cfg, cursor, &source).await
            }
            CollectorSpec::ConnectionsOutbound(p) => outbound::collect_outbound(p, cfg).await,
            CollectorSpec::PackagesInventory(p) => packages::collect_packages(p, cfg).await,
        }
    }
}

/// Recorded invocation of the fake backend (for assertions in tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeCollectorCall {
    pub collector: CollectorType,
    pub cursor: Option<String>,
}

/// Scriptable, thread-safe simulated host state. Tests populate exactly the
/// observations they want — no host OS state is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeHostState {
    /// Artificial delay applied to every collect call (timeout testing).
    pub sleep_ms: Option<u64>,
    pub sockets: SocketsListeningSnapshot,
    pub sockets_status: Option<ObservationStatus>,
    pub sockets_partial_reasons: Vec<String>,
    pub systemd: BTreeMap<String, SystemdUnitSnapshot>,
    pub systemd_status: BTreeMap<String, ObservationStatus>,
    pub files: BTreeMap<String, FileMetadataEntry>,
    pub outbound: ConnectionsOutboundSnapshot,
    pub outbound_status: Option<ObservationStatus>,
    pub outbound_partial_reasons: Vec<String>,
    pub packages: PackagesInventorySnapshot,
    pub packages_status: Option<ObservationStatus>,
    pub packages_partial_reasons: Vec<String>,
    /// FIFO of scripted journal batches; when empty, `journal_default` is used.
    pub journal_batches: VecDeque<journal::JournalFetchOutcome>,
    pub journal_default: journal::JournalFetchOutcome,
    /// Every collect() invocation, in order.
    pub calls: Vec<FakeCollectorCall>,
}

impl Default for FakeHostState {
    fn default() -> Self {
        Self {
            sleep_ms: None,
            sockets: SocketsListeningSnapshot {
                count: 0,
                partial_attribution: false,
                sockets: Vec::new(),
            },
            sockets_status: None,
            sockets_partial_reasons: Vec::new(),
            systemd: BTreeMap::new(),
            systemd_status: BTreeMap::new(),
            files: BTreeMap::new(),
            outbound: ConnectionsOutboundSnapshot {
                flows: Vec::new(),
                total_flows: 0,
                attribution_partial: false,
                truncated: None,
                omitted_flows: None,
            },
            outbound_status: None,
            outbound_partial_reasons: Vec::new(),
            packages: PackagesInventorySnapshot {
                packages: Vec::new(),
                total_packages: 0,
                // SHA-256 of the empty string: a deterministic, well-formed
                // digest for the empty fake host.
                status_file_sha256: sha256_hex(&[]),
                malformed_stanzas: 0,
                duplicate_stanzas: 0,
                truncated: None,
                omitted_packages: None,
            },
            packages_status: None,
            packages_partial_reasons: Vec::new(),
            journal_batches: VecDeque::new(),
            journal_default: journal::JournalFetchOutcome::default(),
            calls: Vec::new(),
        }
    }
}

/// Deterministic test simulator implementing [`CollectorBackend`].
#[derive(Clone)]
pub struct FakeHostCollectors {
    state: Arc<Mutex<FakeHostState>>,
}

impl Default for FakeHostCollectors {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeHostCollectors {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeHostState::default())),
        }
    }

    pub fn from_state(state: FakeHostState) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn state_handle(&self) -> Arc<Mutex<FakeHostState>> {
        self.state.clone()
    }
}

impl CollectorBackend for FakeHostCollectors {
    async fn collect(
        &self,
        spec: &CollectorSpec,
        _cfg: &EdgeSafetyConfig,
        cursor: Option<&str>,
    ) -> CollectorOutput {
        let collector_type = spec.collector_type();
        // Snapshot the scripted state under a short lock, never held across
        // an await point.
        let scripted = {
            let mut state = self.state.lock().expect("fake host state poisoned");
            state.calls.push(FakeCollectorCall {
                collector: collector_type,
                cursor: cursor.map(str::to_string),
            });
            match spec {
                CollectorSpec::SocketsListening(p) => fake_sockets(&state, p),
                CollectorSpec::SystemdUnitState(p) => fake_systemd(&state, p),
                CollectorSpec::FilesMetadata(p) => fake_files(&state, p),
                CollectorSpec::ConnectionsOutbound(p) => fake_outbound(&state, p),
                CollectorSpec::PackagesInventory(p) => fake_packages(&state, p),
                CollectorSpec::JournalUnitEvents(p) => fake_journal(&mut state, p, cursor),
            }
        };

        let sleep_ms = self.state.lock().expect("fake host state poisoned").sleep_ms;
        if let Some(ms) = sleep_ms {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }

        scripted
    }
}

fn snapshot_output(status: ObservationStatus, snapshot: &impl serde::Serialize) -> CollectorOutput {
    let payload = if status.is_valid_sample() {
        ObservationPayload::Snapshot {
            data: serde_json::to_value(snapshot).unwrap_or(serde_json::Value::Null),
        }
    } else {
        ObservationPayload::ErrorDetail {
            code: "fake_host_status".to_string(),
            message: format!("fake host scripted status {status:?}"),
        }
    };
    let state_hash = if status.is_valid_sample() {
        canonical_sha256_hex(snapshot).unwrap_or_default()
    } else {
        canonical_sha256_hex(&payload).unwrap_or_default()
    };
    CollectorOutput {
        status,
        payload,
        state_hash,
        next_cursor: None,
        partial_reasons: Vec::new(),
    }
}

fn fake_sockets(state: &FakeHostState, _p: &SocketsListeningParams) -> CollectorOutput {
    let status = state.sockets_status.unwrap_or(ObservationStatus::Ok);
    let mut out = snapshot_output(status, &state.sockets);
    out.partial_reasons = state.sockets_partial_reasons.clone();
    out
}

fn fake_outbound(state: &FakeHostState, _p: &ConnectionsOutboundParams) -> CollectorOutput {
    let status = state.outbound_status.unwrap_or(ObservationStatus::Ok);
    let mut out = snapshot_output(status, &state.outbound);
    out.partial_reasons = state.outbound_partial_reasons.clone();
    out
}

fn fake_packages(state: &FakeHostState, _p: &PackagesInventoryParams) -> CollectorOutput {
    let status = state.packages_status.unwrap_or(ObservationStatus::Ok);
    let mut out = snapshot_output(status, &state.packages);
    out.partial_reasons = state.packages_partial_reasons.clone();
    out
}

fn fake_systemd(state: &FakeHostState, p: &SystemdUnitStateParams) -> CollectorOutput {
    if let Some(status) = state.systemd_status.get(&p.unit) {
        return snapshot_output(*status, &serde_json::json!({ "unit": p.unit }));
    }
    match state.systemd.get(&p.unit) {
        Some(snapshot) => snapshot_output(ObservationStatus::Ok, snapshot),
        None => {
            let payload = ObservationPayload::ErrorDetail {
                code: "unit_not_found".to_string(),
                message: format!("fake host has no unit '{}'", p.unit),
            };
            CollectorOutput {
                status: ObservationStatus::NotFound,
                state_hash: canonical_sha256_hex(&payload).unwrap_or_default(),
                payload,
                next_cursor: None,
                partial_reasons: Vec::new(),
            }
        }
    }
}

fn fake_files(state: &FakeHostState, p: &FilesMetadataParams) -> CollectorOutput {
    let mut files: Vec<FileMetadataEntry> = p
        .paths
        .iter()
        .map(|path| {
            state.files.get(path).cloned().unwrap_or(FileMetadataEntry {
                path: path.clone(),
                status: ObservationStatus::NotFound,
                mode_octal: None,
                uid: None,
                gid: None,
                nlink: None,
                size_bytes: None,
                sha256: None,
                mtime_unix: None,
                detail: Some("fake host has no such file".to_string()),
            })
        })
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let any_ok = files.iter().any(|f| f.status == ObservationStatus::Ok);
    let all_ok = files.iter().all(|f| f.status == ObservationStatus::Ok);
    let status = if all_ok {
        ObservationStatus::Ok
    } else if any_ok {
        ObservationStatus::Partial
    } else {
        ObservationStatus::Error
    };
    snapshot_output(status, &serde_json::json!({ "count": files.len(), "files": files }))
}

fn fake_journal(
    state: &mut FakeHostState,
    _p: &JournalUnitEventsParams,
    cursor: Option<&str>,
) -> CollectorOutput {
    let outcome = state
        .journal_batches
        .pop_front()
        .unwrap_or_else(|| state.journal_default.clone());
    let events = outcome.events.clone();
    let payload = ObservationPayload::StreamBatch {
        events,
        cursor_before: cursor.map(str::to_string),
        cursor_after: outcome.cursor_after.clone(),
        gap_detected: outcome.gap_detected,
    };
    CollectorOutput {
        status: outcome.status,
        state_hash: canonical_sha256_hex(&outcome.events).unwrap_or_default(),
        payload,
        next_cursor: outcome.cursor_after,
        partial_reasons: outcome.partial_reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_host_routes_all_collectors_and_records_calls() {
        let mut state = FakeHostState {
            sockets: SocketsListeningSnapshot {
                count: 1,
                partial_attribution: true,
                sockets: vec![defsec_protocol::observation::ListeningSocketEntry {
                    socket_key: "tcp:0.0.0.0:22:uid=0".into(),
                    protocol: "tcp".into(),
                    local_addr: "0.0.0.0".into(),
                    local_port: 22,
                    uid: 0,
                    inode: 1,
                    pid: Some(10),
                    pid_start_time_ticks: Some(77),
                    comm: Some("sshd".into()),
                    systemd_unit: Some("sshd.service".into()),
                }],
            },
            sockets_status: Some(ObservationStatus::Partial),
            sockets_partial_reasons: vec!["hidepid".into()],
            outbound: defsec_protocol::observation::ConnectionsOutboundSnapshot {
                flows: vec![defsec_protocol::observation::OutboundFlowEntry {
                    flow_key: "tcp:192.0.2.1:443:1000:curl".into(),
                    protocol: "tcp".into(),
                    remote_addr: "192.0.2.1".into(),
                    remote_port: 443,
                    uid: 1000,
                    states: vec!["ESTABLISHED".into()],
                    count: 2,
                    comm: Some("curl".into()),
                    systemd_unit: None,
                    attribution: defsec_protocol::observation::FlowAttribution::Full,
                }],
                total_flows: 1,
                attribution_partial: false,
                truncated: None,
                omitted_flows: None,
            },
            packages: defsec_protocol::observation::PackagesInventorySnapshot {
                packages: vec![defsec_protocol::observation::PackageInventoryEntry {
                    package_key: "bash:amd64".into(),
                    name: "bash".into(),
                    arch: "amd64".into(),
                    version: "5.2".into(),
                }],
                total_packages: 1,
                status_file_sha256: sha256_hex(&[]),
                malformed_stanzas: 0,
                duplicate_stanzas: 0,
                truncated: None,
                omitted_packages: None,
            },
            ..FakeHostState::default()
        };
        state.systemd.insert(
            "sshd.service".into(),
            SystemdUnitSnapshot {
                unit: "sshd.service".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                unit_file_state: Some("enabled".into()),
                main_pid: Some(99),
                main_pid_start_time_ticks: Some(77),
                exec_start_hash: None,
                unit_files: Vec::new(),
            },
        );
        state.files.insert(
            "/etc/ssh/sshd_config".into(),
            FileMetadataEntry {
                path: "/etc/ssh/sshd_config".into(),
                status: ObservationStatus::Ok,
                mode_octal: Some("0600".into()),
                uid: Some(0),
                gid: Some(0),
                nlink: Some(1),
                size_bytes: Some(42),
                sha256: Some("a".repeat(64)),
                mtime_unix: Some(1),
                detail: None,
            },
        );
        state.journal_batches.push_back(journal::JournalFetchOutcome {
            status: ObservationStatus::Ok,
            events: vec![defsec_protocol::observation::JournalEventRecord {
                cursor: "c1".into(),
                timestamp_us: 1,
                unit: "sshd.service".into(),
                priority: 4,
                pid: None,
                uid: None,
                message_redacted: "hi".into(),
                truncated: false,
                redaction_applied: false,
                classification: defsec_protocol::watch::DataClassification::BoundedRedactedText,
            }],
            cursor_after: Some("c1".into()),
            gap_detected: false,
            partial_reasons: Vec::new(),
        });

        let host = FakeHostCollectors::from_state(state);
        let cfg = EdgeSafetyConfig::default();

        let out = host
            .collect(
                &CollectorSpec::SocketsListening(SocketsListeningParams {
                    include_tcp: true,
                    include_udp: false,
                    include_ipv6: false,
                    resolve_process: true,
                }),
                &cfg,
                None,
            )
            .await;
        assert_eq!(out.status, ObservationStatus::Partial);
        assert_eq!(out.partial_reasons, vec!["hidepid".to_string()]);
        assert_eq!(out.state_hash.len(), 64);

        let out = host
            .collect(
                &CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
                    unit: "sshd.service".into(),
                    hash_unit_files: false,
                }),
                &cfg,
                None,
            )
            .await;
        assert_eq!(out.status, ObservationStatus::Ok);

        let out = host
            .collect(
                &CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
                    unit: "missing.service".into(),
                    hash_unit_files: false,
                }),
                &cfg,
                None,
            )
            .await;
        assert_eq!(out.status, ObservationStatus::NotFound);

        let out = host
            .collect(
                &CollectorSpec::FilesMetadata(FilesMetadataParams {
                    paths: vec!["/etc/ssh/sshd_config".into()],
                    compute_hash: true,
                    max_file_bytes: None,
                }),
                &cfg,
                None,
            )
            .await;
        assert_eq!(out.status, ObservationStatus::Ok);

        let out = host
            .collect(
                &CollectorSpec::JournalUnitEvents(JournalUnitEventsParams {
                    unit: "sshd.service".into(),
                    min_priority: Some(6),
                    max_events_per_batch: Some(10),
                    max_message_bytes: None,
                }),
                &cfg,
                Some("c0"),
            )
            .await;
        assert_eq!(out.next_cursor.as_deref(), Some("c1"));

        // The two snapshot collectors serve their scripted state verbatim.
        let out = host
            .collect(
                &CollectorSpec::ConnectionsOutbound(ConnectionsOutboundParams {
                    include_tcp: true,
                    include_udp: false,
                    include_ipv6: true,
                    resolve_process: true,
                    exclude_loopback: true,
                    max_flows: None,
                }),
                &cfg,
                None,
            )
            .await;
        assert_eq!(out.status, ObservationStatus::Ok);
        match &out.payload {
            ObservationPayload::Snapshot { data } => {
                let snap: defsec_protocol::observation::ConnectionsOutboundSnapshot =
                    serde_json::from_value(data.clone()).unwrap();
                assert_eq!(snap.total_flows, 1);
                assert_eq!(snap.flows[0].count, 2);
                assert_eq!(snap.flows[0].flow_key, "tcp:192.0.2.1:443:1000:curl");
            }
            other => panic!("expected snapshot, got {other:?}"),
        }

        let out = host
            .collect(
                &CollectorSpec::PackagesInventory(PackagesInventoryParams {
                    max_packages: Some(64),
                }),
                &cfg,
                None,
            )
            .await;
        assert_eq!(out.status, ObservationStatus::Ok);
        match &out.payload {
            ObservationPayload::Snapshot { data } => {
                let snap: defsec_protocol::observation::PackagesInventorySnapshot =
                    serde_json::from_value(data.clone()).unwrap();
                assert_eq!(snap.packages[0].package_key, "bash:amd64");
                assert_eq!(snap.status_file_sha256, sha256_hex(&[]));
            }
            other => panic!("expected snapshot, got {other:?}"),
        }

        let handle = host.state_handle();
        let guard = handle.lock().unwrap();
        assert_eq!(guard.calls.len(), 7);
        assert_eq!(guard.calls[0].collector, CollectorType::SocketsListening);
        assert_eq!(guard.calls[4].collector, CollectorType::JournalUnitEvents);
        assert_eq!(guard.calls[4].cursor.as_deref(), Some("c0"));
        assert_eq!(guard.calls[5].collector, CollectorType::ConnectionsOutbound);
        assert_eq!(guard.calls[6].collector, CollectorType::PackagesInventory);
    }

    #[tokio::test]
    async fn fake_host_timeout_scripting_and_error_status() {
        let state = FakeHostState {
            sleep_ms: Some(200),
            sockets_status: Some(ObservationStatus::PermissionDenied),
            ..FakeHostState::default()
        };
        let host = FakeHostCollectors::from_state(state);
        let cfg = EdgeSafetyConfig::default();

        let start = std::time::Instant::now();
        let out = host
            .collect(
                &CollectorSpec::SocketsListening(SocketsListeningParams {
                    include_tcp: true,
                    include_udp: true,
                    include_ipv6: true,
                    resolve_process: false,
                }),
                &cfg,
                None,
            )
            .await;
        assert!(start.elapsed() >= std::time::Duration::from_millis(200));
        assert_eq!(out.status, ObservationStatus::PermissionDenied);
    }
}
