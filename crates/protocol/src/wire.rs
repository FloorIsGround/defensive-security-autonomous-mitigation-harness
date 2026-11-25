//! Wire protocol messages, length-prefixed JSON framing, and narrow Transport
//! abstraction supporting UDS, in-process tests, and future fleet mTLS/gRPC.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::observation::{ObservationRecord, ObservationStatus};
use crate::profile::HostProfileSummary;
use crate::signing::SignedEnvelope;

/// Maximum permitted single wire frame payload size (2 MiB).
pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const WIRE_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame exceeds maximum size ({size} > {max})")]
    FrameTooLarge { size: usize, max: usize },
    #[error("unexpected EOF while reading frame")]
    UnexpectedEof,
    #[error("JSON codec error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("transport channel closed")]
    ChannelClosed,
}

/// Bounded per-watch execution summary included in `Heartbeat` so the control
/// plane can distinguish unchanged valid samples from missed/stalled ticks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchRunSummary {
    pub watch_id: String,
    pub spec_version: u32,
    pub completed_runs: u64,
    pub success_runs: u64,
    pub error_runs: u64,
    pub last_status: ObservationStatus,
    #[serde(default)]
    pub last_run_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_success_at: Option<DateTime<Utc>>,
    pub sustained_count: u32,
    pub sustained_active: bool,
    pub retired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResourceHealth {
    #[serde(default)]
    pub rss_bytes: Option<u64>,
    pub spool_bytes_used: u64,
    pub spool_bytes_cap: u64,
    pub active_watches: u32,
    pub dropped_events_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleAckStatus {
    Accepted,
    AlreadyActive,
    Rejected,
}

/// Messages sent from `agent-d` -> `control-d`.
pub type AgentToControl = AgentToControlMessage<HostProfileSummary>;

/// The inbound envelope can decode a registration profile separately from the
/// rest of the message so control can audit a malformed report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case", deny_unknown_fields)]
#[serde(bound(deserialize = "P: Deserialize<'de>"))]
pub enum AgentToControlMessage<P> {
    Register {
        protocol_version: u32,
        host_id: String,
        agent_version: String,
        boot_id: String,
        session_id: String,
        active_bundle_version: u64,
        #[serde(default)]
        active_bundle_digest: Option<String>,
        sent_at: DateTime<Utc>,
        /// Summary of the admin-owned host profile applied by this agent.
        /// Optional and informational; older agents omit it, and it is omitted
        /// when absent so older control planes accept the frame.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host_profile: Option<P>,
    },
    Heartbeat {
        host_id: String,
        session_id: String,
        sent_at: DateTime<Utc>,
        active_bundle_version: u64,
        last_seq_no: u64,
        dropped_events_total: u64,
        stale_desired_state: bool,
        health: AgentResourceHealth,
        watch_summaries: Vec<WatchRunSummary>,
    },
    PushObservationDelta {
        observation: ObservationRecord,
    },
    BundleAck {
        host_id: String,
        bundle_id: String,
        bundle_version: u64,
        payload_digest: String,
        status: BundleAckStatus,
        #[serde(default)]
        reason: Option<String>,
        acked_at: DateTime<Utc>,
    },
}

/// Messages sent from `control-d` -> `agent-d`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlToAgent {
    RegisterAck {
        protocol_version: u32,
        accepted: bool,
        #[serde(default)]
        reason: Option<String>,
        server_time: DateTime<Utc>,
        last_acked_seq_no: u64,
    },
    ObservationAck {
        host_id: String,
        session_id: String,
        /// Highest contiguous durably committed sequence number for this session.
        acked_seq_no: u64,
        acked_at: DateTime<Utc>,
    },
    RequestReconciliation {
        host_id: String,
        /// Empty list means reconcile all active snapshot watches.
        watch_ids: Vec<String>,
        reason: String,
    },
    SyncWatchBundle {
        envelope: SignedEnvelope,
    },
}

/// Write a single 4-byte big-endian length-prefixed JSON frame.
pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<(), WireError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(msg)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge {
            size: payload.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a single 4-byte big-endian length-prefixed JSON frame.
/// Returns `Ok(None)` on clean EOF before the length header.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, WireError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(WireError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge {
            size: len,
            max: MAX_FRAME_BYTES,
        });
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| WireError::UnexpectedEof)?;
    let decoded = serde_json::from_slice(&payload)?;
    Ok(Some(decoded))
}

/// Bidirectional in-process transport channel pair for deterministic tests and
/// single-binary lab mode.
pub struct InMemoryAgentLink {
    pub tx: mpsc::Sender<AgentToControl>,
    pub rx: mpsc::Receiver<ControlToAgent>,
}

pub struct InMemoryControlLink {
    pub tx: mpsc::Sender<ControlToAgent>,
    pub rx: mpsc::Receiver<AgentToControl>,
}

pub fn in_memory_link_pair(capacity: usize) -> (InMemoryAgentLink, InMemoryControlLink) {
    let (a2c_tx, a2c_rx) = mpsc::channel(capacity);
    let (c2a_tx, c2a_rx) = mpsc::channel(capacity);
    (
        InMemoryAgentLink {
            tx: a2c_tx,
            rx: c2a_rx,
        },
        InMemoryControlLink {
            tx: c2a_tx,
            rx: a2c_rx,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_without_profile_preserves_legacy_json() {
        let legacy = serde_json::json!({
            "msg": "register", "protocol_version": WIRE_PROTOCOL_VERSION,
            "host_id": "edge-01", "agent_version": "0.1.0", "boot_id": "boot-1",
            "session_id": "sess-1", "active_bundle_version": 0,
            "active_bundle_digest": null, "sent_at": "2026-01-01T00:00:00Z"
        });
        let register: AgentToControl = serde_json::from_value(legacy.clone()).unwrap();
        assert!(matches!(
            register,
            AgentToControl::Register {
                host_profile: None,
                ..
            }
        ));
        assert_eq!(serde_json::to_value(register).unwrap(), legacy);
    }

    #[tokio::test]
    async fn framed_roundtrip_over_duplex() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let msg = AgentToControl::Register {
            protocol_version: WIRE_PROTOCOL_VERSION,
            host_id: "edge-01".into(),
            agent_version: "0.1.0".into(),
            boot_id: "boot-1".into(),
            session_id: "sess-1".into(),
            active_bundle_version: 0,
            active_bundle_digest: None,
            sent_at: Utc::now(),
            host_profile: None,
        };
        write_frame(&mut client, &msg).await.unwrap();
        drop(client);
        let decoded: AgentToControl = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(decoded, msg);
        let eof: Option<AgentToControl> = read_frame(&mut server).await.unwrap();
        assert!(eof.is_none());
    }

    #[test]
    fn register_without_host_profile_still_decodes() {
        // Backward compatibility: an old agent that omits host_profile must
        // still register (the field defaults to None).
        let raw = serde_json::json!({
            "msg": "register",
            "protocol_version": WIRE_PROTOCOL_VERSION,
            "host_id": "edge-01",
            "agent_version": "0.1.0",
            "boot_id": "boot-1",
            "session_id": "sess-1",
            "active_bundle_version": 3,
            "sent_at": "2026-01-01T00:00:00Z"
        });
        let decoded: AgentToControl = serde_json::from_value(raw).unwrap();
        assert!(matches!(
            decoded,
            AgentToControl::Register {
                host_profile: None,
                ..
            }
        ));

        // A profile summary round-trips through the same wire type.
        let with_profile = AgentToControl::Register {
            protocol_version: WIRE_PROTOCOL_VERSION,
            host_id: "edge-01".into(),
            agent_version: "0.1.0".into(),
            boot_id: "boot-1".into(),
            session_id: "sess-1".into(),
            active_bundle_version: 3,
            active_bundle_digest: None,
            sent_at: Utc::now(),
            host_profile: Some(HostProfileSummary {
                host_tags: vec!["prod".into()],
                expected_services: vec!["sshd.service".into()],
                enabled_collectors: vec![
                    crate::watch::CollectorType::SocketsListening,
                    crate::watch::CollectorType::ConnectionsOutbound,
                ],
            }),
        };
        let encoded = serde_json::to_value(&with_profile).unwrap();
        let decoded: AgentToControl = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, with_profile);
    }
}
