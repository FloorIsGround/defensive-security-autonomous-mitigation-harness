//! Phase 8 typed remediation & bounded autonomous containment schemas.
//!
//! No arbitrary shell commands or scripts exist in the action grammar. Every
//! intent uses a closed catalog of precompiled, idempotent, TTL-bounded verbs
//! verified by Ed25519 signatures (control signature + independent operator
//! approval signature for dual-signed verbs, or explicit human-owned
//! auto-mitigation policy for reversible low-blast-radius verbs).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::signing::SignedEnvelope;

pub const ACTION_INTENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionVerbKind {
    NftBlockIp,
    SystemdStopUnit,
    HostIsolate,
}

impl ActionVerbKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NftBlockIp => "nft_block_ip",
            Self::SystemdStopUnit => "systemd_stop_unit",
            Self::HostIsolate => "host_isolate",
        }
    }
}

/// Closed, strongly typed catalog of precompiled mitigation verbs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionVerb {
    /// Time-limited nftables IP block with mandatory TTL auto-expiry.
    NftBlockIp {
        ip: String,
        direction: TrafficDirection,
        ttl_seconds: u64,
    },
    /// Stop an explicitly non-protected systemd unit.
    SystemdStopUnit {
        unit: String,
        #[serde(default)]
        ttl_seconds: Option<u64>,
    },
    /// Controlled host network isolation strictly preserving management CIDRs.
    HostIsolate {
        preserve_mgmt_cidrs: Vec<String>,
        ttl_seconds: u64,
    },
}

impl ActionVerb {
    pub fn kind(&self) -> ActionVerbKind {
        match self {
            Self::NftBlockIp { .. } => ActionVerbKind::NftBlockIp,
            Self::SystemdStopUnit { .. } => ActionVerbKind::SystemdStopUnit,
            Self::HostIsolate { .. } => ActionVerbKind::HostIsolate,
        }
    }

    pub fn ttl_seconds(&self) -> Option<u64> {
        match self {
            Self::NftBlockIp { ttl_seconds, .. } | Self::HostIsolate { ttl_seconds, .. } => {
                Some(*ttl_seconds)
            }
            Self::SystemdStopUnit { ttl_seconds, .. } => *ttl_seconds,
        }
    }
}

/// Authorization tier required before `action-exec-d` may execute an intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionAuthMode {
    /// Pre-authorized by human-owned auto-mitigation policy for reversible,
    /// low-blast-radius verbs; signed by `control-d` and independently re-checked
    /// against `action-exec-d`'s local opt-in policy.
    PolicyBoundedAutonomous,
    /// Requires BOTH `control-d` signature AND an independent operator Ed25519
    /// approval signature over the exact canonical `ActionIntentPayload`.
    DualSignedOperator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionIntentStatus {
    PendingApproval,
    Authorized,
    Executed,
    DryRunSimulated,
    RolledBack,
    Rejected,
    VerificationFailed,
    Expired,
}

/// Canonical host-bound action intent signed under `DOMAIN_ACTION_INTENT_V1`
/// (by `control-d`) and, for dual-signed intents, under `DOMAIN_ACTION_APPROVAL_V1`
/// (by an independent operator key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionIntentPayload {
    pub schema_version: u32,
    pub intent_id: String,
    pub nonce: String,
    pub host_id: String,
    pub incident_id: String,
    pub proposal_id: i64,
    pub auth_mode: ActionAuthMode,
    pub verb: ActionVerb,
    pub policy_version: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub rollback_plan: String,
    pub evidence_observation_ids: Vec<i64>,
}

/// Cryptographically signed action intent dispatched to `action-exec-d`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedActionIntent {
    /// Control-plane Ed25519 envelope (`DOMAIN_ACTION_INTENT_V1`).
    pub control_envelope: SignedEnvelope,
    /// Independent operator approval Ed25519 envelope (`DOMAIN_ACTION_APPROVAL_V1`),
    /// mandatory whenever `auth_mode == DualSignedOperator`.
    #[serde(default)]
    pub operator_approval: Option<SignedEnvelope>,
}

/// Verifiable execution / rollback receipt returned by `action-exec-d`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionReceipt {
    pub intent_id: String,
    pub host_id: String,
    pub nonce: String,
    pub status: ActionIntentStatus,
    pub dry_run: bool,
    pub executed_at: DateTime<Utc>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub rollback_handle: Option<String>,
    pub verification_passed: bool,
    pub detail: String,
}

/// Compact summary returned by `ListActions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSummary {
    pub proposal_id: i64,
    #[serde(default)]
    pub intent_id: Option<String>,
    pub host_id: String,
    pub incident_id: String,
    pub auth_mode: ActionAuthMode,
    pub status: ActionIntentStatus,
    pub verb: ActionVerb,
    pub expected_effect: String,
    pub blast_radius: String,
    pub rollback_plan: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub approver: Option<String>,
}
