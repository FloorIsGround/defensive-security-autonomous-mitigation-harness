//! Append-only hash-chained audit records for tamper-evident off-host delivery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::canonical::{CanonicalError, sha256_hex, to_canonical_json_bytes};

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    HostEnrolled,
    BundleIssued,
    BundleAcked,
    WatchProposed,
    PolicyDecision,
    BaselinePromoted,
    IncidentOpened,
    IncidentClosed,
    RunStarted,
    RunCompleted,
    FindingRecorded,
    CapabilityMinted,
    ActionProposed,
    ActionApproved,
    ActionReceiptRecorded,
    ActionRolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntryBody {
    pub seq_no: u64,
    pub timestamp: DateTime<Utc>,
    pub prev_hash: String,
    pub event_type: AuditEventType,
    pub actor: String,
    pub request_id: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub seq_no: u64,
    pub timestamp: DateTime<Utc>,
    pub prev_hash: String,
    pub event_type: AuditEventType,
    pub actor: String,
    pub request_id: String,
    pub payload: serde_json::Value,
    pub entry_hash: String,
}

impl AuditEntry {
    pub fn build(
        seq_no: u64,
        timestamp: DateTime<Utc>,
        prev_hash: String,
        event_type: AuditEventType,
        actor: String,
        request_id: String,
        payload: serde_json::Value,
    ) -> Result<Self, CanonicalError> {
        let body = AuditEntryBody {
            seq_no,
            timestamp,
            prev_hash: prev_hash.clone(),
            event_type: event_type.clone(),
            actor: actor.clone(),
            request_id: request_id.clone(),
            payload: payload.clone(),
        };
        let entry_hash = compute_audit_hash(&body)?;
        Ok(Self {
            seq_no,
            timestamp,
            prev_hash,
            event_type,
            actor,
            request_id,
            payload,
            entry_hash,
        })
    }

    pub fn recompute_hash(&self) -> Result<String, CanonicalError> {
        let body = AuditEntryBody {
            seq_no: self.seq_no,
            timestamp: self.timestamp,
            prev_hash: self.prev_hash.clone(),
            event_type: self.event_type.clone(),
            actor: self.actor.clone(),
            request_id: self.request_id.clone(),
            payload: self.payload.clone(),
        };
        compute_audit_hash(&body)
    }
}

pub fn compute_audit_hash(body: &AuditEntryBody) -> Result<String, CanonicalError> {
    let mut input = Vec::new();
    input.extend_from_slice(b"defsecautmit.audit_entry.v1\0");
    input.extend_from_slice(&to_canonical_json_bytes(body)?);
    Ok(sha256_hex(&input))
}

/// Verify an ordered slice of audit entries starting from `expected_start_seq`
/// and `expected_prev_hash`.
pub fn verify_audit_chain(
    entries: &[AuditEntry],
    expected_start_seq: u64,
    expected_prev_hash: &str,
) -> Result<Option<String>, String> {
    let mut prev_hash = expected_prev_hash.to_string();

    for (next_seq, entry) in (expected_start_seq..).zip(entries.iter()) {
        if entry.seq_no != next_seq {
            return Err(format!(
                "sequence gap or mismatch: expected {}, got {}",
                next_seq, entry.seq_no
            ));
        }
        if entry.prev_hash != prev_hash {
            return Err(format!(
                "broken hash chain at seq {}: expected prev_hash {}, got {}",
                entry.seq_no, prev_hash, entry.prev_hash
            ));
        }
        let recomputed = entry
            .recompute_hash()
            .map_err(|e| format!("canonicalization error at seq {}: {e}", entry.seq_no))?;
        if recomputed != entry.entry_hash {
            return Err(format!(
                "tampered audit entry at seq {}: expected hash {}, got {}",
                entry.seq_no, recomputed, entry.entry_hash
            ));
        }
        prev_hash = entry.entry_hash.clone();
    }

    if entries.is_empty() {
        Ok(None)
    } else {
        Ok(Some(prev_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verifies_valid_chain_and_detects_tampering() {
        let e1 = AuditEntry::build(
            1,
            Utc::now(),
            GENESIS_PREV_HASH.into(),
            AuditEventType::HostEnrolled,
            "admin".into(),
            "req-1".into(),
            json!({"host_id": "edge-1"}),
        )
        .unwrap();
        let e2 = AuditEntry::build(
            2,
            Utc::now(),
            e1.entry_hash.clone(),
            AuditEventType::BundleIssued,
            "control-d".into(),
            "req-2".into(),
            json!({"bundle_version": 1}),
        )
        .unwrap();

        let last = verify_audit_chain(&[e1.clone(), e2.clone()], 1, GENESIS_PREV_HASH).unwrap();
        assert_eq!(last.as_deref(), Some(e2.entry_hash.as_str()));

        let mut tampered = e1.clone();
        tampered.payload = json!({"host_id": "evil"});
        let err = verify_audit_chain(&[tampered, e2], 1, GENESIS_PREV_HASH).unwrap_err();
        assert!(err.contains("tampered audit entry"));
    }
}
