//! The action executor: verification, local safety floor, replay protection,
//! TTL expiry and rollback receipts.
//!
//! `ActionExecutor` is the only path from a signed
//! [`AuthorizedActionIntent`] to a host effect. It:
//! 1. verifies the control envelope against the trusted control-plane keys
//!    under `DOMAIN_ACTION_INTENT_V1`,
//! 2. for intents carrying an operator approval, verifies it against the
//!    SEPARATE operator key store under `DOMAIN_ACTION_APPROVAL_V1`, demands
//!    byte-exact equality with the control envelope's canonical payload, and
//!    requires a genuinely distinct signing key,
//! 3. re-checks the decoded payload against the edge-local
//!    [`ActionSafetyConfig`] hard floor,
//! 4. atomically records the nonce BEFORE any driver effect (replay
//!    protection that survives restarts), and
//! 5. dispatches to the driver, tracking an active rollback entry until the
//!    TTL expires and the effect is rolled back.
//!
//! Verification, policy or replay failures never panic: they return an
//! explicit rejected [`ActionReceipt`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use defsec_policy::action_gate::{validate_edge_action_intent, ActionSafetyConfig};
use defsec_protocol::action::{
    ActionIntentPayload, ActionIntentStatus, ActionReceipt, ActionVerb, AuthorizedActionIntent,
};
use defsec_protocol::signing::{
    DOMAIN_ACTION_APPROVAL_V1, DOMAIN_ACTION_INTENT_V1, VerifyingKeyStore,
};

use crate::driver::ActionDriver;
use crate::replay::{NonceReplayStore, ReplayStoreError};

/// A driver effect currently active on the host, awaiting TTL expiry rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveAction {
    pub intent_id: String,
    pub host_id: String,
    pub nonce: String,
    pub verb: ActionVerb,
    pub rollback_handle: String,
    pub expires_at: DateTime<Utc>,
    pub dry_run: bool,
}

/// Isolated privileged executor over an [`ActionDriver`] implementation.
pub struct ActionExecutor<D: ActionDriver> {
    local_host_id: String,
    cfg: ActionSafetyConfig,
    control_keys: VerifyingKeyStore,
    operator_keys: VerifyingKeyStore,
    replay: NonceReplayStore,
    driver: Arc<D>,
    active: BTreeMap<String, ActiveAction>,
}

impl<D: ActionDriver> ActionExecutor<D> {
    /// Build an executor. Fails closed if the replay store cannot be opened
    /// (e.g. corrupt on-disk state): an executor that might have forgotten
    /// already-executed nonces must not start.
    pub fn new(
        local_host_id: String,
        cfg: ActionSafetyConfig,
        control_keys: VerifyingKeyStore,
        operator_keys: VerifyingKeyStore,
        state_dir: PathBuf,
        driver: Arc<D>,
    ) -> Result<Self, ReplayStoreError> {
        let replay = NonceReplayStore::open(&state_dir)?;
        Ok(Self {
            local_host_id,
            cfg,
            control_keys,
            operator_keys,
            replay,
            driver,
            active: BTreeMap::new(),
        })
    }

    pub fn local_host_id(&self) -> &str {
        &self.local_host_id
    }

    pub fn active_action_count(&self) -> usize {
        self.active.len()
    }

    /// Verify, policy-check, replay-protect and execute one signed intent.
    ///
    /// Returns an explicit receipt for every outcome; never panics on
    /// verification, policy or replay failures.
    pub async fn execute_intent(
        &mut self,
        intent: &AuthorizedActionIntent,
        now: DateTime<Utc>,
    ) -> ActionReceipt {
        // 1. Control-plane signature under the intent domain.
        let payload: ActionIntentPayload =
            match self
                .control_keys
                .verify_and_decode(DOMAIN_ACTION_INTENT_V1, &intent.control_envelope)
            {
                Ok((payload, _digest)) => payload,
                Err(e) => {
                    return rejected_receipt("", "", "", now, format!(
                        "control intent signature verification failed: {e}"
                    ))
                }
            };

        // 2. Independent operator approval, whenever one is attached.
        let mut has_verified_operator_approval = false;
        if let Some(op_env) = &intent.operator_approval {
            let decoded: Result<(ActionIntentPayload, String), _> = self
                .operator_keys
                .verify_and_decode(DOMAIN_ACTION_APPROVAL_V1, op_env);
            let op_payload = match decoded {
                Ok((p, _)) => p,
                Err(e) => {
                    return rejected_receipt(
                        &payload.intent_id,
                        &payload.host_id,
                        &payload.nonce,
                        now,
                        format!("operator approval signature verification failed: {e}"),
                    )
                }
            };
            // The operator must have signed the EXACT same canonical bytes as
            // the control plane — no parameter substitution between signatures.
            if op_env.raw_payload != intent.control_envelope.raw_payload {
                return rejected_receipt(
                    &payload.intent_id,
                    &payload.host_id,
                    &payload.nonce,
                    now,
                    "operator approval rejected: approval signature covers different canonical bytes than the control intent",
                );
            }
            // The approval must come from a genuinely distinct key.
            if op_env.signing_key_id == intent.control_envelope.signing_key_id {
                return rejected_receipt(
                    &payload.intent_id,
                    &payload.host_id,
                    &payload.nonce,
                    now,
                    format!(
                        "operator approval rejected: approval key '{}' must differ from control signing key '{}'",
                        op_env.signing_key_id, intent.control_envelope.signing_key_id
                    ),
                );
            }
            if let (Some(control_vk), Some(operator_vk)) = (
                self.control_keys
                    .get(&intent.control_envelope.signing_key_id),
                self.operator_keys.get(&op_env.signing_key_id),
            ) && control_vk.to_bytes() == operator_vk.to_bytes()
            {
                return rejected_receipt(
                    &payload.intent_id,
                    &payload.host_id,
                    &payload.nonce,
                    now,
                    "operator approval rejected: approval key material is identical to the control signing key",
                );
            }
            // Defense in depth: the decoded approval payload must equal the
            // control payload (implied by byte equality, re-checked cheaply).
            if op_payload != payload {
                return rejected_receipt(
                    &payload.intent_id,
                    &payload.host_id,
                    &payload.nonce,
                    now,
                    "operator approval rejected: decoded approval payload differs from control intent",
                );
            }
            has_verified_operator_approval = true;
        }

        // 3. Edge-local hard floor: host binding, policy version, protected
        //    assets, TTL bounds, auth-mode tier and clock window.
        if let Err(e) = validate_edge_action_intent(
            &payload,
            has_verified_operator_approval,
            &self.local_host_id,
            &self.cfg,
            now,
        ) {
            return rejected_receipt(
                &payload.intent_id,
                &payload.host_id,
                &payload.nonce,
                now,
                e.to_string(),
            );
        }

        // 4. Replay protection: commit the nonce durably BEFORE any effect.
        if self.replay.contains(&payload.nonce) {
            return rejected_receipt(
                &payload.intent_id,
                &payload.host_id,
                &payload.nonce,
                now,
                "replay rejected",
            );
        }
        if let Err(e) = self.replay.record(&payload.nonce, &payload.intent_id, now) {
            return rejected_receipt(
                &payload.intent_id,
                &payload.host_id,
                &payload.nonce,
                now,
                format!("replay protection unavailable: {e}"),
            );
        }

        // 5. Dispatch to the driver.
        let exec = match self.driver.execute(&payload).await {
            Ok(exec) => exec,
            Err(e) => {
                return rejected_receipt(
                    &payload.intent_id,
                    &payload.host_id,
                    &payload.nonce,
                    now,
                    format!("driver execution failed: {e}"),
                )
            }
        };

        let expires_at = payload
            .verb
            .ttl_seconds()
            .map(|ttl| now + Duration::seconds(ttl as i64));
        let status = if exec.verification_passed {
            if exec.dry_run {
                ActionIntentStatus::DryRunSimulated
            } else {
                ActionIntentStatus::Executed
            }
        } else {
            ActionIntentStatus::VerificationFailed
        };
        let receipt = ActionReceipt {
            intent_id: payload.intent_id.clone(),
            host_id: payload.host_id.clone(),
            nonce: payload.nonce.clone(),
            status,
            dry_run: exec.dry_run,
            executed_at: now,
            expires_at,
            rollback_handle: Some(exec.rollback_handle.clone()),
            verification_passed: exec.verification_passed,
            detail: exec.detail,
        };

        // 6. Track the active effect for TTL expiry rollback. Effects without
        //    a TTL (ttl_seconds == None) stay until an operator manually
        //    rolls them back via `rollback_intent`.
        if exec.verification_passed
            && let Some(expires_at) = expires_at
        {
            self.active.insert(
                payload.intent_id.clone(),
                ActiveAction {
                    intent_id: payload.intent_id,
                    host_id: payload.host_id,
                    nonce: payload.nonce,
                    verb: payload.verb,
                    rollback_handle: exec.rollback_handle,
                    expires_at,
                    dry_run: exec.dry_run,
                },
            );
        }

        receipt
    }

    /// Roll back every action whose TTL has elapsed, returning one receipt
    /// per rolled-back action. Safe to call repeatedly.
    pub async fn expire_due_actions(&mut self, now: DateTime<Utc>) -> Vec<ActionReceipt> {
        let due: Vec<ActiveAction> = self
            .active
            .values()
            .filter(|action| action.expires_at <= now)
            .cloned()
            .collect();
        let mut receipts = Vec::with_capacity(due.len());
        for action in due {
            self.active.remove(&action.intent_id);
            receipts.push(self.perform_rollback(action, now).await);
        }
        receipts
    }

    /// Manually roll back one active action by intent id.
    pub async fn rollback_intent(
        &mut self,
        intent_id: &str,
        now: DateTime<Utc>,
    ) -> Option<ActionReceipt> {
        let action = self.active.remove(intent_id)?;
        Some(self.perform_rollback(action, now).await)
    }

    async fn perform_rollback(&self, action: ActiveAction, now: DateTime<Utc>) -> ActionReceipt {
        let result = self
            .driver
            .rollback(&action.intent_id, &action.verb, &action.rollback_handle)
            .await;
        let (verification_passed, detail) = match result {
            Ok(msg) => (true, format!("rollback complete: {msg}")),
            Err(e) => (false, format!("rollback failed: {e}")),
        };
        tracing::warn!(
            intent_id = %action.intent_id,
            %verification_passed,
            "expired TTL action rolled back"
        );
        ActionReceipt {
            intent_id: action.intent_id,
            host_id: action.host_id,
            nonce: action.nonce,
            status: ActionIntentStatus::RolledBack,
            dry_run: action.dry_run,
            executed_at: now,
            expires_at: None,
            rollback_handle: Some(action.rollback_handle),
            verification_passed,
            detail,
        }
    }
}

/// Explicit fail-closed receipt used for every pre-execution rejection.
fn rejected_receipt(
    intent_id: &str,
    host_id: &str,
    nonce: &str,
    now: DateTime<Utc>,
    detail: impl Into<String>,
) -> ActionReceipt {
    ActionReceipt {
        intent_id: intent_id.to_string(),
        host_id: host_id.to_string(),
        nonce: nonce.to_string(),
        status: ActionIntentStatus::Rejected,
        dry_run: false,
        executed_at: now,
        expires_at: None,
        rollback_handle: None,
        verification_passed: false,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::FakeActionDriver;
    use defsec_protocol::action::{ActionAuthMode, ActionVerb, TrafficDirection};
    use defsec_protocol::signing::SigningKeyPair;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "action-exec-unit-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn executor_fails_closed_on_corrupt_replay_store() {
        let dir = temp_dir();
        std::fs::write(dir.join("executed_nonces.json"), "garbage").unwrap();
        let control = SigningKeyPair::generate("control-key-01");
        let operator = SigningKeyPair::generate("operator-key-01");
        let mut control_keys = VerifyingKeyStore::new();
        control_keys
            .insert_public_hex(control.key_id(), &control.public_hex())
            .unwrap();
        let mut operator_keys = VerifyingKeyStore::new();
        operator_keys
            .insert_public_hex(operator.key_id(), &operator.public_hex())
            .unwrap();
        let err = ActionExecutor::<FakeActionDriver>::new(
            "edge-01".into(),
            ActionSafetyConfig::default(),
            control_keys,
            operator_keys,
            dir.clone(),
            Arc::new(FakeActionDriver::new()),
        )
        .err()
        .expect("corrupt replay store must fail executor construction");
        assert!(matches!(err, ReplayStoreError::Corrupt(_)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn verification_failed_effects_never_enter_active_rollback_tracking() {
        let dir = temp_dir();
        let control = SigningKeyPair::generate("control-key-01");
        let mut control_keys = VerifyingKeyStore::new();
        control_keys
            .insert_public_hex(control.key_id(), &control.public_hex())
            .unwrap();
        let driver = Arc::new(FakeActionDriver::new());
        driver.set_fail_verification(true);
        let mut executor = ActionExecutor::new(
            "edge-01".into(),
            ActionSafetyConfig::with_bounded_autonomous_containment(),
            control_keys,
            VerifyingKeyStore::new(),
            dir.clone(),
            driver,
        )
        .unwrap();

        let now = Utc::now();
        let uid = uuid::Uuid::new_v4().simple().to_string();
        let payload = ActionIntentPayload {
            schema_version: 1,
            intent_id: format!("intent-{uid}"),
            nonce: format!("nonce-{uid}"),
            host_id: "edge-01".into(),
            incident_id: "inc-1".into(),
            proposal_id: 1,
            auth_mode: ActionAuthMode::PolicyBoundedAutonomous,
            verb: ActionVerb::NftBlockIp {
                ip: "203.0.113.42".into(),
                direction: TrafficDirection::Inbound,
                ttl_seconds: 600,
            },
            policy_version: 1,
            issued_at: now - Duration::seconds(60),
            expires_at: now + Duration::seconds(600),
            rollback_plan: "manual".into(),
            evidence_observation_ids: vec![1],
        };
        let intent = AuthorizedActionIntent {
            control_envelope: control
                .sign_payload(DOMAIN_ACTION_INTENT_V1, &payload)
                .unwrap(),
            operator_approval: None,
        };

        let receipt = executor.execute_intent(&intent, now).await;
        assert_eq!(receipt.status, ActionIntentStatus::VerificationFailed);
        assert!(!receipt.verification_passed);
        assert_eq!(executor.active_action_count(), 0);
        assert!(executor.expire_due_actions(now + Duration::seconds(3600)).await.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
