//! In-process integration tests driving `ActionExecutor` exactly the way
//! `control-d` integration harnesses do: through the public library API.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use action_exec_d::driver::{ActionDriver, FakeActionDriver};
use action_exec_d::executor::ActionExecutor;
use action_exec_d::replay::ReplayStoreError;
use chrono::{DateTime, Duration, Utc};
use defsec_policy::action_gate::ActionSafetyConfig;
use defsec_protocol::action::{
    ActionAuthMode, ActionIntentPayload, ActionIntentStatus, ActionVerb, AuthorizedActionIntent,
    TrafficDirection,
};
use defsec_protocol::signing::{
    DOMAIN_ACTION_APPROVAL_V1, DOMAIN_ACTION_INTENT_V1, SigningKeyPair, VerifyingKeyStore,
};

const HOST: &str = "edge-01";

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "action-exec-it-{tag}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key_store(kp: &SigningKeyPair) -> VerifyingKeyStore {
    let mut store = VerifyingKeyStore::new();
    store.insert_public_hex(kp.key_id(), &kp.public_hex()).unwrap();
    store
}

fn payload(
    host_id: &str,
    verb: ActionVerb,
    auth_mode: ActionAuthMode,
    now: DateTime<Utc>,
) -> ActionIntentPayload {
    let uid = uuid::Uuid::new_v4().simple().to_string();
    ActionIntentPayload {
        schema_version: 1,
        intent_id: format!("intent-{uid}"),
        nonce: format!("nonce-{uid}"),
        host_id: host_id.into(),
        incident_id: "inc-100".into(),
        proposal_id: 7,
        auth_mode,
        verb,
        policy_version: 1,
        issued_at: now - Duration::seconds(60),
        expires_at: now + Duration::seconds(600),
        rollback_plan: "operator manual rollback".into(),
        evidence_observation_ids: vec![11, 12],
    }
}

/// Sign `payload` with the control key and (optionally) an independent
/// operator key over the exact same canonical bytes.
fn signed_intent(
    payload: &ActionIntentPayload,
    control: &SigningKeyPair,
    operator: Option<&SigningKeyPair>,
) -> AuthorizedActionIntent {
    AuthorizedActionIntent {
        control_envelope: control
            .sign_payload(DOMAIN_ACTION_INTENT_V1, payload)
            .unwrap(),
        operator_approval: operator
            .map(|op| op.sign_payload(DOMAIN_ACTION_APPROVAL_V1, payload).unwrap()),
    }
}

fn new_executor<D: ActionDriver>(
    dir: &Path,
    host_id: &str,
    cfg: ActionSafetyConfig,
    control_keys: VerifyingKeyStore,
    operator_keys: VerifyingKeyStore,
    driver: Arc<D>,
) -> ActionExecutor<D> {
    ActionExecutor::new(
        host_id.to_string(),
        cfg,
        control_keys,
        operator_keys,
        dir.to_path_buf(),
        driver,
    )
    .unwrap()
}

/// Standard dual-key setup: control and operator stores hold only their own
/// independently generated keys.
fn dual_key_stores() -> (SigningKeyPair, SigningKeyPair, VerifyingKeyStore, VerifyingKeyStore) {
    let control = SigningKeyPair::generate("control-key-01");
    let operator = SigningKeyPair::generate("operator-key-01");
    let control_keys = key_store(&control);
    let operator_keys = key_store(&operator);
    (control, operator, control_keys, operator_keys)
}

// -------------------------------------------------------------------------
// 1. Policy-bounded autonomous verbs
// -------------------------------------------------------------------------

#[tokio::test]
async fn autonomous_nft_block_executes_only_when_locally_enabled() {
    let now = Utc::now();
    let verb = ActionVerb::NftBlockIp {
        ip: "203.0.113.42".into(),
        direction: TrafficDirection::Inbound,
        ttl_seconds: 900,
    };

    // Enabled locally (explicit opt-in): executed.
    let (control, _operator, control_keys, _op_keys) = dual_key_stores();
    let dir = temp_dir("autonomous-on");
    let driver = Arc::new(FakeActionDriver::new());
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::with_bounded_autonomous_containment(),
        control_keys,
        VerifyingKeyStore::new(),
        driver.clone(),
    );
    let p = payload(HOST, verb.clone(), ActionAuthMode::PolicyBoundedAutonomous, now);
    let intent = signed_intent(&p, &control, None);
    let receipt = executor.execute_intent(&intent, now).await;
    assert_eq!(receipt.status, ActionIntentStatus::Executed);
    assert!(receipt.verification_passed);
    assert!(!receipt.dry_run);
    assert_eq!(receipt.expires_at, Some(now + Duration::seconds(900)));
    assert_eq!(receipt.intent_id, p.intent_id);
    assert_eq!(driver.executed_intents().len(), 1);
    assert_eq!(executor.active_action_count(), 1);
    std::fs::remove_dir_all(&dir).unwrap();

    // Safe default (allow_autonomous_verbs empty): rejected, no effect.
    let (control2, _op2, control_keys2, _op_keys2) = dual_key_stores();
    let dir = temp_dir("autonomous-off");
    let driver2 = Arc::new(FakeActionDriver::new());
    let mut executor2 = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::default(),
        control_keys2,
        VerifyingKeyStore::new(),
        driver2.clone(),
    );
    let p2 = payload(HOST, verb, ActionAuthMode::PolicyBoundedAutonomous, now);
    let intent2 = signed_intent(&p2, &control2, None);
    let receipt2 = executor2.execute_intent(&intent2, now).await;
    assert_eq!(receipt2.status, ActionIntentStatus::Rejected);
    assert!(!receipt2.verification_passed);
    assert!(receipt2.detail.contains("not enabled on this executor"), "detail: {}", receipt2.detail);
    assert!(driver2.executed_intents().is_empty());
    assert_eq!(executor2.active_action_count(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

// -------------------------------------------------------------------------
// 2. Dual-signed HostIsolate authorization matrix
// -------------------------------------------------------------------------

#[tokio::test]
async fn host_isolate_dual_signature_matrix() {
    let now = Utc::now();
    let verb = ActionVerb::HostIsolate {
        preserve_mgmt_cidrs: vec!["10.10.0.0/24".into()],
        ttl_seconds: 900,
    };
    let (control, operator, control_keys, operator_keys) = dual_key_stores();

    // (a) Control signature alone is NOT sufficient.
    let dir = temp_dir("isolate-control-only");
    let driver = Arc::new(FakeActionDriver::new());
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::default(),
        control_keys.clone(),
        operator_keys.clone(),
        driver.clone(),
    );
    let p = payload(HOST, verb.clone(), ActionAuthMode::DualSignedOperator, now);
    let intent = signed_intent(&p, &control, None);
    let receipt = executor.execute_intent(&intent, now).await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert!(receipt.detail.contains("dual-signed operator approval"), "detail: {}", receipt.detail);
    assert!(driver.executed_intents().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();

    // (b) Operator signed DIFFERENT canonical bytes (parameter substitution).
    let dir = temp_dir("isolate-different-bytes");
    let driver = Arc::new(FakeActionDriver::new());
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::default(),
        control_keys.clone(),
        operator_keys.clone(),
        driver.clone(),
    );
    let p = payload(HOST, verb.clone(), ActionAuthMode::DualSignedOperator, now);
    let mut p_tampered = p.clone();
    p_tampered.verb = ActionVerb::HostIsolate {
        preserve_mgmt_cidrs: vec!["10.10.0.0/24".into()],
        ttl_seconds: 901,
    };
    let intent = AuthorizedActionIntent {
        control_envelope: control
            .sign_payload(DOMAIN_ACTION_INTENT_V1, &p)
            .unwrap(),
        operator_approval: Some(
            operator
                .sign_payload(DOMAIN_ACTION_APPROVAL_V1, &p_tampered)
                .unwrap(),
        ),
    };
    let receipt = executor.execute_intent(&intent, now).await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert!(receipt.detail.contains("different canonical bytes"), "detail: {}", receipt.detail);
    assert!(driver.executed_intents().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();

    // (c) "Operator" approval signed by the SAME key id as control.
    let dir = temp_dir("isolate-same-key-id");
    let driver = Arc::new(FakeActionDriver::new());
    // The operator store trusts the control key id too, so the signature
    // itself verifies — only the distinct-key rule can save us.
    let mut operator_store_clone = operator_keys.clone();
    operator_store_clone
        .insert_public_hex(control.key_id(), &control.public_hex())
        .unwrap();
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::default(),
        control_keys.clone(),
        operator_store_clone,
        driver.clone(),
    );
    let p = payload(HOST, verb.clone(), ActionAuthMode::DualSignedOperator, now);
    let intent = signed_intent(&p, &control, Some(&control));
    let receipt = executor.execute_intent(&intent, now).await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert!(receipt.detail.contains("must differ from control signing key"), "detail: {}", receipt.detail);
    assert!(driver.executed_intents().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();

    // (d) Same key MATERIAL under a different key id is equally rejected.
    let dir = temp_dir("isolate-cloned-material");
    let driver = Arc::new(FakeActionDriver::new());
    let clone_kp =
        SigningKeyPair::from_secret_hex("operator-clone", &control.secret_hex()).unwrap();
    assert_eq!(clone_kp.public_hex(), control.public_hex());
    let mut operator_store_with_clone = operator_keys.clone();
    operator_store_with_clone
        .insert_public_hex(clone_kp.key_id(), &clone_kp.public_hex())
        .unwrap();
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::default(),
        control_keys.clone(),
        operator_store_with_clone,
        driver.clone(),
    );
    let p = payload(HOST, verb.clone(), ActionAuthMode::DualSignedOperator, now);
    let intent = signed_intent(&p, &control, Some(&clone_kp));
    let receipt = executor.execute_intent(&intent, now).await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert!(receipt.detail.contains("identical to the control signing key"), "detail: {}", receipt.detail);
    assert!(driver.executed_intents().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();

    // (e) Distinct control + operator keys over identical bytes: accepted.
    let dir = temp_dir("isolate-valid");
    let driver = Arc::new(FakeActionDriver::new());
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::default(),
        control_keys,
        operator_keys,
        driver.clone(),
    );
    let p = payload(HOST, verb, ActionAuthMode::DualSignedOperator, now);
    let intent = signed_intent(&p, &control, Some(&operator));
    let receipt = executor.execute_intent(&intent, now).await;
    assert_eq!(receipt.status, ActionIntentStatus::Executed);
    assert!(receipt.verification_passed);
    assert_eq!(receipt.intent_id, p.intent_id);
    assert_eq!(receipt.nonce, p.nonce);
    assert_eq!(driver.executed_intents().len(), 1);
    assert_eq!(executor.active_action_count(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

// -------------------------------------------------------------------------
// 3. Replay protection (in-memory and across restart)
// -------------------------------------------------------------------------

#[tokio::test]
async fn replay_rejection_in_memory_and_across_restart() {
    let now = Utc::now();
    let (control, _operator, control_keys, _op_keys) = dual_key_stores();
    let verb = ActionVerb::NftBlockIp {
        ip: "198.51.100.7".into(),
        direction: TrafficDirection::Both,
        ttl_seconds: 600,
    };
    let p = payload(HOST, verb, ActionAuthMode::PolicyBoundedAutonomous, now);
    let intent = signed_intent(&p, &control, None);
    let dir = temp_dir("replay");

    // First execution succeeds.
    let driver = Arc::new(FakeActionDriver::new());
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::with_bounded_autonomous_containment(),
        control_keys.clone(),
        VerifyingKeyStore::new(),
        driver.clone(),
    );
    let first = executor.execute_intent(&intent, now).await;
    assert_eq!(first.status, ActionIntentStatus::Executed);

    // Same nonce again in the same process: replay rejected.
    let second = executor.execute_intent(&intent, now).await;
    assert_eq!(second.status, ActionIntentStatus::Rejected);
    assert_eq!(second.detail, "replay rejected");
    assert_eq!(driver.executed_intents().len(), 1);

    // Simulated full restart: a brand-new executor over the same state dir
    // (and a brand-new driver) still refuses the replayed nonce.
    let driver2 = Arc::new(FakeActionDriver::new());
    let mut executor2 = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::with_bounded_autonomous_containment(),
        control_keys,
        VerifyingKeyStore::new(),
        driver2.clone(),
    );
    let third = executor2.execute_intent(&intent, now).await;
    assert_eq!(third.status, ActionIntentStatus::Rejected);
    assert_eq!(third.detail, "replay rejected");
    assert!(driver2.executed_intents().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

// -------------------------------------------------------------------------
// 4. Protected assets reject even valid dual-signed intents
// -------------------------------------------------------------------------

#[tokio::test]
async fn protected_assets_rejected_even_when_dual_signed() {
    let now = Utc::now();
    let (control, operator, control_keys, operator_keys) = dual_key_stores();
    let dir = temp_dir("protected");
    let driver = Arc::new(FakeActionDriver::new());
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::default(),
        control_keys,
        operator_keys,
        driver.clone(),
    );

    // Blocking loopback would self-DoS the edge host.
    let loopback = payload(
        HOST,
        ActionVerb::NftBlockIp {
            ip: "127.0.0.1".into(),
            direction: TrafficDirection::Inbound,
            ttl_seconds: 600,
        },
        ActionAuthMode::DualSignedOperator,
        now,
    );
    let receipt = executor
        .execute_intent(&signed_intent(&loopback, &control, Some(&operator)), now)
        .await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert!(receipt.detail.contains("protected"), "detail: {}", receipt.detail);

    // Stopping sshd.service would lock out operators.
    let sshd = payload(
        HOST,
        ActionVerb::SystemdStopUnit {
            unit: "sshd.service".into(),
            ttl_seconds: Some(600),
        },
        ActionAuthMode::DualSignedOperator,
        now,
    );
    let receipt = executor
        .execute_intent(&signed_intent(&sshd, &control, Some(&operator)), now)
        .await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert!(receipt.detail.contains("protected"), "detail: {}", receipt.detail);

    assert!(driver.executed_intents().is_empty());
    assert_eq!(executor.active_action_count(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

// -------------------------------------------------------------------------
// 5. Automatic TTL expiry & rollback, plus manual rollback
// -------------------------------------------------------------------------

#[tokio::test]
async fn ttl_expiry_rolls_back_and_manual_rollback_works() {
    let now = Utc::now();
    let (control, _operator, control_keys, _op_keys) = dual_key_stores();
    let dir = temp_dir("ttl");
    let driver = Arc::new(FakeActionDriver::new());
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::with_bounded_autonomous_containment(),
        control_keys,
        VerifyingKeyStore::new(),
        driver.clone(),
    );

    let p = payload(
        HOST,
        ActionVerb::NftBlockIp {
            ip: "203.0.113.99".into(),
            direction: TrafficDirection::Inbound,
            ttl_seconds: 600,
        },
        ActionAuthMode::PolicyBoundedAutonomous,
        now,
    );
    let receipt = executor
        .execute_intent(&signed_intent(&p, &control, None), now)
        .await;
    assert_eq!(receipt.status, ActionIntentStatus::Executed);

    // Not yet due.
    assert!(executor.expire_due_actions(now + Duration::seconds(599)).await.is_empty());

    // After the TTL: exactly one rolled-back receipt, driver.rollback invoked.
    let later = now + Duration::seconds(601);
    let receipts = executor.expire_due_actions(later).await;
    assert_eq!(receipts.len(), 1);
    let rb = &receipts[0];
    assert_eq!(rb.status, ActionIntentStatus::RolledBack);
    assert!(rb.verification_passed);
    assert_eq!(rb.intent_id, p.intent_id);
    assert_eq!(rb.nonce, p.nonce);
    assert_eq!(executor.active_action_count(), 0);
    let calls = driver.rollback_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].intent_id, p.intent_id);
    assert_eq!(calls[0].rollback_handle, format!("fake:{}", p.intent_id));

    // Idempotent: nothing left to roll back.
    assert!(executor.expire_due_actions(later).await.is_empty());

    // Manual rollback of a second, still-active intent.
    let p2 = payload(
        HOST,
        ActionVerb::NftBlockIp {
            ip: "198.51.100.20".into(),
            direction: TrafficDirection::Outbound,
            ttl_seconds: 600,
        },
        ActionAuthMode::PolicyBoundedAutonomous,
        now,
    );
    executor
        .execute_intent(&signed_intent(&p2, &control, None), now)
        .await;
    let manual = executor.rollback_intent(&p2.intent_id, later).await;
    let manual = manual.expect("manual rollback must find the active action");
    assert_eq!(manual.status, ActionIntentStatus::RolledBack);
    assert!(manual.verification_passed);
    assert_eq!(driver.rollback_calls().len(), 2);
    assert!(executor.rollback_intent(&p2.intent_id, later).await.is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}

// -------------------------------------------------------------------------
// 6. Wrong-host and expired-window intents
// -------------------------------------------------------------------------

#[tokio::test]
async fn wrong_host_and_expired_window_intents_are_rejected() {
    let now = Utc::now();
    let (control, _operator, control_keys, _op_keys) = dual_key_stores();
    let dir = temp_dir("host-window");
    let driver = Arc::new(FakeActionDriver::new());
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::default(),
        control_keys,
        VerifyingKeyStore::new(),
        driver.clone(),
    );

    // Intent bound to a different host.
    let wrong_host = payload(
        "edge-02",
        ActionVerb::NftBlockIp {
            ip: "203.0.113.42".into(),
            direction: TrafficDirection::Inbound,
            ttl_seconds: 600,
        },
        ActionAuthMode::PolicyBoundedAutonomous,
        now,
    );
    let receipt = executor
        .execute_intent(&signed_intent(&wrong_host, &control, None), now)
        .await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert!(receipt.detail.contains("does not match local host"), "detail: {}", receipt.detail);

    // Intent whose validity window has fully elapsed.
    let mut expired = payload(
        HOST,
        ActionVerb::NftBlockIp {
            ip: "203.0.113.43".into(),
            direction: TrafficDirection::Inbound,
            ttl_seconds: 600,
        },
        ActionAuthMode::PolicyBoundedAutonomous,
        now,
    );
    expired.issued_at = now - Duration::seconds(4000);
    expired.expires_at = now - Duration::seconds(3600);
    let receipt = executor
        .execute_intent(&signed_intent(&expired, &control, None), now)
        .await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert!(receipt.detail.contains("expired"), "detail: {}", receipt.detail);

    assert!(driver.executed_intents().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

// -------------------------------------------------------------------------
// Additional hardening checks
// -------------------------------------------------------------------------

#[tokio::test]
async fn tampered_control_envelope_and_scripted_driver_failures_are_explicit() {
    let now = Utc::now();
    let (control, operator, control_keys, operator_keys) = dual_key_stores();
    let dir = temp_dir("hardening");
    let driver = Arc::new(FakeActionDriver::new());
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::default(),
        control_keys,
        operator_keys,
        driver.clone(),
    );

    // Tampered control envelope bytes fail verification before any decode.
    let p = payload(
        HOST,
        ActionVerb::HostIsolate {
            preserve_mgmt_cidrs: vec!["10.10.0.0/24".into()],
            ttl_seconds: 900,
        },
        ActionAuthMode::DualSignedOperator,
        now,
    );
    let mut intent = signed_intent(&p, &control, Some(&operator));
    intent.control_envelope.raw_payload = intent
        .control_envelope
        .raw_payload
        .replace("900", "901");
    let receipt = executor.execute_intent(&intent, now).await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert!(receipt.detail.contains("control intent signature verification failed"), "detail: {}", receipt.detail);
    assert!(receipt.intent_id.is_empty(), "untrusted fields must not leak into the receipt");

    // Scripted driver failure: explicit rejected receipt (fail closed).
    driver.set_fail_execute(true);
    let p2 = payload(
        HOST,
        ActionVerb::SystemdStopUnit {
            unit: "nginx.service".into(),
            ttl_seconds: Some(600),
        },
        ActionAuthMode::DualSignedOperator,
        now,
    );
    let receipt = executor
        .execute_intent(&signed_intent(&p2, &control, Some(&operator)), now)
        .await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert!(receipt.detail.contains("driver execution failed"), "detail: {}", receipt.detail);
    assert_eq!(executor.active_action_count(), 0);

    // The nonce was durably committed BEFORE dispatch, so retrying the same
    // intent (even once the driver is healthy again) is replay-rejected.
    driver.set_fail_execute(false);
    let receipt = executor
        .execute_intent(&signed_intent(&p2, &control, Some(&operator)), now)
        .await;
    assert_eq!(receipt.status, ActionIntentStatus::Rejected);
    assert_eq!(receipt.detail, "replay rejected");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn dry_run_driver_yields_dry_run_simulated_receipts_with_rollback() {
    use action_exec_d::driver::DryRunDriver;

    let now = Utc::now();
    let (control, operator, control_keys, operator_keys) = dual_key_stores();
    let dir = temp_dir("dryrun");
    let mut executor = new_executor(
        &dir,
        HOST,
        ActionSafetyConfig::default(),
        control_keys,
        operator_keys,
        Arc::new(DryRunDriver::new()),
    );

    // Autonomous host_isolate is never allowed; dry-run is dual-signed here.
    let p = payload(
        HOST,
        ActionVerb::HostIsolate {
            preserve_mgmt_cidrs: vec!["10.10.0.0/24".into()],
            ttl_seconds: 300,
        },
        ActionAuthMode::DualSignedOperator,
        now,
    );
    let intent = signed_intent(&p, &control, Some(&operator));
    let receipt = executor.execute_intent(&intent, now).await;
    assert_eq!(receipt.status, ActionIntentStatus::DryRunSimulated);
    assert!(receipt.dry_run);
    assert!(receipt.verification_passed);
    assert!(receipt.rollback_handle.as_deref().is_some_and(|h| h.starts_with("dry-run:")));

    // TTL expiry still drives simulated rollback.
    let receipts = executor
        .expire_due_actions(now + Duration::seconds(301))
        .await;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].status, ActionIntentStatus::RolledBack);
    assert!(receipts[0].dry_run);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn corrupt_replay_store_prevents_executor_construction() {
    let dir = temp_dir("corrupt-exec");
    std::fs::write(dir.join("executed_nonces.json"), "{{{garbage").unwrap();
    let (_control, _operator, control_keys, _op_keys) = dual_key_stores();
    let err = ActionExecutor::<FakeActionDriver>::new(
        HOST.into(),
        ActionSafetyConfig::default(),
        control_keys,
        VerifyingKeyStore::new(),
        dir.clone(),
        Arc::new(FakeActionDriver::new()),
    )
    .err()
    .expect("corrupt replay store must fail executor construction");
    assert!(matches!(err, ReplayStoreError::Corrupt(_)));
    std::fs::remove_dir_all(&dir).unwrap();
}
