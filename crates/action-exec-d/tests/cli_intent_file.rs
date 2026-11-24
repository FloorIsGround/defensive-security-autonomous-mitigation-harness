//! End-to-end CLI tests: sign an intent, invoke the `action-exec-d` binary
//! with `--intent-file`, and assert the printed `ActionReceipt` JSON.

use std::path::PathBuf;
use std::process::Command;

use chrono::{Duration, Utc};
use defsec_protocol::action::{
    ActionAuthMode, ActionIntentPayload, ActionVerb, AuthorizedActionIntent, TrafficDirection,
};
use defsec_protocol::signing::{
    DOMAIN_ACTION_APPROVAL_V1, DOMAIN_ACTION_INTENT_V1, SigningKeyPair,
};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_action-exec-d")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "action-exec-cli-{tag}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn payload(host_id: &str, verb: ActionVerb, auth_mode: ActionAuthMode) -> ActionIntentPayload {
    let now = Utc::now();
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
        evidence_observation_ids: vec![11],
    }
}

fn write_intent(
    dir: &PathBuf,
    name: &str,
    intent: &AuthorizedActionIntent,
) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string(intent).unwrap()).unwrap();
    path
}

fn run_cli(
    state_dir: &PathBuf,
    control: &SigningKeyPair,
    operator: &SigningKeyPair,
    extra_args: &[&str],
    intent_file: &PathBuf,
) -> (bool, String) {
    let output = Command::new(bin())
        .arg("--host-id")
        .arg("edge-01")
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--control-key-id")
        .arg(control.key_id())
        .arg("--control-pub-hex")
        .arg(control.public_hex())
        .arg("--operator-key-id")
        .arg(operator.key_id())
        .arg("--operator-pub-hex")
        .arg(operator.public_hex())
        .args(extra_args)
        .arg("--intent-file")
        .arg(intent_file)
        .output()
        .expect("failed to spawn action-exec-d binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

fn receipt_status(stdout: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("stdout is not receipt JSON ({e}): {stdout}"));
    parsed["status"]
        .as_str()
        .unwrap_or_else(|| panic!("receipt missing status: {stdout}"))
        .to_string()
}

#[test]
fn cli_dry_run_executes_dual_signed_intent_and_rejects_replay() {
    let dir = temp_dir("dryrun");
    let control = SigningKeyPair::generate("control-key-01");
    let operator = SigningKeyPair::generate("operator-key-01");

    let p = payload(
        "edge-01",
        ActionVerb::HostIsolate {
            preserve_mgmt_cidrs: vec!["10.10.0.0/24".into()],
            ttl_seconds: 900,
        },
        ActionAuthMode::DualSignedOperator,
    );
    let intent = AuthorizedActionIntent {
        control_envelope: control
            .sign_payload(DOMAIN_ACTION_INTENT_V1, &p)
            .unwrap(),
        operator_approval: Some(
            operator
                .sign_payload(DOMAIN_ACTION_APPROVAL_V1, &p)
                .unwrap(),
        ),
    };
    let intent_file = write_intent(&dir, "isolate.json", &intent);

    // Dry-run mode (default): simulated, verification passed, exit 0.
    let (ok, stdout) = run_cli(&dir, &control, &operator, &["--mode", "dry-run"], &intent_file);
    assert!(ok, "stdout: {stdout}");
    assert_eq!(receipt_status(&stdout), "dry_run_simulated");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["verification_passed"], serde_json::Value::Bool(true));
    assert_eq!(parsed["intent_id"], serde_json::json!(p.intent_id));

    // Same nonce again: replay rejected, non-zero exit.
    let (ok, stdout) = run_cli(&dir, &control, &operator, &["--mode", "dry-run"], &intent_file);
    assert!(!ok, "replayed intent must exit non-zero, stdout: {stdout}");
    assert_eq!(receipt_status(&stdout), "rejected");
    assert!(stdout.contains("replay rejected"), "stdout: {stdout}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_autonomous_containment_requires_explicit_opt_in() {
    let operator = SigningKeyPair::generate("operator-key-01");

    // Without --enable-autonomous-containment: rejected (safe default).
    let dir_off = temp_dir("autonomous-off");
    let control = SigningKeyPair::generate("control-key-01");
    let p = payload(
        "edge-01",
        ActionVerb::NftBlockIp {
            ip: "203.0.113.42".into(),
            direction: TrafficDirection::Inbound,
            ttl_seconds: 900,
        },
        ActionAuthMode::PolicyBoundedAutonomous,
    );
    let intent = AuthorizedActionIntent {
        control_envelope: control
            .sign_payload(DOMAIN_ACTION_INTENT_V1, &p)
            .unwrap(),
        operator_approval: None,
    };
    let intent_file = write_intent(&dir_off, "block.json", &intent);
    let (ok, stdout) = run_cli(&dir_off, &control, &operator, &[], &intent_file);
    assert!(!ok, "autonomous verb must be rejected by default: {stdout}");
    assert_eq!(receipt_status(&stdout), "rejected");
    assert!(stdout.contains("not enabled on this executor"), "stdout: {stdout}");
    std::fs::remove_dir_all(&dir_off).unwrap();

    // With the flag: dry-run simulated.
    let dir_on = temp_dir("autonomous-on");
    let intent_file = write_intent(&dir_on, "block.json", &intent);
    let (ok, stdout) = run_cli(
        &dir_on,
        &control,
        &operator,
        &["--enable-autonomous-containment"],
        &intent_file,
    );
    assert!(ok, "stdout: {stdout}");
    assert_eq!(receipt_status(&stdout), "dry_run_simulated");
    std::fs::remove_dir_all(&dir_on).unwrap();
}

#[test]
fn cli_rejects_wrong_control_key_without_printing_untrusted_fields() {
    let dir = temp_dir("wrong-key");
    let control = SigningKeyPair::generate("control-key-01");
    let other_control = SigningKeyPair::generate("control-key-02");
    let operator = SigningKeyPair::generate("operator-key-01");

    // Intent signed by a key the CLI does not trust.
    let p = payload(
        "edge-01",
        ActionVerb::HostIsolate {
            preserve_mgmt_cidrs: vec!["10.10.0.0/24".into()],
            ttl_seconds: 900,
        },
        ActionAuthMode::DualSignedOperator,
    );
    let intent = AuthorizedActionIntent {
        control_envelope: other_control
            .sign_payload(DOMAIN_ACTION_INTENT_V1, &p)
            .unwrap(),
        operator_approval: Some(
            operator
                .sign_payload(DOMAIN_ACTION_APPROVAL_V1, &p)
                .unwrap(),
        ),
    };
    let intent_file = write_intent(&dir, "rogue.json", &intent);
    let (ok, stdout) = run_cli(&dir, &control, &operator, &[], &intent_file);
    assert!(!ok, "untrusted control signature must fail: {stdout}");
    assert_eq!(receipt_status(&stdout), "rejected");
    assert!(stdout.contains("control intent signature verification failed"), "stdout: {stdout}");
    // No untrusted payload fields leak into the rejection receipt.
    assert!(!stdout.contains(&p.intent_id), "stdout: {stdout}");
    std::fs::remove_dir_all(&dir).unwrap();
}
