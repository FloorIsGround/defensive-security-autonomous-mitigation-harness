//! Full cross-crate Phase 8 End-to-End Mitigation Suite
//!
//! Wires real `agent-d` (`AgentEngine<FakeHostCollectors>`), real `control-d`
//! (`ControlService`), real `action-exec-d` (`ActionExecutor<FakeActionDriver>`),
//! and an independent operator Ed25519 key end-to-end across:
//! 1. Policy-Bounded Autonomous Containment (`NftBlockIp`) -> execution ->
//!    replay rejection -> automatic TTL rollback -> audit-chain verification.
//! 2. Dual-Signed Operator Approval (`HostIsolate`) -> single-sig rejection ->
//!    independent operator signing -> dual-sig execution -> causal feedback-loop
//!    cooldown & protected-asset rejection.

use std::sync::Arc;

use action_exec_d::driver::FakeActionDriver;
use action_exec_d::executor::ActionExecutor;
use agent_d::collectors::FakeHostCollectors;
use agent_d::engine::AgentEngine;
use agent_d::spool::DurabilityProfile;
use chrono::{Duration, Utc};
use control_d::ControlService;
use defsec_policy::action_gate::ActionSafetyConfig;
use defsec_policy::control_gate::ControlPolicyConfig;
use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::action::{
    ActionAuthMode, ActionIntentStatus, ActionVerb, AuthorizedActionIntent, TrafficDirection,
};
use defsec_protocol::observation::{ListeningSocketEntry, SocketsListeningSnapshot};
use defsec_protocol::rpc::*;
use defsec_protocol::signing::{
    DOMAIN_ACTION_APPROVAL_V1, SigningKeyPair, VerifyingKeyStore,
};
use defsec_protocol::watch::*;
use defsec_protocol::wire::*;

fn socket_entry(port: u16, uid: u32, comm: &str) -> ListeningSocketEntry {
    ListeningSocketEntry {
        socket_key: format!("tcp:0.0.0.0:{port}:uid={uid}"),
        protocol: "tcp".into(),
        local_addr: "0.0.0.0".into(),
        local_port: port,
        uid,
        inode: 20_000 + u64::from(port),
        pid: Some(200 + u32::from(port)),
        pid_start_time_ticks: Some(700),
        comm: Some(comm.into()),
        systemd_unit: Some(format!("{comm}.service")),
    }
}

fn baseline_sockets_watch(host: &str) -> WatchSpec {
    WatchSpec {
        id: "base-sockets".into(),
        version: 1,
        host_id: host.into(),
        class: WatchClass::Baseline,
        incident_id: None,
        collector: CollectorSpec::SocketsListening(SocketsListeningParams {
            include_tcp: true,
            include_udp: false,
            include_ipv6: false,
            resolve_process: true,
        }),
        schedule: WatchSchedule {
            interval_seconds: 30,
            timeout_seconds: 5,
        },
        trigger: TriggerPredicate::SetDiff {
            compare_against: CompareTarget::AcceptedBaseline,
            set_field: "sockets".into(),
            identity_key: "socket_key".into(),
            ignore_fields: vec![],
        },
        wake_policy: WakePolicy {
            cooldown_seconds: 60,
            max_wakeups_per_hour: 10,
        },
        lifecycle: WatchLifecycle {
            enabled: true,
            expires_at: None,
            max_runs: None,
        },
    }
}

async fn pump(
    control: &ControlService,
    agent: &mut AgentEngine<FakeHostCollectors>,
    initial: Vec<AgentToControl>,
    now: chrono::DateTime<Utc>,
) {
    let mut outbound = initial;
    for _ in 0..16 {
        if outbound.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for msg in outbound {
            for reply in control.handle_agent_message(msg) {
                next.extend(agent.handle_control(reply, now).await);
            }
        }
        outbound = next;
    }
}

/// Helper: sets up enrolled host, baseline promotion, anomaly drift -> open incident,
/// investigator token & active run, returning `(control, executor, driver, operator_kp, inv_token, run_id, incident_id, drift_obs_id)`.
async fn setup_triggered_incident(
    host_id: &str,
) -> (
    ControlService,
    ActionExecutor<FakeActionDriver>,
    Arc<FakeActionDriver>,
    SigningKeyPair,
    String,
    String,
    String,
    i64,
) {
    let short = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let root = std::env::temp_dir().join(format!("p8-{short}"));

    let action_cfg = ActionSafetyConfig::with_bounded_autonomous_containment();
    let control = ControlService::open_with_policies(
        root.join("ctrl"),
        "control-key-01",
        ControlPolicyConfig::default(),
        action_cfg.clone(),
    )
    .unwrap();

    // Independent operator approval key (distinct from control-d signing key).
    let operator_kp = SigningKeyPair::generate("operator-yubikey-01");
    control
        .register_operator_key(operator_kp.key_id(), &operator_kp.public_hex())
        .unwrap();

    let AdminResponse::HostEnrolled {
        control_signing_key_id,
        control_public_key_hex,
        ..
    } = control.handle_admin_request(AdminRequest::EnrollHost {
        host_id: host_id.into(),
        agent_public_key_hex: None,
    })
    else {
        panic!("enroll failed");
    };

    let mut control_store = VerifyingKeyStore::new();
    control_store
        .insert_public_hex(&control_signing_key_id, &control_public_key_hex)
        .unwrap();
    let mut operator_store = VerifyingKeyStore::new();
    operator_store
        .insert_public_hex(operator_kp.key_id(), &operator_kp.public_hex())
        .unwrap();

    let fake_host = Arc::new(FakeHostCollectors::new());
    let mut agent = AgentEngine::new(
        EdgeSafetyConfig::default(),
        host_id.into(),
        DurabilityProfile::Minimal {
            max_ram_bytes: 256 * 1024,
        },
        root.join("agent"),
        control_store.clone(),
        fake_host.clone(),
    )
    .unwrap();

    let driver = Arc::new(FakeActionDriver::new());
    let executor = ActionExecutor::new(
        host_id.into(),
        action_cfg,
        control_store,
        operator_store,
        root.join("exec"),
        driver.clone(),
    )
    .unwrap();

    // Apply baseline watch, register, collect initial baseline, and promote it.
    assert!(matches!(
        control.handle_admin_request(AdminRequest::ApplyBaselineWatch {
            spec: baseline_sockets_watch(host_id),
            actor: "ops".into(),
            rationale: "baseline".into(),
        }),
        AdminResponse::WatchApplied { .. }
    ));

    let t0 = Utc::now();
    {
        let h = fake_host.state_handle();
        let mut st = h.lock().unwrap();
        st.sockets = SocketsListeningSnapshot {
            count: 1,
            partial_attribution: false,
            sockets: vec![socket_entry(22, 0, "sshd")],
        };
    }
    let reg = agent.make_register(t0);
    pump(&control, &mut agent, vec![reg], t0).await;

    let t1 = t0 + Duration::seconds(45);
    let emitted = agent.run_due_watches(t1).await;
    pump(&control, &mut agent, emitted, t1).await;

    let AdminResponse::TokenMinted { token: obs_tok, .. } =
        control.handle_admin_request(AdminRequest::MintCapabilityToken {
            principal_id: "obs".into(),
            role: PrincipalRole::Observer,
            allowed_hosts: vec![host_id.into()],
            allowed_collectors: vec![CollectorType::SocketsListening],
            incident_id: None,
            ttl_seconds: 3600,
        })
    else {
        panic!("mint observer failed");
    };
    let InvestigationResponse::Observations { observations } =
        control.handle_investigation_call(InvestigationCall {
            request_id: "req-base".into(),
            capability_token: obs_tok.clone(),
            request: InvestigationRequest::QueryObservations {
                host_id: host_id.into(),
                watch_id: Some("base-sockets".into()),
                since: None,
                limit: Some(5),
            },
        })
    else {
        panic!("query obs failed");
    };
    assert!(matches!(
        control.handle_admin_request(AdminRequest::PromoteBaseline {
            host_id: host_id.into(),
            watch_id: "base-sockets".into(),
            observation_id: observations[0].observation_id,
            approver: "ops".into(),
            rationale: "known good".into(),
            ticket_ref: Some("CHG-200".into()),
        }),
        AdminResponse::BaselinePromoted { .. }
    ));

    // Inject unexpected listener -> triggers open incident!
    {
        let h = fake_host.state_handle();
        let mut st = h.lock().unwrap();
        st.sockets = SocketsListeningSnapshot {
            count: 2,
            partial_attribution: false,
            sockets: vec![
                socket_entry(22, 0, "sshd"),
                socket_entry(4444, 1000, "rogue-beacon"),
            ],
        };
    }
    let t2 = t1 + Duration::seconds(45);
    let emitted = agent.run_due_watches(t2).await;
    pump(&control, &mut agent, emitted, t2).await;

    let AdminResponse::Incidents { incidents } =
        control.handle_admin_request(AdminRequest::ListIncidents)
    else {
        panic!("list incidents failed");
    };
    assert_eq!(incidents.len(), 1);
    let incident_id = incidents[0].incident_id.clone();

    let InvestigationResponse::Observations { observations: all_obs } =
        control.handle_investigation_call(InvestigationCall {
            request_id: "req-drift".into(),
            capability_token: obs_tok,
            request: InvestigationRequest::QueryObservations {
                host_id: host_id.into(),
                watch_id: Some("base-sockets".into()),
                since: None,
                limit: Some(10),
            },
        })
    else {
        panic!("query drift failed");
    };
    let drift_obs_id = all_obs.last().unwrap().observation_id;

    let AdminResponse::TokenMinted { token: inv_tok, .. } =
        control.handle_admin_request(AdminRequest::MintCapabilityToken {
            principal_id: "reasoner-d".into(),
            role: PrincipalRole::Investigator,
            allowed_hosts: vec![host_id.into()],
            allowed_collectors: vec![CollectorType::SocketsListening],
            incident_id: Some(incident_id.clone()),
            ttl_seconds: 3600,
        })
    else {
        panic!("mint inv failed");
    };
    let InvestigationResponse::RunStarted { run_id, .. } =
        control.handle_investigation_call(InvestigationCall {
            request_id: "req-run".into(),
            capability_token: inv_tok.clone(),
            request: InvestigationRequest::StartInvestigationRun {
                incident_id: incident_id.clone(),
                backend_id: "direct-api".into(),
                model_id: "test".into(),
                prompt_schema_version: "v1".into(),
            },
        })
    else {
        panic!("run start failed");
    };

    (
        control,
        executor,
        driver,
        operator_kp,
        inv_tok,
        run_id,
        incident_id,
        drift_obs_id,
    )
}

#[tokio::test]
async fn bounded_autonomous_containment_executes_rejects_replay_and_auto_rolls_back() {
    let (control, mut executor, driver, _op_kp, inv_tok, run_id, incident_id, obs_id) =
        setup_triggered_incident("edge-auto").await;

    // Reasoner autonomously proposes reversible 600s nftables IP block on attacker IP.
    let InvestigationResponse::ActionProposalEvaluated {
        decision,
        intent_id,
        auth_mode,
        status,
        authorized_intent,
        ..
    } = control.handle_investigation_call(InvestigationCall {
        request_id: "req-act-1".into(),
        capability_token: inv_tok,
        request: InvestigationRequest::ProposeAction {
            run_id,
            incident_id,
            idempotency_key: "block-attacker-1".into(),
            verb: ActionVerb::NftBlockIp {
                ip: "203.0.113.42".into(),
                direction: TrafficDirection::Inbound,
                ttl_seconds: 600,
            },
            evidence_observation_ids: vec![obs_id],
            expected_effect: "Drop inbound traffic from 203.0.113.42 for 10m".into(),
            blast_radius: "Single external IP".into(),
            rollback_plan: "Automatic nftables TTL expiry after 600s".into(),
        },
    })
    else {
        panic!("expected ActionProposalEvaluated");
    };

    assert!(decision.allowed);
    assert_eq!(auth_mode, Some(ActionAuthMode::PolicyBoundedAutonomous));
    assert_eq!(status, Some(ActionIntentStatus::Authorized));
    let intent_id = intent_id.expect("intent_id present");
    let intent = authorized_intent.expect("autonomous intent immediately signed");

    // Edge executor verifies Ed25519 signature, local floor, nonce, and executes!
    let now = Utc::now();
    let receipt = executor.execute_intent(&intent, now).await;
    assert_eq!(receipt.status, ActionIntentStatus::Executed);
    assert!(receipt.verification_passed);
    assert_eq!(driver.handle().lock().unwrap().executed.len(), 1);

    // Record execution receipt in control-d ledger.
    assert!(matches!(
        control.handle_admin_request(AdminRequest::RecordActionReceipt { receipt }),
        AdminResponse::ActionReceiptAck {
            status: ActionIntentStatus::Executed,
            ..
        }
    ));

    // Replaying the EXACT same signed intent MUST be rejected!
    let replay_receipt = executor.execute_intent(&intent, now + Duration::seconds(5)).await;
    assert_eq!(replay_receipt.status, ActionIntentStatus::Rejected);
    assert_eq!(driver.handle().lock().unwrap().executed.len(), 1);

    // Advance past 600s TTL -> automatic rollback fires!
    let rollbacks = executor
        .expire_due_actions(now + Duration::seconds(605))
        .await;
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].intent_id, intent_id);
    assert_eq!(rollbacks[0].status, ActionIntentStatus::RolledBack);
    assert_eq!(driver.handle().lock().unwrap().rollbacks.len(), 1);

    // Record rollback receipt and confirm hash-chained audit integrity.
    assert!(matches!(
        control.handle_admin_request(AdminRequest::RecordActionReceipt {
            receipt: rollbacks[0].clone(),
        }),
        AdminResponse::ActionReceiptAck {
            status: ActionIntentStatus::RolledBack,
            ..
        }
    ));
    assert!(matches!(
        control.handle_admin_request(AdminRequest::VerifyAuditChain),
        AdminResponse::AuditChainStatus { valid: true, .. }
    ));
}

#[tokio::test]
async fn dual_signed_host_isolation_enforces_operator_key_cooldown_and_protected_assets() {
    let (control, mut executor, driver, op_kp, inv_tok, run_id, incident_id, obs_id) =
        setup_triggered_incident("edge-dual").await;

    // Adversarial attempt 1: stop protected sshd.service -> rejected at control gate!
    let InvestigationResponse::ActionProposalEvaluated { decision, .. } =
        control.handle_investigation_call(InvestigationCall {
            request_id: "req-sshd".into(),
            capability_token: inv_tok.clone(),
            request: InvestigationRequest::ProposeAction {
                run_id: run_id.clone(),
                incident_id: incident_id.clone(),
                idempotency_key: "stop-sshd".into(),
                verb: ActionVerb::SystemdStopUnit {
                    unit: "sshd.service".into(),
                    ttl_seconds: Some(300),
                },
                evidence_observation_ids: vec![obs_id],
                expected_effect: "lockout".into(),
                blast_radius: "critical".into(),
                rollback_plan: "none".into(),
            },
        })
    else {
        panic!("expected proposal eval");
    };
    assert!(!decision.allowed);
    assert_eq!(decision.rule_id, "action.protected_unit");

    // High-blast-radius HostIsolate -> ALWAYS PendingApproval (never auto-authorized!).
    let InvestigationResponse::ActionProposalEvaluated {
        decision,
        intent_id,
        auth_mode,
        status,
        authorized_intent,
        ..
    } = control.handle_investigation_call(InvestigationCall {
        request_id: "req-iso".into(),
        capability_token: inv_tok.clone(),
        request: InvestigationRequest::ProposeAction {
            run_id: run_id.clone(),
            incident_id: incident_id.clone(),
            idempotency_key: "isolate-host-1".into(),
            verb: ActionVerb::HostIsolate {
                preserve_mgmt_cidrs: vec!["10.10.0.0/24".into()],
                ttl_seconds: 900,
            },
            evidence_observation_ids: vec![obs_id],
            expected_effect: "Quarantine host preserving management subnet".into(),
            blast_radius: "All non-management host traffic".into(),
            rollback_plan: "Flush defsecautmit_isolate table on expiry".into(),
        },
    })
    else {
        panic!("expected proposal eval");
    };
    assert!(decision.allowed);
    assert_eq!(auth_mode, Some(ActionAuthMode::DualSignedOperator));
    assert_eq!(status, Some(ActionIntentStatus::PendingApproval));
    assert!(authorized_intent.is_none());
    let intent_id = intent_id.expect("pending intent_id");

    // Operator retrieves canonical payload to sign independently.
    let AdminResponse::ActionIntentDetail {
        payload,
        authorized_intent: pending_auth,
        status: detail_status,
    } = control.handle_admin_request(AdminRequest::GetActionIntent {
        intent_id: intent_id.clone(),
    })
    else {
        panic!("get intent failed");
    };
    assert_eq!(detail_status, ActionIntentStatus::PendingApproval);
    assert!(pending_auth.is_none());

    // Even if someone tried to feed a single-signed control envelope directly to
    // `action-exec-d`, it MUST be rejected because HostIsolate requires operator approval!
    let fake_ctrl_env = SigningKeyPair::generate("other-ctrl")
        .sign_payload(
            defsec_protocol::signing::DOMAIN_ACTION_INTENT_V1,
            &payload,
        )
        .unwrap();
    let single_sig_attempt = executor
        .execute_intent(
            &AuthorizedActionIntent {
                control_envelope: fake_ctrl_env,
                operator_approval: None,
            },
            Utc::now(),
        )
        .await;
    assert_eq!(single_sig_attempt.status, ActionIntentStatus::Rejected);

    // Operator signs exact canonical payload with independent key and approves!
    let op_envelope = op_kp
        .sign_payload(DOMAIN_ACTION_APPROVAL_V1, &payload)
        .unwrap();
    let AdminResponse::ActionApproved {
        authorized_intent: dual_signed,
        ..
    } = control.handle_admin_request(AdminRequest::ApproveAction {
        intent_id: intent_id.clone(),
        approver: "secops-lead".into(),
        operator_approval: op_envelope,
    })
    else {
        panic!("operator approval failed");
    };

    // ActionExecutor verifies BOTH independent Ed25519 signatures and executes!
    let receipt = executor.execute_intent(&dual_signed, Utc::now()).await;
    assert_eq!(receipt.status, ActionIntentStatus::Executed);
    assert!(receipt.verification_passed);
    assert_eq!(driver.handle().lock().unwrap().executed.len(), 1);

    assert!(matches!(
        control.handle_admin_request(AdminRequest::RecordActionReceipt { receipt }),
        AdminResponse::ActionReceiptAck {
            status: ActionIntentStatus::Executed,
            ..
        }
    ));

    // Causal feedback-loop cooldown blocks immediate follow-up mitigation on same host!
    let InvestigationResponse::ActionProposalEvaluated { decision, .. } =
        control.handle_investigation_call(InvestigationCall {
            request_id: "req-loop".into(),
            capability_token: inv_tok,
            request: InvestigationRequest::ProposeAction {
                run_id,
                incident_id,
                idempotency_key: "rapid-followup".into(),
                verb: ActionVerb::NftBlockIp {
                    ip: "203.0.113.99".into(),
                    direction: TrafficDirection::Inbound,
                    ttl_seconds: 300,
                },
                evidence_observation_ids: vec![obs_id],
                expected_effect: "second rapid block".into(),
                blast_radius: "single IP".into(),
                rollback_plan: "TTL".into(),
            },
        })
    else {
        panic!("expected cooldown evaluation");
    };
    assert!(!decision.allowed);
    assert_eq!(decision.rule_id, "action.causal_cooldown");

    assert!(matches!(
        control.handle_admin_request(AdminRequest::VerifyAuditChain),
        AdminResponse::AuditChainStatus { valid: true, .. }
    ));
}
