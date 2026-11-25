use std::{fs, path::PathBuf};

use chrono::Utc;
use control_d::{ControlService, ledger};
use defsec_policy::action_gate::ActionSafetyConfig;
use defsec_protocol::{
    action::{
        ActionAuthMode, ActionIntentPayload, ActionIntentStatus, ActionReceipt, ActionVerb,
        TrafficDirection,
    },
    audit::AuditEventType,
    rpc::{
        AdminRequest, AdminResponse, InvestigationCall, InvestigationRequest,
        InvestigationResponse, PrincipalRole,
    },
    signing::{
        DOMAIN_ACTION_APPROVAL_V1, DOMAIN_ACTION_INTENT_V1, SigningKeyPair, VerifyingKeyStore,
    },
    watch::CollectorType,
};
use rusqlite::Connection;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let id = uuid::Uuid::new_v4().simple().to_string();
        Self(std::env::temp_dir().join(format!("d-{}", &id[..8])))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Fixture {
    service: ControlService,
    dir: TempDir,
    token: String,
    run_id: String,
    control_public_hex: String,
}

impl Fixture {
    fn new(safety: ActionSafetyConfig) -> Self {
        let dir = TempDir::new();
        let service =
            ControlService::open_with_policies(&dir.0, "control", Default::default(), safety)
                .unwrap();
        let mut control_public_hex = String::new();
        for host in ["edge", "foreign"] {
            let AdminResponse::HostEnrolled {
                control_public_key_hex,
                ..
            } = service.handle_admin_request(AdminRequest::EnrollHost {
                host_id: host.into(),
                agent_public_key_hex: None,
            })
            else {
                panic!("host enrollment failed")
            };
            control_public_hex = control_public_key_hex;
        }
        let db = ledger::open(dir.0.join("ledger.sqlite3")).unwrap();
        db.execute_batch(r#"
            INSERT INTO incidents (incident_id,host_id,status,priority_json,summary,created_at,updated_at)
            VALUES ('incident','edge','open','"high"','investigate','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),
                   ('other','edge','open','"high"','investigate','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');
            INSERT INTO agent_sessions (host_id,session_id,boot_id)
            VALUES ('edge','session','boot'), ('foreign','session','boot');
            INSERT INTO watch_specs VALUES
                ('edge','watch',1,NULL,'{}','admin',1,'2026-01-01T00:00:00Z'),
                ('foreign','watch',1,NULL,'{}','admin',1,'2026-01-01T00:00:00Z'),
                ('edge','other-watch',1,'other','{}','admin',1,'2026-01-01T00:00:00Z');
            INSERT INTO observations (observation_id,host_id,session_id,seq_no,watch_id,spec_version,
                collector_type,observed_at,received_at,status_json,state_hash,payload_json,record_json)
            VALUES
                (1,'edge','session',1,'watch',1,'sockets.listening','now','now','"ok"','hash','{}','{}'),
                (2,'foreign','session',1,'watch',1,'sockets.listening','now','now','"ok"','hash','{}','{}'),
                (3,'edge','session',2,'watch',1,'files.metadata','now','now','"ok"','hash','{}','{}'),
                (4,'edge','session',3,'other-watch',1,'sockets.listening','now','now','"ok"','hash','{}','{}');
        "#).unwrap();
        let token = Self::mint_token(&service, PrincipalRole::Investigator, Some("incident"));
        let started = service.handle_investigation_call(InvestigationCall {
            request_id: "start".into(),
            capability_token: token.clone(),
            request: InvestigationRequest::StartInvestigationRun {
                incident_id: "incident".into(),
                backend_id: "test".into(),
                model_id: "test".into(),
                prompt_schema_version: "1".into(),
            },
        });
        let InvestigationResponse::RunStarted { run_id, .. } = started else {
            panic!("{started:?}")
        };
        Self {
            service,
            dir,
            token,
            run_id,
            control_public_hex,
        }
    }

    fn mint_token(service: &ControlService, role: PrincipalRole, incident: Option<&str>) -> String {
        let response = service.handle_admin_request(AdminRequest::MintCapabilityToken {
            may_spawn_runs: false,
            principal_id: "tester".into(),
            role,
            allowed_hosts: vec!["edge".into(), "foreign".into()],
            allowed_collectors: vec![CollectorType::SocketsListening],
            incident_id: incident.map(str::to_owned),
            ttl_seconds: 3600,
        });
        let AdminResponse::TokenMinted { token, .. } = response else {
            panic!("{response:?}")
        };
        token
    }

    fn db(&self) -> Connection {
        ledger::open(self.dir.0.join("ledger.sqlite3")).unwrap()
    }

    fn call(&self, request: InvestigationRequest) -> InvestigationResponse {
        self.service.handle_investigation_call(InvestigationCall {
            request_id: uuid::Uuid::new_v4().to_string(),
            capability_token: self.token.clone(),
            request,
        })
    }

    fn proposal(&self, key: &str, verb: ActionVerb, evidence: Vec<i64>) -> InvestigationRequest {
        InvestigationRequest::ProposeAction {
            run_id: self.run_id.clone(),
            incident_id: "incident".into(),
            idempotency_key: key.into(),
            verb,
            evidence_observation_ids: evidence,
            expected_effect: "Contain traffic".into(),
            blast_radius: "One host".into(),
            rollback_plan: "Allow expiry".into(),
        }
    }

    fn verify_audit(&self, action_events: &[AuditEventType]) {
        let verified = self
            .service
            .handle_admin_request(AdminRequest::VerifyAuditChain);
        assert!(
            matches!(verified, AdminResponse::AuditChainStatus { valid: true, latest_hash: Some(ref hash), .. }
            if hash.len() == 64),
            "{verified:?}"
        );
        let AdminResponse::AuditEntries { entries } = self
            .service
            .handle_admin_request(AdminRequest::ListAuditEntries { limit: None })
        else {
            panic!("missing audit entries")
        };
        let actual: Vec<_> = entries
            .into_iter()
            .map(|entry| entry.event_type)
            .filter(|event| {
                matches!(
                    event,
                    AuditEventType::ActionProposed
                        | AuditEventType::ActionApproved
                        | AuditEventType::ActionReceiptRecorded
                        | AuditEventType::ActionRolledBack
                )
            })
            .collect();
        assert_eq!(actual, action_events);
    }

    fn get(&self, intent_id: &str) -> AdminResponse {
        self.service
            .handle_admin_request(AdminRequest::GetActionIntent {
                intent_id: intent_id.into(),
            })
    }
}

fn block(ip: &str) -> ActionVerb {
    ActionVerb::NftBlockIp {
        ip: ip.into(),
        direction: TrafficDirection::Inbound,
        ttl_seconds: 300,
    }
}

#[test]
fn migrates_v1_without_rewriting_existing_records() {
    let dir = TempDir::new();
    fs::create_dir(&dir.0).unwrap();
    let path = dir.0.join("ledger.sqlite3");
    {
        let db = Connection::open(&path).unwrap();
        db.execute_batch(include_str!("../src/schema.sql")).unwrap();
        db.pragma_update(None, "user_version", 1).unwrap();
        db.execute_batch(
            "
            INSERT INTO hosts (host_id, agent_version) VALUES ('legacy','v1');
            INSERT INTO incidents (incident_id,host_id,status,priority_json,summary,created_at,updated_at)
            VALUES ('legacy-incident','legacy','open','\"high\"','original incident','now','now');
            INSERT INTO policy_decisions (actor,request_id,decision_json,created_at)
            VALUES ('original','request','{}','now');
        ",
        )
        .unwrap();
    }
    for _ in 0..2 {
        let db = ledger::open(&path).unwrap();
        let version: i32 = db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 7);
        let agent: String = db
            .query_row(
                "SELECT agent_version FROM hosts WHERE host_id='legacy'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(agent, "v1");
        let incident: (String, bool) = db
            .query_row(
                "SELECT summary, is_liveness FROM incidents WHERE incident_id='legacy-incident'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(incident, ("original incident".into(), false));
        let policy: (String, Option<i64>) = db
            .query_row(
                "SELECT actor, action_proposal_id FROM policy_decisions WHERE request_id='request'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(policy, ("original".into(), None));
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM action_proposals", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(
            !db.prepare("PRAGMA foreign_key_check")
                .unwrap()
                .exists([])
                .unwrap()
        );
    }
}

#[test]
fn autonomous_actions_require_scoped_evidence_and_obey_policy() {
    let f = Fixture::new(ActionSafetyConfig::with_bounded_autonomous_containment());
    let cases = [
        (block("127.0.0.1"), vec![1], "action.protected_ip"),
        (
            ActionVerb::SystemdStopUnit {
                unit: "sshd.service".into(),
                ttl_seconds: Some(300),
            },
            vec![1],
            "action.protected_unit",
        ),
        (
            block("203.0.113.42"),
            vec![1, 999],
            "action.evidence_out_of_scope",
        ),
        (
            block("203.0.113.42"),
            vec![1, 2],
            "action.evidence_out_of_scope",
        ),
        (
            block("203.0.113.42"),
            vec![1, 3],
            "action.evidence_out_of_scope",
        ),
        (
            block("203.0.113.42"),
            vec![1, 4],
            "action.evidence_out_of_scope",
        ),
    ];
    for (index, (verb, evidence, rule)) in cases.into_iter().enumerate() {
        let response = f.call(f.proposal(&format!("deny-{index}"), verb, evidence));
        assert!(
            matches!(response, InvestigationResponse::ActionProposalEvaluated {
            decision: ref d, proposal_id: Some(_), intent_id: None, authorized_intent: None, ..
        } if !d.allowed && d.rule_id == rule),
            "{response:?}"
        );
    }

    let request = f.proposal("allow", block("203.0.113.42"), vec![1, 1]);
    let response = f.call(request.clone());
    let InvestigationResponse::ActionProposalEvaluated {
        status: Some(ActionIntentStatus::Authorized),
        authorized_intent: Some(ref authorized),
        auth_mode: Some(ActionAuthMode::PolicyBoundedAutonomous),
        ..
    } = response
    else {
        panic!("{response:?}")
    };
    let mut trust = VerifyingKeyStore::new();
    trust
        .insert_public_hex("control", &f.control_public_hex)
        .unwrap();
    let (payload, _) = trust
        .verify_and_decode::<ActionIntentPayload>(
            DOMAIN_ACTION_INTENT_V1,
            &authorized.control_envelope,
        )
        .unwrap();
    assert_eq!(payload.host_id, "edge");
    assert_eq!(payload.incident_id, "incident");
    assert_eq!(payload.evidence_observation_ids, vec![1]);
    assert_eq!(payload.verb, block("203.0.113.42"));
    assert!(authorized.operator_approval.is_none());
    assert_eq!(f.call(request), response);
    let mut changed = f.proposal("allow", block("203.0.113.42"), vec![1]);
    if let InvestigationRequest::ProposeAction {
        ref mut rollback_plan,
        ..
    } = changed
    {
        *rollback_plan = "Changed rationale".into();
    }
    assert!(matches!(
        f.call(changed),
        InvestigationResponse::Error { .. }
    ));
    assert!(matches!(
        f.call(f.proposal("allow", block("203.0.113.99"), vec![1])),
        InvestigationResponse::Error { .. }
    ));

    let cooldown = f.call(f.proposal("cooldown", block("203.0.113.99"), vec![1]));
    assert!(
        matches!(cooldown, InvestigationResponse::ActionProposalEvaluated { decision, intent_id: None, .. }
        if !decision.allowed && decision.rule_id == "action.causal_cooldown")
    );

    assert!(
        matches!(f.call(InvestigationRequest::ListActions { host_id: None, incident_id: None }),
        InvestigationResponse::Actions { actions } if actions.len() == 1
            && actions[0].intent_id.as_ref() == Some(&payload.intent_id))
    );
    for (host_id, incident_id) in [(Some("foreign".into()), None), (None, Some("other".into()))] {
        assert!(matches!(
            f.call(InvestigationRequest::ListActions {
                host_id,
                incident_id
            }),
            InvestigationResponse::Error { .. }
        ));
    }
    let token = Fixture::mint_token(&f.service, PrincipalRole::Observer, None);
    assert!(matches!(
        f.service.handle_investigation_call(InvestigationCall {
            request_id: "observer-list".into(),
            capability_token: token,
            request: InvestigationRequest::ListActions {
                host_id: None,
                incident_id: None,
            },
        }),
        InvestigationResponse::Error { .. }
    ));

    assert!(matches!(
        f.service.handle_admin_request(AdminRequest::ListActions {
            host_id: Some("edge".into()),
            incident_id: Some("incident".into()),
        }),
        AdminResponse::Actions { actions } if actions.len() == 1
            && actions[0].intent_id.as_ref() == Some(&payload.intent_id)
    ));
    assert!(matches!(
        f.service.handle_admin_request(AdminRequest::ListActions {
            host_id: None,
            incident_id: Some("other".into()),
        }),
        AdminResponse::Actions { actions } if actions.is_empty()
    ));

    let db = f.db();
    let count: i64 = db.query_row(
        "SELECT COUNT(*) FROM action_proposals p JOIN policy_decisions d ON d.action_proposal_id=p.proposal_id
         WHERE p.decision_json=d.decision_json AND json_extract(p.decision_json,'$.allowed')=0", [], |r| r.get(0),
    ).unwrap();
    assert_eq!(count, 7);
    f.verify_audit(&vec![AuditEventType::ActionProposed; 8]);
}

#[test]
fn isolation_requires_an_independent_operator_signature_and_records_receipts() {
    use ActionIntentStatus::*;
    let f = Fixture::new(ActionSafetyConfig::with_bounded_autonomous_containment());
    let response = f.call(f.proposal(
        "isolate",
        ActionVerb::HostIsolate {
            preserve_mgmt_cidrs: vec!["10.10.0.0/24".into()],
            ttl_seconds: 300,
        },
        vec![1],
    ));
    let InvestigationResponse::ActionProposalEvaluated {
        auth_mode: Some(ActionAuthMode::DualSignedOperator),
        status: Some(PendingApproval),
        intent_id: Some(intent_id),
        authorized_intent: None,
        ..
    } = response
    else {
        panic!("{response:?}")
    };
    let AdminResponse::ActionIntentDetail {
        payload,
        status: PendingApproval,
        authorized_intent: None,
    } = f.get(&intent_id)
    else {
        panic!("pending intent was not returned")
    };
    let operator = SigningKeyPair::generate("operator");
    let approval = operator
        .sign_payload(DOMAIN_ACTION_APPROVAL_V1, &payload)
        .unwrap();
    let approve = |operator_approval| {
        f.service.handle_admin_request(AdminRequest::ApproveAction {
            intent_id: intent_id.clone(),
            approver: "Alice".into(),
            operator_approval,
        })
    };
    assert!(matches!(
        approve(approval.clone()),
        AdminResponse::Error { .. }
    ));
    f.service
        .register_operator_key("operator", &operator.public_hex())
        .unwrap();

    let unregistered = SigningKeyPair::generate("unknown");
    let wrong = SigningKeyPair::generate("operator");
    let control_secret = fs::read_to_string(f.dir.0.join("control-signing-key.hex")).unwrap();
    let control = SigningKeyPair::from_secret_hex("control", &control_secret).unwrap();
    let alias = SigningKeyPair::from_secret_hex("alias", &control_secret).unwrap();
    f.service
        .register_operator_key("control", &control.public_hex())
        .unwrap();
    f.service
        .register_operator_key("alias", &alias.public_hex())
        .unwrap();
    for key in [&unregistered, &wrong, &control, &alias] {
        assert!(matches!(
            approve(
                key.sign_payload(DOMAIN_ACTION_APPROVAL_V1, &payload)
                    .unwrap()
            ),
            AdminResponse::Error { .. }
        ));
    }
    let mut tampered = payload.clone();
    tampered.rollback_plan = "Different plan".into();
    assert!(matches!(
        approve(
            operator
                .sign_payload(DOMAIN_ACTION_APPROVAL_V1, &tampered)
                .unwrap()
        ),
        AdminResponse::Error { .. }
    ));
    assert!(matches!(
        approve(
            operator
                .sign_payload(DOMAIN_ACTION_INTENT_V1, &payload)
                .unwrap()
        ),
        AdminResponse::Error { .. }
    ));

    let receipt = ActionReceipt {
        intent_id: intent_id.clone(),
        host_id: payload.host_id.clone(),
        nonce: payload.nonce.clone(),
        status: Executed,
        dry_run: false,
        executed_at: Utc::now(),
        expires_at: Some(payload.expires_at),
        rollback_handle: Some("rollback".into()),
        verification_passed: true,
        detail: "Applied".into(),
    };
    let record = |receipt| {
        f.service
            .handle_admin_request(AdminRequest::RecordActionReceipt { receipt })
    };
    assert!(matches!(
        record(receipt.clone()),
        AdminResponse::Error { .. }
    ));
    let result = approve(approval.clone());
    let AdminResponse::ActionApproved {
        authorized_intent, ..
    } = result
    else {
        panic!("{result:?}")
    };
    assert_eq!(authorized_intent.operator_approval, Some(approval.clone()));
    assert_eq!(
        authorized_intent.control_envelope.raw_payload,
        approval.raw_payload
    );
    let mut trust = VerifyingKeyStore::new();
    trust
        .insert_public_hex("operator", &operator.public_hex())
        .unwrap();
    assert_eq!(
        trust
            .verify_and_decode::<ActionIntentPayload>(DOMAIN_ACTION_APPROVAL_V1, &approval)
            .unwrap()
            .0,
        payload
    );
    assert!(
        matches!(f.get(&intent_id), AdminResponse::ActionIntentDetail {
        status: Authorized, authorized_intent: Some(intent), ..
    } if intent == authorized_intent)
    );
    assert!(matches!(approve(approval), AdminResponse::Error { .. }));

    for bad in [
        ActionReceipt {
            nonce: "wrong".into(),
            ..receipt.clone()
        },
        ActionReceipt {
            host_id: "foreign".into(),
            ..receipt.clone()
        },
        ActionReceipt {
            intent_id: "unknown".into(),
            ..receipt.clone()
        },
    ] {
        assert!(matches!(record(bad), AdminResponse::Error { .. }));
    }
    assert!(matches!(
        record(receipt.clone()),
        AdminResponse::ActionReceiptAck {
            status: Executed,
            ..
        }
    ));
    assert!(matches!(
        record(ActionReceipt {
            status: RolledBack,
            detail: "Rolled back".into(),
            ..receipt.clone()
        }),
        AdminResponse::ActionReceiptAck {
            status: RolledBack,
            ..
        }
    ));
    assert!(matches!(
        record(receipt),
        AdminResponse::ActionReceiptAck {
            status: Executed,
            ..
        }
    ));
    assert!(matches!(
        f.get(&intent_id),
        AdminResponse::ActionIntentDetail {
            status: RolledBack,
            ..
        }
    ));
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM action_receipts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    f.verify_audit(&[
        AuditEventType::ActionProposed,
        AuditEventType::ActionApproved,
        AuditEventType::ActionReceiptRecorded,
        AuditEventType::ActionRolledBack,
    ]);
}

#[test]
fn default_policy_requires_approval_for_ip_blocks() {
    let f = Fixture::new(ActionSafetyConfig::default());
    assert!(matches!(
        f.call(f.proposal("block", block("203.0.113.42"), vec![1])),
        InvestigationResponse::ActionProposalEvaluated {
            auth_mode: Some(ActionAuthMode::DualSignedOperator),
            status: Some(ActionIntentStatus::PendingApproval),
            authorized_intent: None,
            ..
        }
    ));
}

#[test]
fn pending_intents_count_toward_the_hourly_limit() {
    let f = Fixture::new(ActionSafetyConfig {
        max_actions_per_host_per_hour: 1,
        causal_loop_cooldown_seconds: 0,
        ..Default::default()
    });
    assert!(matches!(
        f.call(f.proposal("first", block("203.0.113.42"), vec![1])),
        InvestigationResponse::ActionProposalEvaluated {
            status: Some(ActionIntentStatus::PendingApproval),
            ..
        }
    ));
    assert!(matches!(
        f.call(f.proposal("second", block("203.0.113.43"), vec![1])),
        InvestigationResponse::ActionProposalEvaluated { decision, intent_id: None, .. }
            if !decision.allowed && decision.rule_id == "action.rate_limit"
    ));
}

#[test]
fn proposals_require_the_investigator_role_and_active_matching_run() {
    let f = Fixture::new(ActionSafetyConfig::default());
    let mut wrong_incident = f.proposal("scope", block("203.0.113.42"), vec![1]);
    if let InvestigationRequest::ProposeAction {
        ref mut incident_id,
        ..
    } = wrong_incident
    {
        *incident_id = "other".into();
    }
    assert!(matches!(
        f.call(wrong_incident),
        InvestigationResponse::Error { .. }
    ));

    let token = Fixture::mint_token(&f.service, PrincipalRole::Observer, Some("incident"));
    let request = f.proposal("role", block("203.0.113.42"), vec![1]);
    assert!(matches!(
        f.service.handle_investigation_call(InvestigationCall {
            request_id: "observer-proposal".into(),
            capability_token: token,
            request,
        }),
        InvestigationResponse::Error { .. }
    ));

    let db = f.db();
    db.execute(
        "UPDATE agent_runs SET status='completed' WHERE run_id=?1",
        [&f.run_id],
    )
    .unwrap();
    assert!(matches!(
        f.call(f.proposal("inactive", block("203.0.113.42"), vec![1])),
        InvestigationResponse::Error { .. }
    ));
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM action_proposals", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
