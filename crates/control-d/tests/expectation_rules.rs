use std::{fs, path::PathBuf};

use chrono::{Duration, Utc};
use control_d::{ControlService, ledger};
use defsec_protocol::{
    audit::AuditEventType,
    canonical::canonical_sha256_hex,
    observation::{ObservationPayload, ObservationRecord, ObservationStatus},
    rpc::*,
    rules::ExpectationRuleSpec,
    watch::*,
    wire::*,
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use uuid::Uuid;

struct Fixture {
    dir: PathBuf,
    service: ControlService,
}

impl Fixture {
    fn new(compare_against: CompareTarget) -> Self {
        let dir = std::env::temp_dir().join(format!("control-rules-{}", Uuid::new_v4()));
        let service = ControlService::open(&dir, "test-key", 3).unwrap();
        let fixture = Self { dir, service };
        for host_id in ["edge", "foreign"] {
            assert!(matches!(
                fixture.admin(AdminRequest::EnrollHost {
                    host_id: host_id.into(),
                    agent_public_key_hex: None,
                }),
                AdminResponse::HostEnrolled { .. }
            ));
        }
        let applied = fixture.admin(AdminRequest::ApplyBaselineWatch {
            spec: WatchSpec {
                id: "sockets".into(),
                version: 1,
                host_id: "edge".into(),
                class: WatchClass::Baseline,
                incident_id: None,
                collector: CollectorSpec::SocketsListening(SocketsListeningParams {
                    include_tcp: true,
                    include_udp: false,
                    include_ipv6: true,
                    resolve_process: true,
                }),
                schedule: WatchSchedule {
                    interval_seconds: 30,
                    timeout_seconds: 5,
                },
                trigger: TriggerPredicate::SetDiff {
                    compare_against,
                    set_field: "sockets".into(),
                    identity_key: "socket_key".into(),
                    ignore_fields: vec![
                        "inode".into(),
                        "pid".into(),
                        "pid_start_time_ticks".into(),
                    ],
                },
                wake_policy: WakePolicy {
                    cooldown_seconds: 60,
                    max_wakeups_per_hour: 4,
                },
                lifecycle: WatchLifecycle {
                    enabled: true,
                    expires_at: None,
                    max_runs: None,
                },
            },
            actor: "operator".into(),
            rationale: "monitor local listeners".into(),
        });
        assert!(
            matches!(applied, AdminResponse::WatchApplied { .. }),
            "{applied:?}"
        );
        let replies = fixture
            .service
            .handle_agent_message(AgentToControl::Register {
                protocol_version: WIRE_PROTOCOL_VERSION,
                host_id: "edge".into(),
                agent_version: "test".into(),
                boot_id: "boot".into(),
                session_id: "session".into(),
                active_bundle_version: 0,
                active_bundle_digest: None,
                sent_at: Utc::now(),
            });
        assert!(matches!(
            replies.first(),
            Some(ControlToAgent::RegisterAck { accepted: true, .. })
        ));
        fixture
    }

    fn db(&self) -> Connection {
        ledger::open(self.dir.join("ledger.sqlite3")).unwrap()
    }

    fn admin(&self, request: AdminRequest) -> AdminResponse {
        self.service.handle_admin_request(request)
    }

    fn investigate(&self, token: &str, request: InvestigationRequest) -> InvestigationResponse {
        self.service.handle_investigation_call(InvestigationCall {
            request_id: Uuid::new_v4().to_string(),
            capability_token: token.into(),
            request,
        })
    }

    fn put(&self, seq_no: u64, sockets: Vec<Value>) -> i64 {
        self.put_snapshot(
            seq_no,
            json!({
                "count":sockets.len(),"partial_attribution":false,"sockets":sockets
            }),
        )
    }

    fn put_snapshot(&self, seq_no: u64, data: Value) -> i64 {
        let observation = ObservationRecord {
            host_id: "edge".into(),
            session_id: "session".into(),
            seq_no,
            watch_id: "sockets".into(),
            spec_version: 1,
            collector_type: CollectorType::SocketsListening,
            observed_at: Utc::now(),
            status: ObservationStatus::Ok,
            state_hash: canonical_sha256_hex(&data).unwrap(),
            payload: ObservationPayload::Snapshot { data },
            is_reconciliation: false,
            sustained_count: None,
            sustained_active: None,
            partial_reasons: vec![],
        };
        let reply = self
            .service
            .handle_agent_message(AgentToControl::PushObservationDelta { observation });
        assert!(
            matches!(reply.as_slice(), [ControlToAgent::ObservationAck { acked_seq_no, .. }] if *acked_seq_no == seq_no),
            "{reply:?}"
        );
        self.db()
            .query_row(
                "SELECT observation_id FROM observations WHERE seq_no=?1",
                [seq_no],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn promote(&self, observation_id: i64) {
        let response = self.admin(AdminRequest::PromoteBaseline {
            host_id: "edge".into(),
            watch_id: "sockets".into(),
            observation_id,
            approver: "operator".into(),
            rationale: "reviewed listeners".into(),
            ticket_ref: None,
        });
        assert!(
            matches!(response, AdminResponse::BaselinePromoted { .. }),
            "{response:?}"
        );
    }

    fn outcome(&self) -> Value {
        let raw: String = self
            .db()
            .query_row("SELECT outcome_json FROM watch_state", [], |r| r.get(0))
            .unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn incident(&self) -> String {
        self.db()
            .query_row(
                "SELECT incident_id FROM incidents WHERE host_id='edge'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn token(&self, role: PrincipalRole, incident_id: Option<String>) -> String {
        let response = self.admin(AdminRequest::MintCapabilityToken {
            principal_id: "worker".into(),
            role,
            allowed_hosts: vec!["edge".into()],
            allowed_collectors: vec![CollectorType::SocketsListening],
            incident_id,
            ttl_seconds: 300,
        });
        let AdminResponse::TokenMinted { token, .. } = response else {
            panic!("{response:?}")
        };
        token
    }

    fn run(&self, incident: &str) -> (String, String) {
        let token = self.token(PrincipalRole::Investigator, Some(incident.into()));
        let response = self.investigate(
            &token,
            InvestigationRequest::StartInvestigationRun {
                incident_id: incident.into(),
                backend_id: "fixture".into(),
                model_id: "test".into(),
                prompt_schema_version: "1".into(),
            },
        );
        let InvestigationResponse::RunStarted { run_id, .. } = response else {
            panic!("{response:?}")
        };
        (token, run_id)
    }

    fn propose(
        &self,
        token: &str,
        run: &str,
        key: &str,
        rule: ExpectationRuleSpec,
    ) -> InvestigationResponse {
        self.investigate(
            token,
            InvestigationRequest::ProposeExpectationRule {
                run_id: run.into(),
                idempotency_key: key.into(),
                rule,
            },
        )
    }

    fn list(&self, statuses: Option<Vec<String>>) -> Vec<ExpectationRuleRecord> {
        let response = self.admin(AdminRequest::ListExpectationRules {
            host_id: None,
            statuses,
            limit: Some(100),
        });
        let AdminResponse::ExpectationRules { rules } = response else {
            panic!("{response:?}")
        };
        rules
    }

    fn create(&self, rule: ExpectationRuleSpec) -> String {
        let response = self.admin(AdminRequest::CreateExpectationRule {
            rule,
            actor: "operator".into(),
        });
        let AdminResponse::RuleDecided { rule_id, status } = response else {
            panic!("{response:?}")
        };
        assert_eq!(status, "active");
        rule_id
    }

    fn decide(&self, rule_id: &str, approve: bool) -> AdminResponse {
        self.admin(AdminRequest::DecideExpectationRule {
            rule_id: rule_id.into(),
            approve,
            actor: "reviewer".into(),
            note: Some("checked".into()),
        })
    }

    fn saw_trigger(&self, observation_id: i64) -> bool {
        self.db()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM trigger_evidence WHERE observation_id=?1)",
                [observation_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn backtest(&self, rule: ExpectationRuleSpec) -> RuleBacktest {
        let response = self.admin(AdminRequest::BacktestExpectationRule { rule });
        let AdminResponse::RuleBacktestResult { backtest } = response else {
            panic!("{response:?}")
        };
        backtest
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn socket(unit: &str, port: u16) -> Value {
    json!({
        "socket_key": format!("tcp:127.0.0.5:{port}"), "protocol":"tcp",
        "local_addr":"127.0.0.5", "local_port":port, "systemd_unit":unit, "uid":1000,
        "inode": 3
    })
}

fn allow(unit: &str) -> ExpectationRuleSpec {
    serde_json::from_value(json!({
        "scope":{"host_id":"edge","collector":"sockets.listening","watch_id":"sockets"},
        "matches":[
            {"op":"eq","field":"systemd_unit","value":unit},
            {"op":"eq","field":"bind_scope","value":"loopback"},
            {"op":"range","field":"local_port","min":4000,"max":4100}
        ],
        "effect":"allow_optional",
        "rationale":"expected local service listener"
    }))
    .unwrap()
}

fn proposal_result(response: InvestigationResponse) -> (String, RuleBacktest) {
    let InvestigationResponse::RuleProposalEvaluated {
        decision,
        rule_id: Some(rule_id),
        backtest: Some(backtest),
    } = response
    else {
        panic!("{response:?}")
    };
    assert!(decision.allowed);
    (rule_id, backtest)
}

#[test]
fn rules_change_only_new_observations_and_record_hits_lifecycle_and_audit() {
    let f = Fixture::new(CompareTarget::AcceptedBaseline);
    let ssh = socket("sshd.service", 22);
    let nx = socket("nxserver.service", 4002);
    let another = socket("other.service", 4003);
    let base = f.put(1, vec![ssh.clone()]);
    f.promote(base);

    let first_drift = f.put(2, vec![ssh.clone(), nx.clone()]);
    assert!(f.saw_trigger(first_drift));
    let backtest = f.backtest(allow("nxserver.service"));
    assert_eq!(
        backtest,
        RuleBacktest {
            observations_scanned: 2,
            triggered_before: 1,
            triggered_after: 0,
            items_matched: 1,
            sample_keys: vec!["tcp:127.0.0.5:4002".into()],
            currently_matching: 1,
        }
    );

    let nx_rule = f.create(allow("nxserver.service"));
    assert!(f.saw_trigger(first_drift));
    let suppressed = f.put(3, vec![ssh.clone(), nx.clone()]);
    assert!(!f.saw_trigger(suppressed));
    assert_eq!(f.outcome(), json!({"outcome":"not_triggered"}));
    let record = f.list(None).pop().unwrap();
    assert_eq!((record.rule_id, record.hit_count), (nx_rule.clone(), 1));
    assert!(record.last_matched_at.is_some());

    let other_alert = f.put(4, vec![ssh.clone(), nx.clone(), another.clone()]);
    assert!(f.saw_trigger(other_alert));
    let filtered = f.outcome();
    assert_eq!(filtered["details"]["added"], json!(["tcp:127.0.0.5:4003"]));
    assert_eq!(
        filtered["details"]["suppressed_by_rules"][&nx_rule],
        json!(["tcp:127.0.0.5:4002"])
    );
    let (fingerprint, outcome): (String, String) = f.db().query_row(
        "SELECT fingerprint,outcome_json FROM trigger_events JOIN trigger_evidence USING(event_id) WHERE observation_id=?1",
        [other_alert], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(
        fingerprint,
        canonical_sha256_hex(&(1u32, &filtered["details"])).unwrap()
    );
    assert_eq!(
        serde_json::from_str::<Value>(&outcome).unwrap()["predicate"],
        filtered
    );

    let (token, run) = f.run(&f.incident());
    let mut proposed = allow("other.service");
    assert!(
        matches!(f.propose(&token, &run, "no-expiry", proposed.clone()),
        InvestigationResponse::RuleProposalEvaluated { decision, rule_id: None, backtest: None }
        if decision.rule_id == "rule-gate/investigator-expiry")
    );
    proposed.expires_at = Some(Utc::now() + Duration::days(3));
    let response = f.propose(&token, &run, "proposal", proposed.clone());
    let (proposal_id, backtest) = proposal_result(response.clone());
    assert_eq!(
        (backtest.triggered_before, backtest.triggered_after),
        (1, 0)
    );

    let observer = f.token(PrincipalRole::Observer, None);
    let listed = f.investigate(
        &observer,
        InvestigationRequest::ListExpectationRules {
            host_id: None,
            statuses: Some(vec!["proposed".into()]),
            limit: Some(10),
        },
    );
    assert!(
        matches!(listed, InvestigationResponse::ExpectationRules { rules }
        if rules.len() == 1 && rules[0].rule_id == proposal_id && rules[0].hit_count == 0)
    );

    let still_alerts = f.put(5, vec![ssh.clone(), another.clone()]);
    assert!(f.saw_trigger(still_alerts));
    assert!(
        matches!(f.decide(&proposal_id, true), AdminResponse::RuleDecided { status, .. } if status == "active")
    );
    let now_suppressed = f.put(6, vec![ssh.clone(), another.clone()]);
    assert!(!f.saw_trigger(now_suppressed));
    assert_eq!(
        f.propose(&token, &run, "proposal", proposed.clone()),
        response
    );
    let mut different = proposed.clone();
    different.rationale = "changed".into();
    assert!(matches!(f.propose(&token, &run, "proposal", different),
        InvestigationResponse::Error { code, .. } if code == "conflict"));

    let (rejected, _) = proposal_result(f.propose(&token, &run, "reject", proposed));
    assert!(
        matches!(f.decide(&rejected, false), AdminResponse::RuleDecided { status, .. } if status == "rejected")
    );
    assert!(matches!(
        f.decide(&rejected, true),
        AdminResponse::Error { .. }
    ));
    assert!(matches!(f.admin(AdminRequest::RevokeExpectationRule {
        rule_id: proposal_id.clone(), actor: "operator".into(), reason: "reviewed".into(),
    }), AdminResponse::RuleDecided { status, .. } if status == "revoked"));
    let after_revocation = f.put(7, vec![ssh.clone(), another.clone()]);
    assert!(f.saw_trigger(after_revocation));

    let live_expiry = f.create(allow("other.service"));
    // Advance the fixture's stored expiry without waiting on the wall clock.
    f.db()
        .execute(
            "UPDATE expectation_rules SET expires_at=?2 WHERE rule_id=?1",
            params![live_expiry, "2000-01-01T00:00:00.000000000Z"],
        )
        .unwrap();
    let after_expiry = f.put(8, vec![ssh, another]);
    assert!(f.saw_trigger(after_expiry));
    let expired = f.list(Some(vec!["expired".into()]));
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].rule_id, live_expiry);
    assert_eq!(expired[0].hit_count, 0);

    let required: ExpectationRuleSpec = serde_json::from_value(json!({
        "scope":{"host_id":"edge","collector":"sockets.listening"},
        "matches":[{"op":"eq","field":"local_port","value":22},
                   {"op":"eq","field":"systemd_unit","value":"sshd.service"}],
        "effect":"require_present","rationale":"SSH listener must be available"
    }))
    .unwrap();
    let required_id = f.create(required);
    let missing_ssh = f.put(9, vec![]);
    assert!(f.saw_trigger(missing_ssh));
    assert_eq!(
        f.outcome()["details"]["missing_required"],
        json!([required_id])
    );
    assert_eq!(
        f.outcome()["details"]["removed"],
        json!(["tcp:127.0.0.5:22"])
    );

    let verified = f.admin(AdminRequest::VerifyAuditChain);
    assert!(
        matches!(verified, AdminResponse::AuditChainStatus { valid: true, entries_checked, .. } if entries_checked > 10)
    );
    let AdminResponse::AuditEntries { entries } =
        f.admin(AdminRequest::ListAuditEntries { limit: Some(100) })
    else {
        panic!("audit list failed")
    };
    for event in [
        AuditEventType::RuleProposed,
        AuditEventType::RuleActivated,
        AuditEventType::RuleRejected,
        AuditEventType::RuleRevoked,
    ] {
        assert!(
            entries.iter().any(|entry| entry.event_type == event),
            "{event:?}"
        );
    }
    let activated = entries
        .iter()
        .find(|entry| {
            entry.event_type == AuditEventType::RuleActivated
                && entry.payload["rule_id"] == proposal_id
        })
        .unwrap();
    let record = f
        .list(None)
        .into_iter()
        .find(|record| record.rule_id == proposal_id)
        .unwrap();
    assert_eq!(record.hit_count, 1);
    assert_eq!(activated.payload["approver"], "reviewer");
    assert_eq!(
        activated.payload["spec_hash"],
        canonical_sha256_hex(&record.spec).unwrap()
    );
    let AdminResponse::PolicyDecisions { decisions } =
        f.admin(AdminRequest::ListPolicyDecisions { limit: Some(100) })
    else {
        panic!("decision list failed")
    };
    let rule_decisions: Vec<_> = decisions
        .into_iter()
        .filter(|d| d.decision.rule_id.starts_with("rule-gate/"))
        .collect();
    assert_eq!(rule_decisions.len(), 9);
    assert!(
        rule_decisions
            .iter()
            .all(|d| d.decision.policy_version == 3)
    );
}

#[test]
fn proposals_enforce_run_host_role_and_host_pending_quotas() {
    let f = Fixture::new(CompareTarget::LastObserved);
    f.put(1, vec![]);
    f.put(2, vec![socket("nxserver.service", 4002)]);
    let incident = f.incident();
    let (token, run) = f.run(&incident);
    let mut rule = allow("nxserver.service");
    rule.expires_at = Some(Utc::now() + Duration::days(2));

    let mut cross_host = rule.clone();
    cross_host.scope.host_id = "foreign".into();
    assert!(matches!(
        f.propose(&token, &run, "cross-host", cross_host),
        InvestigationResponse::RuleProposalEvaluated { decision, rule_id: None, backtest: None }
            if !decision.allowed && decision.rule_id == "rule-gate/scope"
    ));
    assert!(
        matches!(f.propose(&token, "wrong-run", "mismatch", rule.clone()),
        InvestigationResponse::Error { code, .. } if code == "forbidden")
    );
    let observer = f.token(PrincipalRole::Observer, None);
    assert!(
        matches!(f.propose(&observer, &run, "observer", rule.clone()),
        InvestigationResponse::Error { code, .. } if code == "forbidden")
    );
    let mut foreign = allow("nxserver.service");
    foreign.scope.host_id = "foreign".into();
    f.create(foreign);
    let listed = f.investigate(
        &observer,
        InvestigationRequest::ListExpectationRules {
            host_id: Some("foreign".into()),
            statuses: None,
            limit: None,
        },
    );
    assert!(matches!(listed, InvestigationResponse::Error { code, .. } if code == "forbidden"));
    let listed = f.investigate(
        &observer,
        InvestigationRequest::ListExpectationRules {
            host_id: None,
            statuses: None,
            limit: None,
        },
    );
    assert_eq!(
        listed,
        InvestigationResponse::ExpectationRules { rules: vec![] }
    );

    for i in 0..3 {
        let (_, backtest) = proposal_result(f.propose(&token, &run, &i.to_string(), rule.clone()));
        assert_eq!(
            (
                backtest.observations_scanned,
                backtest.triggered_before,
                backtest.triggered_after
            ),
            (2, 1, 0)
        );
    }
    let denied = f.propose(&token, &run, "fourth", rule.clone());
    assert!(
        matches!(&denied, InvestigationResponse::RuleProposalEvaluated { decision, rule_id: None, .. }
        if decision.rule_id == "rule-gate/run-quota")
    );
    assert_eq!(f.propose(&token, &run, "fourth", rule.clone()), denied);
    let mut changed = rule.clone();
    changed.rationale = "changed".into();
    assert!(matches!(f.propose(&token, &run, "fourth", changed),
        InvestigationResponse::Error { code, .. } if code == "conflict"));

    for _ in 0..5 {
        let (token, run) = f.run(&incident);
        for i in 0..3 {
            proposal_result(f.propose(&token, &run, &i.to_string(), rule.clone()));
        }
    }

    let (token, run) = f.run(&incident);
    let (first, _) = proposal_result(f.propose(&token, &run, "first", rule.clone()));
    proposal_result(f.propose(&token, &run, "second", rule.clone()));
    assert!(matches!(f.propose(&token, &run, "third", rule.clone()),
        InvestigationResponse::RuleProposalEvaluated { decision, rule_id: None, .. }
        if decision.rule_id == "rule-gate/host-quota"));
    assert_eq!(f.list(Some(vec!["proposed".into()])).len(), 20);
    assert!(matches!(
        f.decide(&first, false),
        AdminResponse::RuleDecided { .. }
    ));
    proposal_result(f.propose(&token, &run, "fourth", rule));
}

#[test]
fn backtest_uses_then_accepted_baseline_and_bounds_the_observation_window() {
    let f = Fixture::new(CompareTarget::AcceptedBaseline);
    let empty = f.put(1, vec![]);
    f.promote(empty);
    let nx = socket("nxserver.service", 4000);
    let drift = f.put(2, vec![nx.clone()]);
    f.promote(drift);
    f.put(3, vec![nx.clone()]);
    f.put_snapshot(4, json!({"sockets":[{"uid":1000}]}));
    assert_eq!(f.outcome()["outcome"], "sample_invalid");
    let rule = allow("nxserver.service");
    let backtest = f.backtest(rule.clone());
    assert_eq!(
        (
            backtest.observations_scanned,
            backtest.triggered_before,
            backtest.triggered_after
        ),
        (3, 1, 0)
    );
    for seq in 5..=55 {
        f.put(seq, vec![nx.clone()]);
    }
    f.put_snapshot(56, json!({"sockets":["invalid"]}));
    let backtest = f.backtest(rule);
    assert_eq!(
        (
            backtest.observations_scanned,
            backtest.triggered_before,
            backtest.triggered_after
        ),
        (50, 0, 0)
    );
    assert_eq!(
        (backtest.items_matched, backtest.currently_matching),
        (1, 1)
    );
}

#[test]
fn migration_from_v4_preserves_data_and_adds_rule_storage() {
    let dir = std::env::temp_dir().join(format!("rule-migration-{}", Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("ledger.sqlite3");
    {
        let db = Connection::open(&path).unwrap();
        for sql in [
            include_str!("../src/schema.sql"),
            include_str!("../src/schema_v2.sql"),
            include_str!("../src/schema_v3.sql"),
            include_str!("../src/schema_v4.sql"),
        ] {
            db.execute_batch(sql).unwrap();
        }
        db.pragma_update(None, "user_version", 4).unwrap();
        db.execute("INSERT INTO hosts (host_id) VALUES ('legacy')", [])
            .unwrap();
    }
    for _ in 0..2 {
        let db = ledger::open(&path).unwrap();
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            5
        );
        assert_eq!(
            db.query_row("SELECT host_id FROM hosts", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "legacy"
        );
        for table in [
            "run_events",
            "expectation_rules",
            "expectation_rule_proposal_receipts",
        ] {
            let exists: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(exists, "{table}");
        }
    }
    fs::remove_dir_all(dir).unwrap();
}
