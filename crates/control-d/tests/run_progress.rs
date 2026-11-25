use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use chrono::{SecondsFormat, Utc};
use control_d::{ControlService, ledger};
use defsec_protocol::rpc::{
    AdminRequest, AdminResponse, InvestigationCall, InvestigationRequest as Request,
    InvestigationResponse as Response, PrincipalRole, RunEventKind, RunOutcome, RunSummary,
    RunTerminalStatus, TriggerSummary,
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let path = std::env::temp_dir().join(format!("rp-{}", &id[..12]));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn seed_incident(db: &Connection, host: &str, incident: &str) {
    db.execute("INSERT OR IGNORE INTO hosts (host_id) VALUES (?1)", [host])
        .unwrap();
    db.execute(
        "INSERT INTO incidents (incident_id,host_id,status,priority_json,summary,created_at,updated_at)
         VALUES (?1,?2,'open','\"info\"','fixture',?3,?3)",
        params![incident, host, now()],
    )
    .unwrap();
}

struct Fixture {
    db: Connection,
    service: ControlService,
    _dir: TestDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = TestDir::new();
        let service = ControlService::open(&dir.0, "test", 1).unwrap();
        let db = ledger::open(dir.0.join("ledger.sqlite3")).unwrap();
        for (host, incident) in [("edge", "inc-1"), ("edge", "inc-2"), ("foreign", "inc-3")] {
            seed_incident(&db, host, incident);
        }
        Self {
            db,
            service,
            _dir: dir,
        }
    }

    fn trigger(&self, status: &str, incident: &str, reason: &str) -> i64 {
        self.db.execute(
            "INSERT OR IGNORE INTO watch_specs (host_id,watch_id,spec_version,spec_json,creator,active,created_at)
             SELECT host_id,'watch',1,'{}','fixture',1,?2 FROM incidents WHERE incident_id=?1",
            params![incident, now()],
        ).unwrap();
        self.db
            .execute(
                "INSERT INTO trigger_events (incident_id,host_id,watch_id,spec_version,fingerprint,
                                         created_at,updated_at,status,outcome_json)
             SELECT incident_id,host_id,'watch',1,'fixture',?2,?2,?3,?4
             FROM incidents WHERE incident_id=?1",
                params![
                    incident,
                    now(),
                    status,
                    json!({"reason": reason}).to_string()
                ],
            )
            .unwrap();
        self.db.last_insert_rowid()
    }

    fn mint(&self, role: PrincipalRole, hosts: &[&str], incident: Option<&str>) -> String {
        let result = self
            .service
            .handle_admin_request(AdminRequest::MintCapabilityToken {
                principal_id: "fixture".into(),
                role,
                allowed_hosts: hosts.iter().map(|s| (*s).into()).collect(),
                allowed_collectors: vec![],
                incident_id: incident.map(str::to_owned),
                ttl_seconds: 300,
            });
        let AdminResponse::TokenMinted { token, .. } = result else {
            panic!("{result:?}");
        };
        token
    }

    fn call(&self, token: &str, request: Request) -> Response {
        self.service.handle_investigation_call(InvestigationCall {
            request_id: "test".into(),
            capability_token: token.into(),
            request,
        })
    }

    fn start(&self, incident: &str, host: &str) -> (String, String) {
        let token = self.mint(PrincipalRole::Investigator, &[host], None);
        let result = self.call(
            &token,
            Request::StartInvestigationRun {
                incident_id: incident.into(),
                backend_id: "backend".into(),
                model_id: "model".into(),
                prompt_schema_version: "1".into(),
            },
        );
        let Response::RunStarted { run_id, .. } = result else {
            panic!("{result:?}")
        };
        (token, run_id)
    }

    fn runs(&self, token: &str) -> Vec<RunSummary> {
        let result = self.call(
            token,
            Request::ListInvestigationRuns {
                incident_id: None,
                host_id: None,
                limit: None,
            },
        );
        let Response::Runs { runs } = result else {
            panic!("{result:?}")
        };
        runs
    }

    fn queue(&self, token: &str, statuses: Option<Vec<String>>) -> Vec<TriggerSummary> {
        let result = self.call(
            token,
            Request::ListTriggerQueue {
                host_id: None,
                incident_id: None,
                statuses,
                limit: None,
            },
        );
        let Response::TriggerQueue { triggers } = result else {
            panic!("{result:?}")
        };
        triggers
    }
}

fn report(run: &str, detail: Value) -> Request {
    Request::ReportRunProgress {
        run_id: run.into(),
        kind: RunEventKind::Note,
        detail,
    }
}

fn events(run: &str, after_seq: Option<i64>) -> Request {
    Request::GetRunEvents {
        run_id: run.into(),
        after_seq,
        limit: None,
    }
}

fn finish(run: &str, status: RunTerminalStatus, summary: &str) -> Request {
    Request::FinishInvestigationRun {
        run_id: run.into(),
        outcome: RunOutcome {
            status,
            summary: summary.into(),
            budget_stop_reason: None,
            turns: 1,
            tool_calls: 0,
            input_tokens: 150,
            output_tokens: 45,
            findings: 0,
            proposals: 0,
            proposals_accepted: 0,
        },
    }
}

fn error(response: Response, expected: &str) {
    assert!(
        matches!(response, Response::Error {ref code, ..} if code == expected),
        "{response:?}"
    );
}

#[test]
fn lifecycle_paginates_events_and_finishes_idempotently() {
    let f = Fixture::new();
    let (owner, run) = f.start("inc-1", "edge");
    let observer = f.mint(PrincipalRole::Observer, &["edge"], None);
    assert_eq!(f.runs(&observer)[0].status, "active");
    let detail = json!({"stage": "review"});
    let Response::RunProgressRecorded { event_seq, .. } =
        f.call(&owner, report(&run, detail.clone()))
    else {
        panic!("first event not recorded")
    };
    let Response::RunProgressRecorded {
        event_seq: last, ..
    } = f.call(&owner, report(&run, json!(null)))
    else {
        panic!("second event not recorded")
    };
    assert!(event_seq < last);
    let request = finish(&run, RunTerminalStatus::Completed, "done");
    let finished = Response::RunFinished {
        run_id: run.clone(),
        status: RunTerminalStatus::Completed,
    };
    assert_eq!(f.call(&owner, request.clone()), finished);
    let completed = f.runs(&observer).remove(0);
    assert_eq!(f.call(&owner, request), finished);
    assert_eq!(f.runs(&owner), std::slice::from_ref(&completed));
    assert_eq!(completed.status, "completed");
    assert!(completed.ended_at.is_some());
    assert_eq!(completed.outcome.unwrap().summary, "done");
    assert_eq!(completed.event_count, 2);
    assert_eq!(completed.last_event.as_ref().unwrap().event_seq, last);
    let Response::RunEvents { events: all, .. } = f.call(&observer, events(&run, None)) else {
        panic!("observer could not read events")
    };
    assert_eq!(all[0].detail, detail);
    assert_eq!(all.len(), 2);
    let Response::RunEvents { events: page, .. } = f.call(&observer, events(&run, Some(event_seq)))
    else {
        panic!("failed to read event page")
    };
    assert_eq!(page, all[1..]);
    error(
        f.call(&owner, finish(&run, RunTerminalStatus::Failed, "different")),
        "conflict",
    );
    error(f.call(&owner, report(&run, json!(null))), "forbidden");
    let count: i64 = f.db.query_row(
        "SELECT COUNT(*) FROM audit_outbox WHERE json_extract(entry_json,'$.event_type')='run_finished'",
        [], |r| r.get(0),
    ).unwrap();
    assert_eq!(count, 1);
    assert!(matches!(
        f.service
            .handle_admin_request(AdminRequest::VerifyAuditChain),
        AdminResponse::AuditChainStatus { valid: true, .. }
    ));
}

#[test]
fn progress_permissions_and_run_incident_and_host_scopes() {
    let f = Fixture::new();
    let (_, own_run) = f.start("inc-1", "edge");
    let (other_owner, other_run) = f.start("inc-2", "edge");
    let (_, foreign_run) = f.start("inc-3", "foreign");
    let observer = f.mint(PrincipalRole::Observer, &["edge"], None);
    let scoped = f.mint(PrincipalRole::Observer, &["edge", "foreign"], Some("inc-1"));
    assert_eq!(
        f.runs(&observer)
            .iter()
            .map(|run| &run.run_id)
            .collect::<Vec<_>>(),
        [&other_run, &own_run]
    );
    assert_eq!(f.runs(&scoped)[0].run_id, own_run);
    assert_eq!(f.runs(&scoped).len(), 1);
    assert!(matches!(
        f.service.handle_admin_request(AdminRequest::CloseIncident {
            incident_id: "inc-2".into(),
            actor: "fixture".into(),
            resolution: "closed".into(),
        }),
        AdminResponse::IncidentClosed { .. }
    ));
    let cancelled = f.runs(&observer).remove(0);
    assert_eq!(cancelled.status, "cancelled");
    assert!(cancelled.ended_at.is_some());

    error(
        f.call(&observer, report(&own_run, json!(null))),
        "forbidden",
    );
    error(
        f.call(
            &observer,
            finish(&own_run, RunTerminalStatus::Failed, "denied"),
        ),
        "forbidden",
    );
    error(
        f.call(&other_owner, report(&own_run, json!(null))),
        "forbidden",
    );
    error(
        f.call(
            &other_owner,
            finish(&own_run, RunTerminalStatus::Failed, "denied"),
        ),
        "forbidden",
    );
    error(f.call(&observer, events(&foreign_run, None)), "forbidden");
    error(f.call(&scoped, events(&other_run, None)), "forbidden");
    error(
        f.call(
            &observer,
            Request::ListInvestigationRuns {
                host_id: Some("foreign".into()),
                incident_id: None,
                limit: None,
            },
        ),
        "forbidden",
    );
}

#[test]
fn byte_limits_quota_and_expiration() {
    let f = Fixture::new();
    let (owner, run) = f.start("inc-1", "edge");
    let observer = f.mint(PrincipalRole::Observer, &["edge"], None);
    error(
        f.call(&owner, report(&run, json!("é".repeat(2048)))),
        "invalid_request",
    );
    error(
        f.call(
            &owner,
            finish(&run, RunTerminalStatus::Completed, &"é".repeat(1025)),
        ),
        "invalid_request",
    );
    let mut request = finish(&run, RunTerminalStatus::BudgetExhausted, "budget");
    if let Request::FinishInvestigationRun { outcome, .. } = &mut request {
        outcome.budget_stop_reason = Some("é".repeat(33));
    }
    error(f.call(&owner, request), "invalid_request");
    for _ in 0..256 {
        assert!(matches!(
            f.call(&owner, report(&run, json!("a".repeat(4094)))),
            Response::RunProgressRecorded { .. }
        ));
    }
    error(f.call(&owner, report(&run, json!(0))), "run_event_quota");
    f.db.execute(
        "UPDATE agent_runs SET expires_at='2000-01-01T00:00:00Z' WHERE run_id=?1",
        [&run],
    )
    .unwrap();
    assert_eq!(f.runs(&observer)[0].status, "expired");
    assert_eq!(f.runs(&observer)[0].event_count, 256);
    error(f.call(&owner, report(&run, json!(0))), "forbidden");
}

#[test]
fn queue_filters_and_lease_completion_preserve_terminal_status() {
    let f = Fixture::new();
    let event_id = f.trigger("pending", "inc-1", &"é".repeat(300));
    let dead = f.trigger("dead_letter", "inc-2", "out of retries");
    f.trigger("suppressed", "inc-1", "cooldown");
    f.trigger("pending", "inc-3", "outside host scope");
    let worker = f.mint(PrincipalRole::Investigator, &["edge"], None);
    let observer = f.mint(PrincipalRole::Observer, &["edge"], None);
    let scoped = f.mint(PrincipalRole::Observer, &["edge"], Some("inc-1"));
    let Response::TriggerLeased { lease: Some(lease) } = f.call(
        &worker,
        Request::LeaseNextTrigger {
            lease_owner: "worker".into(),
            lease_seconds: 120,
        },
    ) else {
        panic!("no ongoing lease")
    };
    assert_eq!(lease.event_id, event_id);
    let only_leased = f.queue(&observer, Some(vec!["leased".into()]));
    assert_eq!(only_leased.len(), 1);
    assert_eq!(only_leased[0].lease_owner.as_deref(), Some("worker"));
    assert_eq!(only_leased[0].reason.as_ref().unwrap().len(), 512);
    assert!(only_leased[0].lease_expires_at.is_some());
    let json = serde_json::to_string(&only_leased).unwrap();
    for forbidden in [
        "lease_token",
        "capability_token",
        &lease.lease_token,
        &worker,
    ] {
        assert!(!json.contains(forbidden));
    }
    assert_eq!(
        f.queue(&observer, None)
            .iter()
            .map(|t| t.event_id)
            .collect::<Vec<_>>(),
        [dead, event_id]
    );
    assert_eq!(f.queue(&scoped, None), only_leased);
    assert!(f.queue(&observer, Some(vec![])).is_empty());
    error(
        f.call(
            &observer,
            Request::ListTriggerQueue {
                statuses: Some(vec!["unknown".into()]),
                host_id: None,
                incident_id: None,
                limit: None,
            },
        ),
        "invalid_request",
    );
    let Response::RunStarted { run_id, .. } = f.call(
        &worker,
        Request::StartInvestigationRun {
            incident_id: "inc-1".into(),
            backend_id: "backend".into(),
            model_id: "model".into(),
            prompt_schema_version: "1".into(),
        },
    ) else {
        panic!("could not start run")
    };
    assert!(matches!(
        f.call(
            &worker,
            finish(&run_id, RunTerminalStatus::BudgetExhausted, "budget")
        ),
        Response::RunFinished { .. }
    ));
    assert_eq!(
        f.call(
            &worker,
            Request::CompleteTriggerLease {
                event_id,
                lease_token: lease.lease_token,
                run_id: Some(run_id.clone()),
                summary: None,
            }
        ),
        Response::LeaseUpdated {
            event_id,
            status: "done".into()
        }
    );
    assert_eq!(f.runs(&observer)[0].status, "budget_exhausted");
    assert_eq!(
        f.queue(&scoped, Some(vec!["done".into()]))[0].event_id,
        event_id
    );
}

#[test]
fn migrates_existing_v3_ledger_with_run_in_place() {
    let dir = TestDir::new();
    let path = dir.0.join("ledger.sqlite3");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(include_str!("../src/schema.sql")).unwrap();
    db.execute_batch(include_str!("../src/schema_v2.sql"))
        .unwrap();
    db.execute_batch(include_str!("../src/schema_v3.sql"))
        .unwrap();
    db.pragma_update(None, "user_version", 3).unwrap();
    seed_incident(&db, "edge", "inc");
    db.execute_batch(
        "INSERT INTO capability_tokens VALUES ('old-token-hash','{}');
         INSERT INTO agent_runs (run_id,incident_id,token_hash,principal_id,backend_id,model_id,
                                  prompt_schema_version,started_at,expires_at,status)
         VALUES ('old-run','inc','old-token-hash','fixture','backend','model','1','2000-01-01T00:00:00Z',
                 '2000-01-02T00:00:00Z','completed');",
    ).unwrap();
    drop(db);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let service = ControlService::open(&dir.0, "test", 1).unwrap();
    let f = Fixture {
        service,
        db: ledger::open(&path).unwrap(),
        _dir: dir,
    };
    let version: u32 =
        f.db.pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
    assert_eq!(version, 4);
    let observer = f.mint(PrincipalRole::Observer, &["edge"], None);
    let runs = f.runs(&observer);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, "old-run");
    assert_eq!(runs[0].status, "completed");
    assert!(runs[0].ended_at.is_none());
    assert!(runs[0].outcome.is_none());
    assert_eq!(runs[0].event_count, 0);
}
