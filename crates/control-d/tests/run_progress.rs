use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use chrono::{SecondsFormat, Utc};
use control_d::{ControlService, ledger};
use defsec_protocol::rpc::{
    AdminRequest, AdminResponse, CapabilityPurpose, InvestigationCall,
    InvestigationRequest as Request, InvestigationResponse as Response, PrincipalRole,
    RunEventKind, RunOutcome, RunSummary, RunTerminalStatus, TriggerSummary,
};
use defsec_protocol::watch::CollectorType;
use rusqlite::{Connection, params};
use serde_json::{Value, json};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let tmp = std::env::temp_dir();
        let candidate = if tmp.as_os_str().len() <= 75 {
            tmp.join(format!("dr{id}"))
        } else {
            std::path::Path::new("/tmp").join(format!("dr{id}"))
        };
        let path = match fs::create_dir(&candidate) {
            Ok(()) => candidate,
            Err(_) => {
                let fallback = tmp.join(format!("dr{id}"));
                fs::create_dir(&fallback).unwrap();
                fallback
            }
        };
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
             SELECT host_id,'watch',1,'{\"collector\":{\"type\":\"sockets.listening\"}}','fixture',1,?2 FROM incidents WHERE incident_id=?1",
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
                may_spawn_runs: false,
                principal_id: "fixture".into(),
                role,
                allowed_hosts: hosts.iter().map(|s| (*s).into()).collect(),
                allowed_purposes: None,
                allowed_collectors: vec![CollectorType::SocketsListening],
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
    let version: i32 =
        f.db.pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
    assert_eq!(version, 18);
    assert_eq!(
        f.db.query_row(
            "SELECT trigger_event_id,trigger_lease_token FROM agent_runs WHERE run_id='old-run'",
            [],
            |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .unwrap(),
        (None, None),
    );
    let observer = f.mint(PrincipalRole::Observer, &["edge"], None);
    let runs = f.runs(&observer);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, "old-run");
    assert_eq!(runs[0].status, "completed");
    assert!(runs[0].ended_at.is_none());
    assert!(runs[0].outcome.is_none());
    assert_eq!(runs[0].event_count, 0);
}

fn mint_parent(
    f: &Fixture,
    principal: &str,
    ttl_seconds: u64,
    hosts: &[&str],
) -> (String, chrono::DateTime<Utc>) {
    let response = f
        .service
        .handle_admin_request(AdminRequest::MintCapabilityToken {
            principal_id: principal.into(),
            role: PrincipalRole::Investigator,
            allowed_hosts: hosts.iter().map(|s| (*s).into()).collect(),
            allowed_purposes: None,
            allowed_collectors: vec![defsec_protocol::watch::CollectorType::SocketsListening],
            incident_id: None,
            may_spawn_runs: true,
            ttl_seconds,
        });
    let AdminResponse::TokenMinted { token, expires_at } = response else {
        panic!("{response:?}")
    };
    (token, expires_at)
}

fn delegate(incident_id: &str, ttl_seconds: Option<u64>) -> Request {
    Request::StartDelegatedRun {
        incident_id: incident_id.into(),
        backend_id: "test-worker".into(),
        model_id: "test-model".into(),
        prompt_schema_version: "1".into(),
        ttl_seconds,
        trigger_event_id: None,
        lease_token: None,
    }
}

fn delegated(response: Response) -> (String, String, chrono::DateTime<Utc>) {
    let Response::DelegatedRunStarted {
        run_id,
        run_token,
        expires_at,
        ..
    } = response
    else {
        panic!("delegation failed");
    };
    (run_id, run_token, expires_at)
}

fn capability(f: &Fixture, token: &str) -> defsec_protocol::rpc::ScopedCapability {
    let Response::Capability { capability, .. } = f.call(token, Request::GetCapability {}) else {
        panic!("could not inspect capability");
    };
    capability
}

fn cancel(run_id: &str) -> Request {
    Request::CancelInvestigationRun {
        run_id: run_id.into(),
        reason: "operator stopped run".into(),
    }
}

#[test]
fn delegated_tokens_expire_at_the_minimum_and_do_not_narrow_parent_scope() {
    use chrono::Duration;

    let f = Fixture::new();
    let (parent, _) = mint_parent(&f, "parent", 7200, &["edge", "foreign"]);
    let before = capability(&f, &parent);
    for (ttl, bound) in [(Some(60), 60), (Some(u64::MAX), 3600), (None, 3600)] {
        let now = Utc::now();
        let (run, child, expires) = delegated(f.call(&parent, delegate("inc-1", ttl)));
        assert!(expires >= now + Duration::seconds(bound));
        assert!(expires <= Utc::now() + Duration::seconds(bound));
        let cap = capability(&f, &child);
        assert_eq!(cap.principal_id, before.principal_id);
        assert_eq!(cap.role, PrincipalRole::Investigator);
        assert_eq!(cap.run_id.as_deref(), Some(run.as_str()));
        assert_eq!(cap.incident_id.as_deref(), Some("inc-1"));
        assert_eq!(cap.expires_at, expires);
        assert_eq!(cap.allowed_hosts, ["edge"]);
        assert_eq!(cap.allowed_collectors, before.allowed_collectors);
        assert!(!cap.may_spawn_runs);
        for request in [
            delegate("inc-1", None),
            Request::ListActiveWatches {
                host_id: "foreign".into(),
            },
            Request::GetIncidentContext {
                incident_id: "inc-2".into(),
            },
        ] {
            assert!(
                matches!(f.call(&child, request), Response::Error { code, .. } if code=="forbidden")
            );
        }
        let Response::Capabilities { capabilities } = f.call(
            &child,
            Request::ListCollectorCapabilities {
                host_id: "edge".into(),
            },
        ) else {
            panic!("collector listing failed")
        };
        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].collector_type, before.allowed_collectors[0]);
    }
    assert_eq!(capability(&f, &parent), before);
    delegated(f.call(&parent, delegate("inc-3", None)));
    let (short, parent_expires) = mint_parent(&f, "short", 45, &["edge"]);
    assert_eq!(
        delegated(f.call(&short, delegate("inc-1", Some(3600)))).2,
        parent_expires
    );
    assert!(matches!(f.call(&short, delegate("inc-1", Some(0))),
        Response::Error {code, ..} if code == "invalid_request"));
    assert!(matches!(f.call(&short, delegate("inc-3", None)),
        Response::Error {code, ..} if code == "forbidden"));
}

#[test]
fn delegation_quota_spans_tokens_and_cancel_revokes_the_child() {
    let f = Fixture::new();
    let (parent, _) = mint_parent(&f, "fixture", 7200, &["edge"]);
    let (same_principal, _) = mint_parent(&f, "fixture", 7200, &["edge"]);
    let (other, _) = mint_parent(&f, "other", 7200, &["edge"]);
    let runs: Vec<_> = (0..4)
        .map(|_| delegated(f.call(&parent, delegate("inc-1", None))))
        .collect();
    let (run, child, _) = &runs[0];
    assert!(matches!(f.call(&same_principal, delegate("inc-1", None)),
        Response::Error {code, ..} if code=="delegated_run_quota"));
    delegated(f.call(&other, delegate("inc-1", None)));
    let no_spawn = f.mint(PrincipalRole::Investigator, &["edge"], None);
    for wrong in [&other, &no_spawn, &runs[1].1] {
        assert!(
            matches!(f.call(wrong, cancel(run)), Response::Error {code, ..} if code=="forbidden")
        );
    }
    let (narrow_parent, _) = mint_parent(&f, "fixture", 7200, &["foreign"]);
    assert!(
        matches!(f.call(&narrow_parent, cancel(run)), Response::Error {code, ..} if code=="forbidden")
    );
    assert!(matches!(f.call(child, Request::CancelInvestigationRun {
        run_id: run.clone(), reason: format!("secret {child}"),
    }), Response::Error {code, ..} if code=="invalid_request"));
    for (caller, (run, child, _)) in [
        (same_principal.as_str(), &runs[0]),
        (runs[1].1.as_str(), &runs[1]),
    ] {
        assert_eq!(
            f.call(caller, cancel(run)),
            Response::RunFinished {
                run_id: run.clone(),
                status: RunTerminalStatus::Cancelled
            }
        );
        for request in [
            Request::GetCapability {},
            events(run, None),
            finish(run, RunTerminalStatus::Completed, "late"),
        ] {
            assert!(
                matches!(f.call(child, request), Response::Error {message, ..} if message=="invalid capability token")
            );
        }
    }
    assert!(matches!(
        f.call(&same_principal, cancel(run)),
        Response::RunFinished { .. }
    ));
    let (finished, finished_token, _) = delegated(f.call(&same_principal, delegate("inc-1", None)));
    assert!(matches!(
        f.call(
            &finished_token,
            finish(&finished, RunTerminalStatus::Completed, "done")
        ),
        Response::RunFinished { .. }
    ));
    // Finished and expired rows do not consume quota.
    f.db.execute(
        "UPDATE agent_runs SET expires_at='2000-01-01T00:00:00Z' WHERE run_id=?1",
        [&runs[2].0],
    )
    .unwrap();
    for _ in 0..3 {
        delegated(f.call(&same_principal, delegate("inc-1", None)));
    }
    assert!(
        matches!(f.call(&same_principal, delegate("inc-1", None)), Response::Error {code, ..} if code=="delegated_run_quota")
    );
    let stored_audit = f
        .service
        .handle_admin_request(AdminRequest::ListAuditEntries { limit: Some(100) });
    let audit = serde_json::to_string(&stored_audit).unwrap();
    assert!(audit.contains(run));
    assert!(!audit.contains(child));
    assert!(!audit.contains(&parent));
    assert!(matches!(
        f.service
            .handle_admin_request(AdminRequest::VerifyAuditChain),
        AdminResponse::AuditChainStatus { valid: true, .. }
    ));
}

#[tokio::test]
async fn delegated_token_cannot_manage_trigger_leases_over_the_socket() {
    use control_d::server::{SocketPolicy, UnixServer};
    use defsec_protocol::wire::{read_frame, write_frame};
    use tokio::net::UnixStream;

    let f = Fixture::new();
    let (parent, _) = mint_parent(&f, "worker", 300, &["edge"]);
    let (_, child, _) = delegated(f.call(&parent, delegate("inc-1", None)));
    let event_id = f.trigger("pending", "inc-1", "fixture");
    let lease_request = Request::LeaseNextTrigger {
        lease_owner: "worker".into(),
        lease_seconds: 120,
    };
    let Response::TriggerLeased { lease: Some(lease) } = f.call(&parent, lease_request.clone())
    else {
        panic!("no ongoing lease");
    };
    assert_eq!(lease.event_id, event_id);
    f.trigger("pending", "inc-1", "second fixture");

    let socket = f._dir.0.join("investigate.sock");
    let server = UnixServer::bind(&socket, SocketPolicy::default()).unwrap();
    let task = tokio::spawn(server.serve_investigation(f.service.clone()));
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    for request in [
        lease_request,
        Request::CompleteTriggerLease {
            event_id,
            lease_token: lease.lease_token.clone(),
            run_id: None,
            summary: None,
        },
        Request::FailTriggerLease {
            event_id,
            lease_token: lease.lease_token,
            error: "fixture".into(),
            retryable: true,
            preserve_retry_count: false,
        },
    ] {
        write_frame(
            &mut stream,
            &InvestigationCall {
                request_id: "child-lease".into(),
                capability_token: child.clone(),
                request,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            read_frame(&mut stream).await.unwrap(),
            Some(Response::Error {
                code: "forbidden".into(),
                message: "delegated runs cannot manage trigger leases".into(),
            })
        );
    }
    assert_eq!(f.queue(&parent, Some(vec!["leased".into()])).len(), 1);
    assert_eq!(f.queue(&parent, Some(vec!["pending".into()])).len(), 1);
    task.abort();
}

#[test]
fn child_cannot_read_another_runs_events_and_cancelled_finish_revokes_it() {
    let f = Fixture::new();
    let (parent, _) = mint_parent(&f, "parent", 300, &["edge"]);
    let (run, child, _) = delegated(f.call(&parent, delegate("inc-1", None)));
    let (other, other_child, _) = delegated(f.call(&parent, delegate("inc-1", None)));
    assert!(matches!(
        f.call(
            &other_child,
            report(&other, json!({"note":"private to the other run"}))
        ),
        Response::RunProgressRecorded { .. }
    ));
    assert!(matches!(
        f.call(&child, events(&run, None)),
        Response::RunEvents { .. }
    ));
    assert!(matches!(
        f.call(&child, events(&other, None)),
        Response::Error { code, .. } if code == "forbidden"
    ));
    assert_eq!(
        f.call(
            &child,
            finish(&run, RunTerminalStatus::Cancelled, "stopped")
        ),
        Response::RunFinished {
            run_id: run.clone(),
            status: RunTerminalStatus::Cancelled,
        }
    );
    assert!(matches!(
        f.call(&child, Request::GetCapability {}),
        Response::Error { message, .. } if message == "invalid capability token"
    ));
    assert!(matches!(
        f.call(&parent, events(&run, None)),
        Response::RunEvents { .. }
    ));
}

#[test]
fn only_spawn_capable_investigators_can_delegate_open_incidents() {
    let f = Fixture::new();
    for role in [PrincipalRole::Observer, PrincipalRole::Investigator] {
        let token = f.mint(role, &["edge"], None);
        assert!(
            matches!(f.call(&token, delegate("inc-1", None)), Response::Error {code, ..} if code=="forbidden")
        );
    }
    assert!(matches!(
        f.service
            .handle_admin_request(AdminRequest::MintCapabilityToken {
                principal_id: "observer".into(),
                role: PrincipalRole::Observer,
                allowed_hosts: vec!["edge".into()],
                allowed_purposes: None,
                allowed_collectors: vec![],
                incident_id: None,
                ttl_seconds: 3600,
                may_spawn_runs: true,
            }),
        AdminResponse::Error { .. }
    ));
    let (parent, _) = mint_parent(&f, "parent", 7200, &["edge"]);
    let (_, child, _) = delegated(f.call(&parent, delegate("inc-1", None)));
    assert!(matches!(
        f.service.handle_admin_request(AdminRequest::CloseIncident {
            incident_id: "inc-1".into(),
            actor: "operator".into(),
            resolution: "fixture closed".into(),
        }),
        AdminResponse::IncidentClosed { .. }
    ));
    assert!(
        matches!(f.call(&parent, delegate("inc-1", None)), Response::Error {message, ..} if message=="incident is closed")
    );
    assert!(
        matches!(f.call(&child, Request::GetCapability {}), Response::Error {message, ..} if message=="invalid capability token")
    );
}

#[tokio::test]
async fn real_control_daemon_keeps_delegated_token_out_of_its_logs() {
    use defsec_protocol::wire::{read_frame, write_frame};
    use std::{process::Stdio, time::Duration};
    use tokio::{
        net::UnixStream,
        process::Command,
        time::{sleep, timeout},
    };

    let f = Fixture::new();
    let (parent, _) = mint_parent(&f, "log-test", 300, &["edge"]);
    let socket = f._dir.0.join("investigate.sock");
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_control-d"))
        .arg("--data-dir")
        .arg(&f._dir.0)
        .args(["--liveness-grace-seconds", "0"])
        .env("RUST_LOG", "trace")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let (child, mut stream) = timeout(Duration::from_secs(5), async {
        let mut stream = loop {
            if let Ok(socket) = UnixStream::connect(&socket).await {
                break socket;
            }
            assert!(daemon.try_wait().unwrap().is_none());
            sleep(Duration::from_millis(10)).await;
        };
        write_frame(
            &mut stream,
            &InvestigationCall {
                request_id: "delegate-on-wire".into(),
                capability_token: parent.clone(),
                request: delegate("inc-1", None),
            },
        )
        .await
        .unwrap();
        let (run_id, child, _) = delegated(read_frame(&mut stream).await.unwrap().unwrap());
        write_frame(
            &mut stream,
            &InvestigationCall {
                request_id: "cancel-on-wire".into(),
                capability_token: child.clone(),
                request: cancel(&run_id),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_frame(&mut stream).await.unwrap(),
            Some(Response::RunFinished {
                status: RunTerminalStatus::Cancelled,
                ..
            })
        ));
        (child, stream)
    })
    .await
    .unwrap();
    // Trigger a transport error that the daemon logs before stopping it.
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let invalid = format!(r#"{{"request_id":"bad","capability_token":"{child}","{child}":null}}"#);
    stream
        .write_all(&(invalid.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(invalid.as_bytes()).await.unwrap();
    assert!(
        read_frame::<_, Response>(&mut stream)
            .await
            .unwrap()
            .is_none()
    );
    let mut logs = BufReader::new(daemon.stderr.take().unwrap());
    let log = timeout(Duration::from_secs(5), async {
        let mut log = String::new();
        while !log.contains("local connection ended") {
            assert!(logs.read_line(&mut log).await.unwrap() > 0);
        }
        log
    })
    .await
    .unwrap();
    daemon.start_kill().unwrap();
    let output = daemon.wait_with_output().await.unwrap();
    for token in [&parent, &child] {
        assert!(!log.contains(token));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(token));
    }
}

fn mint_for_purpose(
    f: &Fixture,
    purpose: CapabilityPurpose,
    collectors: Vec<CollectorType>,
    may_spawn_runs: bool,
) -> String {
    let response = f
        .service
        .handle_admin_request(AdminRequest::MintCapabilityToken {
            principal_id: "scoped-worker".into(),
            role: PrincipalRole::Investigator,
            allowed_hosts: vec!["edge".into()],
            allowed_collectors: collectors,
            allowed_purposes: Some(vec![purpose]),
            incident_id: None,
            ttl_seconds: 300,
            may_spawn_runs,
        });
    let AdminResponse::TokenMinted { token, .. } = response else {
        panic!("{response:?}");
    };
    token
}

fn lease_next() -> Request {
    Request::LeaseNextTrigger {
        lease_owner: "worker".into(),
        lease_seconds: 120,
    }
}

#[test]
fn explicit_purpose_separates_reactive_discovery_and_review_operations() {
    let f = Fixture::new();
    let discovery = mint_for_purpose(
        &f,
        CapabilityPurpose::HostDiscovery,
        vec![CollectorType::SocketsListening],
        true,
    );
    let discovery_no_spawn = mint_for_purpose(
        &f,
        CapabilityPurpose::HostDiscovery,
        vec![CollectorType::SocketsListening],
        false,
    );
    let reactive = mint_for_purpose(
        &f,
        CapabilityPurpose::ReactiveIncident,
        vec![CollectorType::SocketsListening],
        true,
    );
    let denied = |token, request| {
        let response = f.call(token, request);
        assert!(
            matches!(&response, Response::Error { code, message }
            if code == "forbidden" && message.contains("purpose scope")),
            "{response:?}"
        );
    };
    denied(
        &discovery_no_spawn,
        Request::StartInvestigationRun {
            incident_id: "inc-1".into(),
            backend_id: "backend".into(),
            model_id: "model".into(),
            prompt_schema_version: "1".into(),
        },
    );
    denied(&discovery, delegate("inc-1", None));
    denied(&discovery, lease_next());
    denied(
        &reactive,
        Request::AdvanceHostDiscovery {
            host_id: Some("edge".into()),
        },
    );
    denied(
        &reactive,
        Request::ClaimHostInterpretation {
            host_id: "edge".into(),
            source_ids: vec![1],
            export_collectors: vec![CollectorType::SocketsListening],
            lease_seconds: 60,
        },
    );
    denied(
        &reactive,
        Request::FinishHostInterpretation {
            host_id: "edge".into(),
            lease_id: "lease".into(),
            proposal: None,
            usage: None,
            error: None,
        },
    );
    denied(
        &reactive,
        Request::ClaimHostReview {
            allowed_sources: None,
            route: "fixture".into(),
            lease_seconds: 60,
        },
    );
    denied(
        &reactive,
        Request::CompleteHostReview {
            review_id: "review".into(),
            lease_token: "lease".into(),
            citations: vec![],
            interpretation: defsec_protocol::rpc::EvidenceInterpretation::Unresolved,
            summary: "fixture".into(),
        },
    );

    let (_, child, _) = delegated(f.call(&reactive, delegate("inc-1", None)));
    assert_eq!(
        capability(&f, &child).allowed_purposes,
        Some(vec![CapabilityPurpose::ReactiveIncident])
    );
}

#[test]
fn trigger_leases_skip_other_collectors_and_truncate_oversized_legacy_outcomes() {
    let f = Fixture::new();
    let excluded = f.trigger("pending", "inc-1", "foreign collector");
    f.db.execute_batch(r#"
        INSERT INTO watch_specs(host_id,watch_id,spec_version,spec_json,creator,active,created_at)
        VALUES ('edge','files',1,'{"collector":{"type":"files.metadata"}}','fixture',1,'');
        INSERT INTO agent_sessions (host_id,session_id,boot_id) VALUES ('edge','session','boot');
        INSERT INTO observations (observation_id,host_id,session_id,seq_no,watch_id,spec_version,
          collector_type,observed_at,received_at,status_json,state_hash,payload_json,record_json)
        VALUES (1,'edge','session',1,'watch',1,'sockets.listening','now','now','"ok"','hash','{}','{}'),
               (2,'edge','session',2,'files',1,'files.metadata','now','now','"ok"','hash','{}','{}');
    "#).unwrap();
    f.db.execute(
        "UPDATE trigger_events SET watch_id='files' WHERE event_id=?1",
        [excluded],
    )
    .unwrap();
    let oversized = f.trigger(
        "pending",
        "inc-1",
        &"é".repeat(defsec_protocol::wire::MAX_FRAME_BYTES),
    );
    let next = f.trigger("pending", "inc-2", "next eligible");
    f.db.execute(
        "INSERT INTO trigger_evidence VALUES (?1,1),(?1,2)",
        [oversized],
    )
    .unwrap();
    let scoped = mint_for_purpose(
        &f,
        CapabilityPurpose::ReactiveIncident,
        vec![CollectorType::SocketsListening],
        true,
    );

    let Response::TriggerLeased { lease: Some(lease) } = f.call(&scoped, lease_next()) else {
        panic!("legacy outcome blocked the lease");
    };
    assert_eq!(
        (
            lease.event_id,
            lease.incident_id.as_str(),
            lease.host_id.as_str(),
            lease.watch_id.as_str()
        ),
        (oversized, "inc-1", "edge", "watch")
    );
    assert_eq!(lease.outcome["truncated"], true);
    assert!(lease.outcome["reason"].is_string());
    assert_eq!(lease.evidence_observation_ids, [1]);
    assert!(
        !f.queue(&scoped, None)
            .iter()
            .any(|row| row.event_id == excluded)
    );
    assert!(
        matches!(f.call(&scoped, lease_next()), Response::TriggerLeased { lease: Some(lease) } if lease.event_id == next)
    );

    let files = mint_for_purpose(
        &f,
        CapabilityPurpose::ReactiveIncident,
        vec![CollectorType::FilesMetadata],
        true,
    );
    assert!(
        matches!(f.call(&files, lease_next()), Response::TriggerLeased { lease: Some(lease) }
        if lease.event_id == excluded && lease.outcome["reason"] == "foreign collector")
    );
}

#[test]
fn delegated_runs_are_fenced_by_the_current_trigger_lease() {
    let f = Fixture::new();
    let event = f.trigger("pending", "inc-1", "first");
    let (parent, _) = mint_parent(&f, "worker", 3600, &["edge"]);
    let claim = || {
        let Response::TriggerLeased { lease: Some(lease) } = f.call(&parent, lease_next()) else {
            panic!("missing lease");
        };
        lease
    };
    let start = |incident: &str, id, token| Request::StartDelegatedRun {
        incident_id: incident.into(),
        backend_id: "backend".into(),
        model_id: "model".into(),
        prompt_schema_version: "1".into(),
        ttl_seconds: Some(3600),
        trigger_event_id: id,
        lease_token: token,
    };

    let lease = claim();
    error(
        f.call(&parent, start("inc-1", Some(event), None)),
        "invalid_request",
    );
    error(
        f.call(
            &parent,
            start("inc-1", None, Some(lease.lease_token.clone())),
        ),
        "invalid_request",
    );
    error(
        f.call(
            &parent,
            start("inc-2", Some(event), Some(lease.lease_token.clone())),
        ),
        "lease_fenced",
    );
    error(
        f.call(&parent, start("inc-1", Some(event), Some("wrong".into()))),
        "lease_fenced",
    );
    let (run, worker, expires) = delegated(f.call(
        &parent,
        start("inc-1", Some(event), Some(lease.lease_token.clone())),
    ));
    assert_eq!(expires, lease.lease_expires_at);
    assert_eq!(capability(&f, &worker).expires_at, expires);
    assert_eq!(
        f.db.query_row(
            "SELECT trigger_event_id,trigger_lease_token FROM agent_runs WHERE run_id=?1",
            [&run],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        )
        .unwrap(),
        (event, lease.lease_token.clone())
    );
    assert!(matches!(
        f.call(&worker, report(&run, json!({"message":"before reclaim"}))),
        Response::RunProgressRecorded { .. }
    ));

    // Force lease expiry while the original child token still has time remaining.
    f.db.execute(
        "UPDATE trigger_events SET lease_expires_at='2000-01-01T00:00:00Z' WHERE event_id=?1",
        [event],
    )
    .unwrap();
    error(
        f.call(&worker, report(&run, json!({"message":"after expiry"}))),
        "lease_fenced",
    );
    error(
        f.call(
            &parent,
            start("inc-1", Some(event), Some(lease.lease_token.clone())),
        ),
        "lease_fenced",
    );
    let successor = claim();
    assert_eq!(successor.event_id, event);
    assert_ne!(successor.lease_token, lease.lease_token);
    error(
        f.call(&worker, finish(&run, RunTerminalStatus::Completed, "stale")),
        "lease_fenced",
    );
    let (new_run, new_worker, _) = delegated(f.call(
        &parent,
        start("inc-1", Some(event), Some(successor.lease_token.clone())),
    ));
    assert!(matches!(
        f.call(
            &new_worker,
            finish(&new_run, RunTerminalStatus::Completed, "fresh")
        ),
        Response::RunFinished { .. }
    ));
    assert!(matches!(f.call(&parent, Request::CompleteTriggerLease {
        event_id: event, lease_token: successor.lease_token, run_id: Some(new_run), summary: None,
    }), Response::LeaseUpdated { status, .. } if status == "done"));
}

#[test]
fn capacity_deferral_preserves_retry_count_and_followup_cannot_cancel_reactive_run() {
    let f = Fixture::new();
    let event = f.trigger("pending", "inc-1", "capacity");
    let mint = |purposes: Vec<CapabilityPurpose>| {
        let AdminResponse::TokenMinted { token, .. } =
            f.service
                .handle_admin_request(AdminRequest::MintCapabilityToken {
                    principal_id: "codex-parent".into(),
                    role: PrincipalRole::Investigator,
                    allowed_hosts: vec!["edge".into()],
                    allowed_collectors: vec![CollectorType::SocketsListening],
                    incident_id: None,
                    ttl_seconds: 3600,
                    may_spawn_runs: true,
                    allowed_purposes: Some(purposes),
                })
        else {
            panic!("mint failed");
        };
        token
    };
    let parent = mint(vec![CapabilityPurpose::ReactiveIncident]);
    let followup_only = mint(vec![CapabilityPurpose::WatchFollowup]);

    // Six consecutive capacity deferrals must preserve retry_count=0 and keep trigger pending.
    for _ in 0..6 {
        let Response::TriggerLeased {
            lease: Some(lease),
        } = f.call(&parent, lease_next())
        else {
            panic!("expected trigger lease");
        };
        assert_eq!(lease.retry_count, 0);
        assert!(matches!(
            f.call(
                &parent,
                Request::FailTriggerLease {
                    event_id: event,
                    lease_token: lease.lease_token,
                    error: "delegated_run_quota".into(),
                    retryable: true,
                    preserve_retry_count: true,
                },
            ),
            Response::LeaseUpdated { status, .. } if status == "pending"
        ));
    }

    // Start a reactive delegated run and confirm a follow-up-only token cannot cancel it.
    let (run_id, _, _) = delegated(f.call(
        &parent,
        Request::StartDelegatedRun {
            incident_id: "inc-1".into(),
            backend_id: "backend".into(),
            model_id: "model".into(),
            prompt_schema_version: "1".into(),
            ttl_seconds: Some(3600),
            trigger_event_id: None,
            lease_token: None,
        },
    ));
    error(
        f.call(
            &followup_only,
            Request::CancelInvestigationRun {
                run_id: run_id.clone(),
                reason: "cross-purpose cancel".into(),
            },
        ),
        "forbidden",
    );
    assert!(matches!(
        f.call(
            &parent,
            Request::CancelInvestigationRun {
                run_id,
                reason: "reactive parent cancel".into(),
            },
        ),
        Response::RunFinished {
            status: RunTerminalStatus::Cancelled,
            ..
        }
    ));
}
