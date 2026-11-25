use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration as StdDuration};

use chrono::{Duration, Utc};
use control_d::{
    ControlService, ledger,
    server::{SocketPolicy, UnixServer},
};
use defsec_protocol::{
    canonical::canonical_sha256_hex,
    observation::{ObservationPayload, ObservationRecord, ObservationStatus},
    rpc::*,
    signing::{DOMAIN_WATCH_BUNDLE_V1, VerifyingKeyStore},
    watch::*,
    wire::*,
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tokio::{net::UnixStream, time::timeout};

struct Fixture {
    service: ControlService,
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let dir = std::env::temp_dir().join(format!("d-{short_id}"));
        let service = ControlService::open(&dir, "key", 3).unwrap();
        Self { service, dir }
    }

    fn db(&self) -> Connection {
        ledger::open(self.dir.join("ledger.sqlite3")).unwrap()
    }

    fn enroll(&self, host: &str) -> (String, String) {
        let AdminResponse::HostEnrolled {
            control_signing_key_id,
            control_public_key_hex,
            ..
        } = self.service.handle_admin_request(enroll(host))
        else {
            panic!("enroll failed")
        };
        (control_signing_key_id, control_public_key_hex)
    }

    fn apply(&self, spec: WatchSpec) -> u64 {
        let response = self.service.handle_admin_request(apply(spec));
        let AdminResponse::WatchApplied { bundle_version, .. } = response else {
            panic!("{response:?}")
        };
        bundle_version
    }

    fn setup_host(&self, host: &str) {
        self.enroll(host);
        self.apply(watch(host));
        let replies = self.service.handle_agent_message(register(host));
        assert!(matches!(
            replies.first(),
            Some(ControlToAgent::RegisterAck { accepted: true, .. })
        ));
        assert!(matches!(
            replies.get(1),
            Some(ControlToAgent::SyncWatchBundle { .. })
        ));
        assert!(matches!(
            replies.get(2),
            Some(ControlToAgent::RequestReconciliation { .. })
        ));
    }

    fn put(&self, host: &str, seq: u64, state: &str) -> i64 {
        assert!(
            matches!(self.service.handle_agent_message(push(observation(host,seq,state))).as_slice(),
            [ControlToAgent::ObservationAck {acked_seq_no,..}] if *acked_seq_no == seq)
        );
        self.db()
            .query_row(
                "SELECT observation_id FROM observations WHERE host_id=?1 AND seq_no=?2",
                params![host, seq],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn promote(&self, host: &str, id: i64) -> i64 {
        let result = self
            .service
            .handle_admin_request(AdminRequest::PromoteBaseline {
                host_id: host.into(),
                watch_id: "unit".into(),
                observation_id: id,
                approver: "operator".into(),
                rationale: "reviewed expected state".into(),
                ticket_ref: Some("change-3".into()),
            });
        let AdminResponse::BaselinePromoted { revision_id, .. } = result else {
            panic!("{result:?}")
        };
        revision_id
    }

    fn incident(&self, host: &str) -> (String, i64) {
        self.setup_host(host);
        let first = self.put(host, 1, "active");
        self.promote(host, first);
        let evidence = self.put(host, 2, "inactive");
        let incident = self
            .db()
            .query_row(
                "SELECT incident_id FROM incidents WHERE host_id=?1",
                [host],
                |r| r.get(0),
            )
            .unwrap();
        (incident, evidence)
    }

    fn mint(&self, role: PrincipalRole, incident: &str) -> String {
        let response = self
            .service
            .handle_admin_request(AdminRequest::MintCapabilityToken {
                may_spawn_runs: false,
                principal_id: "test-user".into(),
                role,
                allowed_hosts: vec!["edge".into(), "foreign".into()],
                allowed_collectors: vec![CollectorType::SystemdUnitState],
                incident_id: Some(incident.into()),
                ttl_seconds: 300,
            });
        let AdminResponse::TokenMinted { token, .. } = response else {
            panic!("{response:?}")
        };
        token
    }

    fn investigate(&self, token: &str, request: InvestigationRequest) -> InvestigationResponse {
        self.service.handle_investigation_call(InvestigationCall {
            request_id: "request".into(),
            capability_token: token.into(),
            request,
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn enroll(host: &str) -> AdminRequest {
    AdminRequest::EnrollHost {
        host_id: host.into(),
        agent_public_key_hex: None,
    }
}

fn apply(spec: WatchSpec) -> AdminRequest {
    AdminRequest::ApplyBaselineWatch {
        spec,
        actor: "operator".into(),
        rationale: "monitor service state".into(),
    }
}

fn register(host: &str) -> AgentToControl {
    AgentToControl::Register {
        protocol_version: WIRE_PROTOCOL_VERSION,
        host_id: host.into(),
        agent_version: "test".into(),
        boot_id: "boot".into(),
        session_id: "session".into(),
        active_bundle_version: 0,
        active_bundle_digest: None,
        sent_at: Utc::now(),
        host_profile: None,
    }
}

fn watch(host: &str) -> WatchSpec {
    WatchSpec {
        id: "unit".into(),
        version: 1,
        host_id: host.into(),
        class: WatchClass::Baseline,
        incident_id: None,
        collector: CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
            unit: "sshd.service".into(),
            hash_unit_files: false,
        }),
        schedule: WatchSchedule {
            interval_seconds: 30,
            timeout_seconds: 5,
        },
        trigger: TriggerPredicate::FieldChanged {
            compare_against: CompareTarget::AcceptedBaseline,
            fields: vec!["active_state".into()],
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
    }
}

fn observation(host: &str, seq_no: u64, state: &str) -> ObservationRecord {
    let data = json!({"unit":"sshd.service","active_state":state});
    ObservationRecord {
        host_id: host.into(),
        session_id: "session".into(),
        seq_no,
        watch_id: "unit".into(),
        spec_version: 1,
        collector_type: CollectorType::SystemdUnitState,
        observed_at: Utc::now(),
        status: ObservationStatus::Ok,
        state_hash: canonical_sha256_hex(&data).unwrap(),
        payload: ObservationPayload::Snapshot { data },
        is_reconciliation: false,
        sustained_count: None,
        sustained_active: None,
        partial_reasons: vec![],
    }
}

fn push(observation: ObservationRecord) -> AgentToControl {
    AgentToControl::PushObservationDelta { observation }
}

fn outcome(db: &Connection) -> Value {
    let raw: String = db
        .query_row(
            "SELECT outcome_json FROM watch_state WHERE host_id='edge' AND watch_id='unit'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn baseline_is_explicit_and_rollback_creates_a_revision() {
    let f = Fixture::new();
    f.setup_host("edge");
    let original = f.put("edge", 1, "active");
    let db = f.db();
    assert_eq!(outcome(&db), json!({"outcome":"baseline_unavailable"}));
    assert_eq!(count(&db, "baseline_revisions"), 0);
    let first = f.promote("edge", original);
    let drift = f.put("edge", 2, "inactive");
    assert_eq!(outcome(&db)["outcome"], "triggered");
    f.put("edge", 3, "inactive");
    assert_eq!(outcome(&db)["outcome"], "triggered");
    assert_eq!(count(&db, "incidents"), 1);
    assert_eq!(count(&db, "trigger_events"), 1);
    assert_eq!(count(&db, "trigger_evidence"), 2);
    assert_eq!(count(&db, "wake_budget_state"), 1);
    assert_eq!(count(&db, "baseline_revisions"), 1);
    let second = f.promote("edge", drift);
    f.put("edge", 4, "inactive");
    assert_eq!(outcome(&db)["outcome"], "not_triggered");
    let rollback = f.promote("edge", original);
    let mut query = db.prepare("SELECT revision_id,predecessor_id,observation_id FROM baseline_revisions ORDER BY revision_id").unwrap();
    let revisions: Vec<(i64, Option<i64>, i64)> = query
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        revisions,
        [
            (first, None, original),
            (second, Some(first), drift),
            (rollback, Some(second), original)
        ]
    );
    f.put("edge", 5, "active");
    assert_eq!(outcome(&db)["outcome"], "not_triggered");
}

#[test]
fn distinct_drift_diffs_on_same_watch_coalesce_until_closed() {
    let f = Fixture::new();
    f.setup_host("edge");
    let baseline = f.put("edge", 1, "active");
    f.promote("edge", baseline);

    // Two distinct drift states on the same watch coalesce into one open incident.
    f.put("edge", 2, "inactive");
    f.put("edge", 3, "failed");
    let db = f.db();
    assert_eq!(count(&db, "incidents"), 1);
    assert_eq!(count(&db, "trigger_events"), 2);
    assert_eq!(count(&db, "trigger_evidence"), 2);

    // Closing the incident allows subsequent drift on the same watch to open a new one.
    let incident_id: String = db
        .query_row(
            "SELECT incident_id FROM incidents WHERE host_id='edge'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(matches!(
        f.service
            .handle_admin_request(AdminRequest::CloseIncident {
                incident_id,
                actor: "ops".into(),
                resolution: "resolved".into(),
            }),
        AdminResponse::IncidentClosed { .. }
    ));
    f.put("edge", 4, "deactivating");
    assert_eq!(count(&db, "incidents"), 2);
}

#[test]
fn contiguous_ack_deduplicates_and_distinguishes_gaps_from_checkpoints() {
    let f = Fixture::new();
    f.setup_host("edge");
    let first = push(observation("edge", 1, "active"));
    for _ in 0..2 {
        assert!(matches!(
            f.service.handle_agent_message(first.clone()).as_slice(),
            [ControlToAgent::ObservationAck {
                acked_seq_no: 1,
                ..
            }]
        ));
    }
    assert!(matches!(
        f.service
            .handle_agent_message(push(observation("edge", 3, "inactive")))
            .as_slice(),
        [ControlToAgent::RequestReconciliation { .. }]
    ));
    let db = f.db();
    assert_eq!(count(&db, "observations"), 1);
    let mut invalid = observation("edge", 2, "inactive");
    let ObservationPayload::Snapshot { data } = invalid.payload else {
        unreachable!()
    };
    invalid.payload = ObservationPayload::Delta {
        base_hash: "wrong-base".into(),
        data,
    };
    assert!(matches!(
        f.service.handle_agent_message(push(invalid)).as_slice(),
        [ControlToAgent::RequestReconciliation { .. }]
    ));
    let mut checkpoint = observation("edge", 3, "inactive");
    checkpoint.is_reconciliation = true;
    assert!(matches!(
        f.service.handle_agent_message(push(checkpoint)).as_slice(),
        [ControlToAgent::ObservationAck {
            acked_seq_no: 1,
            ..
        }]
    ));
    let mut recovered = observation("edge", 2, "activating");
    let ObservationPayload::Snapshot { data } = recovered.payload else {
        unreachable!()
    };
    recovered.payload = ObservationPayload::Delta {
        base_hash: observation("edge", 1, "active").state_hash,
        data,
    };
    assert!(matches!(
        f.service.handle_agent_message(push(recovered)).as_slice(),
        [ControlToAgent::ObservationAck {
            acked_seq_no: 3,
            ..
        }]
    ));
    let latest: i64 = db.query_row("SELECT o.seq_no FROM watch_state s JOIN observations o ON s.last_success_id=o.observation_id",[],|r|r.get(0)).unwrap();
    assert_eq!(latest, 3);
    let mut delta = observation("edge", 4, "active");
    let ObservationPayload::Snapshot { data } = delta.payload else {
        unreachable!()
    };
    delta.payload = ObservationPayload::Delta {
        base_hash: observation("edge", 3, "inactive").state_hash,
        data,
    };
    assert!(matches!(
        f.service.handle_agent_message(push(delta)).as_slice(),
        [ControlToAgent::ObservationAck {
            acked_seq_no: 4,
            ..
        }]
    ));
    assert_eq!(count(&db, "observations"), 4);
    assert!(matches!(
        f.service.handle_agent_message(register("edge")).first(),
        Some(ControlToAgent::RegisterAck {
            last_acked_seq_no: 4,
            ..
        })
    ));
}

#[test]
fn investigation_enforces_scope_and_closure_retires_watches() {
    use InvestigationRequest::*;
    use InvestigationResponse::{Error, FindingRecorded, ProposalEvaluated, RunStarted, Watches};
    let f = Fixture::new();
    let (incident, evidence) = f.incident("edge");
    let (foreign_incident, foreign_evidence) = f.incident("foreign");
    let token = f.mint(PrincipalRole::Investigator, &incident);
    assert_eq!(token.len(), 64);
    let start = StartInvestigationRun {
        incident_id: incident.clone(),
        backend_id: "backend".into(),
        model_id: "model".into(),
        prompt_schema_version: "1".into(),
    };
    let RunStarted { run_id, .. } = f.investigate(&token, start.clone()) else {
        panic!("run failed")
    };
    assert!(matches!(f.investigate(&token,start),RunStarted {run_id: retry,..} if retry == run_id));

    let expired = f.mint(PrincipalRole::Observer, &incident);
    let db = f.db();
    db.execute("UPDATE capability_tokens SET capability_json=json_set(capability_json,'$.expires_at','2000-01-01T00:00:00Z') WHERE token_hash=?1",
        [defsec_protocol::canonical::sha256_hex(expired.as_bytes())]).unwrap();
    assert!(matches!(
        f.investigate(&expired, ListHosts { limit: None, tag: None }),
        Error { .. }
    ));
    let observer = f.mint(PrincipalRole::Observer, &incident);
    assert!(matches!(
        f.investigate(&observer, GetIncidentContext {incident_id:incident.clone()}),
        InvestigationResponse::IncidentContext {recent_observations,..}
        if recent_observations.iter().any(|item| item.observation_id == evidence)
    ));
    assert!(matches!(
        f.investigate(
            &observer,
            GetIncidentContext {
                incident_id: foreign_incident.clone()
            }
        ),
        Error { .. }
    ));
    assert!(matches!(
        f.investigate(&observer, ListActiveIncidents {host_id:None,limit:None}),
        InvestigationResponse::Incidents {incidents} if incidents.len() == 1 && incidents[0].incident_id == incident
    ));
    assert!(matches!(
        f.investigate(&observer, ListCollectorCapabilities {host_id:"edge".into()}),
        InvestigationResponse::Capabilities {capabilities} if capabilities.len() == 1 && capabilities[0].collector_type == CollectorType::SystemdUnitState
    ));
    assert!(matches!(
        f.investigate(&observer, GetHostBaselineSummary {host_id:"edge".into()}),
        InvestigationResponse::BaselineSummary {baselines,..} if baselines.len() == 1
    ));

    let mut ephemeral = watch("edge");
    ephemeral.id = "follow-up".into();
    ephemeral.class = WatchClass::Ephemeral;
    ephemeral.incident_id = Some(incident.clone());
    ephemeral.collector = CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
        unit: "nginx.service".into(),
        hash_unit_files: false,
    });
    ephemeral.trigger = TriggerPredicate::FieldChanged {
        compare_against: CompareTarget::LastObserved,
        fields: vec!["active_state".into()],
    };
    ephemeral.lifecycle.expires_at = Some(Utc::now() + Duration::minutes(15));
    ephemeral.lifecycle.max_runs = Some(20);
    let propose = |id: &str, spec| ProposeEphemeralWatch {
        run_id: run_id.clone(),
        idempotency_key: id.into(),
        spec,
        rationale: "inspect related service state".into(),
    };
    assert!(matches!(
        f.investigate(&observer, propose("observer", ephemeral.clone())),
        Error { .. }
    ));
    let mut other_host = ephemeral.clone();
    other_host.host_id = "foreign".into();
    let mut other_incident = ephemeral.clone();
    other_incident.incident_id = Some(foreign_incident.clone());
    for (id, spec, rule) in [
        ("baseline", watch("edge"), "baseline.protected"),
        ("host", other_host, "scope.host_denied"),
        ("incident", other_incident, "scope.incident_mismatch"),
    ] {
        assert!(
            matches!(f.investigate(&token,propose(id,spec)),ProposalEvaluated {decision,watch_id:None,..} if !decision.allowed && decision.rule_id == rule)
        );
    }

    let request = propose("valid", ephemeral.clone());
    let accepted = f.investigate(&token, request.clone());
    assert!(
        matches!(&accepted,ProposalEvaluated {decision,watch_id:Some(id),bundle_version:Some(2)} if decision.allowed && id == "follow-up")
    );
    assert_eq!(accepted, f.investigate(&token, request));
    ephemeral.id = "equivalent".into();
    assert!(matches!(
        f.investigate(&token, propose("valid", ephemeral.clone())),
        Error { .. }
    ));
    assert!(
        matches!(f.investigate(&token,propose("equivalent",ephemeral)),ProposalEvaluated {decision,..} if decision.rule_id == "dedup.equivalent_active_watch")
    );
    assert_eq!(count(&db, "watch_proposals"), 5);

    let record = |id| RecordHypothesisOrFinding {
        run_id: run_id.clone(),
        incident_id: incident.clone(),
        kind: FindingKind::Hypothesis,
        severity: Severity::Medium,
        summary: "Related service changed state".into(),
        uncertainty: "cause unknown".into(),
        evidence_observation_ids: vec![id],
        escalation_requested: false,
    };
    for id in [-1, foreign_evidence] {
        assert!(matches!(f.investigate(&token, record(id)), Error { .. }));
    }
    assert!(matches!(
        f.investigate(&token, record(evidence)),
        FindingRecorded {
            verified_evidence_count: 1,
            ..
        }
    ));
    assert_eq!(count(&db, "findings"), 1);
    assert_eq!(count(&db, "finding_evidence"), 1);

    assert!(matches!(
        f.service.handle_admin_request(AdminRequest::CloseIncident {
            incident_id: incident,
            actor: "operator".into(),
            resolution: "explained".into()
        }),
        AdminResponse::IncidentClosed {
            retired_ephemeral_watches: 1,
            ..
        }
    ));
    assert!(
        matches!(f.investigate(&observer,ListActiveWatches {host_id:"edge".into()}),Watches {watches} if watches.len()==1)
    );
    assert!(matches!(
        f.investigate(
            &token,
            ListActiveWatches {
                host_id: "edge".into()
            }
        ),
        Error { .. }
    ));
    assert_eq!(
        db.query_row(
            "SELECT desired_bundle_version FROM hosts WHERE host_id='edge'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        3
    );
    assert!(matches!(
        f.service
            .handle_admin_request(AdminRequest::VerifyAuditChain),
        AdminResponse::AuditChainStatus { valid: true, .. }
    ));
}

#[test]
fn audit_detects_row_tampering_and_signing_key_survives_restart() {
    let f = Fixture::new();
    let key = f.enroll("edge");
    assert_eq!(
        fs::metadata(f.dir.join("control-signing-key.hex"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let reopened = ControlService::open(&f.dir, "key", 3).unwrap();
    assert!(
        matches!(reopened.handle_admin_request(enroll("edge")),AdminResponse::HostEnrolled {control_public_key_hex,..} if control_public_key_hex == key.1)
    );
    assert!(matches!(
        f.service
            .handle_admin_request(AdminRequest::VerifyAuditChain),
        AdminResponse::AuditChainStatus {
            valid: true,
            entries_checked: 1,
            ..
        }
    ));
    f.db().execute("UPDATE audit_outbox SET entry_json=json_set(entry_json,'$.actor','impostor') WHERE seq_no=1",[]).unwrap();
    assert!(matches!(
        reopened.handle_admin_request(AdminRequest::VerifyAuditChain),
        AdminResponse::AuditChainStatus {
            valid: false,
            entries_checked: 1,
            ..
        }
    ));
}

async fn receive<T: serde::de::DeserializeOwned>(socket: &mut UnixStream) -> T {
    timeout(StdDuration::from_secs(3), read_frame(socket))
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn unix_roundtrip_with_live_bundle_and_durable_ack() {
    let f = Fixture::new();
    let admin_path = f.dir.join("admin.sock");
    let agent_path = f.dir.join("agent.sock");
    let investigate_path = f.dir.join("investigate.sock");
    let policy = SocketPolicy::default();
    let admin = tokio::spawn(
        UnixServer::bind(&admin_path, policy.clone())
            .unwrap()
            .serve_admin(f.service.clone()),
    );
    let agent = tokio::spawn(
        UnixServer::bind(&agent_path, policy.clone())
            .unwrap()
            .serve_agent(f.service.clone()),
    );
    let investigate = tokio::spawn(
        UnixServer::bind(&investigate_path, policy)
            .unwrap()
            .serve_investigation(f.service.clone()),
    );
    for path in [&admin_path, &agent_path, &investigate_path] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut operator = UnixStream::connect(admin_path).await.unwrap();
    write_frame(&mut operator, &enroll("edge")).await.unwrap();
    let AdminResponse::HostEnrolled {
        control_signing_key_id,
        control_public_key_hex,
        ..
    } = receive(&mut operator).await
    else {
        panic!("enroll failed")
    };
    let mut edge = UnixStream::connect(agent_path).await.unwrap();
    write_frame(&mut edge, &register("edge")).await.unwrap();
    assert!(matches!(
        receive::<ControlToAgent>(&mut edge).await,
        ControlToAgent::RegisterAck { accepted: true, .. }
    ));
    assert!(matches!(
        receive::<ControlToAgent>(&mut edge).await,
        ControlToAgent::RequestReconciliation { .. }
    ));
    write_frame(&mut operator, &apply(watch("edge")))
        .await
        .unwrap();
    assert!(matches!(
        receive::<AdminResponse>(&mut operator).await,
        AdminResponse::WatchApplied {
            bundle_version: 1,
            ..
        }
    ));
    let ControlToAgent::SyncWatchBundle { envelope } = receive(&mut edge).await else {
        panic!("bundle was not pushed")
    };
    let mut keys = VerifyingKeyStore::new();
    keys.insert_public_hex(control_signing_key_id, &control_public_key_hex)
        .unwrap();
    let (bundle, _): (WatchBundlePayload, String) = keys
        .verify_and_decode(DOMAIN_WATCH_BUNDLE_V1, &envelope)
        .unwrap();
    assert_eq!(bundle.target_host_id, "edge");
    assert_eq!(bundle.policy_version, 3);
    write_frame(
        &mut edge,
        &AgentToControl::BundleAck {
            host_id: "edge".into(),
            bundle_id: bundle.bundle_id,
            bundle_version: bundle.bundle_version,
            payload_digest: envelope.payload_sha256_hex(),
            status: BundleAckStatus::Accepted,
            reason: None,
            acked_at: Utc::now(),
        },
    )
    .await
    .unwrap();
    write_frame(&mut edge, &push(observation("edge", 1, "active")))
        .await
        .unwrap();
    assert!(matches!(
        receive::<ControlToAgent>(&mut edge).await,
        ControlToAgent::ObservationAck {
            acked_seq_no: 1,
            ..
        }
    ));
    assert_eq!(count(&f.db(), "observations"), 1);
    write_frame(
        &mut operator,
        &AdminRequest::MintCapabilityToken {
            may_spawn_runs: false,
            principal_id: "observer".into(),
            role: PrincipalRole::Observer,
            allowed_hosts: vec!["edge".into()],
            allowed_collectors: vec![CollectorType::SystemdUnitState],
            incident_id: None,
            ttl_seconds: 75,
        },
    )
    .await
    .unwrap();
    let AdminResponse::TokenMinted { token, .. } = receive(&mut operator).await else {
        panic!("token was not minted")
    };
    let mut client = UnixStream::connect(investigate_path).await.unwrap();
    write_frame(
        &mut client,
        &InvestigationCall {
            request_id: "query".into(),
            capability_token: token,
            request: InvestigationRequest::QueryObservations {
                host_id: "edge".into(),
                watch_id: None,
                since: None,
                limit: None,
            },
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(receive::<InvestigationResponse>(&mut client).await,InvestigationResponse::Observations {observations} if observations.len()==1)
    );
    write_frame(&mut operator, &AdminRequest::VerifyAuditChain)
        .await
        .unwrap();
    assert!(matches!(
        receive::<AdminResponse>(&mut operator).await,
        AdminResponse::AuditChainStatus {
            valid: true,
            entries_checked: 5,
            ..
        }
    ));
    for task in [admin, agent, investigate] {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}

#[test]
fn heartbeat_health_deduplicates_runs_and_retains_last_success() {
    let f = Fixture::new();
    f.enroll("edge");
    let mut health_watch = watch("edge");
    health_watch.trigger = TriggerPredicate::CollectorStaleOrError {
        max_stale_seconds: 300,
        consecutive_errors: 2,
    };
    f.apply(health_watch);
    f.service.handle_agent_message(register("edge"));
    let first = f.put("edge", 1, "active");
    let mut failed = observation("edge", 2, "unknown");
    failed.status = ObservationStatus::Timeout;
    failed.payload = ObservationPayload::ErrorDetail {
        code: "timeout".into(),
        message: "collector timed out".into(),
    };
    failed.state_hash = canonical_sha256_hex(&failed.payload).unwrap();
    assert!(matches!(
        f.service.handle_agent_message(push(failed)).first(),
        Some(ControlToAgent::ObservationAck {
            acked_seq_no: 2,
            ..
        })
    ));

    let beat = |errors| AgentToControl::Heartbeat {
        host_id: "edge".into(),
        session_id: "session".into(),
        sent_at: Utc::now(),
        active_bundle_version: 1,
        last_seq_no: 2,
        dropped_events_total: 0,
        stale_desired_state: false,
        health: AgentResourceHealth {
            rss_bytes: Some(1024),
            spool_bytes_used: 0,
            spool_bytes_cap: 4096,
            active_watches: 1,
            dropped_events_total: 0,
        },
        watch_summaries: vec![WatchRunSummary {
            watch_id: "unit".into(),
            spec_version: 1,
            completed_runs: errors + 1,
            success_runs: 1,
            error_runs: errors,
            last_status: ObservationStatus::Timeout,
            last_run_at: Some(Utc::now()),
            last_success_at: Some(Utc::now()),
            sustained_count: 0,
            sustained_active: false,
            retired: false,
        }],
    };
    f.service.handle_agent_message(beat(1));
    f.service.handle_agent_message(beat(1));
    let db = f.db();
    assert_eq!(count(&db, "trigger_events"), 0);
    f.service.handle_agent_message(beat(2));
    assert_eq!(count(&db, "trigger_events"), 1);
    assert_eq!(count(&db, "wake_budget_state"), 1);
    assert_eq!(
        db.query_row("SELECT last_success_id FROM watch_state", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        first
    );
    assert_eq!(
        db.query_row("SELECT liveness_status FROM hosts", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "online"
    );
}

#[test]
fn wake_suppression_records_evidence_without_consuming_budget() {
    let f = Fixture::new();
    f.enroll("edge");
    let mut spec = watch("edge");
    spec.wake_policy.max_wakeups_per_hour = 0;
    f.apply(spec);
    f.service.handle_agent_message(register("edge"));
    let initial = f.put("edge", 1, "active");
    f.promote("edge", initial);
    f.put("edge", 2, "inactive");
    f.put("edge", 3, "inactive");
    let db = f.db();
    assert_eq!(count(&db, "incidents"), 1);
    assert_eq!(count(&db, "trigger_evidence"), 2);
    assert_eq!(count(&db, "wake_budget_state"), 0);
    assert_eq!(
        db.query_row("SELECT status FROM trigger_events", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "suppressed"
    );
}
