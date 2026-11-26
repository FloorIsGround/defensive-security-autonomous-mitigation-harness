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
        let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let tmp = std::env::temp_dir();
        let candidate = if tmp.as_os_str().len() <= 75 {
            tmp.join(format!("dm{id}"))
        } else {
            std::path::Path::new("/tmp").join(format!("dm{id}"))
        };
        let dir = match std::fs::create_dir(&candidate) {
            Ok(()) => candidate,
            Err(_) => {
                let fallback = tmp.join(format!("dm{id}"));
                std::fs::create_dir(&fallback).unwrap();
                fallback
            }
        };
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
                allowed_purposes: None,
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
            allowed_purposes: None,
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

#[test]
fn scoped_journal_batch_unblocks_socket_truncation_and_contiguous_ack() {
    use agent_d::collectors::journal::parse_journalctl_json;

    let f = Fixture::new();
    f.setup_host("edge");
    let mut journal = watch("edge");
    journal.id = "journal".into();
    journal.collector = CollectorSpec::JournalUnitEvents(JournalUnitEventsParams {
        unit: "ssh.service".into(),
        min_priority: Some(6),
        max_events_per_batch: None,
        max_message_bytes: None,
    });
    journal.trigger = TriggerPredicate::CollectorStaleOrError {
        max_stale_seconds: 300,
        consecutive_errors: 2,
    };
    f.apply(journal.clone());
    let mut sockets = journal;
    sockets.id = "sockets".into();
    sockets.collector = CollectorSpec::SocketsListening(SocketsListeningParams {
        include_tcp: true,
        include_udp: true,
        include_ipv6: true,
        resolve_process: false,
    });
    f.apply(sockets);
    f.put("edge", 1, "active");

    let stdout = br#"{"__CURSOR":"c1","_SYSTEMD_UNIT":"init.scope","UNIT":"ssh.service","PRIORITY":"6","MESSAGE":"Starting SSH"}
{"__CURSOR":"c2","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"6","MESSAGE":"Listening"}
{"__CURSOR":"c3","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"6","MESSAGE":"Ready"}
{"__CURSOR":"c4","_SYSTEMD_UNIT":"init.scope","UNIT":"ssh.service","PRIORITY":"6","MESSAGE":"Started SSH"}
{"__CURSOR":"c5","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"6"}
{"__CURSOR":"c6","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"6"}
{"__CURSOR":"c7","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"6"}
{"__CURSOR":"c8","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"6"}
{"__CURSOR":"c9","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"6"}
{"__CURSOR":"c10","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"6"}
{"__CURSOR":"c11","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"6"}"#;
    let events = parse_journalctl_json(stdout, "ssh.service");
    assert_eq!(events.len(), 11);
    let batch = |events: Vec<_>| {
        let mut record = observation("edge", 2, "active");
        record.watch_id = "journal".into();
        record.collector_type = CollectorType::JournalUnitEvents;
        record.state_hash = canonical_sha256_hex(&events).unwrap();
        record.payload = ObservationPayload::StreamBatch {
            events,
            cursor_before: None,
            cursor_after: Some("c11".into()),
            gap_detected: false,
        };
        record
    };

    let mut legacy = events.clone();
    legacy[0].unit = "init.scope".into();
    legacy[3].unit = "init.scope".into();
    let mut truncated = observation("edge", 4, "active");
    truncated.watch_id = "sockets".into();
    truncated.collector_type = CollectorType::SocketsListening;
    truncated.status = ObservationStatus::TruncatedRejected;
    truncated.payload = ObservationPayload::ErrorDetail {
        code: "socket_inventory_too_large".into(),
        message: "4119 sockets exceeded the 4096 socket cap".into(),
    };
    truncated.state_hash = canonical_sha256_hex(&truncated.payload).unwrap();

    let send = |record| f.service.handle_agent_message(push(record));
    let ack = |record, seq| {
        let replies = send(record);
        assert!(
            matches!(
                replies.as_slice(),
                [ControlToAgent::ObservationAck { acked_seq_no, .. }] if *acked_seq_no == seq
            ),
            "{replies:?}"
        );
    };
    assert!(matches!(
        send(batch(legacy)).as_slice(),
        [ControlToAgent::RequestReconciliation { reason, .. }]
            if reason == "stream evidence violates collector bounds"
    ));
    let mut checkpoint = observation("edge", 3, "active");
    checkpoint.is_reconciliation = true;
    ack(checkpoint, 1);
    assert!(matches!(
        send(truncated.clone()).as_slice(),
        [ControlToAgent::RequestReconciliation { reason, .. }]
            if reason == "observation sequence gap"
    ));

    let corrected = batch(events);
    ack(corrected.clone(), 3);
    ack(truncated.clone(), 4);
    ack(corrected, 4);
    ack(truncated.clone(), 4);
    let db = f.db();
    assert_eq!(count(&db, "observations"), 4);
    let saved: String = db.query_row(
        "SELECT record_json FROM observations WHERE host_id='edge' AND seq_no=4 AND sample_json IS NULL",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(
        serde_json::from_str::<ObservationRecord>(&saved).unwrap(),
        truncated
    );
}

#[test]
fn monitoring_grant_revisions_and_corroborated_trust() {
    let f = Fixture::new();
    f.setup_host("edge");
    let discovery = f.put("edge", 1, "active");
    f.promote("edge", discovery);
    f.setup_host("foreign");
    let AdminResponse::TokenMinted { token, .. } =
        f.service
            .handle_admin_request(AdminRequest::MintCapabilityToken {
                may_spawn_runs: false,
                principal_id: "monitor".into(),
                role: PrincipalRole::Investigator,
                allowed_hosts: vec!["edge".into()],
                allowed_purposes: Some(vec![CapabilityPurpose::Monitoring]),
                allowed_collectors: vec![CollectorType::SystemdUnitState],
                incident_id: None,
                ttl_seconds: 300,
            })
    else {
        panic!("token mint failed");
    };
    let mut spec = watch("edge");
    spec.id = "app".into();
    let CollectorSpec::SystemdUnitState(unit) = &mut spec.collector else {
        unreachable!()
    };
    unit.unit = "app.service".into();
    spec.trigger = TriggerPredicate::FieldChanged {
        compare_against: CompareTarget::LastObserved,
        fields: vec!["active_state".into(), "sub_state".into()],
    };
    let request = |change| InvestigationRequest::Monitoring {
        host_id: "edge".into(),
        watch_id: "app".into(),
        change,
    };
    let invoke = |change| {
        let response = f.investigate(&token, request(change));
        let InvestigationResponse::Monitoring { detail } = response else {
            panic!("{response:?}");
        };
        detail
    };
    let apply = |spec, expected_revision| MonitoringOperation::Apply {
        spec,
        expected_revision,
        purpose: "detect state changes".into(),
        expected_signal: "service state transition".into(),
        evidence: vec![discovery],
        review_at: Utc::now() + Duration::days(2),
    };
    assert_eq!(
        invoke(MonitoringOperation::Test { spec: spec.clone() })["allowed"],
        false
    );
    assert!(
        matches!(f.service.handle_admin_request(AdminRequest::SetMonitoringGrant {
        host_id: "edge".into(), principal_id: "monitor".into(), max_watches: 1, allow_promotion: true,
    }), AdminResponse::Monitoring { result } if result["allowed"] == true)
    );
    let mut registration = register("edge");
    let AgentToControl::Register { host_profile, .. } = &mut registration else {
        unreachable!()
    };
    *host_profile = Some(defsec_protocol::profile::HostProfileSummary {
        host_tags: vec![],
        expected_services: vec![],
        enabled_collectors: vec![CollectorType::SocketsListening],
    });
    assert!(matches!(
        f.service.handle_agent_message(registration).first(),
        Some(ControlToAgent::RegisterAck { accepted: true, .. })
    ));
    let disabled = invoke(apply(spec.clone(), 0));
    assert_eq!(disabled["rule_id"], "collector_disabled_by_host_profile");
    assert!(disabled.get("bundle_version").is_none());
    assert!(matches!(
        f.service.handle_agent_message(register("edge")).first(),
        Some(ControlToAgent::RegisterAck { accepted: true, .. })
    ));
    assert_eq!(
        invoke(MonitoringOperation::Test { spec: spec.clone() })["allowed"],
        true
    );
    assert!(
        matches!(f.investigate(&token, InvestigationRequest::Monitoring {
        host_id: "foreign".into(), watch_id: "unit".into(), change: MonitoringOperation::Inspect {},
    }), InvestigationResponse::Monitoring { detail } if detail["allowed"] == false)
    );
    let mut protected = watch("edge");
    protected.version = 2;
    protected.schedule.interval_seconds = 15;
    protected.trigger = spec.trigger.clone();
    assert!(matches!(
        f.investigate(&token, InvestigationRequest::Monitoring {
            host_id: "edge".into(),
            watch_id: protected.id.clone(),
            change: apply(protected, 0),
        }),
        InvestigationResponse::Monitoring { detail }
            if detail["allowed"] == false
                && detail["reason"] == "watch is outside the grant or operator-owned"
    ));
    assert_eq!(invoke(apply(spec.clone(), 0))["revision"], 1);

    let mut retired = spec.clone();
    retired.lifecycle.enabled = false;
    std::thread::scope(|scope| {
        let renew = scope.spawn(|| invoke(apply(spec.clone(), 1)));
        let retire = scope.spawn(|| invoke(apply(retired, 1)));
        assert_eq!(renew.join().unwrap()["revision"], 2);
        assert_eq!(retire.join().unwrap()["allowed"], false);
    });
    assert_eq!(invoke(apply(spec, 1))["allowed"], false);
    assert_eq!(invoke(MonitoringOperation::Inspect {})["revision"], 2);

    let submit = |seq, active_state, sub_state| {
        let mut record = observation("edge", seq, active_state);
        record.watch_id = "app".into();
        let data = json!({"unit":"app.service","active_state":active_state,"sub_state":sub_state});
        record.state_hash = canonical_sha256_hex(&data).unwrap();
        record.payload = ObservationPayload::Snapshot { data };
        assert!(
            matches!(f.service.handle_agent_message(push(record)).as_slice(),
            [ControlToAgent::ObservationAck { acked_seq_no, .. }] if *acked_seq_no == seq)
        );
        f.db()
            .query_row(
                "SELECT observation_id FROM observations WHERE seq_no=?1",
                [seq],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
    };
    let first = submit(2, "active", "running");
    std::thread::sleep(StdDuration::from_millis(2));
    let second = submit(3, "active", "running");
    let provisional = || MonitoringOperation::Provisional {
        observations: [first, second],
        rationale: "confirmed service state".into(),
    };
    let set_reconciliation = |id, flag| {
        f.db().execute(
            "UPDATE observations SET record_json=json_set(record_json,'$.is_reconciliation',json(?2))
             WHERE observation_id=?1",
            params![id, if flag { "true" } else { "false" }],
        ).unwrap();
    };
    for sample in [first, second] {
        set_reconciliation(sample, true);
        assert_eq!(invoke(provisional())["allowed"], false);
        set_reconciliation(sample, false);
    }
    let candidate = invoke(provisional())["candidate_id"].as_i64().unwrap();
    let promote = || MonitoringOperation::Promote {
        candidate_id: candidate,
        expected_baseline: None,
    };
    assert_eq!(invoke(promote())["allowed"], false);
    assert!(
        matches!(f.service.handle_admin_request(AdminRequest::CorroborateMonitoring {
        candidate_id: candidate, rationale: "operator verified approved service state".into(),
    }), AdminResponse::Monitoring { result } if result["allowed"] == true)
    );
    // Revalidate candidate provenance at promotion, including after a session rollover.
    set_reconciliation(second, true);
    assert_eq!(invoke(promote())["allowed"], false);
    set_reconciliation(second, false);
    f.db()
        .execute(
            "UPDATE hosts SET session_id='replacement' WHERE host_id='edge'",
            [],
        )
        .unwrap();
    assert_eq!(invoke(promote())["allowed"], false);
    f.db()
        .execute(
            "UPDATE hosts SET session_id='session' WHERE host_id='edge'",
            [],
        )
        .unwrap();

    let revision = invoke(promote())["baseline"].as_i64().unwrap();
    let approver: String = f
        .db()
        .query_row(
            "SELECT approver FROM baseline_revisions WHERE revision_id=?1",
            [revision],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(approver, "local-admin");
    let admin_audits: i64 = f.db().query_row(
        "SELECT COUNT(*) FROM audit_outbox WHERE json_extract(entry_json,'$.actor')='local-admin'
         AND json_extract(entry_json,'$.payload.intent.admin_op')='corroborate_monitoring'",
        [], |r| r.get(0),
    ).unwrap();
    assert_eq!(admin_audits, 1);
    assert_eq!(invoke(promote())["allowed"], false);
    submit(4, "inactive", "dead");
    f.put("edge", 5, "inactive");
    assert_eq!(count(&f.db(), "trigger_events"), 2);
    let third = submit(6, "active", "running");
    let fourth = submit(7, "active", "running");
    let conflicting = invoke(MonitoringOperation::Provisional {
        observations: [third, fourth],
        rationale: "another candidate during open drift".into(),
    })["candidate_id"]
        .as_i64()
        .unwrap();
    assert!(
        matches!(f.service.handle_admin_request(AdminRequest::CorroborateMonitoring {
        candidate_id: conflicting, rationale: "expected maintenance".into(),
    }), AdminResponse::Monitoring { result } if result["allowed"] == true)
    );
    assert_eq!(
        invoke(MonitoringOperation::Promote {
            candidate_id: conflicting,
            expected_baseline: Some(revision),
        })["allowed"],
        false
    );
    assert!(
        matches!(f.service.handle_admin_request(AdminRequest::RollbackMonitoring {
        host_id: "edge".into(), watch_id: "app".into(), expected_baseline: revision, rationale: "revert approved state".into(),
    }), AdminResponse::Monitoring { result } if result["allowed"] == true && result["baseline"].is_null())
    );
    f.put("edge", 8, "failed");
    assert_eq!(count(&f.db(), "baseline_revisions"), 2);
    let unrelated: i64 = f
        .db()
        .query_row(
            "SELECT count(*) FROM trigger_events WHERE watch_id='unit' AND host_id='edge'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unrelated, 2);
    assert!(matches!(
        f.service.handle_admin_request(AdminRequest::VerifyAuditChain),
        AdminResponse::AuditChainStatus { valid: true, .. }
    ));
    let decisions: i64 = f.db().query_row(
        "SELECT count(*) FROM audit_outbox WHERE json_extract(entry_json,'$.payload.decision.revision')=2",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(decisions, 2); // Renewal and inspection both recorded the winning revision.
}

#[test]
fn independent_service_observations_verify_receipts_and_recovery() {
    use defsec_protocol::{
        action::{ActionIntentStatus, ActionReceipt, ActionVerb},
        signing::{DOMAIN_ACTION_APPROVAL_V1, SigningKeyPair},
    };

    for (after, expected) in [
        ("inactive", "verified"),
        ("active", "contradicted"),
        ("missing", "indeterminate"),
        ("legacy", "indeterminate"),
    ] {
        let f = Fixture::new();
        let (incident, _) = f.incident("edge");
        f.enroll("foreign");
        let fixture_unit = "disposable-demo.service";
        let mut spec = watch("edge");
        spec.id = "verify-unit".into();
        let CollectorSpec::SystemdUnitState(ref mut params) = spec.collector else {
            unreachable!()
        };
        params.unit = fixture_unit.into();
        f.apply(spec);
        let sample = |seq, state: &str| {
            let mut o = observation("edge", seq, state);
            o.watch_id = "verify-unit".into();
            let data = json!({"unit":fixture_unit,"active_state":state});
            o.state_hash = canonical_sha256_hex(&data).unwrap();
            o.payload = ObservationPayload::Snapshot { data };
            o
        };
        let send = |o| {
            let replies = f.service.handle_agent_message(push(o));
            assert!(
                matches!(replies.first(), Some(ControlToAgent::ObservationAck { .. })),
                "{replies:?}"
            );
        };
        send(sample(3, "active"));
        let pre: i64 = f
            .db()
            .query_row("SELECT MAX(observation_id) FROM observations", [], |r| {
                r.get(0)
            })
            .unwrap();
        let token = f.mint(PrincipalRole::Investigator, &incident);
        let InvestigationResponse::RunStarted { run_id, .. } = f.investigate(
            &token,
            InvestigationRequest::StartInvestigationRun {
                incident_id: incident.clone(),
                backend_id: "fixture".into(),
                model_id: "fixture".into(),
                prompt_schema_version: "v1".into(),
            },
        ) else {
            panic!("start")
        };
        let propose = |key: &str| {
            f.investigate(
                &token,
                InvestigationRequest::ProposeAction {
                    run_id: run_id.clone(),
                    incident_id: incident.clone(),
                    idempotency_key: key.into(),
                    verb: ActionVerb::SystemdStopUnit {
                        unit: fixture_unit.into(),
                        ttl_seconds: Some(60),
                    },
                    evidence_observation_ids: vec![pre],
                    expected_effect: "Fixture service is inactive".into(),
                    blast_radius: "Disposable fixture unit".into(),
                    rollback_plan: "Restore the previously active fixture unit".into(),
                },
            )
        };
        let response = propose("first");
        let InvestigationResponse::ActionProposalEvaluated {
            intent_id: Some(intent_id),
            ..
        } = response
        else {
            panic!("{response:?}")
        };
        let details = || {
            let AdminResponse::ActionVerification { detail } =
                f.service
                    .handle_admin_request(AdminRequest::GetActionVerification {
                        intent_id: intent_id.clone(),
                    })
            else {
                panic!("get verification")
            };
            detail
        };
        assert_eq!(details()["precondition_observation_id"], pre);
        let AdminResponse::ActionIntentDetail { payload, .. } =
            f.service
                .handle_admin_request(AdminRequest::GetActionIntent {
                    intent_id: intent_id.clone(),
                })
        else {
            panic!("intent")
        };
        let operator = SigningKeyPair::generate("fixture-operator");
        f.service
            .register_operator_key("fixture-operator", &operator.public_hex())
            .unwrap();
        let approval = f.service.handle_admin_request(AdminRequest::ApproveAction {
            intent_id: intent_id.clone(),
            approver: "test".into(),
            operator_approval: operator
                .sign_payload(DOMAIN_ACTION_APPROVAL_V1, &payload)
                .unwrap(),
        });
        assert!(
            matches!(approval, AdminResponse::ActionApproved { .. }),
            "{approval:?}"
        );
        let receipt = ActionReceipt {
            intent_id: intent_id.clone(),
            host_id: "edge".into(),
            nonce: payload.nonce,
            status: ActionIntentStatus::Executed,
            dry_run: false,
            executed_at: Utc::now(),
            expires_at: Some(payload.expires_at),
            rollback_handle: None,
            verification_passed: true,
            detail: "Fixture executor reported success".into(),
        };
        let record = |r: ActionReceipt| {
            assert!(matches!(
                f.service
                    .handle_admin_request(AdminRequest::RecordActionReceipt { receipt: r }),
                AdminResponse::ActionReceiptAck { .. }
            ));
        };
        let delayed = sample(4, "inactive");
        record(receipt.clone());
        record(receipt.clone());
        if after == "legacy" {
            // A pre-verification receipt has a backfilled plan, but no postcondition check.
            f.db()
                .execute(
                    "DELETE FROM action_effect_checks WHERE intent_id=?1",
                    [&intent_id],
                )
                .unwrap();
            f.db()
                .execute(
                    "UPDATE action_verification_plans SET precondition_id=NULL WHERE intent_id=?1",
                    [&intent_id],
                )
                .unwrap();
            // Let the independent action cooldown elapse without aging the current sample.
            f.db().execute("UPDATE action_intents SET updated_at='2000-01-01T00:00:00Z' WHERE intent_id=?1", [&intent_id]).unwrap();
            let checks = details();
            let check = &checks["receipt_checks"][0];
            assert_eq!(check["result"], expected);
            assert!(matches!(propose("legacy-retry"),
                InvestigationResponse::ActionProposalEvaluated { intent_id: None, decision, .. }
                if decision.rule_id == "action.awaiting_reconciliation"));
            assert!(matches!(
                f.service
                    .handle_admin_request(AdminRequest::ReconcileActionOutcome {
                        intent_id: intent_id.clone(),
                        expected_receipt_id: check["receipt_id"].as_i64(),
                        evidence_ref: "operator check 123".into(),
                        rationale: "confirmed service recovery".into(),
                    }),
                AdminResponse::ActionVerification { .. }
            ));
            let retry = propose("reconciled-retry");
            assert!(
                matches!(
                    retry,
                    InvestigationResponse::ActionProposalEvaluated {
                        intent_id: Some(_),
                        ..
                    }
                ),
                "{retry:?}"
            );
            continue;
        }
        send(delayed);
        f.put("edge", 5, "active"); // Different watch on the same host.
        assert_eq!(
            details()["receipt_checks"][0]["result"],
            "awaiting_evidence"
        );
        let retry = propose("another-key");
        assert!(
            matches!(
                retry,
                InvestigationResponse::ActionProposalEvaluated {
                    intent_id: None,
                    ..
                }
            ),
            "{retry:?}"
        );
        if after == "missing" {
            let mut timeout = sample(6, "unknown");
            timeout.status = ObservationStatus::Timeout;
            timeout.payload = ObservationPayload::ErrorDetail {
                code: "timeout".into(), message: "fixture withheld a sample".into(),
            };
            timeout.state_hash = canonical_sha256_hex(&timeout.payload).unwrap();
            send(timeout);
            assert_eq!(details()["receipt_checks"][0]["result"], "awaiting_evidence");
            f.db().execute("UPDATE action_effect_checks SET deadline='2000-01-01T00:00:00Z' WHERE intent_id=?1",
                           [&intent_id]).unwrap();
            send(sample(7, "inactive"));
            let check = &details()["receipt_checks"][0];
            assert_eq!(check["result"], expected);
            assert!(check["observation_id"].is_null());
            continue;
        }
        let evidence = sample(6, after);
        send(evidence.clone());
        send(evidence);
        let detail = details();
        assert_eq!(detail["receipt_checks"].as_array().unwrap().len(), 1);
        assert_eq!(detail["concurrent_service_changes"][0]["watch_id"], "unit");
        let query=InvestigationRequest::GetActionVerification { intent_id:intent_id.clone() };
        let InvestigationResponse::ActionVerification{detail: scoped}=f.investigate(&token,query) else {panic!("scoped verification")};
        assert!(scoped.get("concurrent_service_changes").is_none());
        assert_eq!(scoped["receipt_checks"],detail["receipt_checks"]);
        assert_eq!(detail["receipt_checks"][0]["result"], expected);
        assert_eq!(
            detail["receipt_checks"][0]["state_hash"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        record(ActionReceipt {
            status: ActionIntentStatus::RolledBack,
            executed_at: Utc::now(),
            ..receipt
        });
        send(sample(7, "active"));
        assert_eq!(details()["receipt_checks"][1]["result"], "verified");
        assert!(matches!(
            f.service
                .handle_admin_request(AdminRequest::VerifyAuditChain),
            AdminResponse::AuditChainStatus { valid: true, .. }
        ));
    }
}

#[test]
fn new_collector_proposals_require_agent_support_and_profile_permission() {
    use defsec_protocol::profile::HostProfileSummary;

    let f = Fixture::new();
    let (incident, _) = f.incident("edge");
    let collectors = vec![
        CollectorType::SystemdUnitState,
        CollectorType::ConnectionsOutbound,
        CollectorType::PackagesInventory,
    ];
    let AdminResponse::TokenMinted { token, .. } =
        f.service
            .handle_admin_request(AdminRequest::MintCapabilityToken {
                principal_id: "investigator".into(),
                role: PrincipalRole::Investigator,
                allowed_hosts: vec!["edge".into()],
                allowed_collectors: collectors.clone(),
                allowed_purposes: Some(vec![CapabilityPurpose::ReactiveIncident]),
                incident_id: Some(incident.clone()),
                ttl_seconds: 300,
                may_spawn_runs: false,
            })
    else {
        panic!("mint failed")
    };
    let InvestigationResponse::RunStarted { run_id, .. } = f.investigate(
        &token,
        InvestigationRequest::StartInvestigationRun {
            incident_id: incident.clone(),
            backend_id: "test".into(),
            model_id: "test".into(),
            prompt_schema_version: "1".into(),
        },
    ) else {
        panic!("start failed")
    };

    let report_profile = |version: &str, enabled_collectors| {
        let mut request = register("edge");
        let AgentToControl::Register {
            agent_version,
            host_profile,
            ..
        } = &mut request
        else {
            unreachable!()
        };
        *agent_version = version.into();
        *host_profile = Some(HostProfileSummary {
            enabled_collectors,
            host_tags: vec![],
            expected_services: vec![],
        });
        assert!(matches!(
            f.service.handle_agent_message(request).first(),
            Some(ControlToAgent::RegisterAck { accepted: true, .. })
        ));
    };
    let propose = |spec, key: String| {
        f.investigate(
            &token,
            InvestigationRequest::ProposeEphemeralWatch {
                run_id: run_id.clone(),
                spec,
                idempotency_key: key,
                rationale: "bounded incident follow-up".into(),
            },
        )
    };
    let specs = [
        (
            "outbound",
            CollectorSpec::ConnectionsOutbound(ConnectionsOutboundParams {
                include_tcp: true,
                include_udp: false,
                include_ipv6: true,
                resolve_process: true,
                exclude_loopback: true,
                max_flows: Some(64),
            }),
        ),
        (
            "packages",
            CollectorSpec::PackagesInventory(PackagesInventoryParams {
                max_packages: Some(64),
            }),
        ),
    ];
    for (id, collector) in specs {
        let mut spec = watch("edge");
        spec.id = id.into();
        spec.class = WatchClass::Ephemeral;
        spec.incident_id = Some(incident.clone());
        spec.lifecycle.expires_at = Some(Utc::now() + Duration::minutes(5));
        spec.lifecycle.max_runs = Some(5);
        spec.collector = collector;
        spec.trigger = TriggerPredicate::FieldChanged {
            compare_against: CompareTarget::LastObserved,
            fields: vec!["count".into()],
        };

        report_profile("0.1.0", collectors.clone());
        let old = propose(spec.clone(), format!("old-{id}"));
        assert!(
            matches!(&old, InvestigationResponse::ProposalEvaluated { decision, bundle_version: None, .. }
            if decision.rule_id == "bundle_incompatible"),
            "{old:?}"
        );

        // Leave existing active coverage enabled and disable just the proposed collector.
        report_profile(
            "test+host-discovery-v1",
            collectors
                .iter()
                .copied()
                .filter(|ty| *ty != spec.collector.collector_type())
                .collect(),
        );
        let disabled = propose(spec.clone(), format!("disabled-{id}"));
        assert!(
            matches!(&disabled, InvestigationResponse::ProposalEvaluated { decision, bundle_version: None, .. }
            if decision.rule_id == "collector_disabled_by_host_profile"),
            "{disabled:?}"
        );

        report_profile("test+host-discovery-v1", collectors.clone());
        let supported = propose(spec, format!("supported-{id}"));
        assert!(
            matches!(&supported, InvestigationResponse::ProposalEvaluated { decision, bundle_version: Some(_), .. }
            if decision.allowed),
            "{supported:?}"
        );
    }
}
