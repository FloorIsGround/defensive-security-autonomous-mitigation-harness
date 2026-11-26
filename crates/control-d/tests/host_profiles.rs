use std::{fs, path::PathBuf, time::Duration};

use chrono::Utc;
use control_d::{
    ControlService, ledger,
    server::{SocketPolicy, UnixServer},
};
use defsec_protocol::{
    audit::AuditEventType,
    canonical::to_canonical_json_bytes,
    profile::{HostProfileSummary, MAX_EXPECTED_SERVICES, MAX_HOST_TAGS},
    rpc::*,
    watch::CollectorType,
    wire::{AgentToControl, ControlToAgent, WIRE_PROTOCOL_VERSION, read_frame, write_frame},
};
use rusqlite::Connection;
use serde_json::json;
use tokio::{net::UnixStream, time::timeout};
use uuid::Uuid;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let id = &Uuid::new_v4().simple().to_string()[..8];
        let tmp = std::env::temp_dir();
        let candidate = if tmp.as_os_str().len() <= 75 {
            tmp.join(format!("dh{id}"))
        } else {
            std::path::Path::new("/tmp").join(format!("dh{id}"))
        };
        let path = match fs::create_dir(&candidate) {
            Ok(()) => candidate,
            Err(_) => {
                let fallback = tmp.join(format!("dh{id}"));
                fs::create_dir(&fallback).unwrap();
                fallback
            }
        };
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn enroll(service: &ControlService, host_id: &str) {
    assert!(matches!(
        service.handle_admin_request(AdminRequest::EnrollHost {
            host_id: host_id.into(),
            agent_public_key_hex: None,
        }),
        AdminResponse::HostEnrolled { .. }
    ));
}

fn register(service: &ControlService, host_id: &str, host_profile: Option<HostProfileSummary>) {
    register_version(service, host_id, "test", host_profile);
}

fn register_version(
    service: &ControlService,
    host_id: &str,
    version: &str,
    host_profile: Option<HostProfileSummary>,
) {
    let replies = service.handle_agent_message(AgentToControl::Register {
        protocol_version: WIRE_PROTOCOL_VERSION,
        host_id: host_id.into(),
        agent_version: version.into(),
        boot_id: "boot".into(),
        session_id: "session".into(),
        active_bundle_version: 0,
        active_bundle_digest: None,
        sent_at: Utc::now(),
        host_profile,
    });
    assert!(
        matches!(
            replies.first(),
            Some(ControlToAgent::RegisterAck { accepted: true, .. })
        ),
        "{replies:?}"
    );
}

fn hosts(service: &ControlService, tag: Option<&str>) -> Vec<HostSummary> {
    let AdminResponse::Hosts { hosts } = service.handle_admin_request(AdminRequest::ListHosts {
        tag: tag.map(str::to_owned),
    }) else {
        panic!("list_hosts failed");
    };
    hosts
}

fn profile(collectors: Vec<CollectorType>) -> HostProfileSummary {
    HostProfileSummary {
        host_tags: vec!["prod".into(), "region:west".into()],
        expected_services: vec!["ssh.service".into()],
        enabled_collectors: collectors,
    }
}

#[test]
fn migration_from_v5_preserves_rows_and_adds_nullable_profile_columns() {
    let dir = TempDir::new();
    let path = dir.0.join("ledger.sqlite3");
    {
        let db = Connection::open(&path).unwrap();
        for sql in [
            include_str!("../src/schema.sql"),
            include_str!("../src/schema_v2.sql"),
            include_str!("../src/schema_v3.sql"),
            include_str!("../src/schema_v4.sql"),
            include_str!("../src/schema_v5.sql"),
        ] {
            db.execute_batch(sql).unwrap();
        }
        db.pragma_update(None, "user_version", 5).unwrap();
        db.execute_batch(
            "INSERT INTO hosts (host_id, agent_version) VALUES ('legacy', 'edge-v1');
             INSERT INTO agent_sessions (host_id,session_id,boot_id,acked_seq_no)
             VALUES ('legacy','session','boot',42);",
        )
        .unwrap();
    }
    for _ in 0..2 {
        let db = ledger::open(&path).unwrap();
        let version: i32 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, control_d::ledger::SCHEMA_VERSION);
        let host: (String, Option<String>, Option<String>) = db
            .query_row(
                "SELECT agent_version, profile_json, profile_reported_at FROM hosts WHERE host_id='legacy'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(host, ("edge-v1".into(), None, None));
        let acked: u64 = db
            .query_row("SELECT acked_seq_no FROM agent_sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(acked, 42);
    }
}

#[test]
fn registers_validates_clears_and_audits_profiles() {
    let dir = TempDir::new();
    let service = ControlService::open(&dir.0, "test", 1).unwrap();
    enroll(&service, "edge");
    let full = profile(vec![
        CollectorType::SocketsListening,
        CollectorType::PackagesInventory,
    ]);
    let reduced = profile(vec![CollectorType::SocketsListening]);
    register(&service, "edge", Some(full.clone()));
    assert_eq!(hosts(&service, None)[0].host_profile.as_ref(), Some(&full));

    let db = ledger::open(dir.0.join("ledger.sqlite3")).unwrap();
    let read_report = || -> (Option<String>, String) {
        db.query_row(
            "SELECT profile_json, profile_reported_at FROM hosts WHERE host_id='edge'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };
    let (stored, reported_at) = read_report();
    assert_eq!(
        stored.unwrap().as_bytes(),
        to_canonical_json_bytes(&full).unwrap()
    );
    assert!(chrono::DateTime::parse_from_rfc3339(&reported_at).is_ok());
    db.execute(
        "UPDATE hosts SET profile_reported_at='stale' WHERE host_id='edge'",
        [],
    )
    .unwrap();
    register(&service, "edge", Some(full.clone()));
    assert_ne!(read_report().1, "stale");

    register(&service, "edge", Some(reduced.clone()));
    for invalid in [
        HostProfileSummary {
            host_tags: vec!["Prod".into()],
            ..reduced.clone()
        },
        HostProfileSummary {
            expected_services: vec!["invalid/name.service".into()],
            ..reduced.clone()
        },
        HostProfileSummary {
            host_tags: vec!["prod".into(); MAX_HOST_TAGS + 1],
            ..reduced.clone()
        },
        HostProfileSummary {
            expected_services: vec!["ssh.service".into(); MAX_EXPECTED_SERVICES + 1],
            ..reduced.clone()
        },
        profile(vec![CollectorType::SocketsListening; 2]),
    ] {
        register(&service, "edge", Some(invalid));
        let host = hosts(&service, None).pop().unwrap();
        assert_eq!(host.liveness_status, "online");
        assert_eq!(host.host_profile, None);
        assert_eq!(read_report().0, None);
    }
    register(&service, "edge", Some(reduced.clone()));
    register(&service, "edge", None);
    assert_eq!(read_report().0, None);

    let AdminResponse::AuditEntries { entries } =
        service.handle_admin_request(AdminRequest::ListAuditEntries { limit: None })
    else {
        panic!("audit entries unavailable");
    };
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.event_type == AuditEventType::HostProfileRejected)
            .count(),
        5
    );
    let changes: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == AuditEventType::HostProfileChanged)
        .map(|e| e.payload.clone())
        .collect();
    assert_eq!(
        changes,
        [
            json!({"host_id":"edge", "before":null, "after":full}),
            json!({"host_id":"edge", "before":full, "after":reduced}),
            json!({"host_id":"edge", "before":reduced, "after":null}),
            json!({"host_id":"edge", "before":null, "after":reduced}),
            json!({"host_id":"edge", "before":reduced, "after":null}),
        ]
    );
    assert!(matches!(
        service.handle_admin_request(AdminRequest::VerifyAuditChain),
        AdminResponse::AuditChainStatus { valid: true, .. }
    ));
}

#[tokio::test]
async fn malformed_profile_on_the_wire_does_not_reject_registration() {
    let dir = TempDir::new();
    let service = ControlService::open(&dir.0, "test", 1).unwrap();
    enroll(&service, "edge");
    register(
        &service,
        "edge",
        Some(profile(vec![CollectorType::SocketsListening])),
    );
    let path = dir.0.join("agent.sock");
    let server = UnixServer::bind(&path, SocketPolicy::default()).unwrap();
    let server_task = tokio::spawn(server.serve_agent(service.clone()));
    let mut client = UnixStream::connect(path).await.unwrap();
    write_frame(
        &mut client,
        &json!({
            "msg":"register", "protocol_version":WIRE_PROTOCOL_VERSION,
            "host_id":"edge", "agent_version":"test", "boot_id":"boot",
            "session_id":"session", "active_bundle_version":0, "sent_at":Utc::now(),
            "host_profile":{"host_tags":["prod"],"expected_services":[],"enabled_collectors":["unknown"]}
        }),
    )
    .await
    .unwrap();
    let reply = timeout(Duration::from_secs(3), read_frame(&mut client))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        reply,
        Some(ControlToAgent::RegisterAck { accepted: true, .. })
    ));
    assert_eq!(hosts(&service, None)[0].host_profile, None);
    let AdminResponse::AuditEntries { entries } =
        service.handle_admin_request(AdminRequest::ListAuditEntries { limit: None })
    else {
        panic!("audit entries unavailable");
    };
    assert!(entries.iter().any(|entry| {
        entry.event_type == AuditEventType::HostProfileRejected
            && entry.payload["reason"] == "malformed host profile summary"
    }));
    server_task.abort();
}

#[test]
fn tag_filter_is_exact_and_preserves_investigation_host_scope() {
    let dir = TempDir::new();
    let service = ControlService::open(&dir.0, "test", 1).unwrap();
    for host in ["a-outside", "edge", "untagged"] {
        enroll(&service, host);
    }
    for host in ["a-outside", "edge"] {
        register(&service, host, Some(profile(vec![])));
    }
    assert_eq!(hosts(&service, Some("prod")).len(), 2);
    assert!(hosts(&service, Some("pro")).is_empty());
    assert_eq!(hosts(&service, None).len(), 3);

    let AdminResponse::TokenMinted { token, .. } =
        service.handle_admin_request(AdminRequest::MintCapabilityToken {
            may_spawn_runs: false,
            principal_id: "reader".into(),
            role: PrincipalRole::Observer,
            allowed_hosts: vec!["edge".into(), "untagged".into()],
            allowed_purposes: None,
            allowed_collectors: vec![],
            incident_id: None,
            ttl_seconds: 60,
        })
    else {
        panic!("token mint failed");
    };
    let response = service.handle_investigation_call(InvestigationCall {
        request_id: "tagged".into(),
        capability_token: token,
        request: InvestigationRequest::ListHosts {
            limit: Some(1),
            tag: Some("region:west".into()),
        },
    });
    let InvestigationResponse::Hosts { hosts } = response else {
        panic!("{response:?}");
    };
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host_id, "edge");
    assert!(hosts[0].host_profile.is_some());
}

#[test]
fn reported_disabled_collectors_never_veto_admin_watch_admission() {
    let dir = TempDir::new();
    let service = ControlService::open(&dir.0, "test", 1).unwrap();
    enroll(&service, "edge");
    let apply = || {
        service.handle_admin_request(AdminRequest::ApplyBaselineWatch {
            spec: serde_json::from_value(json!({
                "id":"packages","version":1,"host_id":"edge","class":"baseline",
                "collector":{"type":"packages.inventory","parameters":{}},
                "schedule":{"interval_seconds":900,"timeout_seconds":10},
                "trigger":{"type":"set_diff","compare_against":"last_observed","set_field":"packages","identity_key":"package_key"},
                "wake_policy":{"cooldown_seconds":60,"max_wakeups_per_hour":4},
                "lifecycle":{"enabled":true}
            })).unwrap(),
            actor: "operator".into(),
            rationale: "onboarding".into(),
        })
    };
    // A compromised agent claiming every collector is disabled must not be able
    // to block an operator from deploying detection on it.
    register(&service, "edge", Some(profile(vec![])));
    assert!(matches!(
        apply(),
        AdminResponse::WatchApplied {
            bundle_version: 1,
            ..
        }
    ));
    register(&service, "edge", None);
    assert!(matches!(
        apply(),
        AdminResponse::WatchApplied {
            bundle_version: 2,
            ..
        }
    ));
}

#[test]
fn reordered_profiles_and_repeated_rejections_do_not_flood_the_audit_chain() {
    let dir = TempDir::new();
    let service = ControlService::open(&dir.0, "test", 1).unwrap();
    enroll(&service, "edge");
    let ordered = HostProfileSummary {
        host_tags: vec!["alpha".into(), "beta".into()],
        expected_services: vec!["nginx.service".into(), "ssh.service".into()],
        ..profile(vec![
            CollectorType::PackagesInventory,
            CollectorType::SocketsListening,
        ])
    };
    let mut reordered = ordered.clone();
    reordered.host_tags.reverse();
    reordered.expected_services.reverse();
    reordered.enabled_collectors.reverse();
    let invalid = HostProfileSummary {
        host_tags: vec!["Bad".into()],
        ..ordered.clone()
    };
    for report in [&ordered, &reordered, &ordered, &invalid, &invalid, &invalid] {
        register(&service, "edge", Some(report.clone()));
    }
    let AdminResponse::AuditEntries { entries } =
        service.handle_admin_request(AdminRequest::ListAuditEntries { limit: None })
    else {
        panic!("audit entries unavailable");
    };
    let count = |kind| entries.iter().filter(|e| e.event_type == kind).count();
    // First report, then the transition to "no valid profile"; reordering is not drift.
    assert_eq!(count(AuditEventType::HostProfileChanged), 2);
    assert_eq!(count(AuditEventType::HostProfileRejected), 1);
    register(&service, "edge", Some(reordered.clone()));
    register(&service, "edge", Some(invalid));
    let AdminResponse::AuditEntries { entries } =
        service.handle_admin_request(AdminRequest::ListAuditEntries { limit: None })
    else {
        panic!("audit entries unavailable");
    };
    // A rejection after a valid report is new information and is audited again.
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.event_type == AuditEventType::HostProfileRejected)
            .count(),
        2
    );
}

#[test]
fn discovery_is_durable_scoped_and_uses_one_shot_evidence() {
    use defsec_protocol::{
        canonical::canonical_sha256_hex,
        observation::{ObservationPayload, ObservationRecord, ObservationStatus},
        watch::{HOST_DISCOVERY_AGENT_SUFFIX, WatchClass},
    };

    let dir = TempDir::new();
    let service = ControlService::open(&dir.0, "test", 1).unwrap();
    enroll(&service, "edge");
    enroll(&service, "edge");
    enroll(&service, "outside");
    let AdminResponse::TokenMinted { token, .. } =
        service.handle_admin_request(AdminRequest::MintCapabilityToken {
            may_spawn_runs: false,
            principal_id: "discovery".into(),
            role: PrincipalRole::Investigator,
            allowed_hosts: vec!["edge".into()],
            allowed_purposes: None,
            allowed_collectors: vec![CollectorType::SocketsListening],
            incident_id: None,
            ttl_seconds: 300,
        })
    else {
        panic!("token mint failed");
    };
    let call = |service: &ControlService, request| {
        service.handle_investigation_call(InvestigationCall {
            request_id: "discovery-test".into(),
            capability_token: token.clone(),
            request,
        })
    };
    let advance = || InvestigationRequest::AdvanceHostDiscovery {
        host_id: Some("edge".into()),
    };
    let assessment = |service: &ControlService, version| {
        let InvestigationResponse::HostAssessment {
            assessment: Some(value),
        } = call(
            service,
            InvestigationRequest::GetHostAssessment {
                host_id: "edge".into(),
                version,
            },
        )
        else {
            panic!("expected an assessment");
        };
        value
    };
    assert_eq!(assessment(&service, None).version, 1);
    assert!(matches!(
        call(
            &service,
            InvestigationRequest::AdvanceHostDiscovery {
                host_id: Some("outside".into())
            }
        ),
        InvestigationResponse::Error { .. }
    ));
    register(&service, "edge", None);
    assert!(matches!(
        call(&service, advance()),
        InvestigationResponse::HostDiscoveryAdvanced {
            bundle_version: None,
            ..
        }
    ));
    assert_eq!(
        assessment(&service, None).collectors[0].gap,
        Some(HostDiscoveryGap::AgentUnsupported)
    );

    register_version(
        &service,
        "edge",
        &format!("test{HOST_DISCOVERY_AGENT_SUFFIX}"),
        None,
    );
    assert!(matches!(
        call(
            &service,
            InvestigationRequest::AdvanceHostDiscovery { host_id: None }
        ),
        InvestigationResponse::HostDiscoveryAdvanced {
            bundle_version: None,
            ..
        }
    ));
    assert!(matches!(
        call(&service, advance()),
        InvestigationResponse::HostDiscoveryAdvanced {
            bundle_version: Some(_),
            ..
        }
    ));
    let InvestigationResponse::Watches { watches } = call(
        &service,
        InvestigationRequest::ListActiveWatches {
            host_id: "edge".into(),
        },
    ) else {
        panic!("expected active watches");
    };
    assert_eq!(watches.len(), 1);
    let watch = &watches[0];
    assert_eq!(watch.class, WatchClass::Ephemeral);
    assert_eq!(watch.incident_id, None);
    assert_eq!(watch.lifecycle.max_runs, Some(1));
    drop(service);

    let service = ControlService::open(&dir.0, "test", 1).unwrap();
    assert!(matches!(
        call(&service, advance()),
        InvestigationResponse::HostDiscoveryAdvanced {
            bundle_version: None,
            ..
        }
    ));
    let data = json!({"count": 0, "partial_attribution": false, "sockets": []});
    let hash = canonical_sha256_hex(&data).unwrap();
    let observation = ObservationRecord {
        host_id: "edge".into(),
        session_id: "session".into(),
        seq_no: 1,
        watch_id: watch.id.clone(),
        spec_version: watch.version,
        collector_type: CollectorType::SocketsListening,
        observed_at: Utc::now(),
        status: ObservationStatus::Partial,
        state_hash: hash.clone(),
        payload: ObservationPayload::Snapshot { data },
        is_reconciliation: true,
        sustained_count: None,
        sustained_active: None,
        partial_reasons: vec!["limited visibility".into()],
    };
    service.handle_agent_message(AgentToControl::PushObservationDelta { observation });
    call(&service, advance());
    let latest = assessment(&service, None);
    assert_eq!(latest.collectors.len(), 1);
    assert_eq!(
        latest.collectors[0].gap,
        Some(HostDiscoveryGap::IncompleteSample)
    );
    let evidence = latest.collectors[0].evidence.as_ref().unwrap();
    assert_eq!(evidence.state_hash, hash);
    assert_eq!(evidence.status, ObservationStatus::Partial);
    assert_eq!(
        assessment(&service, Some(1)).collectors[0].gap,
        Some(HostDiscoveryGap::AwaitingAgent)
    );
    call(&service, advance());
    assert_eq!(assessment(&service, None), latest);
}
