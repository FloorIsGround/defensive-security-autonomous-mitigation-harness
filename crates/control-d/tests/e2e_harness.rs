//! Milestone 4 End-to-End Deterministic Simulation & Adversarial Suite
//!
//! Wires real `control-d` (`ControlService` + `UnixServer`) directly to real
//! `agent-d` (`AgentEngine<FakeHostCollectors>` and `AgentEngine<RealLinuxCollectors>`)
//! to validate Section 9 scenarios end-to-end across both trust domains.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use agent_d::collectors::{FakeHostCollectors, FakeHostState, RealLinuxCollectors};
use agent_d::engine::AgentEngine;
use agent_d::spool::DurabilityProfile;
use chrono::{DateTime, Duration, Utc};
use control_d::ControlService;
use control_d::server::{SocketPolicy, UnixServer};
use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::observation::{
    ListeningSocketEntry, SocketsListeningSnapshot, SystemdUnitSnapshot,
};
use defsec_protocol::rpc::*;
use defsec_protocol::signing::{DOMAIN_WATCH_BUNDLE_V1, SigningKeyPair, VerifyingKeyStore};
use defsec_protocol::watch::*;
use defsec_protocol::wire::*;
use tokio::net::UnixStream;
use tokio::time::timeout;

struct E2eHarness {
    _root: PathBuf,
    control: ControlService,
    agent_dir: PathBuf,
    trust_store: VerifyingKeyStore,
    host_id: String,
    fake: Arc<FakeHostCollectors>,
    agent: AgentEngine<FakeHostCollectors>,
}

impl E2eHarness {
    fn new(host_id: &str, durability: DurabilityProfile) -> Self {
        let short = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let root = std::env::temp_dir().join(format!("e2e-{short}"));
        let control_dir = root.join("ctrl");
        let agent_dir = root.join("agent");
        let control = ControlService::open(&control_dir, "control-key-01", 1).unwrap();

        let AdminResponse::HostEnrolled {
            control_signing_key_id,
            control_public_key_hex,
            ..
        } = control.handle_admin_request(AdminRequest::EnrollHost {
            host_id: host_id.to_string(),
            agent_public_key_hex: None,
        })
        else {
            panic!("host enrollment failed");
        };

        let mut trust_store = VerifyingKeyStore::new();
        trust_store
            .insert_public_hex(&control_signing_key_id, &control_public_key_hex)
            .unwrap();

        let fake = Arc::new(FakeHostCollectors::new());
        let agent = AgentEngine::new(
            EdgeSafetyConfig::default(),
            host_id.to_string(),
            durability,
            agent_dir.clone(),
            trust_store.clone(),
            fake.clone(),
        )
        .unwrap();

        Self {
            _root: root,
            control,
            agent_dir,
            trust_store,
            host_id: host_id.to_string(),
            fake,
            agent,
        }
    }

    /// Pump a single agent->control->agent exchange cycle until quiescent.
    async fn exchange(&mut self, initial: Vec<AgentToControl>, now: DateTime<Utc>) {
        let mut outbound = initial;
        for _ in 0..16 {
            if outbound.is_empty() {
                break;
            }
            let mut next_outbound = Vec::new();
            for msg in outbound {
                let replies = self.control.handle_agent_message(msg);
                for reply in replies {
                    let followups = self.agent.handle_control(reply, now).await;
                    next_outbound.extend(followups);
                }
            }
            outbound = next_outbound;
        }
    }

    async fn register_and_sync(&mut self, now: DateTime<Utc>) {
        let reg = self.agent.make_register(now);
        self.exchange(vec![reg], now).await;
    }

    async fn tick_and_sync(&mut self, now: DateTime<Utc>) -> Vec<AgentToControl> {
        let emitted = self.agent.run_due_watches(now).await;
        self.exchange(emitted.clone(), now).await;
        emitted
    }

    fn restart_agent(&mut self, durability: DurabilityProfile) {
        self.agent = AgentEngine::new(
            EdgeSafetyConfig::default(),
            self.host_id.clone(),
            durability,
            self.agent_dir.clone(),
            self.trust_store.clone(),
            self.fake.clone(),
        )
        .unwrap();
    }

    fn mint_token(
        &self,
        principal: &str,
        role: PrincipalRole,
        hosts: Vec<String>,
        collectors: Vec<CollectorType>,
        incident_id: Option<String>,
        ttl_seconds: u64,
    ) -> String {
        let AdminResponse::TokenMinted { token, .. } =
            self.control
                .handle_admin_request(AdminRequest::MintCapabilityToken {
                    may_spawn_runs: false,
                    principal_id: principal.into(),
                    role,
                    allowed_hosts: hosts,
                    allowed_purposes: None,
                    allowed_collectors: collectors,
                    incident_id,
                    ttl_seconds,
                })
        else {
            panic!("mint token failed");
        };
        token
    }

    fn assert_audit_valid(&self) {
        let status = self
            .control
            .handle_admin_request(AdminRequest::VerifyAuditChain);
        match status {
            AdminResponse::AuditChainStatus {
                valid: true,
                entries_checked,
                ..
            } => assert!(entries_checked > 0),
            other => panic!("audit chain verification failed: {other:?}"),
        }
    }
}

fn socket_entry(port: u16, uid: u32, comm: &str) -> ListeningSocketEntry {
    ListeningSocketEntry {
        socket_key: format!("tcp:0.0.0.0:{port}:uid={uid}"),
        protocol: "tcp".into(),
        local_addr: "0.0.0.0".into(),
        local_port: port,
        uid,
        inode: 10_000 + u64::from(port),
        pid: Some(100 + u32::from(port)),
        pid_start_time_ticks: Some(500),
        comm: Some(comm.into()),
        systemd_unit: Some(format!("{comm}.service")),
    }
}

fn sockets_baseline_watch(host: &str) -> WatchSpec {
    WatchSpec {
        id: "base-sockets".into(),
        version: 1,
        host_id: host.into(),
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

/// Scenario 1 + 2:
/// - Benign baseline establishment & explicit promotion (no silent auto-promotion)
/// - Two-stage unexpected service change: new listening socket opens incident ->
///   scoped investigator inspects context -> proposes bounded ephemeral `systemd.unit_state` watch ->
///   signed bundle syncs to `agent-d` -> agent collects follow-up evidence ->
///   investigator records evidence-bound finding -> operator closes incident ->
///   ephemeral watch retired while baseline continues.
#[tokio::test]
async fn two_stage_unexpected_service_change_and_ephemeral_lifecycle() {
    let mut h = E2eHarness::new(
        "edge-vm-07",
        DurabilityProfile::Durable {
            max_disk_bytes: 1024 * 1024,
        },
    );
    let t0 = Utc::now();

    // Initial known-good socket inventory: sshd on :22.
    {
        let handle = h.fake.state_handle();
        let mut st = handle.lock().unwrap();
        st.sockets = SocketsListeningSnapshot {
            count: 1,
            partial_attribution: false,
            sockets: vec![socket_entry(22, 0, "sshd")],
        };
    }

    // Apply baseline watch & register agent.
    assert!(matches!(
        h.control
            .handle_admin_request(AdminRequest::ApplyBaselineWatch {
                spec: sockets_baseline_watch("edge-vm-07"),
                actor: "ops-admin".into(),
                rationale: "initial host baseline".into(),
            }),
        AdminResponse::WatchApplied {
            bundle_version: 1,
            ..
        }
    ));
    h.register_and_sync(t0).await;
    assert_eq!(h.agent.active_bundle_version(), 1);

    // Tick 1: initial observation establishes state; before promotion, no incident opened.
    let t1 = t0 + Duration::seconds(60);
    let emitted = h.tick_and_sync(t1).await;
    assert_eq!(emitted.len(), 1);
    assert!(h.agent.pending_observations().is_empty());

    // Fetch observation_id via observer token and explicitly promote baseline.
    let obs_token = h.mint_token(
        "observer-1",
        PrincipalRole::Observer,
        vec!["edge-vm-07".into()],
        vec![
            CollectorType::SocketsListening,
            CollectorType::SystemdUnitState,
        ],
        None,
        3600,
    );
    let InvestigationResponse::Observations { observations } =
        h.control.handle_investigation_call(InvestigationCall {
            request_id: "req-obs-1".into(),
            capability_token: obs_token.clone(),
            request: InvestigationRequest::QueryObservations {
                host_id: "edge-vm-07".into(),
                watch_id: Some("base-sockets".into()),
                since: None,
                limit: Some(10),
            },
        })
    else {
        panic!("expected observations");
    };
    assert_eq!(observations.len(), 1);
    let initial_obs_id = observations[0].observation_id;

    assert!(matches!(
        h.control
            .handle_admin_request(AdminRequest::PromoteBaseline {
                host_id: "edge-vm-07".into(),
                watch_id: "base-sockets".into(),
                observation_id: initial_obs_id,
                approver: "ops-admin".into(),
                rationale: "verified initial sshd baseline".into(),
                ticket_ref: Some("CHG-1001".into()),
            }),
        AdminResponse::BaselinePromoted { revision_id: 1, .. }
    ));

    // Stage 1 anomaly: unexpected listener on :4444 backed by custom-helper.service.
    {
        let handle = h.fake.state_handle();
        let mut st = handle.lock().unwrap();
        st.sockets = SocketsListeningSnapshot {
            count: 2,
            partial_attribution: false,
            sockets: vec![
                socket_entry(22, 0, "sshd"),
                socket_entry(4444, 1000, "custom-helper"),
            ],
        };
        st.systemd.insert(
            "custom-helper.service".into(),
            SystemdUnitSnapshot {
                unit: "custom-helper.service".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                unit_file_state: Some("enabled".into()),
                main_pid: Some(4544),
                main_pid_start_time_ticks: Some(900),
                exec_start_hash: Some("deadbeef".into()),
                unit_files: vec![],
            },
        );
    }

    let t2 = t1 + Duration::seconds(45);
    let emitted = h.tick_and_sync(t2).await;
    assert_eq!(emitted.len(), 1);

    // Confirm an open incident was created.
    let AdminResponse::Incidents { incidents } =
        h.control.handle_admin_request(AdminRequest::ListIncidents)
    else {
        panic!("expected incidents");
    };
    assert_eq!(incidents.len(), 1);
    let incident_id = incidents[0].incident_id.clone();

    // Investigator mints token, starts run, inspects context, and proposes ephemeral watch.
    let inv_token = h.mint_token(
        "reasoner-1",
        PrincipalRole::Investigator,
        vec!["edge-vm-07".into()],
        vec![
            CollectorType::SocketsListening,
            CollectorType::SystemdUnitState,
        ],
        Some(incident_id.clone()),
        3600,
    );
    let InvestigationResponse::RunStarted { run_id, .. } =
        h.control.handle_investigation_call(InvestigationCall {
            request_id: "req-run-1".into(),
            capability_token: inv_token.clone(),
            request: InvestigationRequest::StartInvestigationRun {
                incident_id: incident_id.clone(),
                backend_id: "direct-api".into(),
                model_id: "test-model".into(),
                prompt_schema_version: "v1".into(),
            },
        })
    else {
        panic!("expected run started");
    };

    let ephem_spec = WatchSpec {
        id: "ephem-custom-helper".into(),
        version: 1,
        host_id: "edge-vm-07".into(),
        class: WatchClass::Ephemeral,
        incident_id: Some(incident_id.clone()),
        collector: CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
            unit: "custom-helper.service".into(),
            hash_unit_files: true,
        }),
        schedule: WatchSchedule {
            interval_seconds: 30,
            timeout_seconds: 5,
        },
        trigger: TriggerPredicate::FieldChanged {
            compare_against: CompareTarget::LastObserved,
            fields: vec!["active_state".into(), "exec_start_hash".into()],
        },
        wake_policy: WakePolicy {
            cooldown_seconds: 120,
            max_wakeups_per_hour: 4,
        },
        lifecycle: WatchLifecycle {
            enabled: true,
            expires_at: Some(t2 + Duration::hours(2)),
            max_runs: Some(120),
        },
    };

    let InvestigationResponse::ProposalEvaluated {
        decision,
        watch_id,
        bundle_version,
    } = h.control.handle_investigation_call(InvestigationCall {
        request_id: "req-prop-1".into(),
        capability_token: inv_token.clone(),
        request: InvestigationRequest::ProposeEphemeralWatch {
            run_id: run_id.clone(),
            idempotency_key: "idem-custom-helper-1".into(),
            spec: ephem_spec,
            rationale: "Inspect unexpected custom-helper.service bound to port 4444".into(),
        },
    })
    else {
        panic!("expected proposal evaluated");
    };
    assert!(decision.allowed);
    assert_eq!(watch_id.as_deref(), Some("ephem-custom-helper"));
    assert_eq!(bundle_version, Some(2));

    // Heartbeat triggers signed bundle v2 delivery to agent-d; agent accepts and activates ephemeral watch.
    let t3 = t2 + Duration::seconds(10);
    let hb = h.agent.make_heartbeat(t3);
    h.exchange(vec![hb], t3).await;
    assert_eq!(h.agent.active_bundle_version(), 2);
    assert!(
        h.agent
            .watch_ids()
            .contains(&"ephem-custom-helper".to_string())
    );

    // Tick collects follow-up evidence from the ephemeral systemd watch.
    let t4 = t3 + Duration::seconds(60);
    h.tick_and_sync(t4).await;

    let InvestigationResponse::Observations {
        observations: unit_obs,
    } = h.control.handle_investigation_call(InvestigationCall {
        request_id: "req-obs-unit".into(),
        capability_token: inv_token.clone(),
        request: InvestigationRequest::QueryObservations {
            host_id: "edge-vm-07".into(),
            watch_id: Some("ephem-custom-helper".into()),
            since: None,
            limit: Some(10),
        },
    })
    else {
        panic!("expected unit observations");
    };
    assert_eq!(unit_obs.len(), 1);
    let unit_obs_id = unit_obs[0].observation_id;

    // Investigator records evidence-bound finding.
    let InvestigationResponse::FindingRecorded {
        verified_evidence_count,
        ..
    } = h.control.handle_investigation_call(InvestigationCall {
        request_id: "req-find-1".into(),
        capability_token: inv_token.clone(),
        request: InvestigationRequest::RecordHypothesisOrFinding {
            run_id,
            incident_id: incident_id.clone(),
            kind: FindingKind::VerifiedFinding,
            severity: Severity::High,
            summary: "Unexpected listener :4444 belongs to enabled unit custom-helper.service"
                .into(),
            uncertainty: "Package provenance not yet verified".into(),
            evidence_observation_ids: vec![unit_obs_id],
            escalation_requested: true,
        },
    })
    else {
        panic!("expected finding recorded");
    };
    assert_eq!(verified_evidence_count, 1);

    // Operator closes incident -> ephemeral watch retired & bundle v3 synced.
    assert!(matches!(
        h.control
            .handle_admin_request(AdminRequest::CloseIncident {
                incident_id,
                actor: "ops-admin".into(),
                resolution: "Investigated and remediated manually".into(),
            }),
        AdminResponse::IncidentClosed {
            retired_ephemeral_watches: 1,
            ..
        }
    ));
    let t5 = t4 + Duration::seconds(10);
    let hb = h.agent.make_heartbeat(t5);
    h.exchange(vec![hb], t5).await;
    assert_eq!(h.agent.active_bundle_version(), 3);
    assert!(
        !h.agent
            .watch_ids()
            .contains(&"ephem-custom-helper".to_string())
    );
    assert!(h.agent.watch_ids().contains(&"base-sockets".to_string()));

    h.assert_audit_valid();
}

/// Scenario 3: Sustained unchanged condition across suppressed ticks.
/// Identical snapshot hashes are suppressed at the edge, yet edge tracks valid
/// sample counts and emits immediately on the N-th sustained tick -> control opens incident.
#[tokio::test]
async fn sustained_unchanged_condition_emits_on_nth_tick_and_triggers_control() {
    let mut h = E2eHarness::new(
        "edge-sustained",
        DurabilityProfile::Minimal {
            max_ram_bytes: 256 * 1024,
        },
    );
    let t0 = Utc::now();
    {
        let handle = h.fake.state_handle();
        let mut st = handle.lock().unwrap();
        st.sockets = SocketsListeningSnapshot {
            count: 3,
            partial_attribution: false,
            sockets: vec![
                socket_entry(22, 0, "sshd"),
                socket_entry(80, 0, "nginx"),
                socket_entry(443, 0, "nginx"),
            ],
        };
    }

    let sustained_watch = WatchSpec {
        id: "w-sustained-sockets".into(),
        version: 1,
        host_id: "edge-sustained".into(),
        class: WatchClass::Baseline,
        incident_id: None,
        collector: CollectorSpec::SocketsListening(SocketsListeningParams {
            include_tcp: true,
            include_udp: false,
            include_ipv6: false,
            resolve_process: false,
        }),
        schedule: WatchSchedule {
            interval_seconds: 15,
            timeout_seconds: 5,
        },
        trigger: TriggerPredicate::ThresholdSustained {
            field: "count".into(),
            operator: ThresholdOp::Gte,
            threshold: 3,
            consecutive_samples: 3,
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
    };
    assert!(matches!(
        h.control
            .handle_admin_request(AdminRequest::ApplyBaselineWatch {
                spec: sustained_watch,
                actor: "ops".into(),
                rationale: "monitor sustained listener count".into(),
            }),
        AdminResponse::WatchApplied { .. }
    ));
    h.register_and_sync(t0).await;

    // Tick 1 (initial reconciliation snapshot): count=1, no incident yet.
    let t1 = t0 + Duration::seconds(20);
    assert_eq!(h.tick_and_sync(t1).await.len(), 1);
    let AdminResponse::Incidents { incidents } =
        h.control.handle_admin_request(AdminRequest::ListIncidents)
    else {
        panic!("expected incidents");
    };
    assert!(incidents.is_empty());

    // Tick 2 (unchanged snapshot): payload SUPPRESSED, heartbeat carries sustained_count=2.
    let t2 = t1 + Duration::seconds(20);
    assert!(h.tick_and_sync(t2).await.is_empty());
    let AgentToControl::Heartbeat {
        watch_summaries, ..
    } = h.agent.make_heartbeat(t2)
    else {
        panic!("expected heartbeat");
    };
    assert_eq!(watch_summaries[0].sustained_count, 2);
    assert!(!watch_summaries[0].sustained_active);

    // Tick 3 (still unchanged snapshot!): sustained flips true -> EMITS immediately!
    let t3 = t2 + Duration::seconds(20);
    let emitted = h.tick_and_sync(t3).await;
    assert_eq!(emitted.len(), 1);
    let AgentToControl::PushObservationDelta { observation } = &emitted[0] else {
        panic!("expected observation");
    };
    assert_eq!(observation.sustained_count, Some(3));
    assert_eq!(observation.sustained_active, Some(true));

    // Control plane opened an incident from that 3rd sustained valid sample!
    let AdminResponse::Incidents { incidents } =
        h.control.handle_admin_request(AdminRequest::ListIncidents)
    else {
        panic!("expected incidents");
    };
    assert_eq!(incidents.len(), 1);
}

/// Scenario 4: Disconnect, durable disk spool across agent restart, and clean drain.
#[tokio::test]
async fn durable_spool_drains_prior_session_observations_after_restart() {
    let profile = DurabilityProfile::Durable {
        max_disk_bytes: 512 * 1024,
    };
    let mut h = E2eHarness::new("edge-durable", profile);
    let t0 = Utc::now();

    assert!(matches!(
        h.control
            .handle_admin_request(AdminRequest::ApplyBaselineWatch {
                spec: sockets_baseline_watch("edge-durable"),
                actor: "ops".into(),
                rationale: "baseline".into(),
            }),
        AdminResponse::WatchApplied { .. }
    ));
    h.register_and_sync(t0).await;
    let first_session = h.agent.session_id().to_string();

    // Agent loses connectivity: ticks locally twice while disconnected!
    {
        let handle = h.fake.state_handle();
        let mut st = handle.lock().unwrap();
        st.sockets = SocketsListeningSnapshot {
            count: 1,
            partial_attribution: false,
            sockets: vec![socket_entry(22, 0, "sshd")],
        };
    }
    let t1 = t0 + Duration::seconds(40);
    let _offline_1 = h.agent.run_due_watches(t1).await;

    {
        let handle = h.fake.state_handle();
        let mut st = handle.lock().unwrap();
        st.sockets = SocketsListeningSnapshot {
            count: 2,
            partial_attribution: false,
            sockets: vec![
                socket_entry(22, 0, "sshd"),
                socket_entry(8080, 1000, "app"),
            ],
        };
    }
    let t2 = t1 + Duration::seconds(40);
    let _offline_2 = h.agent.run_due_watches(t2).await;
    assert_eq!(h.agent.pending_observations().len(), 2);

    // Agent crashes and restarts with a BRAND-NEW session_id.
    h.restart_agent(profile);
    assert_ne!(h.agent.session_id(), first_session);
    assert_eq!(h.agent.pending_observations().len(), 2);
    assert_eq!(h.agent.pending_observations()[0].session_id, first_session);

    // Reconnect: register new session, then flush durable spool containing prior-session records.
    let t3 = t2 + Duration::seconds(10);
    h.register_and_sync(t3).await;
    let pending: Vec<AgentToControl> = h
        .agent
        .pending_observations()
        .into_iter()
        .map(|observation| AgentToControl::PushObservationDelta { observation })
        .collect();
    h.exchange(pending, t3).await;

    // Both prior-session observations must be durably committed & pruned from disk spool!
    assert!(
        h.agent.pending_observations().is_empty(),
        "prior-session durable spool should drain and prune cleanly after restart"
    );

    let obs_token = h.mint_token(
        "auditor",
        PrincipalRole::Observer,
        vec!["edge-durable".into()],
        vec![CollectorType::SocketsListening],
        None,
        3600,
    );
    let InvestigationResponse::Observations { observations } =
        h.control.handle_investigation_call(InvestigationCall {
            request_id: "req-check-drained".into(),
            capability_token: obs_token,
            request: InvestigationRequest::QueryObservations {
                host_id: "edge-durable".into(),
                watch_id: Some("base-sockets".into()),
                since: None,
                limit: Some(10),
            },
        })
    else {
        panic!("expected observations");
    };
    assert_eq!(observations.len(), 2);
}

/// Scenario 5: Adversarial corpus — 100% deterministic rejection at BOTH
/// `control-d` policy gate AND `agent-d` independent local safety floor.
#[tokio::test]
async fn adversarial_corpus_rejected_at_both_control_and_edge_boundaries() {
    let mut h = E2eHarness::new(
        "edge-adv",
        DurabilityProfile::Minimal {
            max_ram_bytes: 128 * 1024,
        },
    );
    let t0 = Utc::now();

    // Enroll a second host to test cross-host isolation.
    h.control.handle_admin_request(AdminRequest::EnrollHost {
        host_id: "edge-other".into(),
        agent_public_key_hex: None,
    });
    h.control
        .handle_admin_request(AdminRequest::ApplyBaselineWatch {
            spec: sockets_baseline_watch("edge-adv"),
            actor: "ops".into(),
            rationale: "baseline".into(),
        });
    h.register_and_sync(t0).await;

    // Seed baseline + drift to produce an open incident.
    {
        let handle = h.fake.state_handle();
        let mut st = handle.lock().unwrap();
        st.sockets = SocketsListeningSnapshot {
            count: 1,
            partial_attribution: false,
            sockets: vec![socket_entry(22, 0, "sshd")],
        };
    }
    let t1 = t0 + Duration::seconds(40);
    h.tick_and_sync(t1).await;
    let obs_token = h.mint_token(
        "obs",
        PrincipalRole::Observer,
        vec!["edge-adv".into()],
        vec![
            CollectorType::SocketsListening,
            CollectorType::FilesMetadata,
            CollectorType::SystemdUnitState,
        ],
        None,
        3600,
    );
    let InvestigationResponse::Observations { observations } =
        h.control.handle_investigation_call(InvestigationCall {
            request_id: "r1".into(),
            capability_token: obs_token.clone(),
            request: InvestigationRequest::QueryObservations {
                host_id: "edge-adv".into(),
                watch_id: Some("base-sockets".into()),
                since: None,
                limit: Some(5),
            },
        })
    else {
        panic!("expected obs");
    };
    h.control
        .handle_admin_request(AdminRequest::PromoteBaseline {
            host_id: "edge-adv".into(),
            watch_id: "base-sockets".into(),
            observation_id: observations[0].observation_id,
            approver: "ops".into(),
            rationale: "baseline".into(),
            ticket_ref: None,
        });
    {
        let handle = h.fake.state_handle();
        let mut st = handle.lock().unwrap();
        st.sockets.sockets.push(socket_entry(9999, 1000, "bad"));
        st.sockets.count = 2;
    }
    let t2 = t1 + Duration::seconds(40);
    h.tick_and_sync(t2).await;

    let AdminResponse::Incidents { incidents } =
        h.control.handle_admin_request(AdminRequest::ListIncidents)
    else {
        panic!("expected incidents");
    };
    let inc_id = incidents[0].incident_id.clone();

    let inv_token = h.mint_token(
        "hijacked-reasoner",
        PrincipalRole::Investigator,
        vec!["edge-adv".into()],
        vec![
            CollectorType::FilesMetadata,
            CollectorType::SystemdUnitState,
            CollectorType::SocketsListening,
        ],
        Some(inc_id.clone()),
        3600,
    );
    let InvestigationResponse::RunStarted { run_id, .. } =
        h.control.handle_investigation_call(InvestigationCall {
            request_id: "r-run".into(),
            capability_token: inv_token.clone(),
            request: InvestigationRequest::StartInvestigationRun {
                incident_id: inc_id.clone(),
                backend_id: "test".into(),
                model_id: "test".into(),
                prompt_schema_version: "v1".into(),
            },
        })
    else {
        panic!("expected run");
    };

    // Build adversarial proposal corpus (simulating prompt injection).
    let base_ephem = |id: &str, collector: CollectorSpec| WatchSpec {
        id: id.into(),
        version: 1,
        host_id: "edge-adv".into(),
        class: WatchClass::Ephemeral,
        incident_id: Some(inc_id.clone()),
        collector,
        schedule: WatchSchedule {
            interval_seconds: 30,
            timeout_seconds: 5,
        },
        trigger: TriggerPredicate::FieldChanged {
            compare_against: CompareTarget::LastObserved,
            fields: vec!["count".into()],
        },
        wake_policy: WakePolicy {
            cooldown_seconds: 60,
            max_wakeups_per_hour: 4,
        },
        lifecycle: WatchLifecycle {
            enabled: true,
            expires_at: Some(t2 + Duration::hours(1)),
            max_runs: Some(60),
        },
    };

    let mut adversarial_specs: Vec<(&str, WatchSpec)> = vec![
        (
            "read-shadow",
            base_ephem(
                "adv-shadow",
                CollectorSpec::FilesMetadata(FilesMetadataParams {
                    paths: vec!["/etc/shadow".into()],
                    compute_hash: true,
                    max_file_bytes: Some(4096),
                }),
            ),
        ),
        (
            "read-ssh-private-key",
            base_ephem(
                "adv-key",
                CollectorSpec::FilesMetadata(FilesMetadataParams {
                    paths: vec!["/etc/ssh/ssh_host_ed25519_key".into()],
                    compute_hash: true,
                    max_file_bytes: Some(4096),
                }),
            ),
        ),
        (
            "path-traversal",
            base_ephem(
                "adv-trav",
                CollectorSpec::FilesMetadata(FilesMetadataParams {
                    paths: vec!["/etc/ssh/../shadow".into()],
                    compute_hash: true,
                    max_file_bytes: Some(4096),
                }),
            ),
        ),
        (
            "shell-injection-unit",
            base_ephem(
                "adv-shell",
                CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
                    unit: "sshd.service; cat /etc/shadow".into(),
                    hash_unit_files: true,
                }),
            ),
        ),
    ];

    // Add: baseline modification attempt
    let mut touch_baseline = base_ephem(
        "base-sockets",
        CollectorSpec::SocketsListening(SocketsListeningParams {
            include_tcp: true,
            include_udp: false,
            include_ipv6: false,
            resolve_process: false,
        }),
    );
    touch_baseline.class = WatchClass::Baseline;
    touch_baseline.incident_id = None;
    adversarial_specs.push(("modify-baseline", touch_baseline));

    // Add: cross-host proposal
    let mut cross_host = base_ephem(
        "adv-cross",
        CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
            unit: "sshd.service".into(),
            hash_unit_files: true,
        }),
    );
    cross_host.host_id = "edge-other".into();
    adversarial_specs.push(("cross-host", cross_host));

    // Add: interval below 15s floor
    let mut fast_poll = base_ephem(
        "adv-fast",
        CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
            unit: "sshd.service".into(),
            hash_unit_files: true,
        }),
    );
    fast_poll.schedule.interval_seconds = 2;
    fast_poll.schedule.timeout_seconds = 1;
    adversarial_specs.push(("sub-floor-interval", fast_poll));

    // Add: excessive TTL (48 hours)
    let mut huge_ttl = base_ephem(
        "adv-ttl",
        CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
            unit: "sshd.service".into(),
            hash_unit_files: true,
        }),
    );
    huge_ttl.lifecycle.expires_at = Some(t2 + Duration::hours(48));
    adversarial_specs.push(("excessive-ttl", huge_ttl));

    // 100% of adversarial proposals MUST be rejected by control-d!
    for (label, spec) in adversarial_specs {
        let resp = h.control.handle_investigation_call(InvestigationCall {
            request_id: format!("req-{label}"),
            capability_token: inv_token.clone(),
            request: InvestigationRequest::ProposeEphemeralWatch {
                run_id: run_id.clone(),
                idempotency_key: format!("idem-{label}"),
                spec,
                rationale: format!("adversarial case {label}"),
            },
        });
        match resp {
            InvestigationResponse::ProposalEvaluated { decision, .. } => {
                assert!(
                    !decision.allowed,
                    "adversarial proposal '{label}' was unexpectedly allowed!"
                );
            }
            InvestigationResponse::Error { .. } => {}
            other => panic!("unexpected response for '{label}': {other:?}"),
        }
    }

    // Observer attempting to start a run must be denied.
    assert!(matches!(
        h.control.handle_investigation_call(InvestigationCall {
            request_id: "req-obs-escalate".into(),
            capability_token: obs_token,
            request: InvestigationRequest::StartInvestigationRun {
                incident_id: inc_id.clone(),
                backend_id: "b".into(),
                model_id: "m".into(),
                prompt_schema_version: "v1".into(),
            },
        }),
        InvestigationResponse::Error { .. }
    ));

    // Citing nonexistent evidence ID must be denied.
    assert!(matches!(
        h.control.handle_investigation_call(InvestigationCall {
            request_id: "req-fake-ev".into(),
            capability_token: inv_token,
            request: InvestigationRequest::RecordHypothesisOrFinding {
                run_id,
                incident_id: inc_id,
                kind: FindingKind::VerifiedFinding,
                severity: Severity::Critical,
                summary: "forged".into(),
                uncertainty: "none".into(),
                evidence_observation_ids: vec![999_999],
                escalation_requested: true,
            },
        }),
        InvestigationResponse::Error { .. }
    ));

    // Compromised-control defense-in-depth: even a VALIDLY SIGNED malicious bundle
    // with `/etc/shadow` MUST be rejected independently by `agent-d`!
    let compromised_kp = SigningKeyPair::generate("compromised-key");
    let mut comp_store = VerifyingKeyStore::new();
    comp_store.insert_key(compromised_kp.key_id(), compromised_kp.verifying_key());
    let short = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let mut isolated_agent = AgentEngine::new(
        EdgeSafetyConfig::default(),
        "edge-adv".into(),
        DurabilityProfile::Minimal {
            max_ram_bytes: 64 * 1024,
        },
        std::env::temp_dir().join(format!("iso-{short}")),
        comp_store,
        Arc::new(FakeHostCollectors::from_state(FakeHostState::default())),
    )
    .unwrap();

    let evil_bundle = WatchBundlePayload {
        schema_version: WATCH_BUNDLE_SCHEMA_VERSION,
        bundle_id: "evil-1".into(),
        target_host_id: "edge-adv".into(),
        bundle_version: 1,
        issued_at: t2,
        expires_at: t2 + Duration::hours(1),
        policy_version: 1,
        watches: vec![WatchSpec {
            id: "steal-shadow".into(),
            version: 1,
            host_id: "edge-adv".into(),
            class: WatchClass::Baseline,
            incident_id: None,
            collector: CollectorSpec::FilesMetadata(FilesMetadataParams {
                paths: vec!["/etc/shadow".into()],
                compute_hash: true,
                max_file_bytes: Some(1024),
            }),
            schedule: WatchSchedule {
                interval_seconds: 30,
                timeout_seconds: 5,
            },
            trigger: TriggerPredicate::FieldChanged {
                compare_against: CompareTarget::LastObserved,
                fields: vec!["count".into()],
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
        }],
    };
    let signed_evil = compromised_kp
        .sign_payload(DOMAIN_WATCH_BUNDLE_V1, &evil_bundle)
        .unwrap();
    let acks = isolated_agent
        .handle_control(
            ControlToAgent::SyncWatchBundle {
                envelope: signed_evil,
            },
            t2,
        )
        .await;
    assert!(matches!(
        acks.first(),
        Some(AgentToControl::BundleAck {
            status: BundleAckStatus::Rejected,
            ..
        })
    ));
    assert_eq!(isolated_agent.active_bundle_version(), 0);

    h.assert_audit_valid();
}

/// Scenario 6: Live single-host UDS smoke test using RealLinuxCollectors on this
/// Ubuntu/Debian host (real `/proc/net` sockets + real `/proc/self/statm` RSS).
#[tokio::test]
async fn live_linux_uds_smoke_test_and_rss_telemetry() {
    let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    struct SocketTestDir(PathBuf);
    impl Drop for SocketTestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let tmp = std::env::temp_dir();
    let candidate = if tmp.as_os_str().len() <= 75 {
        tmp.join(format!("dl{id}"))
    } else {
        std::path::Path::new("/tmp").join(format!("dl{id}"))
    };
    let path = match std::fs::create_dir(&candidate) {
        Ok(()) => candidate,
        Err(_) => {
            let fallback = tmp.join(format!("dl{id}"));
            std::fs::create_dir(&fallback).unwrap();
            fallback
        }
    };
    let dir = SocketTestDir(path);
    let control = ControlService::open(&dir.0, "live-key-01", 1).unwrap();
    let agent_sock = dir.0.join("ag.sock");
    let admin_sock = dir.0.join("ad.sock");

    let policy = SocketPolicy::default();
    let agent_task = tokio::spawn(
        UnixServer::bind(&agent_sock, policy.clone())
            .unwrap()
            .serve_agent(control.clone()),
    );
    let admin_task = tokio::spawn(
        UnixServer::bind(&admin_sock, policy)
            .unwrap()
            .serve_admin(control.clone()),
    );

    // Enroll host and apply real sockets watch over admin.sock.
    let mut admin = UnixStream::connect(&admin_sock).await.unwrap();
    write_frame(
        &mut admin,
        &AdminRequest::EnrollHost {
            host_id: "live-host".into(),
            agent_public_key_hex: None,
        },
    )
    .await
    .unwrap();
    let AdminResponse::HostEnrolled {
        control_signing_key_id,
        control_public_key_hex,
        ..
    } = timeout(StdDuration::from_secs(3), read_frame(&mut admin))
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    else {
        panic!("enroll failed");
    };

    write_frame(
        &mut admin,
        &AdminRequest::ApplyBaselineWatch {
            spec: sockets_baseline_watch("live-host"),
            actor: "smoke".into(),
            rationale: "live probe".into(),
        },
    )
    .await
    .unwrap();
    let AdminResponse::WatchApplied {
        bundle_version: 1, ..
    } = timeout(StdDuration::from_secs(3), read_frame(&mut admin))
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    else {
        panic!("apply failed");
    };

    // Start real AgentEngine<RealLinuxCollectors> and connect over agent.sock.
    let mut store = VerifyingKeyStore::new();
    store
        .insert_public_hex(&control_signing_key_id, &control_public_key_hex)
        .unwrap();
    let mut engine = AgentEngine::new(
        EdgeSafetyConfig::default(),
        "live-host".into(),
        DurabilityProfile::Minimal {
            max_ram_bytes: 256 * 1024,
        },
        dir.0.join("ag-state"),
        store,
        Arc::new(RealLinuxCollectors::new()),
    )
    .unwrap();

    let mut conn = UnixStream::connect(&agent_sock).await.unwrap();
    let now = Utc::now();
    write_frame(&mut conn, &engine.make_register(now))
        .await
        .unwrap();

    // Receive RegisterAck + SyncWatchBundle + RequestReconciliation.
    for _ in 0..3 {
        let reply: ControlToAgent = timeout(StdDuration::from_secs(3), read_frame(&mut conn))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        for ack in engine.handle_control(reply, now).await {
            write_frame(&mut conn, &ack).await.unwrap();
        }
    }
    assert_eq!(engine.active_bundle_version(), 1);

    // Run real `/proc/net` collection and push over UDS!
    let msgs = engine.run_due_watches(now + Duration::seconds(60)).await;
    assert_eq!(msgs.len(), 1);
    write_frame(&mut conn, &msgs[0]).await.unwrap();
    let obs_ack: ControlToAgent = timeout(StdDuration::from_secs(3), read_frame(&mut conn))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        obs_ack,
        ControlToAgent::ObservationAck {
            acked_seq_no: 1,
            ..
        }
    ));

    // Send real Heartbeat and verify RSS telemetry is populated on Linux.
    let hb = engine.make_heartbeat(now + Duration::seconds(61));
    let AgentToControl::Heartbeat { ref health, .. } = hb else {
        panic!("expected heartbeat");
    };
    assert!(health.rss_bytes.unwrap_or(0) > 0);
    write_frame(&mut conn, &hb).await.unwrap();

    drop(conn);
    drop(admin);
    agent_task.abort();
    admin_task.abort();
}
