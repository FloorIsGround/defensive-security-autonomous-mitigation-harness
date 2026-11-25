//! Integration tests for the `agent-d` edge engine: signed bundle lifecycle,
//! edge-lite diffing with sustained counters, spool emission and pruning,
//! stream cursors, and ephemeral lifecycle across restarts — all driven
//! in-process against `FakeHostCollectors`.

use std::collections::VecDeque;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{Duration, Utc};
use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::observation::{
    ConnectionsOutboundSnapshot, FlowAttribution, JournalEventRecord, ListeningSocketEntry,
    ObservationPayload, ObservationStatus, PackageInventoryEntry, PackagesInventorySnapshot,
    SocketsListeningSnapshot,
};
use defsec_protocol::profile::HostProfileSummary;
use defsec_protocol::signing::{
    SigningKeyPair, VerifyingKeyStore, DOMAIN_WATCH_BUNDLE_V1, SignedEnvelope,
};
use defsec_protocol::watch::{
    CollectorSpec, ConnectionsOutboundParams, DataClassification, JournalUnitEventsParams,
    PackagesInventoryParams, SocketsListeningParams, SystemdUnitStateParams, ThresholdOp,
    TriggerPredicate, WATCH_BUNDLE_SCHEMA_VERSION, WakePolicy, WatchBundlePayload, WatchClass,
    WatchLifecycle, WatchSchedule, WatchSpec,
};
use defsec_protocol::wire::{AgentToControl, BundleAckStatus, ControlToAgent};
use uuid::Uuid;

use agent_d::collectors::{FakeHostCollectors, FakeHostState};
use agent_d::engine::AgentEngine;
use agent_d::profile::load_profile;
use agent_d::spool::DurabilityProfile;

const HOST: &str = "edge-01";

fn state_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("agent-d-tests/engine")
        .join(format!("{tag}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create state dir");
    dir
}

fn key_pair() -> SigningKeyPair {
    SigningKeyPair::generate("control-key-01")
}

fn store_for(kp: &SigningKeyPair) -> VerifyingKeyStore {
    let mut store = VerifyingKeyStore::new();
    store
        .insert_public_hex(kp.key_id(), &kp.public_hex())
        .expect("valid public key");
    store
}

fn sockets_watch(id: &str) -> WatchSpec {
    WatchSpec {
        id: id.into(),
        version: 1,
        host_id: HOST.into(),
        class: WatchClass::Baseline,
        incident_id: None,
        collector: CollectorSpec::SocketsListening(SocketsListeningParams {
            include_tcp: true,
            include_udp: true,
            include_ipv6: true,
            resolve_process: false,
        }),
        schedule: WatchSchedule {
            interval_seconds: 15,
            timeout_seconds: 5,
        },
        trigger: TriggerPredicate::ThresholdSustained {
            field: "count".into(),
            operator: ThresholdOp::Gte,
            threshold: 40,
            consecutive_samples: 3,
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

fn journal_watch(id: &str, class: WatchClass) -> WatchSpec {
    WatchSpec {
        id: id.into(),
        version: 1,
        host_id: HOST.into(),
        class,
        incident_id: (class == WatchClass::Ephemeral).then(|| "inc-1".into()),
        collector: CollectorSpec::JournalUnitEvents(JournalUnitEventsParams {
            unit: "sshd.service".into(),
            min_priority: Some(6),
            max_events_per_batch: Some(50),
            max_message_bytes: None,
        }),
        schedule: WatchSchedule {
            interval_seconds: 15,
            timeout_seconds: 5,
        },
        trigger: TriggerPredicate::FieldChanged {
            compare_against: defsec_protocol::watch::CompareTarget::LastObserved,
            fields: vec!["message_redacted".into()],
        },
        wake_policy: WakePolicy {
            cooldown_seconds: 60,
            max_wakeups_per_hour: 4,
        },
        lifecycle: WatchLifecycle {
            enabled: true,
            expires_at: (class == WatchClass::Ephemeral).then(|| Utc::now() + Duration::hours(1)),
            max_runs: (class == WatchClass::Ephemeral).then_some(2),
        },
    }
}

fn outbound_watch(id: &str) -> WatchSpec {
    WatchSpec {
        id: id.into(),
        version: 1,
        host_id: HOST.into(),
        class: WatchClass::Baseline,
        incident_id: None,
        collector: CollectorSpec::ConnectionsOutbound(ConnectionsOutboundParams {
            include_tcp: true,
            include_udp: true,
            include_ipv6: true,
            resolve_process: false,
            exclude_loopback: true,
            max_flows: Some(256),
        }),
        schedule: WatchSchedule {
            interval_seconds: 15,
            timeout_seconds: 5,
        },
        trigger: TriggerPredicate::SetDiff {
            compare_against: defsec_protocol::watch::CompareTarget::LastObserved,
            set_field: "flows".into(),
            identity_key: "flow_key".into(),
            ignore_fields: vec![],
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

fn packages_watch(id: &str) -> WatchSpec {
    WatchSpec {
        id: id.into(),
        version: 1,
        host_id: HOST.into(),
        class: WatchClass::Baseline,
        incident_id: None,
        collector: CollectorSpec::PackagesInventory(PackagesInventoryParams {
            max_packages: Some(4096),
        }),
        schedule: WatchSchedule {
            interval_seconds: 15,
            timeout_seconds: 5,
        },
        trigger: TriggerPredicate::ThresholdSustained {
            field: "total_packages".into(),
            operator: ThresholdOp::Gte,
            threshold: 1_000_000,
            consecutive_samples: 2,
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

fn signed_bundle(
    kp: &SigningKeyPair,
    target_host: &str,
    version: u64,
    watches: Vec<WatchSpec>,
) -> SignedEnvelope {
    let now = Utc::now();
    let payload = WatchBundlePayload {
        schema_version: WATCH_BUNDLE_SCHEMA_VERSION,
        bundle_id: format!("bundle-{version}"),
        target_host_id: target_host.into(),
        bundle_version: version,
        issued_at: now,
        expires_at: now + Duration::hours(12),
        policy_version: 1,
        watches,
    };
    kp.sign_payload(DOMAIN_WATCH_BUNDLE_V1, &payload)
        .expect("sign bundle")
}

fn fake_sockets_host(count: i64) -> FakeHostCollectors {
    let state = FakeHostState {
        sockets: SocketsListeningSnapshot {
            count: count as usize,
            partial_attribution: false,
            sockets: (0..count.max(0))
                .map(|i| ListeningSocketEntry {
                    socket_key: format!("tcp:0.0.0.0:{i}:uid=0"),
                    protocol: "tcp".into(),
                    local_addr: "0.0.0.0".into(),
                    local_port: 1000 + i as u16,
                    uid: 0,
                    inode: i as u64,
                    pid: None,
                    pid_start_time_ticks: None,
                    comm: None,
                    systemd_unit: None,
                })
                .collect(),
        },
        ..FakeHostState::default()
    };
    FakeHostCollectors::from_state(state)
}

fn engine_with(
    kp: &SigningKeyPair,
    dir: &Path,
    host: FakeHostCollectors,
    durable: bool,
) -> AgentEngine<FakeHostCollectors> {
    engine_with_cfg(kp, dir, host, durable, EdgeSafetyConfig::default())
}

fn engine_with_cfg(
    kp: &SigningKeyPair,
    dir: &Path,
    host: FakeHostCollectors,
    durable: bool,
    cfg: EdgeSafetyConfig,
) -> AgentEngine<FakeHostCollectors> {
    let durability = if durable {
        DurabilityProfile::Durable {
            max_disk_bytes: 1024 * 1024,
        }
    } else {
        DurabilityProfile::Minimal {
            max_ram_bytes: 1024 * 1024,
        }
    };
    AgentEngine::new(
        cfg,
        HOST.into(),
        durability,
        dir.to_path_buf(),
        store_for(kp),
        Arc::new(host),
    )
    .expect("engine")
}

fn sync_bundle_msg(kp: &SigningKeyPair, target: &str, version: u64, watches: Vec<WatchSpec>) -> ControlToAgent {
    ControlToAgent::SyncWatchBundle {
        envelope: signed_bundle(kp, target, version, watches),
    }
}

fn deltas(msgs: &[AgentToControl]) -> Vec<&defsec_protocol::observation::ObservationRecord> {
    msgs.iter()
        .filter_map(|m| match m {
            AgentToControl::PushObservationDelta { observation } => Some(observation),
            _ => None,
        })
        .collect()
}

fn base_time() -> chrono::DateTime<Utc> {
    Utc::now() - Duration::seconds(60)
}

#[tokio::test]
async fn rejects_tampered_wrong_host_and_stale_bundles() {
    let kp = key_pair();
    let dir = state_dir("reject");
    let mut engine = engine_with(&kp, &dir, fake_sockets_host(42), false);
    let now = Utc::now();

    // 1. Tampered payload: valid signature over other bytes.
    let mut tampered = signed_bundle(&kp, HOST, 5, vec![sockets_watch("w1")]);
    let original = tampered.raw_payload.clone();
    tampered.raw_payload = original.replace("\"bundle_version\":5", "\"bundle_version\":6");
    assert_ne!(tampered.raw_payload, original);
    let msgs = engine
        .handle_control(ControlToAgent::SyncWatchBundle { envelope: tampered }, now)
        .await;
    match &msgs[0] {
        AgentToControl::BundleAck { status, reason, .. } => {
            assert_eq!(*status, BundleAckStatus::Rejected);
            assert!(reason.as_deref().unwrap().contains("signature"));
        }
        other => panic!("expected BundleAck, got {other:?}"),
    }
    assert!(engine.watch_ids().is_empty());

    // 2. Wrong host (correctly signed): rejected by host binding.
    let msgs = engine
        .handle_control(
            sync_bundle_msg(&kp, "other-host", 5, vec![sockets_watch("w1")]),
            now,
        )
        .await;
    match &msgs[0] {
        AgentToControl::BundleAck { status, reason, .. } => {
            assert_eq!(*status, BundleAckStatus::Rejected);
            assert!(reason.as_deref().unwrap().contains("target_host_id"));
        }
        other => panic!("expected BundleAck, got {other:?}"),
    }

    // 3. Accept a good bundle, then reject a stale (lower) version.
    let msgs = engine
        .handle_control(sync_bundle_msg(&kp, HOST, 5, vec![sockets_watch("w1")]), now)
        .await;
    assert!(matches!(
        &msgs[0],
        AgentToControl::BundleAck {
            status: BundleAckStatus::Accepted,
            ..
        }
    ));
    assert_eq!(engine.watch_ids(), vec!["w1".to_string()]);

    let msgs = engine
        .handle_control(sync_bundle_msg(&kp, HOST, 4, vec![sockets_watch("w1")]), now)
        .await;
    match &msgs[0] {
        AgentToControl::BundleAck { status, reason, .. } => {
            assert_eq!(*status, BundleAckStatus::Rejected);
            assert!(reason.as_deref().unwrap().contains("stale"));
        }
        other => panic!("expected BundleAck, got {other:?}"),
    }
    // The good bundle stays active.
    assert_eq!(engine.active_bundle_version(), 5);
}

#[tokio::test]
async fn identical_bundle_retransmission_is_already_active() {
    let kp = key_pair();
    let dir = state_dir("retransmit");
    let mut engine = engine_with(&kp, &dir, fake_sockets_host(42), false);
    let now = Utc::now();

    let envelope = signed_bundle(&kp, HOST, 7, vec![sockets_watch("w1")]);
    engine
        .handle_control(ControlToAgent::SyncWatchBundle { envelope: envelope.clone() }, now)
        .await;
    let msgs = engine
        .handle_control(ControlToAgent::SyncWatchBundle { envelope }, now)
        .await;
    match &msgs[0] {
        AgentToControl::BundleAck { status, bundle_version, .. } => {
            assert_eq!(*status, BundleAckStatus::AlreadyActive);
            assert_eq!(*bundle_version, 7);
        }
        other => panic!("expected BundleAck, got {other:?}"),
    }
    // Same version with DIFFERENT payload is rejected outright.
    let conflicting = signed_bundle(&kp, HOST, 7, vec![sockets_watch("w2")]);
    let msgs = engine
        .handle_control(ControlToAgent::SyncWatchBundle { envelope: conflicting }, now)
        .await;
    match &msgs[0] {
        AgentToControl::BundleAck { status, reason, .. } => {
            assert_eq!(*status, BundleAckStatus::Rejected);
            assert!(reason.as_deref().unwrap().contains("different payload digest"));
        }
        other => panic!("expected BundleAck, got {other:?}"),
    }
}

#[tokio::test]
async fn unchanged_snapshots_are_suppressed_but_sustained_transitions_emit() {
    let kp = key_pair();
    let dir = state_dir("suppression");
    let mut engine = engine_with(&kp, &dir, fake_sockets_host(42), false);
    let now = Utc::now();

    engine
        .handle_control(
            sync_bundle_msg(&kp, HOST, 1, vec![sockets_watch("w-sustained")]),
            now,
        )
        .await;

    let t0 = base_time();
    // First tick far past the (0..14s) stagger phase: first observation.
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1000)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 1, "first sample must establish baseline");
    assert_eq!(emitted[0].sustained_count, Some(1));
    assert_eq!(emitted[0].sustained_active, Some(false));
    assert!(emitted[0].is_reconciliation, "first snapshot is a full checkpoint");

    // Second identical sample: suppressed, but the sustained counter grows.
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1016)).await;
    assert!(deltas(&msgs).is_empty(), "unchanged snapshot must be suppressed");

    // Third identical sample: counter reaches 3 and active flips -> the
    // transition MUST emit immediately even though the hash is unchanged.
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1032)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 1, "sustained transition must emit");
    assert_eq!(emitted[0].sustained_count, Some(3));
    assert_eq!(emitted[0].sustained_active, Some(true));
    assert!(!emitted[0].is_reconciliation);

    // Fourth identical sample: no new transition -> suppressed again.
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1048)).await;
    assert!(deltas(&msgs).is_empty());

    // Heartbeat reports the counter so a central predicate can see progress.
    let hb = match engine.make_heartbeat(Utc::now()) {
        AgentToControl::Heartbeat {
            watch_summaries, ..
        } => watch_summaries,
        other => panic!("expected heartbeat, got {other:?}"),
    };
    let summary = hb.iter().find(|s| s.watch_id == "w-sustained").unwrap();
    assert_eq!(summary.completed_runs, 4);
    assert_eq!(summary.success_runs, 4);
    assert_eq!(summary.sustained_count, 4);
    assert!(summary.sustained_active);
    assert!(!summary.retired);
}

#[tokio::test]
async fn request_reconciliation_forces_a_full_snapshot_of_unchanged_state() {
    let kp = key_pair();
    let dir = state_dir("reconcile");
    let mut engine = engine_with(&kp, &dir, fake_sockets_host(42), false);
    let now = Utc::now();

    engine
        .handle_control(sync_bundle_msg(&kp, HOST, 1, vec![sockets_watch("w1")]), now)
        .await;
    let t0 = base_time();
    engine.run_due_watches(t0 + Duration::seconds(1000)).await;
    // Second identical sample: suppressed.
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1016)).await;
    assert!(deltas(&msgs).is_empty());

    // Explicit reconciliation request must break the suppression.
    engine
        .handle_control(
            ControlToAgent::RequestReconciliation {
                host_id: HOST.into(),
                watch_ids: vec!["w1".into()],
                reason: "operator requested".into(),
            },
            Utc::now(),
        )
        .await;
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1032)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 1);
    assert!(emitted[0].is_reconciliation);

    // Empty watch_ids list reconciles ALL active snapshot watches.
    engine
        .handle_control(
            ControlToAgent::RequestReconciliation {
                host_id: HOST.into(),
                watch_ids: vec![],
                reason: "all".into(),
            },
            Utc::now(),
        )
        .await;
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1048)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 1);
    assert!(emitted[0].is_reconciliation);
}

#[tokio::test]
async fn ephemeral_max_runs_retirement_survives_restart() {
    let kp = key_pair();
    let dir = state_dir("ephemeral");
    let mut engine = engine_with(&kp, &dir, fake_sockets_host(42), false);
    let now = Utc::now();

    let mut w = journal_watch("w-eph", WatchClass::Ephemeral);
    w.collector = CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
        unit: "sshd.service".into(),
        hash_unit_files: false,
    });
    // Ephemeral snapshot watch (threshold_sustained is invalid on streams).
    w.trigger = TriggerPredicate::FieldChanged {
        compare_against: defsec_protocol::watch::CompareTarget::LastObserved,
        fields: vec!["active_state".into()],
    };
    let bundle = signed_bundle(&kp, HOST, 3, vec![w]);
    engine
        .handle_control(ControlToAgent::SyncWatchBundle { envelope: bundle }, now)
        .await;

    let t0 = base_time();
    engine.run_due_watches(t0 + Duration::seconds(1000)).await;
    engine.run_due_watches(t0 + Duration::seconds(1016)).await;
    // max_runs = 2: the third tick must NOT run the watch again.
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1032)).await;
    assert!(deltas(&msgs).is_empty());

    let hb = match engine.make_heartbeat(Utc::now()) {
        AgentToControl::Heartbeat { watch_summaries, .. } => watch_summaries,
        other => panic!("expected heartbeat, got {other:?}"),
    };
    let summary = hb.iter().find(|s| s.watch_id == "w-eph").unwrap();
    assert_eq!(summary.completed_runs, 2);
    assert!(summary.retired, "ephemeral watch must retire after max_runs");

    // Restart with the same state dir: the retirement must survive.
    let mut engine2 = engine_with(&kp, &dir, fake_sockets_host(42), false);
    assert_eq!(engine2.watch_ids(), vec!["w-eph".to_string()]);
    let msgs = engine2.run_due_watches(t0 + Duration::seconds(2000)).await;
    assert!(deltas(&msgs).is_empty(), "retired watch must not run after restart");
    let hb = match engine2.make_heartbeat(Utc::now()) {
        AgentToControl::Heartbeat { watch_summaries, .. } => watch_summaries,
        other => panic!("expected heartbeat, got {other:?}"),
    };
    let summary = hb.iter().find(|s| s.watch_id == "w-eph").unwrap();
    assert!(summary.retired);
    assert_eq!(summary.completed_runs, 2, "run counts must persist across restart");
}

#[tokio::test]
async fn bundle_expiry_flags_stale_state_and_retires_only_ephemerals() {
    let kp = key_pair();
    let dir = state_dir("expiry");

    // A bundle that expires in one second.
    let now = Utc::now();
    let mut payload_watches = vec![sockets_watch("w-base")];
    let mut ephem = sockets_watch("w-eph2");
    ephem.class = WatchClass::Ephemeral;
    ephem.incident_id = Some("inc-9".into());
    ephem.lifecycle = WatchLifecycle {
        enabled: true,
        expires_at: Some(now + Duration::hours(1)),
        max_runs: Some(50),
    };
    payload_watches.push(ephem);
    let bundle_payload = WatchBundlePayload {
        schema_version: WATCH_BUNDLE_SCHEMA_VERSION,
        bundle_id: "bundle-exp".into(),
        target_host_id: HOST.into(),
        bundle_version: 1,
        issued_at: now,
        expires_at: now + Duration::seconds(1),
        policy_version: 1,
        watches: payload_watches,
    };
    let envelope = kp
        .sign_payload(DOMAIN_WATCH_BUNDLE_V1, &bundle_payload)
        .unwrap();
    let mut engine = engine_with(&kp, &dir, fake_sockets_host(42), false);
    engine
        .handle_control(ControlToAgent::SyncWatchBundle { envelope }, now)
        .await;
    assert!(!engine.stale_desired_state());

    // "Reconnect" long after the bundle expired while disconnected.
    let msgs = engine
        .run_due_watches(now + Duration::hours(2))
        .await;
    assert!(engine.stale_desired_state());
    let hb = match engine.make_heartbeat(Utc::now()) {
        AgentToControl::Heartbeat {
            stale_desired_state,
            watch_summaries,
            ..
        } => {
            assert!(stale_desired_state);
            watch_summaries
        }
        other => panic!("expected heartbeat, got {other:?}"),
    };
    let eph = hb.iter().find(|s| s.watch_id == "w-eph2").unwrap();
    let base = hb.iter().find(|s| s.watch_id == "w-base").unwrap();
    assert!(eph.retired, "ephemeral watches retire conservatively on expiry");
    assert!(!base.retired, "baseline monitoring is preserved");
    // And the baseline watch still collected (2h past due).
    assert_eq!(base.completed_runs, 1);
    assert_eq!(deltas(&msgs).len(), 1, "baseline watch still emits");
}

#[tokio::test]
async fn observation_ack_prunes_spooled_records() {
    let kp = key_pair();
    let dir = state_dir("ack");
    let mut engine = engine_with(&kp, &dir, fake_sockets_host(42), true);
    let now = Utc::now();
    engine
        .handle_control(sync_bundle_msg(&kp, HOST, 1, vec![sockets_watch("w1")]), now)
        .await;

    let t0 = base_time();
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1000)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 1);
    assert_eq!(engine.pending_observations().len(), 1);

    // Acknowledge the emitted sequence number for this session.
    engine
        .handle_control(
            ControlToAgent::ObservationAck {
                host_id: HOST.into(),
                session_id: engine.session_id().to_string(),
                acked_seq_no: 1,
                acked_at: Utc::now(),
            },
            Utc::now(),
        )
        .await;
    assert!(engine.pending_observations().is_empty(), "ack must prune spool");
}

#[tokio::test]
async fn journal_stream_always_emits_and_checkpoints_cursors_across_restart() {
    let kp = key_pair();
    let dir = state_dir("journal");

    let make_event = |cursor: &str, msg: &str| JournalEventRecord {
        cursor: cursor.into(),
        timestamp_us: 1_700_000_000_000_000,
        unit: "sshd.service".into(),
        priority: 4,
        pid: None,
        uid: None,
        message_redacted: msg.into(),
        truncated: false,
        redaction_applied: false,
        classification: DataClassification::BoundedRedactedText,
    };
    let batch = |cursor: &str, msg: &str| agent_d::collectors::journal::JournalFetchOutcome {
        status: ObservationStatus::Ok,
        events: vec![make_event(cursor, msg)],
        cursor_after: Some(cursor.into()),
        gap_detected: false,
        partial_reasons: Vec::new(),
    };

    let state = FakeHostState {
        journal_batches: VecDeque::from(vec![
            batch("c1", "identical text"),
            batch("c2", "identical text"), // identical recurring text still emits
            batch("c3", "identical text"),
        ]),
        // Once scripted batches run out, an explicit gap event follows.
        journal_default: agent_d::collectors::journal::JournalFetchOutcome {
            status: ObservationStatus::Ok,
            events: Vec::new(),
            cursor_after: None,
            gap_detected: true,
            partial_reasons: vec!["journal cursor invalidated".into()],
        },
        ..FakeHostState::default()
    };
    let host = FakeHostCollectors::from_state(state);

    let mut engine = engine_with(&kp, &dir, host.clone(), true);
    let now = Utc::now();
    engine
        .handle_control(
            sync_bundle_msg(&kp, HOST, 1, vec![journal_watch("w-j", WatchClass::Baseline)]),
            now,
        )
        .await;

    let t0 = base_time();
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1000)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 1);
    match &emitted[0].payload {
        ObservationPayload::StreamBatch {
            events, cursor_after, ..
        } => {
            assert_eq!(events.len(), 1);
            assert_eq!(cursor_after.as_deref(), Some("c1"));
        }
        other => panic!("expected stream batch, got {other:?}"),
    }

    // Identical recurring text must NOT be suppressed on streams.
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1016)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 1, "streams always emit non-empty batches");

    // The durable cursor survived a restart: the next fetch must be asked
    // for --after-cursor c2.
    let mut engine2 = engine_with(&kp, &dir, host.clone(), true);
    assert_eq!(engine2.watch_ids(), vec!["w-j".to_string()]);
    engine2
        .run_due_watches(t0 + Duration::seconds(1032))
        .await;
    {
        let handle = host.state_handle();
        let guard = handle.lock().unwrap();
        let journal_calls: Vec<_> = guard
            .calls
            .iter()
            .filter(|c| c.collector == defsec_protocol::watch::CollectorType::JournalUnitEvents)
            .collect();
        assert_eq!(journal_calls.len(), 3);
        assert_eq!(journal_calls[0].cursor, None);
        assert_eq!(journal_calls[1].cursor.as_deref(), Some("c1"));
        assert_eq!(
            journal_calls[2].cursor.as_deref(),
            Some("c2"),
            "durable cursor must survive restart"
        );
    }

    // Gap event (scripted default): explicitly reported, never silent.
    let msgs = engine2.run_due_watches(t0 + Duration::seconds(1048)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 1, "gap events must emit");
    match &emitted[0].payload {
        ObservationPayload::StreamBatch {
            gap_detected, events, ..
        } => {
            assert!(gap_detected);
            assert!(events.is_empty());
        }
        other => panic!("expected stream batch, got {other:?}"),
    }
    assert!(!emitted[0].partial_reasons.is_empty());
}

#[tokio::test]
async fn collector_error_status_is_always_emitted_never_suppressed() {
    let kp = key_pair();
    let dir = state_dir("errors");

    let state = FakeHostState {
        sockets_status: Some(ObservationStatus::PermissionDenied),
        sockets_partial_reasons: vec!["hidepid=2 blocks /proc/<pid>/fd".into()],
        ..FakeHostState::default()
    };
    let host = FakeHostCollectors::from_state(state);

    let mut engine = engine_with(&kp, &dir, host, false);
    let now = Utc::now();
    engine
        .handle_control(sync_bundle_msg(&kp, HOST, 1, vec![sockets_watch("w1")]), now)
        .await;

    let t0 = base_time();
    for k in 0..3u64 {
        let msgs = engine
            .run_due_watches(t0 + Duration::seconds(1000 + (k as i64) * 16))
            .await;
        let emitted = deltas(&msgs);
        assert_eq!(emitted.len(), 1, "errors must never be suppressed");
        assert_eq!(emitted[0].status, ObservationStatus::PermissionDenied);
        assert!(!emitted[0].partial_reasons.is_empty());
    }
    let hb = match engine.make_heartbeat(Utc::now()) {
        AgentToControl::Heartbeat { watch_summaries, .. } => watch_summaries,
        other => panic!("expected heartbeat, got {other:?}"),
    };
    assert_eq!(hb[0].error_runs, 3);
    assert_eq!(hb[0].success_runs, 0);
}

#[tokio::test]
async fn collector_timeout_produces_explicit_timeout_status() {
    let kp = key_pair();
    let dir = state_dir("timeout");

    let state = FakeHostState {
        sleep_ms: Some(2_000), // watch timeout is 5s? No: make it 10x the cap.
        ..FakeHostState::default()
    };
    let host = FakeHostCollectors::from_state(state);

    let mut engine = engine_with(&kp, &dir, host, false);
    let now = Utc::now();
    // A watch with a 1-second timeout.
    let mut w = sockets_watch("w-timeout");
    w.schedule = WatchSchedule {
        interval_seconds: 15,
        timeout_seconds: 1,
    };
    engine
        .handle_control(sync_bundle_msg(&kp, HOST, 1, vec![w]), now)
        .await;

    let t0 = base_time();
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1000)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].status, ObservationStatus::Timeout);
    assert!(emitted[0].partial_reasons[0].contains("timed out"));
}

#[tokio::test]
async fn register_and_bundle_reload_from_state_dir() {
    let kp = key_pair();
    let dir = state_dir("reload");
    let now = Utc::now();
    {
        let mut engine = engine_with(&kp, &dir, fake_sockets_host(42), false);
        engine
            .handle_control(sync_bundle_msg(&kp, HOST, 9, vec![sockets_watch("w1")]), now)
            .await;
        let reg = engine.make_register(now);
        match &reg {
            AgentToControl::Register {
                active_bundle_version,
                active_bundle_digest,
                ..
            } => {
                assert_eq!(*active_bundle_version, 9);
                assert!(active_bundle_digest.is_some());
            }
            other => panic!("expected register, got {other:?}"),
        }
    }
    // Fresh process on the same state dir: the verified cached bundle is
    // reloaded (active_bundle_version preserved).
    let engine2 = engine_with(&kp, &dir, fake_sockets_host(42), false);
    assert_eq!(engine2.active_bundle_version(), 9);
    assert_eq!(engine2.watch_ids(), vec!["w1".to_string()]);
    let reg = engine2.make_register(now);
    match &reg {
        AgentToControl::Register {
            active_bundle_version,
            session_id,
            ..
        } => {
            assert_eq!(*active_bundle_version, 9);
            // New session per process start: restart differentiation.
            assert!(!session_id.is_empty());
        }
        other => panic!("expected register, got {other:?}"),
    }
}

fn scripted_new_collector_host() -> FakeHostState {
    use defsec_protocol::canonical::sha256_hex;
    FakeHostState {
        outbound: ConnectionsOutboundSnapshot {
            flows: vec![defsec_protocol::observation::OutboundFlowEntry {
                flow_key: "tcp:192.0.2.10:443:1000:curl".into(),
                protocol: "tcp".into(),
                remote_addr: "192.0.2.10".into(),
                remote_port: 443,
                uid: 1000,
                states: vec!["ESTABLISHED".into()],
                count: 3,
                comm: Some("curl".into()),
                systemd_unit: None,
                attribution: FlowAttribution::Full,
            }],
            total_flows: 1,
            attribution_partial: false,
            truncated: None,
            omitted_flows: None,
        },
        packages: PackagesInventorySnapshot {
            packages: vec![PackageInventoryEntry {
                package_key: "bash:amd64".into(),
                name: "bash".into(),
                arch: "amd64".into(),
                version: "5.2-3".into(),
            }],
            total_packages: 1,
            status_file_sha256: sha256_hex(&[]),
            malformed_stanzas: 0,
            truncated: None,
            omitted_packages: None,
        },
        ..FakeHostState::default()
    }
}

#[tokio::test]
async fn new_snapshot_collectors_produce_valid_observations_through_the_engine() {
    let kp = key_pair();
    let dir = state_dir("new-collectors");
    let host = FakeHostCollectors::from_state(scripted_new_collector_host());
    let mut engine = engine_with(&kp, &dir, host.clone(), false);
    let now = Utc::now();

    engine
        .handle_control(
            sync_bundle_msg(
                &kp,
                HOST,
                1,
                vec![outbound_watch("w-out"), packages_watch("w-pkg")],
            ),
            now,
        )
        .await;
    assert_eq!(
        engine.watch_ids(),
        vec!["w-out".to_string(), "w-pkg".to_string()]
    );

    let t0 = base_time();
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1000)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 2, "both snapshot collectors must sample");

    let out_obs = emitted
        .iter()
        .find(|o| o.watch_id == "w-out")
        .expect("outbound observation");
    assert_eq!(
        out_obs.collector_type,
        defsec_protocol::watch::CollectorType::ConnectionsOutbound
    );
    assert_eq!(out_obs.status, ObservationStatus::Ok);
    assert!(out_obs.is_reconciliation, "first sample is a checkpoint");
    let ObservationPayload::Snapshot { data } = &out_obs.payload else {
        panic!("expected snapshot payload for connections.outbound");
    };
    let snap: ConnectionsOutboundSnapshot = serde_json::from_value(data.clone()).unwrap();
    assert_eq!(snap.total_flows, 1);
    assert_eq!(snap.flows[0].count, 3);
    assert_eq!(snap.flows[0].flow_key, "tcp:192.0.2.10:443:1000:curl");
    assert_eq!(snap.flows[0].attribution, FlowAttribution::Full);
    assert_eq!(out_obs.state_hash.len(), 64);

    let pkg_obs = emitted
        .iter()
        .find(|o| o.watch_id == "w-pkg")
        .expect("packages observation");
    assert_eq!(
        pkg_obs.collector_type,
        defsec_protocol::watch::CollectorType::PackagesInventory
    );
    assert_eq!(pkg_obs.status, ObservationStatus::Ok);
    let ObservationPayload::Snapshot { data } = &pkg_obs.payload else {
        panic!("expected snapshot payload for packages.inventory");
    };
    let snap: PackagesInventorySnapshot = serde_json::from_value(data.clone()).unwrap();
    assert_eq!(snap.packages[0].package_key, "bash:amd64");
    assert_eq!(snap.status_file_sha256.len(), 64);
    assert_eq!(snap.malformed_stanzas, 0);

    // Both snapshot collectors follow the standard diffing rules: an
    // unchanged second sample is suppressed...
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1016)).await;
    assert!(deltas(&msgs).is_empty(), "unchanged snapshots are suppressed");

    // ...and reconciliation requests force a full re-observation.
    engine
        .handle_control(
            ControlToAgent::RequestReconciliation {
                host_id: HOST.into(),
                watch_ids: vec!["w-out".into(), "w-pkg".into()],
                reason: "operator requested".into(),
            },
            Utc::now(),
        )
        .await;
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1032)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 2);
    assert!(emitted.iter().all(|o| o.is_reconciliation));

    // Run summaries count both as successful valid samples.
    let hb = match engine.make_heartbeat(Utc::now()) {
        AgentToControl::Heartbeat { watch_summaries, .. } => watch_summaries,
        other => panic!("expected heartbeat, got {other:?}"),
    };
    for id in ["w-out", "w-pkg"] {
        let summary = hb.iter().find(|s| s.watch_id == id).unwrap();
        assert_eq!(summary.completed_runs, 3);
        assert_eq!(summary.success_runs, 3);
        assert_eq!(summary.error_runs, 0);
    }
}

#[tokio::test]
async fn truncated_outbound_snapshot_reports_partial_with_explicit_reason() {
    let kp = key_pair();
    let dir = state_dir("outbound-truncated");
    let mut state = scripted_new_collector_host();
    state.outbound.truncated = Some(true);
    state.outbound.omitted_flows = Some(900);
    state.outbound.total_flows = 901;
    state.outbound_status = Some(ObservationStatus::Partial);
    state.outbound_partial_reasons = vec!["outbound flow inventory of 901 groups exceeds cap 1: retained the first 1 by flow key and omitted 900".into()];
    let host = FakeHostCollectors::from_state(state);
    let mut engine = engine_with(&kp, &dir, host, false);
    let now = Utc::now();

    engine
        .handle_control(
            sync_bundle_msg(&kp, HOST, 1, vec![outbound_watch("w-out")]),
            now,
        )
        .await;

    let t0 = base_time();
    let msgs = engine.run_due_watches(t0 + Duration::seconds(1000)).await;
    let emitted = deltas(&msgs);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].status, ObservationStatus::Partial);
    assert!(!emitted[0].partial_reasons.is_empty());
    assert!(emitted[0].partial_reasons[0].contains("omitted 900"));
    let ObservationPayload::Snapshot { data } = &emitted[0].payload else {
        panic!("expected snapshot payload");
    };
    let snap: ConnectionsOutboundSnapshot = serde_json::from_value(data.clone()).unwrap();
    assert_eq!(snap.truncated, Some(true));
    assert_eq!(snap.omitted_flows, Some(900));
    assert_eq!(snap.total_flows, 901);
    // A Partial sample is still a usable (valid) sample for diffing.
    let hb = match engine.make_heartbeat(Utc::now()) {
        AgentToControl::Heartbeat { watch_summaries, .. } => watch_summaries,
        other => panic!("expected heartbeat, got {other:?}"),
    };
    assert_eq!(hb[0].success_runs, 1);
}

fn write_profile_file(dir: &Path, contents: &str) -> PathBuf {
    let path = dir.join("profile.json");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    path
}

#[tokio::test]
async fn profile_disabled_collector_bundle_is_rejected_with_explicit_reason() {
    let kp = key_pair();
    let dir = state_dir("profile-reject");
    let profile_dir = state_dir("profile-reject-file");
    let profile_path = write_profile_file(
        &profile_dir,
        r#"{
            "schema_version": 1,
            "host_tags": ["prod"],
            "enabled_collectors": ["sockets.listening"],
            "collector_caps": { "max_outbound_flows": 32 }
        }"#,
    );
    let loaded = load_profile(&profile_path, &EdgeSafetyConfig::default())
        .expect("valid profile file loads");
    assert!(!loaded
        .cfg
        .allowed_collectors
        .contains(&defsec_protocol::watch::CollectorType::ConnectionsOutbound));

    let mut engine = engine_with_cfg(&kp, &dir, fake_sockets_host(3), false, loaded.cfg.clone());
    let now = Utc::now();

    // A bundle containing a watch whose collector is disabled by the profile
    // is rejected through the existing BundleAck rejection path.
    let msgs = engine
        .handle_control(
            sync_bundle_msg(&kp, HOST, 2, vec![outbound_watch("w-out")]),
            now,
        )
        .await;
    match &msgs[0] {
        AgentToControl::BundleAck { status, reason, .. } => {
            assert_eq!(*status, BundleAckStatus::Rejected);
            let reason = reason.as_deref().unwrap();
            assert!(reason.contains("connections.outbound"), "reason: {reason}");
            assert!(reason.contains("not allowed by local safety floor"), "reason: {reason}");
        }
        other => panic!("expected BundleAck, got {other:?}"),
    }
    assert!(engine.watch_ids().is_empty());

    let msgs = engine
        .handle_control(
            sync_bundle_msg(&kp, HOST, 2, vec![packages_watch("w-pkg")]),
            now,
        )
        .await;
    match &msgs[0] {
        AgentToControl::BundleAck { status, reason, .. } => {
            assert_eq!(*status, BundleAckStatus::Rejected);
            assert!(reason.as_deref().unwrap().contains("packages.inventory"));
        }
        other => panic!("expected BundleAck, got {other:?}"),
    }

    // A bundle containing only still-enabled collectors is accepted.
    let msgs = engine
        .handle_control(
            sync_bundle_msg(&kp, HOST, 3, vec![sockets_watch("w-sock")]),
            now,
        )
        .await;
    assert!(matches!(
        &msgs[0],
        AgentToControl::BundleAck {
            status: BundleAckStatus::Accepted,
            ..
        }
    ));
    assert_eq!(engine.watch_ids(), vec!["w-sock".to_string()]);

    // The profile also tightened the outbound cap centrally mirrored bounds:
    // even if the collector were enabled, max_flows beyond 32 would fail.
    assert_eq!(loaded.cfg.max_outbound_flows, 32);
}

#[tokio::test]
async fn register_reports_host_profile_summary_when_present() {
    let kp = key_pair();
    let dir = state_dir("register-profile");

    // Without a profile the Register message omits the summary entirely.
    let mut engine = engine_with(&kp, &dir, fake_sockets_host(1), false);
    match engine.make_register(Utc::now()) {
        AgentToControl::Register { host_profile, .. } => assert_eq!(host_profile, None),
        other => panic!("expected register, got {other:?}"),
    }

    // With a profile applied, the summary rides along on Register.
    engine.set_host_profile_summary(Some(HostProfileSummary {
        host_tags: vec!["prod".into(), "dc:eu-west-1".into()],
        expected_services: vec!["sshd.service".into()],
        enabled_collectors: vec![
            defsec_protocol::watch::CollectorType::SocketsListening,
            defsec_protocol::watch::CollectorType::ConnectionsOutbound,
        ],
    }));
    match engine.make_register(Utc::now()) {
        AgentToControl::Register { host_profile, .. } => {
            let summary = host_profile.expect("profile summary on register");
            assert_eq!(summary.host_tags, vec!["prod".to_string(), "dc:eu-west-1".to_string()]);
            assert_eq!(summary.expected_services, vec!["sshd.service".to_string()]);
            assert!(summary
                .enabled_collectors
                .contains(&defsec_protocol::watch::CollectorType::ConnectionsOutbound));
        }
        other => panic!("expected register, got {other:?}"),
    }
}
