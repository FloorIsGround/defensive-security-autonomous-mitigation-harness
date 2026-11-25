use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use agent_d::{collectors::FakeHostCollectors, engine::AgentEngine, spool::DurabilityProfile};
use chrono::{TimeDelta, Utc};
use control_d::{ControlService, server::MtlsAgentServer};
use defsec_mtls::{
    MtlsAcceptor, MtlsClientStream, MtlsConnector, RevocationList,
    pki::{CaPem, init_ca, issue_host_cert, issue_server_cert},
};
use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::{
    rpc::{AdminRequest, AdminResponse, HostSummary, Severity},
    signing::VerifyingKeyStore,
    watch::*,
    wire::{AgentToControl, BundleAckStatus, ControlToAgent, read_frame, write_frame},
};
use tokio::{task::JoinHandle, time::timeout};

const HOST: &str = "edge-01";
const TIMEOUT: Duration = Duration::from_secs(5);

struct Fixture {
    dir: PathBuf,
    control: ControlService,
}

impl Fixture {
    fn new() -> Self {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let dir = std::env::temp_dir().join(format!("fleet-{}", &id[..12]));
        fs::create_dir(&dir).unwrap();
        let control = ControlService::open(dir.join("control"), "control-key-01", 1).unwrap();
        Self { dir, control }
    }

    fn enroll(&self, host_id: &str) -> VerifyingKeyStore {
        let AdminResponse::HostEnrolled {
            control_signing_key_id,
            control_public_key_hex,
            ..
        } = self.control.handle_admin_request(AdminRequest::EnrollHost {
            host_id: host_id.into(),
            agent_public_key_hex: None,
        })
        else {
            panic!("host enrollment failed");
        };
        let mut keys = VerifyingKeyStore::new();
        keys.insert_public_hex(&control_signing_key_id, &control_public_key_hex)
            .unwrap();
        keys
    }

    fn agent(&self, host_id: &str) -> AgentEngine<FakeHostCollectors> {
        AgentEngine::new(
            EdgeSafetyConfig::default(),
            host_id.into(),
            DurabilityProfile::Minimal {
                max_ram_bytes: 1024 * 1024,
            },
            self.dir.join(host_id),
            self.enroll(host_id),
            Arc::new(FakeHostCollectors::new()),
        )
        .unwrap()
    }

    fn status(&self, host_id: &str) -> HostSummary {
        let AdminResponse::Hosts { hosts } =
            self.control.handle_admin_request(AdminRequest::ListHosts)
        else {
            panic!("host lookup failed");
        };
        hosts
            .into_iter()
            .find(|host| host.host_id == host_id)
            .unwrap()
    }

    async fn serve_mtls(&self) -> Fleet {
        let ca = init_ca("Test Fleet CA", 7).unwrap();
        let server = issue_server_cert(
            &ca.cert_pem,
            &ca.key_pem,
            "control",
            &["localhost".into()],
            &[],
            2,
        )
        .unwrap();
        let ca_path = write_pem(&self.dir, "ca.crt", &ca.cert_pem);
        let revoked = self.dir.join("revoked_serials.json");
        let acceptor = MtlsAcceptor::from_pem_files(
            &ca_path,
            write_pem(&self.dir, "server.crt", &server.cert_pem),
            write_pem(&self.dir, "server.key", &server.key_pem),
            Some(revoked.clone()),
        )
        .unwrap();
        let server = MtlsAgentServer::bind("127.0.0.1:0".parse().unwrap(), acceptor)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let control = self.control.clone();
        let task = tokio::spawn(async move { server.serve_agent(control).await.unwrap() });
        Fleet {
            ca,
            ca_path,
            revoked,
            addr,
            task,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

struct Fleet {
    ca: CaPem,
    ca_path: PathBuf,
    revoked: PathBuf,
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Fleet {
    fn connector(&self, host: &str, issuer: &CaPem) -> (MtlsConnector, String) {
        let cert = issue_host_cert(&issuer.cert_pem, &issuer.key_pem, host, 2).unwrap();
        let dir = self.ca_path.parent().unwrap();
        let client = MtlsConnector::from_pem_files(
            &self.ca_path,
            write_pem(dir, "client.crt", &cert.cert_pem),
            write_pem(dir, "client.key", &cert.key_pem),
        )
        .unwrap();
        (client, cert.serial_hex)
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn write_pem(dir: &Path, name: &str, pem: &str) -> PathBuf {
    let path = dir.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(pem.as_bytes()).unwrap();
    path
}

async fn send(stream: &mut MtlsClientStream, msg: &AgentToControl) {
    timeout(TIMEOUT, write_frame(stream, msg))
        .await
        .unwrap()
        .unwrap();
}

async fn receive(stream: &mut MtlsClientStream) -> ControlToAgent {
    timeout(TIMEOUT, read_frame(stream))
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

async fn assert_registration_refused(
    fleet: &Fleet,
    connector: &MtlsConnector,
    register: AgentToControl,
) {
    timeout(TIMEOUT, async {
        // With TLS 1.3 a client may receive the server flight before server-side
        // client authentication has finished. Either way, it cannot register.
        if let Ok(mut stream) = connector.connect(fleet.addr, "localhost").await {
            let _ = write_frame(&mut stream, &register).await;
            assert!(!matches!(
                read_frame::<_, ControlToAgent>(&mut stream).await,
                Ok(Some(_))
            ));
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fleet_mtls_runs_agent_protocol_end_to_end() {
    let fixture = Fixture::new();
    let mut agent = fixture.agent(HOST);
    let spec = WatchSpec {
        id: "base-sockets".into(),
        version: 1,
        host_id: HOST.into(),
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
        fixture
            .control
            .handle_admin_request(AdminRequest::ApplyBaselineWatch {
                spec,
                actor: "ops".into(),
                rationale: "initial baseline".into(),
            }),
        AdminResponse::WatchApplied {
            bundle_version: 1,
            ..
        }
    ));
    let fleet = fixture.serve_mtls().await;
    let (connector, _) = fleet.connector(HOST, &fleet.ca);
    let mut stream = timeout(TIMEOUT, connector.connect(fleet.addr, "localhost"))
        .await
        .unwrap()
        .unwrap();
    let now = Utc::now();
    send(&mut stream, &agent.make_register(now)).await;
    let response = receive(&mut stream).await;
    assert!(matches!(
        response,
        ControlToAgent::RegisterAck { accepted: true, .. }
    ));
    assert!(agent.handle_control(response, now).await.is_empty());
    let response = receive(&mut stream).await;
    assert!(matches!(response, ControlToAgent::SyncWatchBundle { .. }));
    let replies = agent.handle_control(response, now).await;
    assert!(matches!(
        replies.as_slice(),
        [AgentToControl::BundleAck {
            status: BundleAckStatus::Accepted,
            ..
        }]
    ));
    send(&mut stream, &replies[0]).await;
    let response = receive(&mut stream).await;
    assert!(matches!(
        response,
        ControlToAgent::RequestReconciliation { .. }
    ));
    agent.handle_control(response, now).await;
    assert_eq!(agent.active_bundle_version(), 1);

    let sample_time = now + TimeDelta::seconds(30);
    let observations = agent.run_due_watches(sample_time).await;
    assert!(matches!(
        observations.as_slice(),
        [AgentToControl::PushObservationDelta { .. }]
    ));
    send(&mut stream, &observations[0]).await;
    let ack = receive(&mut stream).await;
    assert!(matches!(
        ack,
        ControlToAgent::ObservationAck {
            acked_seq_no: 1,
            ..
        }
    ));
    agent.handle_control(ack, sample_time).await;
    assert!(agent.pending_observations().is_empty());

    let registered_at = fixture.status(HOST).last_heartbeat_at;
    send(&mut stream, &agent.make_heartbeat(Utc::now())).await;
    timeout(TIMEOUT, async {
        loop {
            let status = fixture.status(HOST);
            if status.last_heartbeat_at > registered_at {
                assert_eq!(status.liveness_status, "online");
                assert_eq!(status.active_bundle_version, 1);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn certificate_cannot_register_another_host() {
    let fixture = Fixture::new();
    let spoofed = fixture.agent("edge-02");
    fixture.enroll(HOST);
    let fleet = fixture.serve_mtls().await;
    let (connector, _) = fleet.connector(HOST, &fleet.ca);
    assert_registration_refused(&fleet, &connector, spoofed.make_register(Utc::now())).await;
    let status = fixture.status("edge-02");
    assert_eq!(status.liveness_status, "enrolled");
    assert!(status.last_heartbeat_at.is_none());
}

#[tokio::test]
async fn newly_revoked_certificate_cannot_reconnect() {
    let fixture = Fixture::new();
    let agent = fixture.agent(HOST);
    let fleet = fixture.serve_mtls().await;
    let (connector, serial) = fleet.connector(HOST, &fleet.ca);
    let mut first = timeout(TIMEOUT, connector.connect(fleet.addr, "localhost"))
        .await
        .unwrap()
        .unwrap();
    send(&mut first, &agent.make_register(Utc::now())).await;
    assert!(matches!(
        receive(&mut first).await,
        ControlToAgent::RegisterAck { accepted: true, .. }
    ));
    let original_contact = fixture.status(HOST).last_heartbeat_at;
    RevocationList::revoke(&fleet.revoked, &serial, Some("test revocation")).unwrap();
    assert_registration_refused(&fleet, &connector, agent.make_register(Utc::now())).await;
    assert_eq!(fixture.status(HOST).last_heartbeat_at, original_contact);
}

#[tokio::test]
async fn untrusted_client_certificate_cannot_register() {
    let fixture = Fixture::new();
    let agent = fixture.agent(HOST);
    let fleet = fixture.serve_mtls().await;
    let rogue = init_ca("Untrusted CA", 7).unwrap();
    let (connector, _) = fleet.connector(HOST, &rogue);
    assert_registration_refused(&fleet, &connector, agent.make_register(Utc::now())).await;
    assert_eq!(fixture.status(HOST).liveness_status, "enrolled");
}

#[test]
fn watchdog_tracks_offline_and_recovery_with_one_open_incident() {
    let fixture = Fixture::new();
    let agent = fixture.agent(HOST);
    fixture.enroll("never-connected");
    let control = &fixture.control;
    assert!(matches!(
        control
            .handle_agent_message(agent.make_register(Utc::now()))
            .first(),
        Some(ControlToAgent::RegisterAck { accepted: true, .. })
    ));
    control.handle_agent_message(agent.make_heartbeat(Utc::now()));
    let t0 = fixture.status(HOST).last_heartbeat_at.unwrap();

    assert!(
        control
            .sweep_stale_hosts(t0 + TimeDelta::seconds(90), 90)
            .unwrap()
            .is_empty()
    );
    let stale_time = t0 + TimeDelta::seconds(120);
    assert_eq!(control.sweep_stale_hosts(stale_time, 90).unwrap(), [HOST]);
    assert_eq!(fixture.status(HOST).liveness_status, "offline");
    assert_eq!(
        fixture.status("never-connected").liveness_status,
        "enrolled"
    );
    assert!(
        control
            .sweep_stale_hosts(stale_time, 90)
            .unwrap()
            .is_empty()
    );

    control.handle_agent_message(agent.make_heartbeat(Utc::now()));
    assert_eq!(fixture.status(HOST).liveness_status, "online");
    let recovery = fixture.status(HOST).last_heartbeat_at.unwrap();
    assert_eq!(
        control
            .sweep_stale_hosts(recovery + TimeDelta::seconds(120), 90)
            .unwrap(),
        [HOST]
    );
    control.handle_agent_message(agent.make_register(Utc::now()));
    assert_eq!(fixture.status(HOST).liveness_status, "online");

    let AdminResponse::Incidents { incidents } =
        control.handle_admin_request(AdminRequest::ListIncidents)
    else {
        panic!("could not list incidents");
    };
    let [incident] = incidents.as_slice() else {
        panic!("expected one open liveness incident")
    };
    assert_eq!(incident.priority, Severity::High);
    assert_eq!(incident.status, "open");
    assert!(incident.summary.contains("missed heartbeats"));
    let AdminResponse::AuditEntries { entries } =
        control.handle_admin_request(AdminRequest::ListAuditEntries { limit: None })
    else {
        panic!("could not list audit entries");
    };
    let offline: Vec<_> = entries
        .iter()
        .filter(|entry| entry.payload["action"] == "host_liveness_offline")
        .collect();
    assert_eq!(offline.len(), 2);
    for entry in offline {
        assert_eq!(entry.payload["host_id"], HOST);
        assert_eq!(entry.payload["incident_id"], incident.incident_id);
    }
    assert!(matches!(
        control.handle_admin_request(AdminRequest::VerifyAuditChain),
        AdminResponse::AuditChainStatus { valid: true, .. }
    ));
}
