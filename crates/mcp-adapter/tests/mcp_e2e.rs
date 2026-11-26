use std::{fs, io, path::PathBuf, time::Duration};

use chrono::Utc;
use control_d::{
    ControlService,
    server::{SocketPolicy, UnixServer},
};
use defsec_protocol::{
    canonical::canonical_sha256_hex,
    observation::{ObservationPayload, ObservationRecord, ObservationStatus},
    rpc::{
        AdminRequest, AdminResponse, InvestigationCall, InvestigationRequest as Request,
        InvestigationResponse as Response, PrincipalRole, RunOutcome, RunTerminalStatus,
    },
    watch::{CollectorType, WatchSpec},
    wire::{AgentToControl, ControlToAgent, WIRE_PROTOCOL_VERSION},
};
use mcp_adapter::{McpServer, Mode};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf},
    task::JoinHandle,
    time::timeout,
};

const HOST: &str = "edge";
const READ_TOOLS: &[&str] = &[
    "correlate_package_snapshots",
    "get_host_discovery_samples",
    "list_host_interpretation_attempts",
    "get_host_assessment",
    "list_hosts",
    "list_active_incidents",
    "list_active_watches",
    "list_collector_capabilities",
    "list_watch_followups",
    "get_incident_context",
    "query_observations",
    "get_host_baseline_summary",
    "list_investigation_runs",
    "get_run_events",
    "list_trigger_queue",
    "get_action_verification",
    "list_actions",
    "list_expectation_rules",
];
const WRITE_TOOLS: &[&str] = &[
    "advance_host_discovery",
    "start_investigation_run",
    "monitoring",
    "propose_ephemeral_watch",
    "record_hypothesis_or_finding",
    "activate_expectation_rule",
    "propose_expectation_rule",
];

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let tmp = std::env::temp_dir();
        let candidate = if tmp.as_os_str().len() <= 75 {
            tmp.join(format!("dp{id}"))
        } else {
            std::path::Path::new("/tmp").join(format!("dp{id}"))
        };
        let path = match fs::create_dir(&candidate) {
            Ok(()) => candidate,
            Err(_) => {
                let fallback = tmp.join(format!("dp{id}"));
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

struct Client {
    input: BufReader<ReadHalf<DuplexStream>>,
    output: WriteHalf<DuplexStream>,
    token: String,
    task: JoinHandle<io::Result<()>>,
    next_id: u64,
}

impl Client {
    fn new(mode: Mode, socket: PathBuf, token: String) -> Self {
        let server = McpServer::new(mode, socket, token.clone(), Duration::from_secs(2));
        let (client, server_io) = tokio::io::duplex(4096);
        let (input, output) = tokio::io::split(server_io);
        let task = tokio::spawn(async move { server.serve(BufReader::new(input), output).await });
        let (input, output) = tokio::io::split(client);
        Self {
            input: BufReader::new(input),
            output,
            token,
            task,
            next_id: 1,
        }
    }

    async fn send(&mut self, frame: Value) {
        self.output
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
            .await;
        let mut line = String::new();
        let bytes = timeout(Duration::from_secs(3), self.input.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert!(bytes > 0);
        assert!(
            !line.contains(&self.token),
            "response exposed capability token"
        );
        let frame: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(frame["jsonrpc"], "2.0");
        assert_eq!(frame["id"], id);
        frame
    }

    async fn handshake(&mut self, version: &str, tools: &[&str]) {
        let reply = self
            .request(
                "initialize",
                json!({
                    "protocolVersion":version, "capabilities":{},
                    "clientInfo":{"name":"test", "version":"1"}
                }),
            )
            .await;
        assert_eq!(
            reply["result"],
            json!({
                "protocolVersion":version,
                "capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"defsecautmit-mcp", "version":env!("CARGO_PKG_VERSION")}
            })
        );
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        assert_eq!(self.request("ping", json!({})).await["result"], json!({}));
        let reply = self.request("tools/list", json!({})).await;
        let descriptors = reply["result"]["tools"].as_array().unwrap();
        let names: Vec<_> = descriptors
            .iter()
            .map(|tool| {
                assert_eq!(tool["inputSchema"]["type"], "object");
                assert_eq!(tool["inputSchema"]["additionalProperties"], false);
                tool["name"].as_str().unwrap()
            })
            .collect();
        assert_eq!(names, tools);
    }

    async fn tool(&mut self, name: &str, arguments: Value, is_error: bool) -> Value {
        let reply = self
            .request("tools/call", json!({"name":name,"arguments":arguments}))
            .await;
        let result = &reply["result"];
        assert_eq!(result["isError"], is_error, "{reply}");
        assert_eq!(result["content"][0]["type"], "text");
        serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn read_only_handshake_and_local_rejection() {
    let dir = TestDir::new();
    let path = dir.0.join("investigate.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut client = Client::new(Mode::default(), path, "test-capability-token".into());
    client.handshake("2024-11-05", READ_TOOLS).await;

    for name in WRITE_TOOLS.iter().copied().chain([
        "enroll",
        "promote_baseline",
        "apply_baseline_watch",
        "close_incident",
        "mint_token",
        "lease_next_trigger",
        "complete_trigger_lease",
        "fail_trigger_lease",
        "report_run_progress",
        "finish_investigation_run",
    ]) {
        let reply = client
            .request("tools/call", json!({"name":name,"arguments":{}}))
            .await;
        assert_eq!(reply["error"]["code"], -32602);
        assert_eq!(
            reply["error"]["message"],
            "Tool is unavailable in this mode"
        );
    }
    for (name, arguments) in [
        ("list_hosts", json!({"op":"start_investigation_run"})),
        ("list_hosts", json!({"extra":false})),
        ("list_hosts", json!({"limit":-1})),
        ("list_active_watches", json!({})),
        (
            "query_observations",
            json!({"host_id":HOST,"since":"yesterday"}),
        ),
    ] {
        let reply = client
            .request("tools/call", json!({"name":name,"arguments":arguments}))
            .await;
        assert_eq!(reply["error"]["code"], -32602);
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

fn baseline() -> Value {
    json!({
        "id":"unit", "version":1, "host_id":HOST, "class":"baseline",
        "collector":{"type":"systemd.unit_state","parameters":{"unit":"sshd.service","hash_unit_files":false}},
        "schedule":{"interval_seconds":30,"timeout_seconds":5},
        "trigger":{"type":"field_changed","compare_against":"last_observed","fields":["active_state"]},
        "wake_policy":{"cooldown_seconds":60,"max_wakeups_per_hour":4},
        "lifecycle":{"enabled":true}
    })
}

fn sockets_baseline() -> Value {
    json!({
        "id":"listeners", "version":1, "host_id":HOST, "class":"baseline",
        "collector":{"type":"sockets.listening","parameters":{"include_tcp":true,"include_udp":false,"include_ipv6":true,"resolve_process":true}},
        "schedule":{"interval_seconds":30,"timeout_seconds":5},
        "trigger":{"type":"set_diff","compare_against":"last_observed","set_field":"sockets",
                   "identity_key":"socket_key","ignore_fields":["inode","pid","pid_start_time_ticks"]},
        "wake_policy":{"cooldown_seconds":60,"max_wakeups_per_hour":4},
        "lifecycle":{"enabled":true}
    })
}

fn socket_entry(key: &str, port: u16, unit: &str) -> Value {
    json!({
        "socket_key":key, "protocol":"tcp", "local_addr":"127.0.0.5", "local_port":port,
        "uid":1000, "inode":3, "systemd_unit":unit
    })
}

fn seed_sockets_incident(service: &ControlService) {
    assert!(matches!(
        service.handle_admin_request(AdminRequest::EnrollHost {
            host_id: HOST.into(),
            agent_public_key_hex: None,
        }),
        AdminResponse::HostEnrolled { .. }
    ));
    assert!(matches!(
        service.handle_admin_request(AdminRequest::ApplyBaselineWatch {
            spec: serde_json::from_value::<WatchSpec>(sockets_baseline()).unwrap(),
            actor: "operator".into(),
            rationale: "monitor local listeners".into(),
        }),
        AdminResponse::WatchApplied { .. }
    ));
    let replies = service.handle_agent_message(AgentToControl::Register {
        protocol_version: WIRE_PROTOCOL_VERSION,
        host_id: HOST.into(),
        agent_version: "test".into(),
        boot_id: "boot".into(),
        session_id: "session".into(),
        active_bundle_version: 0,
        active_bundle_digest: None,
        sent_at: Utc::now(),
        host_profile: None,
    });
    assert!(matches!(
        replies.first(),
        Some(ControlToAgent::RegisterAck { accepted: true, .. })
    ));
    let snapshots = [
        vec![socket_entry("tcp:127.0.0.5:22", 22, "sshd.service")],
        vec![
            socket_entry("tcp:127.0.0.5:22", 22, "sshd.service"),
            socket_entry("tcp:127.0.0.5:4002", 4002, "nxserver.service"),
        ],
    ];
    for (index, sockets) in snapshots.into_iter().enumerate() {
        let seq_no = index as u64 + 1;
        let data = json!({"count":sockets.len(), "partial_attribution":false, "sockets":sockets});
        let observation = ObservationRecord {
            host_id: HOST.into(),
            session_id: "session".into(),
            seq_no,
            watch_id: "listeners".into(),
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
        let replies =
            service.handle_agent_message(AgentToControl::PushObservationDelta { observation });
        assert!(matches!(replies.as_slice(),
            [ControlToAgent::ObservationAck { acked_seq_no, .. }] if *acked_seq_no == seq_no));
    }
}

fn expectation_rule(expires_at: Option<Value>) -> Value {
    let mut rule = json!({
        "scope":{"host_id":HOST,"collector":"sockets.listening"},
        "matches":[
            {"op":"eq","field":"systemd_unit","value":"nxserver.service"},
            {"op":"eq","field":"bind_scope","value":"loopback"},
            {"op":"range","field":"local_port","min":4000,"max":4100}
        ],
        "effect":"allow_optional",
        "rationale":"expected local service listener"
    });
    if let Some(expires_at) = expires_at {
        rule["expires_at"] = expires_at;
    }
    rule
}

fn seed_incident(service: &ControlService) {
    assert!(matches!(
        service.handle_admin_request(AdminRequest::EnrollHost {
            host_id: HOST.into(),
            agent_public_key_hex: None,
        }),
        AdminResponse::HostEnrolled { .. }
    ));
    assert!(matches!(
        service.handle_admin_request(AdminRequest::ApplyBaselineWatch {
            spec: serde_json::from_value::<WatchSpec>(baseline()).unwrap(),
            actor: "operator".into(),
            rationale: "monitor service state".into(),
        }),
        AdminResponse::WatchApplied { .. }
    ));
    let replies = service.handle_agent_message(AgentToControl::Register {
        protocol_version: WIRE_PROTOCOL_VERSION,
        host_id: HOST.into(),
        agent_version: "test".into(),
        boot_id: "boot".into(),
        session_id: "session".into(),
        active_bundle_version: 0,
        active_bundle_digest: None,
        sent_at: Utc::now(),
        host_profile: None,
    });
    assert!(matches!(
        replies.first(),
        Some(ControlToAgent::RegisterAck { accepted: true, .. })
    ));
    for (seq_no, state) in [(1, "active"), (2, "inactive")] {
        let data = json!({"unit":"sshd.service", "active_state":state});
        let observation = ObservationRecord {
            host_id: HOST.into(),
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
        };
        let replies =
            service.handle_agent_message(AgentToControl::PushObservationDelta { observation });
        assert!(matches!(replies.as_slice(),
            [ControlToAgent::ObservationAck {acked_seq_no, ..}] if *acked_seq_no == seq_no));
    }
}

#[tokio::test]
async fn investigator_flow_preserves_controller_decisions() {
    let dir = TestDir::new();
    let service = ControlService::open(&dir.0, "key", 1).unwrap();
    seed_incident(&service);
    let AdminResponse::Incidents { incidents } =
        service.handle_admin_request(AdminRequest::ListIncidents)
    else {
        panic!("could not discover fixture incident")
    };
    assert_eq!(incidents.len(), 1);
    let incident_id = &incidents[0].incident_id;
    let AdminResponse::TokenMinted { token, .. } =
        service.handle_admin_request(AdminRequest::MintCapabilityToken {
            may_spawn_runs: false,
            principal_id: "operator".into(),
            role: PrincipalRole::Investigator,
            allowed_hosts: vec![HOST.into()],
            allowed_purposes: None,
            allowed_collectors: vec![
                CollectorType::SystemdUnitState,
                CollectorType::FilesMetadata,
            ],
            incident_id: Some(incident_id.clone()),
            ttl_seconds: 300,
        })
    else {
        panic!("could not mint fixture token")
    };
    let AdminResponse::TokenMinted {
        token: observer_token,
        ..
    } = service.handle_admin_request(AdminRequest::MintCapabilityToken {
        may_spawn_runs: false,
        principal_id: "observer".into(),
        role: PrincipalRole::Observer,
        allowed_hosts: vec![HOST.into()],
        allowed_purposes: None,
        allowed_collectors: vec![CollectorType::SystemdUnitState],
        incident_id: Some(incident_id.clone()),
        ttl_seconds: 300,
    })
    else {
        panic!("could not mint observer token");
    };
    let socket = dir.0.join("investigate.sock");
    let server = UnixServer::bind(&socket, SocketPolicy::default()).unwrap();
    let server_task = tokio::spawn(server.serve_investigation(service));
    let mut client = Client::new(Mode::Investigator, socket.clone(), token);
    client
        .handshake("2025-03-26", &[READ_TOOLS, WRITE_TOOLS].concat())
        .await;

    let assessment = client.tool("get_host_assessment", json!({"host_id":HOST}), false).await;
    assert_eq!(assessment["assessment"]["host_id"], HOST);
    assert_eq!(assessment["assessment"]["version"], 1);
    let monitoring = client.tool(
        "monitoring",
        json!({"host_id":HOST,"watch_id":"unit","change":{"operation":"inspect"}}),
        false,
    ).await;
    assert_eq!(monitoring["detail"]["allowed"], false);

    let samples = client
        .tool("get_host_discovery_samples", json!({"host_id":HOST}), true)
        .await;
    assert_eq!(samples["code"], "forbidden");
    let correlation = client
        .tool(
            "correlate_package_snapshots",
            json!({"host_ids":[HOST,"other"],"package_name":"openssl","max_age_seconds":120}),
            true,
        )
        .await;
    assert_eq!(correlation["code"], "forbidden");
    let hosts = client.tool("list_hosts", json!({}), false).await;
    assert_eq!(hosts["hosts"][0]["host_id"], HOST);
    let filtered_hosts = client
        .tool("list_hosts", json!({"tag":"unreported"}), false)
        .await;
    assert_eq!(filtered_hosts["hosts"], json!([]));
    let incidents = client
        .tool("list_active_incidents", json!({"host_id":HOST}), false)
        .await;
    assert_eq!(incidents["incidents"][0]["incident_id"], *incident_id);
    let context = client
        .tool(
            "get_incident_context",
            json!({"incident_id":incident_id}),
            false,
        )
        .await;
    assert_eq!(context["incident"]["incident_id"], *incident_id);
    let evidence = &context["recent_observations"][0]["observation_id"];
    assert!(evidence.is_i64());
    let caps = client
        .tool(
            "list_collector_capabilities",
            json!({"host_id":HOST}),
            false,
        )
        .await;
    assert!(
        caps["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|cap| cap["collector_type"] == "files.metadata")
    );
    let run = client.tool("start_investigation_run", json!({
        "incident_id":incident_id, "backend_id":"mcp", "model_id":"fixture", "prompt_schema_version":"1"
    }), false).await;
    let run_id = run["run_id"].as_str().unwrap();
    for name in ["report_run_progress", "finish_investigation_run"] {
        let reply = client
            .request("tools/call", json!({"name":name,"arguments":{}}))
            .await;
        assert_eq!(
            reply["error"]["message"],
            "Tool is unavailable in this mode"
        );
    }
    let runs = client
        .tool("list_investigation_runs", json!({}), false)
        .await;
    assert_eq!(runs["runs"][0]["run_id"], run_id);

    let mut follow_up = baseline();
    follow_up["id"] = json!("follow-up");
    follow_up["class"] = json!("ephemeral");
    follow_up["incident_id"] = json!(incident_id);
    follow_up["collector"]["parameters"]["unit"] = json!("nginx.service");
    follow_up["lifecycle"]["expires_at"] = json!(Utc::now() + chrono::Duration::minutes(15));
    follow_up["lifecycle"]["max_runs"] = json!(20);
    let proposal = |key, spec| {
        json!({
            "idempotency_key":key, "spec":spec, "rationale":"inspect related state"
        })
    };
    let accepted = client
        .tool(
            "propose_ephemeral_watch",
            proposal("valid", follow_up.clone()),
            false,
        )
        .await;
    assert_eq!(accepted["decision"]["allowed"], true);
    assert_eq!(accepted["watch_id"], "follow-up");

    follow_up["id"] = json!("sensitive");
    follow_up["collector"] =
        json!({"type":"files.metadata", "parameters":{"paths":["/etc/shadow"]}});
    for (key, spec, rule_id, reason) in [
        (
            "sensitive",
            follow_up,
            "spec.safety_floor",
            "invalid watch 'sensitive': file path '/etc/shadow' is blocked by local sensitive path denylist",
        ),
        (
            "baseline",
            baseline(),
            "baseline.protected",
            "reasoning/investigator identities cannot create or modify baseline watches",
        ),
    ] {
        let denied = client
            .tool("propose_ephemeral_watch", proposal(key, spec), false)
            .await;
        assert_eq!(denied["result"], "proposal_evaluated");
        assert_eq!(
            denied["decision"],
            json!({
                "allowed":false, "rule_id":rule_id, "reason":reason, "policy_version":1
            })
        );
        assert!(denied["watch_id"].is_null());
    }

    let finding = |evidence: Value| {
        json!({
            "incident_id":incident_id, "kind":"hypothesis", "severity":"medium",
            "summary":"Service state changed", "uncertainty":"Cause unknown",
            "evidence_observation_ids":[evidence], "escalation_requested":false
        })
    };
    let recorded = client
        .tool(
            "record_hypothesis_or_finding",
            finding(evidence.clone()),
            false,
        )
        .await;
    assert_eq!(recorded["verified_evidence_count"], 1);
    let invalid = client
        .tool("record_hypothesis_or_finding", finding(json!(-1)), true)
        .await;
    assert_eq!(invalid["result"], "error");
    assert_eq!(
        invalid["message"],
        "observation evidence is missing or outside incident scope"
    );

    let mut observer = Client::new(Mode::ReadOnly, socket.clone(), observer_token);
    let watches = observer
        .tool("list_active_watches", json!({"host_id":HOST}), false)
        .await;
    assert!(
        watches["watches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|watch| watch["id"] == "unit")
    );
    let observations = observer
        .tool(
            "query_observations",
            json!({
                "host_id":HOST, "watch_id":"unit", "limit":1
            }),
            false,
        )
        .await;
    assert_eq!(observations["observations"][0]["observation_id"], *evidence);
    let baseline = observer
        .tool("get_host_baseline_summary", json!({"host_id":HOST}), false)
        .await;
    assert_eq!(baseline["host_id"], HOST);

    let runs = observer
        .tool("list_investigation_runs", json!({"limit":1}), false)
        .await;
    assert_eq!(runs["runs"][0]["findings_count"], 1);
    assert_eq!(runs["runs"][0]["proposals_count"], 3);
    let events = observer
        .tool(
            "get_run_events",
            json!({"run_id":run_id,"after_seq":0}),
            false,
        )
        .await;
    assert_eq!(events["events"], json!([]));
    let queue = observer
        .tool("list_trigger_queue", json!({"statuses":["pending"]}), false)
        .await;
    assert_eq!(queue["triggers"][0]["incident_id"], *incident_id);
    assert!(queue["triggers"][0].get("lease_token").is_none());

    let mut unauthorized = Client::new(Mode::ReadOnly, socket, "invalid-capability-token".into());
    assert_eq!(
        unauthorized.tool("list_hosts", json!({}), true).await["result"],
        "error"
    );
    server_task.abort();
    assert!(server_task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn investigator_proposes_expectation_rule_for_current_run() {
    let dir = TestDir::new();
    let service = ControlService::open(&dir.0, "key", 1).unwrap();
    seed_sockets_incident(&service);
    let AdminResponse::Incidents { incidents } =
        service.handle_admin_request(AdminRequest::ListIncidents)
    else {
        panic!("could not discover fixture incident")
    };
    assert_eq!(incidents.len(), 1);
    let incident_id = incidents[0].incident_id.clone();
    let AdminResponse::TokenMinted { token, .. } =
        service.handle_admin_request(AdminRequest::MintCapabilityToken {
            may_spawn_runs: false,
            principal_id: "investigator".into(),
            role: PrincipalRole::Investigator,
            allowed_hosts: vec![HOST.into()],
            allowed_purposes: None,
            allowed_collectors: vec![CollectorType::SocketsListening],
            incident_id: Some(incident_id.clone()),
            ttl_seconds: 300,
        })
    else {
        panic!("could not mint fixture token")
    };
    let AdminResponse::TokenMinted {
        token: observer_token,
        ..
    } = service.handle_admin_request(AdminRequest::MintCapabilityToken {
        may_spawn_runs: false,
        principal_id: "observer".into(),
        role: PrincipalRole::Observer,
        allowed_hosts: vec![HOST.into()],
        allowed_purposes: None,
        allowed_collectors: vec![CollectorType::SocketsListening],
        incident_id: Some(incident_id.clone()),
        ttl_seconds: 300,
    })
    else {
        panic!("could not mint observer token")
    };
    let socket = dir.0.join("investigate.sock");
    let server = UnixServer::bind(&socket, SocketPolicy::default()).unwrap();
    let server_task = tokio::spawn(server.serve_investigation(service));
    let mut client = Client::new(Mode::Investigator, socket.clone(), token);
    client
        .handshake("2025-03-26", &[READ_TOOLS, WRITE_TOOLS].concat())
        .await;

    // Before any run exists the proposal is refused locally...
    let reply = client
        .request(
            "tools/call",
            json!({"name":"propose_expectation_rule","arguments":{
                "idempotency_key":"early","rule":expectation_rule(None)
            }}),
        )
        .await;
    assert_eq!(reply["error"]["code"], -32602);
    assert_eq!(
        reply["error"]["message"],
        "No investigation run is active; call start_investigation_run first"
    );
    // ... and the caller cannot choose the run binding.
    let reply = client
        .request(
            "tools/call",
            json!({"name":"propose_expectation_rule","arguments":{
                "run_id":"run-x","idempotency_key":"early","rule":expectation_rule(None)
            }}),
        )
        .await;
    assert_eq!(reply["error"]["code"], -32602);
    assert_eq!(
        reply["error"]["message"],
        "run_id is bound to the adapter's current investigation run"
    );

    let run = client
        .tool(
            "start_investigation_run",
            json!({
                "incident_id":incident_id, "backend_id":"mcp",
                "model_id":"fixture", "prompt_schema_version":"1"
            }),
            false,
        )
        .await;
    let run_id = run["run_id"].as_str().unwrap().to_string();

    let accepted = client
        .tool(
            "propose_expectation_rule",
            json!({
                "idempotency_key":"nx",
                "rule":expectation_rule(Some(json!(Utc::now() + chrono::Duration::days(3))))
            }),
            false,
        )
        .await;
    assert_eq!(accepted["result"], "rule_proposal_evaluated");
    assert_eq!(accepted["decision"]["allowed"], true);
    assert_eq!(accepted["decision"]["policy_version"], 1);
    let rule_id = accepted["rule_id"].as_str().unwrap().to_string();
    assert!(rule_id.starts_with("rule-"));
    let activation = client
        .tool("activate_expectation_rule", json!({"rule_id":rule_id}), false)
        .await;
    assert_eq!(activation["result"], "rule_activation_evaluated");
    assert_eq!(activation["decision"]["allowed"], false);
    assert!(activation["backtest"].is_null());
    assert_eq!(
        accepted["backtest"],
        json!({
            "observations_scanned":2, "triggered_before":1, "triggered_after":0,
            "items_matched":1, "sample_keys":["tcp:127.0.0.5:4002"],
            "currently_matching":1
        })
    );

    // A gate denial surfaces as a decision, not a crash: investigator rules
    // must carry an expiry within 30 days.
    let denied = client
        .tool(
            "propose_expectation_rule",
            json!({"idempotency_key":"no-expiry","rule":expectation_rule(None)}),
            false,
        )
        .await;
    assert_eq!(denied["result"], "rule_proposal_evaluated");
    assert_eq!(denied["decision"]["allowed"], false);
    assert_eq!(
        denied["decision"]["rule_id"],
        "rule-gate/investigator-expiry"
    );
    assert!(denied["rule_id"].is_null());
    assert!(denied["backtest"].is_null());

    // Unknown rule fields are rejected against the closed typed schema.
    let mut unknown = expectation_rule(Some(json!(Utc::now() + chrono::Duration::days(3))));
    unknown["rationale_backup"] = json!("not part of the schema");
    let reply = client
        .request(
            "tools/call",
            json!({"name":"propose_expectation_rule","arguments":{
                "idempotency_key":"unknown-field","rule":unknown
            }}),
        )
        .await;
    assert_eq!(reply["error"]["code"], -32602);

    let listed = client
        .tool(
            "list_expectation_rules",
            json!({"statuses":["proposed"]}),
            false,
        )
        .await;
    assert_eq!(listed["result"], "expectation_rules");
    let rules = listed["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["rule_id"], *rule_id);
    assert_eq!(rules[0]["status"], "proposed");
    assert_eq!(rules[0]["origin"], "investigator");
    assert_eq!(rules[0]["run_id"], *run_id);
    assert_eq!(rules[0]["incident_id"], *incident_id);
    assert_eq!(rules[0]["spec"]["matches"][0]["value"], "nxserver.service");
    assert_eq!(rules[0]["backtest"]["observations_scanned"], 2);
    assert_eq!(rules[0]["hit_count"], 0);

    // An invalid status filter surfaces as a tool error, not a crash.
    let invalid = client
        .tool(
            "list_expectation_rules",
            json!({"statuses":["bogus"]}),
            true,
        )
        .await;
    assert_eq!(invalid["result"], "error");
    assert_eq!(invalid["code"], "invalid_request");
    assert_eq!(invalid["message"], "unknown expectation rule status");

    // Read-only mode lists the same scoped rules but cannot propose.
    let mut observer = Client::new(Mode::ReadOnly, socket.clone(), observer_token);
    observer.handshake("2024-11-05", READ_TOOLS).await;
    let observed = observer
        .tool("list_expectation_rules", json!({"host_id":HOST}), false)
        .await;
    assert_eq!(observed["rules"][0]["rule_id"], *rule_id);
    let reply = observer
        .request(
            "tools/call",
            json!({"name":"propose_expectation_rule","arguments":{}}),
        )
        .await;
    assert_eq!(reply["error"]["code"], -32602);
    assert_eq!(
        reply["error"]["message"],
        "Tool is unavailable in this mode"
    );
    server_task.abort();
    assert!(server_task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn binary_uses_stdio_and_requires_credentials() {
    use std::process::Stdio;
    use tokio::process::Command;

    let dir = TestDir::new();
    let token_file = dir.0.join("token");
    let token = "fixture-token-from-file";
    fs::write(&token_file, format!("{token}\n")).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-adapter"));
    command
        .env_remove("DEFSEC_CAPABILITY_TOKEN")
        .kill_on_drop(true);
    let missing = timeout(Duration::from_secs(3), command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("provide a capability token"));

    let mut child = command
        .arg("--token-file")
        .arg(token_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
        .await
        .unwrap();
    let output = timeout(Duration::from_secs(3), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(token));
    let frame: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        frame["result"]["tools"].as_array().unwrap().len(),
        READ_TOOLS.len()
    );
}

fn mint_operator_fixture(service: &ControlService, spawn: bool, hosts: &[&str]) -> String {
    let AdminResponse::TokenMinted { token, .. } =
        service.handle_admin_request(AdminRequest::MintCapabilityToken {
            principal_id: "operator".into(),
            role: PrincipalRole::Investigator,
            allowed_hosts: hosts.iter().map(|host| (*host).into()).collect(),
            allowed_purposes: None,
            allowed_collectors: vec![CollectorType::SocketsListening],
            incident_id: None,
            ttl_seconds: 300,
            may_spawn_runs: spawn,
        })
    else {
        panic!("could not mint operator fixture")
    };
    token
}

fn fixture_incident(service: &ControlService) -> String {
    let AdminResponse::Incidents { incidents } =
        service.handle_admin_request(AdminRequest::ListIncidents)
    else {
        panic!("could not list incidents")
    };
    incidents[0].incident_id.clone()
}

fn direct(service: &ControlService, token: &str, request: Request) -> Response {
    service.handle_investigation_call(InvestigationCall {
        request_id: uuid::Uuid::new_v4().to_string(),
        capability_token: token.into(),
        request,
    })
}

#[tokio::test]
async fn operator_routes_delayed_calls_to_named_run_and_reports_lifecycle() {
    let dir = TestDir::new();
    let service = ControlService::open_with_policies(
        &dir.0,
        "key",
        Default::default(),
        defsec_policy::action_gate::ActionSafetyConfig::with_bounded_autonomous_containment(),
    )
    .unwrap();
    seed_sockets_incident(&service);
    let incident_id = fixture_incident(&service);
    assert!(matches!(
        service.handle_admin_request(AdminRequest::EnrollHost {
            host_id: "other-allowed".into(),
            agent_public_key_hex: None,
        }),
        AdminResponse::HostEnrolled { .. }
    ));
    assert!(matches!(
        service.handle_admin_request(AdminRequest::EnrollHost {
            host_id: "foreign".into(),
            agent_public_key_hex: None,
        }),
        AdminResponse::HostEnrolled { .. }
    ));

    let parent = mint_operator_fixture(&service, true, &[HOST, "other-allowed"]);
    let socket = dir.0.join("investigate.sock");
    let server = UnixServer::bind(&socket, SocketPolicy::default()).unwrap();
    let server_task = tokio::spawn(server.serve_investigation(service.clone()));
    let mut client = Client::new(Mode::Operator, socket, parent.clone());
    client
        .handshake(
            "2025-03-26",
            &[
                READ_TOOLS,
                &[
                    "advance_host_discovery",
                    "start_investigation",
                    "finish_investigation",
                    "cancel_investigation",
                    "propose_action",
                    "propose_ephemeral_watch",
                    "record_hypothesis_or_finding",
                    "activate_expectation_rule",
                    "propose_expectation_rule",
                ],
            ]
            .concat(),
        )
        .await;

    let first = client
        .tool(
            "start_investigation",
            json!({"incident_id":incident_id, "note":"Inspect socket drift"}),
            false,
        )
        .await;
    let first = first.as_object().unwrap();
    assert_eq!(first.len(), 2);
    assert!(first["expires_at"].is_string());
    let first_run = first["run_id"].as_str().unwrap();
    let second = client
        .tool(
            "start_investigation",
            json!({"incident_id":incident_id}),
            false,
        )
        .await;
    let second_run = second["run_id"].as_str().unwrap();
    assert_ne!(first_run, second_run);

    let hosts = client.tool("list_hosts", json!({}), false).await;
    assert_eq!(hosts["hosts"].as_array().unwrap().len(), 2);
    assert!(
        hosts["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|host| host["host_id"] == "other-allowed")
    );
    for tool in [
        "list_investigation_runs",
        "list_expectation_rules",
        "list_actions",
    ] {
        assert_eq!(
            client.tool(tool, json!({"host_id":"foreign"}), true).await["code"],
            "forbidden"
        );
    }

    let context = client
        .tool(
            "get_incident_context",
            json!({"incident_id":incident_id}),
            false,
        )
        .await;
    let evidence = &context["recent_observations"][0]["observation_id"];
    let finding = |run: &str| {
        json!({
            "run_id":run, "incident_id":incident_id, "kind":"hypothesis", "severity":"low",
            "summary":"Service state changed", "uncertainty":"Cause unknown",
            "evidence_observation_ids":[evidence], "escalation_requested":false
        })
    };
    let missing = client
        .request(
            "tools/call",
            json!({"name":"record_hypothesis_or_finding","arguments":{}}),
        )
        .await;
    assert_eq!(missing["error"]["code"], -32602);
    assert_eq!(
        client
            .tool("record_hypothesis_or_finding", finding("unknown"), true)
            .await["code"],
        "run_inactive"
    );
    let found = client
        .tool("record_hypothesis_or_finding", finding(first_run), false)
        .await;
    assert_eq!(found["verified_evidence_count"], 1);

    let allowed = client
        .tool(
            "propose_expectation_rule",
            json!({
                "run_id":first_run, "idempotency_key":"nx",
                "rule":expectation_rule(Some(json!(Utc::now() + chrono::Duration::days(3))))
            }),
            false,
        )
        .await;
    assert_eq!(allowed["decision"]["allowed"], true);
    let mut watch = sockets_baseline();
    watch["id"] = json!("operator-watch");
    watch["class"] = json!("ephemeral");
    watch["collector"]["parameters"]["include_udp"] = json!(true);
    watch["incident_id"] = json!(incident_id);
    watch["lifecycle"]["expires_at"] = json!(Utc::now() + chrono::Duration::minutes(15));
    watch["lifecycle"]["max_runs"] = json!(20);
    for (key, spec, expected) in [
        ("valid-watch", watch, true),
        ("baseline-watch", sockets_baseline(), false),
    ] {
        let proposal = client
            .tool(
                "propose_ephemeral_watch",
                json!({
                    "run_id":first_run, "idempotency_key":key,
                    "spec":spec, "rationale":"Confirm socket state"
                }),
                false,
            )
            .await;
        assert_eq!(proposal["result"], "proposal_evaluated");
        assert_eq!(proposal["decision"]["allowed"], expected, "{proposal}");
        if !expected {
            assert_eq!(proposal["decision"]["rule_id"], "baseline.protected");
        }
    }
    let denied = client
        .tool(
            "propose_expectation_rule",
            json!({"run_id":first_run,"idempotency_key":"no-expiry","rule":expectation_rule(None)}),
            false,
        )
        .await;
    assert_eq!(denied["result"], "rule_proposal_evaluated");
    assert_eq!(denied["decision"]["allowed"], false);
    assert_eq!(
        denied["decision"]["rule_id"],
        "rule-gate/investigator-expiry"
    );

    let action = client.tool("propose_action", json!({
        "run_id":first_run, "incident_id":incident_id, "idempotency_key":"action",
        "verb":{"verb":"nft_block_ip","ip":"203.0.113.99","ttl_seconds":60,"direction":"both"},
        "evidence_observation_ids":[evidence], "expected_effect":"Contain traffic",
        "blast_radius":"One host", "rollback_plan":"Allow expiry"
    }), false).await;
    assert_eq!(action["status"], "pending_approval");
    assert!(action["authorized_intent"].is_null());
    let actions = client.tool("list_actions", json!({}), false).await;
    assert_eq!(actions["actions"].as_array().unwrap().len(), 1);

    let runs = client
        .tool("list_investigation_runs", json!({}), false)
        .await;
    let runs = runs["runs"].as_array().unwrap();
    assert_eq!(
        runs.iter().find(|run| run["run_id"] == first_run).unwrap()["findings_count"],
        1
    );
    assert_eq!(
        runs.iter().find(|run| run["run_id"] == second_run).unwrap()["event_count"],
        0
    );
    let finished = client
        .tool(
            "finish_investigation",
            json!({"run_id":first_run,"summary":"Investigated drift"}),
            false,
        )
        .await;
    assert_eq!(finished["status"], "completed");
    assert_eq!(finished["proposals"], 5);
    assert_eq!(finished["proposals_accepted"], 3);
    let cancelled = client
        .tool(
            "cancel_investigation",
            json!({"run_id":second_run,"reason":"Duplicate run"}),
            false,
        )
        .await;
    assert_eq!(cancelled["status"], "cancelled");
    for run in [first_run, second_run] {
        assert_eq!(
            client
                .tool("record_hypothesis_or_finding", finding(run), true)
                .await["code"],
            "run_inactive"
        );
        let events = client
            .tool("get_run_events", json!({"run_id":run}), false)
            .await;
        let events = events["events"].as_array().unwrap();
        let (offset, pairs) = if run == first_run {
            assert_eq!(events[0]["kind"], "note");
            assert_eq!(events[0]["detail"]["note"], "Inspect socket drift");
            (1, 7)
        } else {
            (0, 1)
        };
        assert_eq!(events.len(), offset + pairs * 2);
        for pair in events[offset..].chunks_exact(2) {
            assert_eq!(pair[0]["kind"], "tool_call");
            assert_eq!(pair[1]["kind"], "tool_result");
            assert_eq!(
                pair[0]["detail"]["request_id"],
                pair[1]["detail"]["request_id"]
            );
        }
        assert_eq!(events.last().unwrap()["detail"]["result"], "run_finished");
    }
    let runs = client
        .tool("list_investigation_runs", json!({}), false)
        .await;
    let outcome = &runs["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|run| run["run_id"] == first_run)
        .unwrap()["outcome"];
    assert_eq!(outcome["tool_calls"], 7);
    assert_eq!(outcome["findings"], 1);
    assert_eq!(outcome["proposals"], finished["proposals"]);
    assert_eq!(
        outcome["proposals_accepted"],
        finished["proposals_accepted"]
    );
    server_task.abort();
}

// Serve real control responses for each RPC except the injected connection cuts.
fn instrumented_socket(
    socket: &std::path::Path,
    service: ControlService,
    mut drop_response: impl FnMut(&Request) -> bool + Send + 'static,
) -> (
    JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use defsec_protocol::wire::{read_frame, write_frame};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::net::UnixListener;

    let listener = UnixListener::bind(socket).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let call: InvestigationCall = read_frame(&mut stream).await.unwrap().unwrap();
            counter.fetch_add(1, Ordering::Relaxed);
            if !drop_response(&call.request) {
                let response = service.handle_investigation_call(call);
                write_frame(&mut stream, &response).await.unwrap();
            }
        }
    });
    (task, calls)
}

fn denied_rule(run_id: &Value) -> Value {
    json!({"run_id":run_id,"idempotency_key":"no-expiry","rule":expectation_rule(None)})
}

#[tokio::test]
async fn operator_keeps_failed_start_reachable_for_terminal_cleanup() {
    use defsec_protocol::rpc::RunEventKind;

    let dir = TestDir::new();
    let service = ControlService::open(&dir.0, "key", 1).unwrap();
    seed_sockets_incident(&service);
    let incident = fixture_incident(&service);
    let token = mint_operator_fixture(&service, true, &[HOST]);
    let socket = dir.0.join("investigate.sock");
    let mut cut_cancel = true;
    let (server, _) = instrumented_socket(&socket, service, move |request| match request {
        Request::ReportRunProgress {
            kind: RunEventKind::Note,
            ..
        } => true,
        Request::CancelInvestigationRun { .. } => std::mem::take(&mut cut_cancel),
        _ => false,
    });
    let mut client = Client::new(Mode::Operator, socket, token);
    let start = client
        .tool(
            "start_investigation",
            json!({"incident_id":incident,"note":"starting"}),
            true,
        )
        .await;
    assert_eq!(start["code"], "run_progress_failed");
    let run = &start["run_id"];
    assert!(run.is_string());
    assert_eq!(
        client
            .tool("propose_expectation_rule", denied_rule(run), true)
            .await["code"],
        "run_cancel_pending"
    );
    assert_eq!(
        client
            .tool(
                "cancel_investigation",
                json!({"run_id":run,"reason":"cleanup"}),
                false
            )
            .await["status"],
        "cancelled"
    );
    assert_eq!(
        client
            .tool(
                "finish_investigation",
                json!({"run_id":run,"summary":"late"}),
                true
            )
            .await["code"],
        "run_inactive"
    );
    server.abort();
}

#[tokio::test]
async fn operator_reserves_event_slots_for_finish_and_rejects_unknown_finish_locally() {
    use std::sync::atomic::Ordering;

    let dir = TestDir::new();
    let service = ControlService::open(&dir.0, "key", 1).unwrap();
    seed_sockets_incident(&service);
    let incident = fixture_incident(&service);
    let token = mint_operator_fixture(&service, true, &[HOST]);
    let socket = dir.0.join("investigate.sock");
    let (server, calls) = instrumented_socket(&socket, service, |_| false);
    let mut client = Client::new(Mode::Operator, socket, token);
    let start = client
        .tool(
            "start_investigation",
            json!({"incident_id":incident}),
            false,
        )
        .await;
    let run = &start["run_id"];
    for _ in 0..127 {
        let reply = client
            .tool("propose_expectation_rule", denied_rule(run), false)
            .await;
        assert_eq!(reply["decision"]["allowed"], false, "{reply}");
    }
    let before = calls.load(Ordering::Relaxed);
    assert_eq!(
        client
            .tool("propose_expectation_rule", denied_rule(run), true)
            .await["code"],
        "run_event_quota"
    );
    assert_eq!(
        client
            .tool(
                "finish_investigation",
                json!({"run_id":"foreign","summary":"unknown"}),
                true
            )
            .await["code"],
        "run_inactive"
    );
    assert_eq!(calls.load(Ordering::Relaxed), before);
    let finished = client
        .tool(
            "finish_investigation",
            json!({"run_id":run,"summary":"at quota"}),
            false,
        )
        .await;
    assert_eq!(finished["status"], "completed");
    assert_eq!(finished["proposals"], 127);
    let runs = client
        .tool("list_investigation_runs", json!({}), false)
        .await;
    assert_eq!(runs["runs"][0]["event_count"], 256);
    server.abort();
}

#[tokio::test]
async fn operator_pins_event_budget_when_transport_cuts_the_operation_or_result_event() {
    use defsec_protocol::rpc::RunEventKind;
    use std::sync::atomic::Ordering;

    for cut_operation in [true, false] {
        let dir = TestDir::new();
        let service = ControlService::open(&dir.0, "key", 1).unwrap();
        seed_sockets_incident(&service);
        let incident = fixture_incident(&service);
        let token = mint_operator_fixture(&service, true, &[HOST]);
        let socket = dir.0.join("investigate.sock");
        let (server, calls) = instrumented_socket(&socket, service, move |request| {
            if cut_operation {
                matches!(request, Request::ProposeExpectationRule { .. })
            } else {
                matches!(
                    request,
                    Request::ReportRunProgress {
                        kind: RunEventKind::ToolResult,
                        ..
                    }
                )
            }
        });
        let mut client = Client::new(Mode::Operator, socket, token);
        let start = client
            .tool(
                "start_investigation",
                json!({"incident_id":incident}),
                false,
            )
            .await;
        let run = &start["run_id"];
        if cut_operation {
            let failed = client
                .request(
                    "tools/call",
                    json!({"name":"propose_expectation_rule","arguments":denied_rule(run)}),
                )
                .await;
            assert_eq!(failed["error"]["code"], -32000);
        } else {
            let reply = client
                .tool("propose_expectation_rule", denied_rule(run), false)
                .await;
            assert_eq!(reply["decision"]["allowed"], false);
        }
        let before = calls.load(Ordering::Relaxed);
        assert_eq!(
            client
                .tool("propose_expectation_rule", denied_rule(run), true)
                .await["code"],
            "run_event_quota"
        );
        assert_eq!(calls.load(Ordering::Relaxed), before);
        let finished = client
            .tool(
                "finish_investigation",
                json!({"run_id":run,"summary":"transport cut"}),
                false,
            )
            .await;
        assert_eq!(finished["status"], "completed");
        let timeline = client
            .tool("get_run_events", json!({"run_id":run}), false)
            .await;
        let events = timeline["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["kind"], "tool_call");
        assert_eq!(events[0]["detail"]["tool"], "propose_expectation_rule");
        assert_eq!(events[1]["detail"]["tool"], "finish_investigation");
        assert_eq!(events[2]["kind"], "tool_result");
        assert_eq!(
            events[2]["detail"]["request_id"],
            events[1]["detail"]["request_id"]
        );
        server.abort();
    }
}

#[tokio::test]
async fn investigator_binds_delegated_token_at_startup_and_keeps_binding_after_failed_switch() {
    let dir = TestDir::new();
    let service = ControlService::open(&dir.0, "key", 1).unwrap();
    seed_sockets_incident(&service);
    let incident_id = fixture_incident(&service);
    let parent = mint_operator_fixture(&service, true, &[HOST]);
    let Response::DelegatedRunStarted {
        run_id, run_token, ..
    } = direct(
        &service,
        &parent,
        Request::StartDelegatedRun {
            incident_id: incident_id.clone(),
            backend_id: "worker".into(),
            model_id: "fixture".into(),
            prompt_schema_version: "1".into(),
            trigger_event_id: None,
            lease_token: None,
            ttl_seconds: None,
        },
    )
    else {
        panic!("delegation failed")
    };
    let socket = dir.0.join("investigate.sock");
    let server = UnixServer::bind(&socket, SocketPolicy::default()).unwrap();
    let server_task = tokio::spawn(server.serve_investigation(service.clone()));

    let mut client = Client::new(Mode::Investigator, socket, run_token.clone());
    let tools = client.request("tools/list", json!({})).await;
    let action = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "propose_action")
        .unwrap();
    assert!(action["inputSchema"]["properties"].get("run_id").is_none());
    let propose = |key| {
        json!({
            "idempotency_key":key,
            "rule":expectation_rule(Some(json!(Utc::now() + chrono::Duration::days(3))))
        })
    };
    let first = client
        .tool("propose_expectation_rule", propose("first"), false)
        .await;
    assert_eq!(first["decision"]["allowed"], true);
    let failed = client.tool("start_investigation_run", json!({
        "incident_id":incident_id,"backend_id":"worker","model_id":"different","prompt_schema_version":"1"
    }), true).await;
    assert_eq!(failed["code"], "forbidden");
    let second = client
        .tool("propose_expectation_rule", propose("second"), false)
        .await;
    let rules = client
        .tool("list_expectation_rules", json!({}), false)
        .await;
    for proposal in [first, second] {
        assert!(
            rules["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| rule["rule_id"] == proposal["rule_id"] && rule["run_id"] == run_id)
        );
    }
    for tool in [
        "list_investigation_runs",
        "list_expectation_rules",
        "list_actions",
    ] {
        assert_eq!(
            client.tool(tool, json!({"host_id":"foreign"}), true).await["code"],
            "forbidden"
        );
    }
    assert!(matches!(
        direct(
            &service,
            &run_token,
            Request::FinishInvestigationRun {
                run_id,
                outcome: RunOutcome {
                    status: RunTerminalStatus::Completed,
                    summary: "Finished".into(),
                    budget_stop_reason: None,
                    turns: 0,
                    tool_calls: 2,
                    input_tokens: 0,
                    output_tokens: 0,
                    findings: 0,
                    proposals: 2,
                    proposals_accepted: 2,
                }
            }
        ),
        Response::RunFinished { .. }
    ));
    assert_eq!(
        client
            .tool("propose_expectation_rule", propose("late"), true)
            .await["message"],
        "investigation run is inactive"
    );
    let reply = client
        .request(
            "tools/call",
            json!({"name":"propose_expectation_rule","arguments":propose("later")}),
        )
        .await;
    assert_eq!(
        reply["error"]["message"],
        "No investigation run is active; call start_investigation_run first"
    );
    server_task.abort();
}

#[tokio::test]
async fn operator_binary_rejects_token_without_spawn_permission_before_serving_stdio() {
    let dir = TestDir::new();
    let service = ControlService::open(&dir.0, "key", 1).unwrap();
    seed_sockets_incident(&service);
    let socket = dir.0.join("investigate.sock");
    let token = mint_operator_fixture(&service, false, &[HOST]);
    let token_file = dir.0.join("token");
    fs::write(&token_file, &token).unwrap();
    let server = UnixServer::bind(&socket, SocketPolicy::default()).unwrap();
    let server_task = tokio::spawn(server.serve_investigation(service));
    let output = timeout(
        Duration::from_secs(3),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-adapter"))
            .args(["--mode", "operator", "--token-file"])
            .arg(token_file)
            .arg("--investigate-sock")
            .arg(socket)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let log = String::from_utf8(output.stderr).unwrap();
    assert!(log.contains("with may_spawn_runs"));
    assert!(!log.contains(&token));
    server_task.abort();
}

#[tokio::test]
async fn package_correlation_uses_only_authorized_recorded_discovery() {
    use defsec_protocol::watch::HOST_DISCOVERY_AGENT_SUFFIX;

    let dir = TestDir::new();
    let service = ControlService::open(&dir.0, "key", 1).unwrap();
    let host_ids = [HOST, "other"];
    let enrolled = [HOST, "other", "current"];
    for host in enrolled {
        assert!(matches!(
            service.handle_admin_request(AdminRequest::EnrollHost {
                host_id: host.into(),
                agent_public_key_hex: None,
            }),
            AdminResponse::HostEnrolled { .. }
        ));
        let replies = service.handle_agent_message(AgentToControl::Register {
            protocol_version: WIRE_PROTOCOL_VERSION,
            host_id: host.into(),
            agent_version: format!("fixture{HOST_DISCOVERY_AGENT_SUFFIX}"),
            boot_id: "boot".into(),
            session_id: "session".into(),
            active_bundle_version: 0,
            active_bundle_digest: None,
            sent_at: Utc::now(),
            host_profile: None,
        });
        assert!(matches!(
            replies.first(),
            Some(ControlToAgent::RegisterAck { accepted: true, .. })
        ));
    }
    let mint = |allowed_hosts: &[&str], collector| {
        let AdminResponse::TokenMinted { token, .. } =
            service.handle_admin_request(AdminRequest::MintCapabilityToken {
                principal_id: "correlation".into(),
                role: PrincipalRole::Investigator,
                allowed_hosts: allowed_hosts.iter().map(|host| (*host).into()).collect(),
                allowed_purposes: None,
                allowed_collectors: vec![collector],
                incident_id: None,
                ttl_seconds: 300,
                may_spawn_runs: false,
            })
        else {
            panic!("token mint failed");
        };
        token
    };
    let collector = CollectorType::PackagesInventory;
    let token = mint(&enrolled, collector);
    let restricted_host = mint(&host_ids[..1], collector);
    let restricted_collector = mint(&host_ids, CollectorType::SocketsListening);
    let call = |token: &str, request| {
        service.handle_investigation_call(InvestigationCall {
            request_id: "package-correlation".into(),
            capability_token: token.into(),
            request,
        })
    };
    let compare = || Request::CorrelatePackageSnapshots {
        host_ids: host_ids.map(str::to_owned),
        package_name: "openssl".into(),
        max_age_seconds: 120,
    };
    for restricted in [&restricted_host, &restricted_collector] {
        assert!(
            matches!(call(restricted, compare()), Response::Error {code, ..} if code == "forbidden")
        );
    }
    let mut watches = Vec::new();
    for host in enrolled {
        let result = call(
            &token,
            Request::AdvanceHostDiscovery {
                host_id: Some(host.into()),
            },
        );
        assert!(
            matches!(
                result,
                Response::HostDiscoveryAdvanced {
                    bundle_version: Some(_),
                    ..
                }
            ),
            "{result:?}"
        );
        let Response::Watches { watches: active } = call(
            &token,
            Request::ListActiveWatches {
                host_id: host.into(),
            },
        ) else {
            panic!("could not list discovery watches")
        };
        assert_eq!(active.len(), 1);
        watches.extend(active);
    }
    let socket = dir.0.join("investigate.sock");
    let server = UnixServer::bind(&socket, SocketPolicy::default()).unwrap();
    let server_task = tokio::spawn(server.serve_investigation(service.clone()));
    let mut client = Client::new(Mode::ReadOnly, socket.clone(), token.clone());
    client.handshake("2025-03-26", READ_TOOLS).await;
    let tool = "correlate_package_snapshots";
    let args = json!({"host_ids":host_ids,"package_name":"openssl","max_age_seconds":120});
    let mut denied = Client::new(Mode::ReadOnly, socket, restricted_host);
    denied.handshake("2025-03-26", READ_TOOLS).await;
    assert_eq!(
        denied.tool(tool, args.clone(), true).await["code"],
        "forbidden"
    );

    let observed_at = Utc::now();
    let record = |watch: &WatchSpec, status, observed_at| {
        let data = json!({
            "packages":[{"package_key":"openssl:amd64","name":"openssl","arch":"amd64","version":watch.host_id}],
            "total_packages":1,"status_file_sha256":"a".repeat(64)
        });
        let state_hash = canonical_sha256_hex(&data).unwrap();
        let replies = service.handle_agent_message(AgentToControl::PushObservationDelta {
            observation: ObservationRecord {
                host_id: watch.host_id.clone(),
                session_id: "session".into(),
                seq_no: 1,
                watch_id: watch.id.clone(),
                spec_version: watch.version,
                collector_type: collector,
                observed_at,
                status,
                state_hash: state_hash.clone(),
                payload: ObservationPayload::Snapshot { data },
                is_reconciliation: true,
                sustained_count: None,
                sustained_active: None,
                partial_reasons: if status == ObservationStatus::Partial {
                    vec!["limited visibility".into()]
                } else {
                    vec![]
                },
            },
        });
        assert!(
            matches!(
                replies.as_slice(),
                [ControlToAgent::ObservationAck {
                    acked_seq_no: 1,
                    ..
                }]
            ),
            "{replies:?}"
        );
        state_hash
    };

    let first_hash = record(&watches[0], ObservationStatus::Ok, observed_at);
    let missing = client.tool(tool, args.clone(), false).await;
    assert_eq!(missing["hosts"][0]["present"], true);
    assert_eq!(missing["hosts"][1]["gap"], "missing_observation");
    assert!(missing["both_present"].is_null());

    let second_hash = record(&watches[1], ObservationStatus::Partial, observed_at);
    let response = client.tool(tool, args, false).await;
    assert_eq!(response["hosts"][1]["gap"], "incomplete_observation");
    assert!(response["hosts"][1]["present"].is_null());
    assert!(response["both_present"].is_null());
    let Response::PackageSnapshotsCorrelated { hosts, .. } = call(&token, compare()) else {
        panic!("expected package comparison");
    };
    for (index, hash) in [first_hash, second_hash].iter().enumerate() {
        let citation = hosts[index].citation.as_ref().unwrap();
        assert_eq!(hosts[index].host_id, host_ids[index]);
        assert_eq!(hosts[index].observed_at, Some(observed_at));
        assert_eq!(&citation.state_hash, hash);
        assert_eq!(citation.watch_id, watches[index].id);
        assert_eq!(citation.spec_version, watches[index].version);
        assert_eq!(response["hosts"][index]["citation"], json!(citation));
        assert_eq!(response["hosts"][index]["observed_at"], json!(observed_at));
        assert!(citation.observation_id > 0);
    }
    assert_ne!(hosts[0].citation, hosts[1].citation);
    let current_hash = record(
        &watches[2],
        ObservationStatus::Ok,
        observed_at - chrono::Duration::seconds(10),
    );
    let current = client
        .tool(
            tool,
            json!({
                "host_ids":[HOST,"current"], "package_name":"openssl","max_age_seconds":120
            }),
            false,
        )
        .await;
    assert_eq!(current["both_present"], true);
    assert_eq!(current["hosts"][1]["citation"]["state_hash"], current_hash);
    let different_package = client
        .tool(
            tool,
            json!({
                "host_ids":[HOST,"current"], "package_name":"openssl-extra","max_age_seconds":120
            }),
            false,
        )
        .await;
    assert_eq!(different_package["both_present"], false);
    let stale = client
        .tool(
            tool,
            json!({
                "host_ids":[HOST,"current"], "package_name":"openssl","max_age_seconds":1
            }),
            false,
        )
        .await;
    assert_eq!(stale["hosts"][1]["gap"], "stale_observation");
    assert_eq!(stale["hosts"][1]["citation"]["state_hash"], current_hash);
    assert!(stale["both_present"].is_null());
    server_task.abort();
}
