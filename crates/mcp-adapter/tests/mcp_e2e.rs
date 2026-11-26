use std::{fs, io, path::PathBuf, time::Duration};

use chrono::Utc;
use control_d::{
    ControlService,
    server::{SocketPolicy, UnixServer},
};
use defsec_protocol::{
    canonical::canonical_sha256_hex,
    observation::{ObservationPayload, ObservationRecord, ObservationStatus},
    rpc::{AdminRequest, AdminResponse, PrincipalRole},
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
    "list_hosts",
    "list_active_incidents",
    "list_active_watches",
    "list_collector_capabilities",
    "get_incident_context",
    "query_observations",
    "get_host_baseline_summary",
    "list_investigation_runs",
    "get_run_events",
    "list_trigger_queue",
    "list_expectation_rules",
];
const WRITE_TOOLS: &[&str] = &[
    "start_investigation_run",
    "propose_ephemeral_watch",
    "record_hypothesis_or_finding",
    "propose_expectation_rule",
];

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let path = std::env::temp_dir().join(format!("m-{}", &id[..8]));
        fs::create_dir(&path).unwrap();
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
            principal_id: "operator".into(),
            role: PrincipalRole::Investigator,
            allowed_hosts: vec![HOST.into()],
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
        principal_id: "observer".into(),
        role: PrincipalRole::Observer,
        allowed_hosts: vec![HOST.into()],
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
            "run_id":run_id, "idempotency_key":key, "spec":spec, "rationale":"inspect related state"
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
            "run_id":run_id, "incident_id":incident_id, "kind":"hypothesis", "severity":"medium",
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
    let AdminResponse::TokenMinted { token, .. } = service.handle_admin_request(
        AdminRequest::MintCapabilityToken {
            principal_id: "investigator".into(),
            role: PrincipalRole::Investigator,
            allowed_hosts: vec![HOST.into()],
            allowed_collectors: vec![CollectorType::SocketsListening],
            incident_id: Some(incident_id.clone()),
            ttl_seconds: 300,
        },
    )
    else {
        panic!("could not mint fixture token")
    };
    let AdminResponse::TokenMinted {
        token: observer_token,
        ..
    } = service.handle_admin_request(AdminRequest::MintCapabilityToken {
        principal_id: "observer".into(),
        role: PrincipalRole::Observer,
        allowed_hosts: vec![HOST.into()],
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
    assert_eq!(denied["decision"]["rule_id"], "rule-gate/investigator-expiry");
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
        .tool("list_expectation_rules", json!({"statuses":["proposed"]}), false)
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
        .tool("list_expectation_rules", json!({"statuses":["bogus"]}), true)
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
        .request("tools/call", json!({"name":"propose_expectation_rule","arguments":{}}))
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
