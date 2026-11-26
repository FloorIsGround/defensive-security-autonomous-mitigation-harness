mod operator;

use std::{collections::HashMap, io, path::PathBuf, time::Duration};

use clap::ValueEnum;
use defsec_protocol::{
    rpc::{InvestigationCall, InvestigationRequest, InvestigationResponse, PrincipalRole},
    rules::MatchClause,
    wire::{MAX_FRAME_BYTES, read_frame, write_frame},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};
use uuid::Uuid;

use crate::tools::{available_tools, is_run_tool};
use operator::OperatorRun;

const CURRENT_PROTOCOL: &str = "2025-03-26";

#[derive(Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum Mode {
    #[default]
    ReadOnly,
    Investigator,
    Operator,
}

pub struct McpServer {
    mode: Mode,
    socket: PathBuf,
    token: String,
    timeout: Duration,
    investigator_run: Option<String>,
    delegated_investigator: bool,
    operator_runs: HashMap<String, OperatorRun>,
}

#[derive(Deserialize)]
struct Initialize {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
}

#[derive(Deserialize)]
struct ToolCall {
    name: String,
    #[serde(default = "empty_object")]
    arguments: Value,
}

fn empty_object() -> Value {
    json!({})
}

type RpcError = (i32, &'static str);
const INVALID_PARAMS: RpcError = (-32602, "Invalid params");
const INTERNAL_ERROR: RpcError = (-32603, "Internal server error");
const RUN_BOUND_BY_ADAPTER: RpcError = (
    -32602,
    "run_id is bound to the adapter's current investigation run",
);
const NO_ACTIVE_RUN: RpcError = (
    -32602,
    "No investigation run is active; call start_investigation_run first",
);

impl McpServer {
    pub fn new(mode: Mode, socket: PathBuf, token: String, timeout: Duration) -> Self {
        Self {
            mode,
            socket,
            token,
            timeout,
            investigator_run: None,
            delegated_investigator: false,
            operator_runs: HashMap::new(),
        }
    }

    pub async fn serve(
        mut self,
        mut input: impl AsyncBufRead + Unpin,
        mut output: impl AsyncWrite + Unpin,
    ) -> io::Result<()> {
        self.check_capability().await?;
        let mut line = Vec::new();
        while let Some(oversized) = read_line(&mut input, &mut line).await? {
            let response = if oversized {
                Some(error(
                    Value::Null,
                    (-32700, "JSON-RPC frame exceeds size limit"),
                ))
            } else {
                self.handle_line(&line).await
            };
            if let Some(response) = response {
                let mut frame = serde_json::to_vec(&response)?;
                frame.push(b'\n');
                output.write_all(&frame).await?;
                output.flush().await?;
            }
        }
        Ok(())
    }

    async fn handle_line(&mut self, line: &[u8]) -> Option<Value> {
        let Ok(message) = serde_json::from_slice::<Value>(line) else {
            return Some(error(Value::Null, (-32700, "Parse error")));
        };
        let id = message.get("id");
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || id.is_some_and(|id| !(id.is_string() || id.is_number() || id.is_null()))
        {
            return Some(error(Value::Null, (-32600, "Invalid Request")));
        }
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return Some(error(Value::Null, (-32600, "Invalid Request")));
        };
        let mut id = id?.clone();
        self.redact(&mut id);
        let params = message.get("params").cloned().unwrap_or_else(empty_object);
        Some(match self.dispatch(method, params).await {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(failure) => error(id, failure),
        })
    }

    async fn dispatch(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        match method {
            "initialize" => {
                let params: Initialize =
                    serde_json::from_value(params).map_err(|_| INVALID_PARAMS)?;
                let version = match params.protocol_version.as_str() {
                    "2024-11-05" | CURRENT_PROTOCOL => &params.protocol_version,
                    _ => CURRENT_PROTOCOL,
                };
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "defsecautmit-mcp", "version": env!("CARGO_PKG_VERSION")},
                }))
            }
            "ping" if params.is_object() => Ok(empty_object()),
            "tools/list" if params.is_object() => {
                let tools: Vec<_> = available_tools(self.mode, self.delegated_investigator)
                    .map(|tool| tool.descriptor(self.mode))
                    .collect();
                Ok(json!({"tools": tools}))
            }
            "tools/call" => self.call_tool(params).await,
            "ping" | "tools/list" => Err(INVALID_PARAMS),
            _ => Err((-32601, "Method not found")),
        }
    }

    async fn check_capability(&mut self) -> io::Result<()> {
        if self.mode == Mode::ReadOnly {
            return Ok(());
        }
        let result = self
            .investigate(InvestigationRequest::GetCapability {})
            .await;
        if let Ok(InvestigationResponse::Capability {
            capability,
            delegated,
        }) = result
        {
            if self.mode == Mode::Investigator {
                self.investigator_run = capability.run_id;
                self.delegated_investigator = delegated;
                return Ok(());
            }
            if capability.role == PrincipalRole::Investigator
                && capability.may_spawn_runs
                && capability.run_id.is_none()
            {
                return Ok(());
            }
        }
        let message = match self.mode {
            Mode::Operator => {
                "operator mode requires a valid, unbound investigator token with may_spawn_runs"
            }
            _ => "could not verify the investigator capability at startup",
        };
        Err(io::Error::new(io::ErrorKind::PermissionDenied, message))
    }

    async fn call_tool(&mut self, params: Value) -> Result<Value, RpcError> {
        let call: ToolCall = serde_json::from_value(params).map_err(|_| INVALID_PARAMS)?;
        let Some(tool) = available_tools(self.mode, self.delegated_investigator)
            .find(|tool| tool.name == call.name)
        else {
            return Err((-32602, "Tool is unavailable in this mode"));
        };
        let Value::Object(mut arguments) = call.arguments else {
            return Err(INVALID_PARAMS);
        };
        if self.mode == Mode::Operator {
            self.expire_operator_runs();
            if tool.name == "start_investigation" {
                return self.start_operator_run(arguments).await;
            }
            if is_run_tool(tool.name) {
                return self.call_operator_run(tool.name, arguments).await;
            }
        }
        if is_run_tool(tool.name) {
            if arguments.contains_key("run_id") {
                return Err(RUN_BOUND_BY_ADAPTER);
            }
            let run_id = self.investigator_run.as_deref().ok_or(NO_ACTIVE_RUN)?;
            arguments.insert("run_id".into(), json!(run_id));
        }
        let response = self
            .investigate(parse_request(tool.name, arguments)?)
            .await?;
        if let InvestigationResponse::RunStarted { run_id, .. } = &response {
            self.investigator_run = Some(run_id.clone());
        }
        if run_inactive(&response) {
            self.investigator_run = None;
        }
        self.tool_response(response)
    }

    fn tool_response(&self, response: InvestigationResponse) -> Result<Value, RpcError> {
        if matches!(response, InvestigationResponse::DelegatedRunStarted { .. }) {
            return Err(INTERNAL_ERROR);
        }
        let is_error = matches!(response, InvestigationResponse::Error { .. });
        self.tool_payload(
            serde_json::to_value(response).map_err(|_| INTERNAL_ERROR)?,
            is_error,
        )
    }

    fn tool_payload(&self, mut payload: Value, is_error: bool) -> Result<Value, RpcError> {
        self.redact(&mut payload);
        let text = serde_json::to_string_pretty(&payload).map_err(|_| INTERNAL_ERROR)?;
        Ok(json!({"content": [{"type": "text", "text": text}], "isError": is_error}))
    }

    async fn investigate(
        &self,
        request: InvestigationRequest,
    ) -> Result<InvestigationResponse, RpcError> {
        self.exchange(&self.token, Uuid::new_v4().to_string(), request)
            .await
    }

    async fn exchange(
        &self,
        token: &str,
        request_id: String,
        request: InvestigationRequest,
    ) -> Result<InvestigationResponse, RpcError> {
        let exchange = async {
            let mut socket = UnixStream::connect(&self.socket)
                .await
                .map_err(|_| (-32000, "Could not connect to the investigation socket"))?;
            let call = InvestigationCall {
                request_id,
                capability_token: token.to_owned(),
                request,
            };
            write_frame(&mut socket, &call)
                .await
                .map_err(|_| (-32000, "Could not send investigation request"))?;
            read_frame(&mut socket)
                .await
                .map_err(|_| (-32000, "Invalid investigation response"))?
                .ok_or((-32000, "Investigation socket closed without a response"))
        };
        timeout(self.timeout, exchange)
            .await
            .map_err(|_| (-32000, "Investigation request timed out"))?
    }

    // Telemetry and policy responses may contain caller-controlled strings.
    fn redact(&self, value: &mut Value) {
        redact_token(value, &self.token);
        for run in self.operator_runs.values() {
            redact_token(value, &run.token);
        }
    }
}

fn parse_request(
    name: &str,
    mut arguments: serde_json::Map<String, Value>,
) -> Result<InvestigationRequest, RpcError> {
    if arguments.insert("op".into(), json!(name)).is_some() {
        return Err(INVALID_PARAMS);
    }
    let request = serde_json::from_value(Value::Object(arguments)).map_err(|_| INVALID_PARAMS)?;
    if let InvestigationRequest::ProposeExpectationRule { rule, .. } = &request
        && (!(1..=8).contains(&rule.matches.len())
            || rule.matches.iter().any(|clause| {
                matches!(clause, MatchClause::In { values, .. } if !(1..=32).contains(&values.len()))
            }))
    {
        return Err(INVALID_PARAMS);
    }
    Ok(request)
}

fn run_inactive(response: &InvestigationResponse) -> bool {
    matches!(response, InvestigationResponse::Error { code, message }
        if code == "forbidden" && matches!(message.as_str(),
            "investigation run is inactive" | "invalid capability token"
            | "capability expired or role is unavailable on this interface" | "incident is closed"))
}

fn redact_token(value: &mut Value, token: &str) {
    if token.is_empty() {
        return;
    }
    match value {
        Value::String(text) if text.contains(token) => {
            *text = text.replace(token, "[redacted]");
        }
        Value::Array(items) => {
            for item in items {
                redact_token(item, token);
            }
        }
        Value::Object(fields) => {
            fields.retain(|key, _| !key.contains(token));
            for item in fields.values_mut() {
                redact_token(item, token);
            }
        }
        _ => {}
    }
}

fn error(id: Value, (code, message): RpcError) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

// Drain oversized frames without allocating past the wire limit, then resume
// at the next message. A final frame may end at EOF.
async fn read_line(
    input: &mut (impl AsyncBufRead + Unpin),
    line: &mut Vec<u8>,
) -> io::Result<Option<bool>> {
    line.clear();
    let mut oversized = false;
    loop {
        let bytes = input.fill_buf().await?;
        if bytes.is_empty() {
            return Ok((oversized || !line.is_empty()).then_some(oversized));
        }
        let newline = bytes.iter().position(|&byte| byte == b'\n');
        let length = newline.unwrap_or(bytes.len());
        oversized |= line.len() + length > MAX_FRAME_BYTES;
        if !oversized {
            line.extend_from_slice(&bytes[..length]);
        }
        input.consume(length + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(oversized));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    fn server(token: &str) -> McpServer {
        McpServer::new(
            Mode::ReadOnly,
            PathBuf::new(),
            token.into(),
            Duration::from_secs(1),
        )
    }

    #[tokio::test]
    async fn distinguishes_rpc_errors_and_ignores_notifications() {
        let mut server = server("fixture-secret");
        for (input, expected_code) in [
            ("{", -32700),
            (r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#, -32600),
            (r#"{"jsonrpc":"2.0","id":{},"method":"ping"}"#, -32600),
            (r#"{"jsonrpc":"2.0","id":1,"method":"unknown"}"#, -32601),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                -32602,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[]}"#,
                -32602,
            ),
        ] {
            let reply = server.handle_line(input.as_bytes()).await.unwrap();
            assert_eq!(reply["error"]["code"], expected_code);
        }
        assert!(
            server
                .handle_line(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn recovers_after_oversized_frame() {
        let mut data = vec![b' '; MAX_FRAME_BYTES + 1];
        data.extend_from_slice(b"\n");
        data.extend_from_slice(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
        let mut output = Vec::new();
        server("fixture-secret")
            .serve(BufReader::new(data.as_slice()), &mut output)
            .await
            .unwrap();
        let frames: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0]["error"]["code"], -32700);
        assert_eq!(frames[1], json!({"jsonrpc":"2.0","id":1,"result":{}}));
    }

    #[tokio::test]
    async fn redacts_token_in_request_ids_and_nested_payloads() {
        let mut server = server("fixture-secret");
        let reply = server
            .handle_line(br#"{"jsonrpc":"2.0","id":"fixture-secret","method":"unknown"}"#)
            .await
            .unwrap();
        assert_eq!(reply["id"], "[redacted]");

        let mut payload = json!({
            "code":"denied",
            "message":[
                "bad request fixture-secret",
                {"fixture-secret":"key also contains token","detail":"fixture-secret"}
            ]
        });
        server.redact(&mut payload);
        assert_eq!(
            payload,
            json!({
                "code":"denied",
                "message":["bad request [redacted]", {"detail":"[redacted]"}]
            })
        );
    }

    #[tokio::test]
    async fn rule_proposals_require_the_adapters_current_run() {
        let mut server = server("fixture-secret");
        server.mode = Mode::Investigator;
        let reply = server
            .handle_line(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
            .await
            .unwrap();
        let names: Vec<_> = reply["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"propose_expectation_rule"));

        let call = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"propose_expectation_rule","arguments":{}}}"#;
        // No run has been started yet: the call is refused before any RPC.
        let reply = server.handle_line(call.as_bytes()).await.unwrap();
        assert_eq!(reply["error"]["code"], -32602);
        assert_eq!(reply["error"]["message"], NO_ACTIVE_RUN.1);
        // The caller cannot pick the run; the adapter binds it.
        let call = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"propose_expectation_rule","arguments":{"run_id":"run-1","idempotency_key":"k","rule":{}}}}"#;
        let reply = server.handle_line(call.as_bytes()).await.unwrap();
        assert_eq!(reply["error"]["code"], -32602);
        assert_eq!(reply["error"]["message"], RUN_BOUND_BY_ADAPTER.1);
    }

    #[test]
    fn expectation_rule_schema_enforces_bounds_and_json_integers_before_rpc() {
        let parse = |collector: &str, matches: Vec<Value>| {
            parse_request(
                "propose_expectation_rule",
                json!({
                    "run_id":"run-1","idempotency_key":"example",
                    "rule":{
                        "scope":{"host_id":"edge","collector":collector},
                        "matches":matches,"effect":"require_present","rationale":"fixture",
                    },
                })
                .as_object()
                .unwrap()
                .clone(),
            )
        };
        let clause = json!({"op":"eq","field":"local_port","value":22});
        for count in [0, 1, 8, 9] {
            assert_eq!(
                parse("sockets.listening", vec![clause.clone(); count]).is_ok(),
                (1..=8).contains(&count)
            );
        }
        for count in [0, 1, 32, 33] {
            let clause = json!({"op":"in","field":"remote_port","values":vec![22;count]});
            assert_eq!(
                parse("connections.outbound", vec![clause]).is_ok(),
                (1..=32).contains(&count)
            );
        }
        for clause in [
            json!({"op":"eq","field":"local_port","value":22.0}),
            json!({"op":"in","field":"local_port","values":[22.0]}),
            json!({"op":"range","field":"local_port","min":22.0,"max":24}),
        ] {
            assert!(parse("sockets.listening", vec![clause]).is_err());
        }
        assert!(
            parse(
                "packages.inventory",
                vec![json!({"op":"eq", "field":"name", "value":"curl"})]
            )
            .is_ok()
        );

        for mode in [Mode::Operator, Mode::Investigator] {
            let rule_tool = available_tools(mode, false)
                .find(|tool| tool.name == "propose_expectation_rule")
                .unwrap();
            let schema = &rule_tool.descriptor(mode)["inputSchema"];
            let properties = &schema["properties"]["rule"]["properties"];
            let collectors = properties["scope"]["properties"]["collector"]["enum"]
                .as_array()
                .unwrap();
            assert!(collectors.contains(&json!("connections.outbound")));
            assert!(collectors.contains(&json!("packages.inventory")));
            assert_eq!(properties["matches"]["minItems"], 1);
            assert_eq!(properties["matches"]["maxItems"], 8);
            assert_eq!(
                schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("run_id")),
                mode == Mode::Operator
            );
        }
    }
}
