use std::{io, path::PathBuf, sync::Mutex, time::Duration};

use clap::ValueEnum;
use defsec_protocol::{
    rpc::{InvestigationCall, InvestigationRequest, InvestigationResponse},
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

use crate::tools::available_tools;

const CURRENT_PROTOCOL: &str = "2025-03-26";

#[derive(Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum Mode {
    #[default]
    ReadOnly,
    Investigator,
}

pub struct McpServer {
    mode: Mode,
    socket: PathBuf,
    token: String,
    timeout: Duration,
    /// The investigation run this adapter started; run-scoped proposal tools
    /// bind to it instead of trusting a caller-supplied run_id.
    run: Mutex<Option<String>>,
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
            run: Mutex::new(None),
        }
    }

    pub async fn serve(
        &self,
        mut input: impl AsyncBufRead + Unpin,
        mut output: impl AsyncWrite + Unpin,
    ) -> io::Result<()> {
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

    async fn handle_line(&self, line: &[u8]) -> Option<Value> {
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

    async fn dispatch(&self, method: &str, params: Value) -> Result<Value, RpcError> {
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
                let tools: Vec<_> = available_tools(self.mode)
                    .map(|tool| tool.descriptor())
                    .collect();
                Ok(json!({"tools": tools}))
            }
            "tools/call" => self.call_tool(params).await,
            "ping" | "tools/list" => Err(INVALID_PARAMS),
            _ => Err((-32601, "Method not found")),
        }
    }

    async fn call_tool(&self, params: Value) -> Result<Value, RpcError> {
        let call: ToolCall = serde_json::from_value(params).map_err(|_| INVALID_PARAMS)?;
        let Some(tool) = available_tools(self.mode).find(|tool| tool.name == call.name) else {
            return Err((-32602, "Tool is unavailable in this mode"));
        };
        let Value::Object(mut arguments) = call.arguments else {
            return Err(INVALID_PARAMS);
        };
        if tool.name == "propose_expectation_rule" {
            if arguments.remove("run_id").is_some() {
                return Err(RUN_BOUND_BY_ADAPTER);
            }
            let run_id = self.current_run().ok_or(NO_ACTIVE_RUN)?;
            arguments.insert("run_id".into(), json!(run_id));
        }
        if arguments.insert("op".into(), json!(tool.name)).is_some() {
            return Err(INVALID_PARAMS);
        }
        let request =
            serde_json::from_value(Value::Object(arguments)).map_err(|_| INVALID_PARAMS)?;
        let response = self.investigate(request).await?;
        if let InvestigationResponse::RunStarted { run_id, .. } = &response {
            self.bind_run(run_id.clone());
        }
        let is_error = matches!(response, InvestigationResponse::Error { .. });
        let mut payload = serde_json::to_value(response).map_err(|_| INTERNAL_ERROR)?;
        self.redact(&mut payload);
        let text = serde_json::to_string_pretty(&payload).map_err(|_| INTERNAL_ERROR)?;
        Ok(json!({"content": [{"type": "text", "text": text}], "isError": is_error}))
    }

    fn current_run(&self) -> Option<String> {
        // A poisoned lock fails closed: no proposal leaves the adapter.
        self.run.lock().ok().and_then(|run| run.clone())
    }

    fn bind_run(&self, run_id: String) {
        if let Ok(mut run) = self.run.lock() {
            *run = Some(run_id);
        }
    }

    async fn investigate(
        &self,
        request: InvestigationRequest,
    ) -> Result<InvestigationResponse, RpcError> {
        let exchange = async {
            let mut socket = UnixStream::connect(&self.socket)
                .await
                .map_err(|_| (-32000, "Could not connect to the investigation socket"))?;
            let call = InvestigationCall {
                request_id: Uuid::new_v4().to_string(),
                capability_token: self.token.clone(),
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
        if self.token.is_empty() {
            return;
        }
        match value {
            Value::String(text) if text.contains(&self.token) => {
                *text = text.replace(&self.token, "[redacted]");
            }
            Value::Array(items) => {
                for item in items {
                    self.redact(item);
                }
            }
            Value::Object(fields) => {
                fields.retain(|key, _| !key.contains(&self.token));
                for item in fields.values_mut() {
                    self.redact(item);
                }
            }
            _ => {}
        }
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
        let server = server("fixture-secret");
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
        let server = server("fixture-secret");
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

    #[tokio::test]
    async fn run_state_is_bound_once_a_run_starts() {
        let server = server("fixture-secret");
        server.bind_run("run-42".into());
        assert_eq!(server.current_run().as_deref(), Some("run-42"));
    }
}
