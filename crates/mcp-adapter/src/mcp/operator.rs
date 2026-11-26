use chrono::{DateTime, Utc};
use defsec_protocol::rpc::{RunEventKind, RunOutcome, RunTerminalStatus};
use serde_json::Map;

use super::*;

const MAX_EVENTS: u32 = 256;

pub(super) struct OperatorRun {
    pub(super) token: String,
    expires_at: DateTime<Utc>,
    outcome: RunOutcome,
    event_slots_used: u32,
    cancel_pending: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartArgs {
    incident_id: String,
    note: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishArgs {
    summary: String,
    status: Option<RunTerminalStatus>,
}

impl McpServer {
    pub(super) fn expire_operator_runs(&mut self) {
        let now = Utc::now();
        self.operator_runs.retain(|_, run| run.expires_at > now);
    }

    pub(super) async fn start_operator_run(
        &mut self,
        arguments: Map<String, Value>,
    ) -> Result<Value, RpcError> {
        let args: StartArgs =
            serde_json::from_value(Value::Object(arguments)).map_err(|_| INVALID_PARAMS)?;
        if args.note.as_ref().is_some_and(|note| note.len() > 512) {
            return Err(INVALID_PARAMS);
        }
        let response = self
            .investigate(InvestigationRequest::StartDelegatedRun {
                incident_id: args.incident_id,
                backend_id: "mcp-operator".into(),
                model_id: "interactive".into(),
                prompt_schema_version: "1".into(),
                trigger_event_id: None,
                lease_token: None,
                ttl_seconds: None,
            })
            .await?;
        let InvestigationResponse::DelegatedRunStarted {
            run_id,
            expires_at,
            run_token,
            ..
        } = response
        else {
            return self.tool_response(response);
        };
        self.operator_runs.insert(
            run_id.clone(),
            OperatorRun {
                token: run_token,
                expires_at,
                event_slots_used: u32::from(args.note.is_some()),
                cancel_pending: false,
                outcome: RunOutcome {
                    status: RunTerminalStatus::Completed,
                    summary: String::new(),
                    budget_stop_reason: None,
                    turns: 0,
                    tool_calls: 0,
                    input_tokens: 0,
                    output_tokens: 0,
                    findings: 0,
                    proposals: 0,
                    proposals_accepted: 0,
                },
            },
        );
        if let Some(note) = args.note {
            let mut detail = json!({"note": note});
            self.redact(&mut detail);
            let recorded = self
                .progress(
                    &self.operator_runs[&run_id].token,
                    &run_id,
                    RunEventKind::Note,
                    detail,
                )
                .await;
            if !matches!(
                recorded,
                Ok(InvestigationResponse::RunProgressRecorded { .. })
            ) {
                let cancelled = self
                    .investigate(InvestigationRequest::CancelInvestigationRun {
                        run_id: run_id.clone(),
                        reason: "Could not record the operator's starting note".into(),
                    })
                    .await;
                if matches!(cancelled, Ok(InvestigationResponse::RunFinished { .. })) {
                    self.operator_runs.remove(&run_id);
                    return self
                        .tool_error("run_progress_failed", "Could not record the starting note");
                }
                self.operator_runs
                    .get_mut(&run_id)
                    .expect("run inserted above")
                    .cancel_pending = true;
                return self.tool_payload(
                    json!({
                        "result": "error",
                        "code": "run_progress_failed",
                        "message": "Could not record the starting note or confirm cancellation; cancel or finish the run",
                        "run_id": run_id,
                        "expires_at": expires_at
                    }),
                    true,
                );
            }
        }
        self.tool_payload(json!({"run_id": run_id, "expires_at": expires_at}), false)
    }

    pub(super) async fn call_operator_run(
        &mut self,
        tool: &str,
        mut arguments: Map<String, Value>,
    ) -> Result<Value, RpcError> {
        let run_id = arguments
            .get("run_id")
            .and_then(Value::as_str)
            .ok_or((-32602, "Operator tools require an explicit run_id"))?
            .to_owned();
        let Some(run) = self.operator_runs.get(&run_id) else {
            return self.tool_error(
                "run_inactive",
                "Unknown, finished, cancelled or expired run_id",
            );
        };
        let terminal = matches!(tool, "finish_investigation" | "cancel_investigation");
        if run.cancel_pending && !terminal {
            return self.tool_error(
                "run_cancel_pending",
                "Starting note failed; cancel or finish the run",
            );
        }
        let mut outcome = run.outcome.clone();
        outcome.tool_calls += 1;
        let token = run.token.clone();
        let request = match tool {
            "finish_investigation" => {
                arguments.remove("run_id");
                let args: FinishArgs =
                    serde_json::from_value(Value::Object(arguments)).map_err(|_| INVALID_PARAMS)?;
                if args.status == Some(RunTerminalStatus::Cancelled) || args.summary.len() > 2048 {
                    return Err(INVALID_PARAMS);
                }
                outcome.status = args.status.unwrap_or(RunTerminalStatus::Completed);
                outcome.summary = args.summary;
                InvestigationRequest::FinishInvestigationRun {
                    run_id: run_id.clone(),
                    outcome: outcome.clone(),
                }
            }
            "cancel_investigation" => parse_request("cancel_investigation_run", arguments)?,
            _ => {
                // Apply the typed validation before making or logging an RPC.
                // The registry lookup above is the only source of the child token.
                if tool.starts_with("propose_") {
                    outcome.proposals += 1;
                }
                parse_request(tool, arguments)?
            }
        };
        let required_slots = if terminal { 2 } else { 4 };
        if run.event_slots_used + required_slots > MAX_EVENTS {
            return self.tool_error(
                "run_event_quota",
                "Run event budget exhausted; finish or cancel the run",
            );
        }

        let request_id = Uuid::new_v4().to_string();
        let call_detail = json!({"tool":tool,"request_id":request_id});
        let recorded = self
            .progress(&token, &run_id, RunEventKind::ToolCall, call_detail)
            .await?;
        if !matches!(recorded, InvestigationResponse::RunProgressRecorded { .. }) {
            if run_inactive(&recorded) {
                self.operator_runs.remove(&run_id);
                return self.tool_error("run_inactive", "Run is no longer active");
            }
            return self.tool_response(recorded);
        }
        let run = self
            .operator_runs
            .get_mut(&run_id)
            .expect("run selected above");
        run.event_slots_used += 2;
        let result = self.exchange(&token, request_id.clone(), request).await;
        let ended = matches!(result, Ok(InvestigationResponse::RunFinished { .. }));
        let inactive = result.as_ref().is_ok_and(run_inactive);
        if !ended && !inactive {
            let result_recorded = match &result {
                Ok(response) => {
                    let detail = result_detail(tool, &request_id, response);
                    matches!(
                        self.progress(&token, &run_id, RunEventKind::ToolResult, detail)
                            .await,
                        Ok(InvestigationResponse::RunProgressRecorded { .. })
                    )
                }
                Err(_) => false,
            };
            if !result_recorded {
                // The operation may already have taken effect. Return its result and
                // stop ordinary calls so a missing event cannot go unnoticed.
                self.operator_runs
                    .get_mut(&run_id)
                    .expect("run selected above")
                    .event_slots_used = MAX_EVENTS - 2;
            }
        }

        if let Ok(response) = &result {
            match response {
                InvestigationResponse::FindingRecorded { .. } => outcome.findings += 1,
                InvestigationResponse::ProposalEvaluated { decision, .. }
                | InvestigationResponse::RuleProposalEvaluated { decision, .. }
                | InvestigationResponse::ActionProposalEvaluated { decision, .. } => {
                    outcome.proposals_accepted += u32::from(decision.allowed);
                }
                _ => {}
            }
        }
        if let Ok(InvestigationResponse::RunFinished { status, .. }) = &result
            && tool == "finish_investigation"
        {
            self.operator_runs.remove(&run_id);
            return self.tool_payload(
                json!({
                    "result": "run_finished",
                    "run_id": run_id,
                    "status": status,
                    "proposals": outcome.proposals,
                    "proposals_accepted": outcome.proposals_accepted
                }),
                false,
            );
        }
        if ended || inactive {
            let response = self.tool_response(result?);
            self.operator_runs.remove(&run_id);
            return response;
        }
        self.operator_runs
            .get_mut(&run_id)
            .expect("run selected above")
            .outcome = outcome;
        self.tool_response(result?)
    }

    async fn progress(
        &self,
        token: &str,
        run_id: &str,
        kind: RunEventKind,
        detail: Value,
    ) -> Result<InvestigationResponse, RpcError> {
        self.exchange(
            token,
            Uuid::new_v4().to_string(),
            InvestigationRequest::ReportRunProgress {
                run_id: run_id.into(),
                kind,
                detail,
            },
        )
        .await
    }

    fn tool_error(&self, code: &str, message: &str) -> Result<Value, RpcError> {
        self.tool_response(InvestigationResponse::Error {
            code: code.into(),
            message: message.into(),
        })
    }
}

fn result_detail(tool: &str, request_id: &str, response: &InvestigationResponse) -> Value {
    let (result, allowed) = match response {
        InvestigationResponse::FindingRecorded { .. } => ("finding_recorded", None),
        InvestigationResponse::ProposalEvaluated { decision, .. } => {
            ("proposal_evaluated", Some(decision.allowed))
        }
        InvestigationResponse::RuleProposalEvaluated { decision, .. } => {
            ("rule_proposal_evaluated", Some(decision.allowed))
        }
        InvestigationResponse::ActionProposalEvaluated { decision, .. } => {
            ("action_proposal_evaluated", Some(decision.allowed))
        }
        InvestigationResponse::Error { .. } => ("error", None),
        _ => ("unexpected_response", None),
    };
    json!({"tool":tool,"request_id":request_id,"result":result,"allowed":allowed})
}
