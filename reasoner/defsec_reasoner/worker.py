"""The automated episodic reasoning worker (`reasoner-d`, Design §7.4).

Lifecycle of one run:

1. Lease the next pending trigger (dormant when the queue is empty).
2. Mint/obtain short-lived run-scoped authority and start a durable
   investigation run bound to the incident.
3. Fetch bounded incident context + collector capabilities and render all
   monitored data inside provenance envelopes (never raw).
4. Execute a bounded tool-calling loop through the Investigation RPC only —
   no shell, no filesystem, no direct database access.
5. Commit findings/proposals, then — and only then — complete the trigger
   lease. Retryable provider failures requeue the trigger with bounded
   backoff; non-retryable failures dead-letter it. Expired or fenced leases
   are dropped without committing results.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from defsec_reasoner import PROMPT_SCHEMA_VERSION
from defsec_reasoner.models import ModelAdapter, ModelTurnResult, ProviderError, ToolCall
from defsec_reasoner.provenance import (
    build_system_prompt,
    clip_utf8,
    render_context_block,
    wrap_json,
    wrap_observation,
)
from defsec_reasoner.rpc_client import ControlRpcClient, RpcError, RpcTransportError

__all__ = ["RunBudgets", "ReasonerWorker", "WorkerOutcome", "INVESTIGATION_TOOLS"]

logger = logging.getLogger("defsec.reasoner.worker")


@dataclass
class RunBudgets:
    """Hard, worker-enforced limits for one investigation run."""

    max_turns: int = 6
    max_wall_seconds: float = 45.0
    max_total_tokens: int = 16000
    max_cost_usd: float = 0.25
    max_proposals_per_run: int = 3
    max_context_bytes: int = 32768
    lease_seconds: int = 120


@dataclass
class WorkerOutcome:
    """What happened in one ``run_once`` attempt."""

    status: str  # dormant | completed | requeued | dead_letter | lease_stale
    event_id: int | None = None
    incident_id: str | None = None
    run_id: str | None = None
    turns: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    findings: int = 0
    proposals: int = 0
    proposals_accepted: int = 0
    budget_stop_reason: str | None = None
    summary: str = ""
    error: str | None = None


#: The closed investigation tool surface exposed to any model backend.
INVESTIGATION_TOOLS: list[dict[str, Any]] = [
    {
        "name": "query_observations",
        "description": (
            "Bounded, classified evidence slices with stable observation IDs. "
            "Arguments: host_id (string, must equal the run host), optional "
            "watch_id (string), optional limit (integer <= 100)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host_id": {"type": "string"},
                "watch_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "required": ["host_id"],
        },
    },
    {
        "name": "get_incident_context",
        "description": (
            "Compact incident timeline, active watches, recent observations and "
            "prior findings. Arguments: incident_id (string, must equal the run incident)."
        ),
        "parameters": {
            "type": "object",
            "properties": {"incident_id": {"type": "string"}},
            "required": ["incident_id"],
        },
    },
    {
        "name": "list_active_watches",
        "description": "Effective active watches on the run host. Arguments: host_id (string).",
        "parameters": {
            "type": "object",
            "properties": {"host_id": {"type": "string"}},
            "required": ["host_id"],
        },
    },
    {
        "name": "get_host_baseline_summary",
        "description": "Accepted reference state and revision IDs. Arguments: host_id (string).",
        "parameters": {
            "type": "object",
            "properties": {"host_id": {"type": "string"}},
            "required": ["host_id"],
        },
    },
    {
        "name": "propose_ephemeral_watch",
        "description": (
            "Submit a typed ephemeral WatchSpec for the incident. The central "
            "policy gate validates it deterministically; a rejection is final. "
            "Arguments: spec (WatchSpec object), rationale (string)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "spec": {"type": "object"},
                "rationale": {"type": "string"},
            },
            "required": ["spec", "rationale"],
        },
    },
    {
        "name": "record_hypothesis_or_finding",
        "description": (
            "Record a scoped conclusion. kind is 'hypothesis' or 'verified_finding'; "
            "evidence_observation_ids must be IDs actually seen in telemetry envelopes. "
            "Arguments: kind, severity (info|low|medium|high|critical), summary, "
            "uncertainty, evidence_observation_ids (array of integers), "
            "escalation_requested (boolean)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["hypothesis", "verified_finding"]},
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                },
                "summary": {"type": "string"},
                "uncertainty": {"type": "string"},
                "evidence_observation_ids": {"type": "array", "items": {"type": "integer"}},
                "escalation_requested": {"type": "boolean"},
            },
            "required": ["kind", "severity", "summary", "uncertainty", "evidence_observation_ids"],
        },
    },
    {
        "name": "finish",
        "description": (
            "End the investigation run. Any final assessment must already be "
            "recorded via record_hypothesis_or_finding. Arguments: summary (string)."
        ),
        "parameters": {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": [],
        },
    },
]

TOOL_NAMES = [tool["name"] for tool in INVESTIGATION_TOOLS]


class ReasonerWorker:
    """Bounded episodic worker; dormant until a trigger is leased."""

    def __init__(
        self,
        client_or_factory: ControlRpcClient | Callable[[], ControlRpcClient],
        adapter: ModelAdapter,
        *,
        backend_id: str = "reasoner-d",
        model_id: str = "scripted-mock",
        lease_owner: str = "reasoner-d",
        budgets: RunBudgets | None = None,
        prompt_schema_version: str = PROMPT_SCHEMA_VERSION,
        backoff_base_seconds: float = 0.5,
        max_backoff_seconds: float = 30.0,
    ) -> None:
        self._client_or_factory = client_or_factory
        self.adapter = adapter
        self.backend_id = backend_id
        self.model_id = model_id
        self.lease_owner = lease_owner
        self.budgets = budgets or RunBudgets()
        self.prompt_schema_version = prompt_schema_version
        self.backoff_base_seconds = backoff_base_seconds
        self.max_backoff_seconds = max_backoff_seconds
        #: Debug/test hook: the final bounded conversation of the last run.
        self.last_messages: list[dict[str, Any]] | None = None

    def _new_client(self) -> ControlRpcClient:
        if callable(self._client_or_factory) and not isinstance(self._client_or_factory, ControlRpcClient):
            return self._client_or_factory()
        return self._client_or_factory  # type: ignore[return-value]

    # ------------------------------------------------------------- one attempt

    def run_once(self) -> WorkerOutcome | None:
        """Lease and process a single trigger; ``None`` when dormant."""
        client = self._new_client()
        try:
            lease = client.lease_next_trigger(self.lease_owner, self.budgets.lease_seconds)
        except RpcError as exc:
            logger.warning("lease attempt rejected: %s", exc)
            return None
        if not lease:
            return None  # dormant: nothing pending in scope
        event_id = int(lease["event_id"])
        incident_id = str(lease["incident_id"])
        host_id = str(lease["host_id"])
        lease_token = str(lease["lease_token"])
        outcome = WorkerOutcome(status="completed", event_id=event_id, incident_id=incident_id)

        # Durable run + bounded context.
        try:
            run = client.start_investigation_run(
                incident_id, self.backend_id, self.model_id, self.prompt_schema_version
            )
            run_id = str(run["run_id"])
            outcome.run_id = run_id
            context = client.get_incident_context(incident_id)
            capabilities = client.list_collector_capabilities(host_id)
        except RpcError as exc:
            logger.warning(
                "run setup failed for event %s incident %s: %s", event_id, incident_id, exc
            )
            return self._fail_lease(client, outcome, lease_token, f"run setup failed: {exc}", retryable=False)

        # A fresh capability is bound to the run by control-d; keep using the
        # same client (same token) for the rest of the run.
        run_header = {
            "run_id": run_id,
            "incident_id": incident_id,
            "host_id": host_id,
            "trigger": {
                "watch_id": lease.get("watch_id"),
                "spec_version": lease.get("spec_version"),
                "retry_count": lease.get("retry_count"),
                "outcome": lease.get("outcome"),
                "evidence_observation_ids": lease.get("evidence_observation_ids", []),
            },
            "budgets": {
                "max_turns": self.budgets.max_turns,
                "max_proposals_per_run": self.budgets.max_proposals_per_run,
                "max_total_tokens": self.budgets.max_total_tokens,
                "max_cost_usd": self.budgets.max_cost_usd,
            },
        }
        envelopes = [wrap_json("trigger:lease", lease)]
        envelopes.append(
            wrap_json("rpc:get_incident_context", context, max_content_bytes=8192)
        )
        for observation in (context.get("recent_observations") or [])[:20]:
            envelopes.append(wrap_observation(observation))
        context_block = render_context_block(
            run_header, envelopes, capabilities, max_block_bytes=self.budgets.max_context_bytes
        )
        system_prompt = build_system_prompt(
            self.backend_id, self.model_id, self.budgets, TOOL_NAMES, self.prompt_schema_version
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": context_block},
        ]

        # ------------------------------------------------------- bounded loop
        deadline = time.monotonic() + self.budgets.max_wall_seconds
        proposals = findings = 0
        proposals_accepted = 0
        finish_requested = False
        final_text: str | None = None

        try:
            for _turn in range(self.budgets.max_turns):
                if finish_requested:
                    break
                if time.monotonic() > deadline:
                    outcome.budget_stop_reason = "max_wall_seconds"
                    break
                if outcome.input_tokens + outcome.output_tokens > self.budgets.max_total_tokens:
                    outcome.budget_stop_reason = "max_total_tokens"
                    break
                if outcome.estimated_cost_usd > self.budgets.max_cost_usd:
                    outcome.budget_stop_reason = "max_cost_usd"
                    break
                try:
                    turn = self.adapter.chat(messages, INVESTIGATION_TOOLS)
                except ProviderError as exc:
                    return self._fail_lease(
                        client, outcome, lease_token, f"provider failure: {exc}", retryable=exc.retryable
                    )
                outcome.turns += 1
                outcome.input_tokens += turn.input_tokens
                outcome.output_tokens += turn.output_tokens
                outcome.estimated_cost_usd += turn.estimated_cost_usd

                if turn.tool_calls:
                    messages.append(
                        {
                            "role": "assistant",
                            "content": turn.final_text or "",
                            "tool_calls": [
                                {"id": call.id, "name": call.name, "arguments": call.arguments}
                                for call in turn.tool_calls
                            ],
                        }
                    )
                    for call in turn.tool_calls:
                        outcome.tool_calls += 1
                        result, stop = self._execute_tool(
                            client,
                            call,
                            run_id=run_id,
                            incident_id=incident_id,
                            host_id=host_id,
                            proposals_done=proposals,
                            findings_done=findings,
                        )
                        if result.get("_accepted_proposal"):
                            proposals += 1
                            proposals_accepted += 1
                        elif result.get("_proposal_attempted"):
                            proposals += 1
                        if result.get("_finding_recorded"):
                            findings += 1
                        result.pop("_accepted_proposal", None)
                        result.pop("_proposal_attempted", None)
                        result.pop("_finding_recorded", None)
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": call.id,
                                "name": call.name,
                                "content": self._tool_message(result),
                            }
                        )
                        if call.name == "finish":
                            finish_requested = True
                        if stop:
                            break
                    self._compact_messages(messages)
                    if not finish_requested:
                        continue
                if turn.final_text is not None or not turn.tool_calls:
                    final_text = turn.final_text or ""
                    break
            else:
                outcome.budget_stop_reason = outcome.budget_stop_reason or "max_turns"
        except RpcTransportError as exc:
            return self._fail_lease(client, outcome, lease_token, f"control-d transport failure: {exc}", retryable=True)

        outcome.proposals = proposals
        outcome.proposals_accepted = proposals_accepted
        outcome.findings = findings
        outcome.summary = clip_utf8(
            final_text or "investigation run finished without a final model summary", 2048
        )
        self.last_messages = messages

        # Findings/proposals are durably submitted; only now complete the lease.
        try:
            client.complete_trigger_lease(
                event_id, lease_token, run_id=run_id, summary=outcome.summary
            )
        except RpcError as exc:
            # Fencing token rejection: an expired or reclaimed lease can never
            # commit results. Drop the run; control-d requeued or dead-lettered
            # the trigger on expiry.
            logger.warning("lease %s could not be completed (fencing): %s", event_id, exc)
            outcome.status = "lease_stale"
            outcome.error = str(exc)
            return outcome
        logger.info(
            "event %s completed: turns=%s findings=%s proposals=%s (accepted=%s)",
            event_id, outcome.turns, findings, proposals, proposals_accepted,
        )
        return outcome

    # -------------------------------------------------------------- tool exec

    def _execute_tool(
        self,
        client: ControlRpcClient,
        call: ToolCall,
        *,
        run_id: str,
        incident_id: str,
        host_id: str,
        proposals_done: int,
        findings_done: int,
    ) -> tuple[dict[str, Any], bool]:
        """Execute ONE allowed investigation tool via the RPC. No shell ever.

        Returns ``(result_dict, stop_loop)`` where the result dict is what the
        model sees (enveloped upstream) plus private bookkeeping flags.
        """
        name = call.name
        args = call.arguments if isinstance(call.arguments, dict) else {}
        try:
            if name == "query_observations":
                target_host = str(args.get("host_id") or host_id)
                if target_host != host_id:
                    return {"error": "forbidden", "detail": "host is outside run scope"}, False
                observations = client.query_observations(
                    host_id,
                    watch_id=args.get("watch_id"),
                    limit=int(args.get("limit") or 50),
                )
                return {"observations": observations}, False
            if name == "get_incident_context":
                if str(args.get("incident_id") or incident_id) != incident_id:
                    return {"error": "forbidden", "detail": "incident is outside run scope"}, False
                return client.get_incident_context(incident_id), False
            if name == "list_active_watches":
                if str(args.get("host_id") or host_id) != host_id:
                    return {"error": "forbidden", "detail": "host is outside run scope"}, False
                return {"watches": client.list_active_watches(host_id)}, False
            if name == "get_host_baseline_summary":
                if str(args.get("host_id") or host_id) != host_id:
                    return {"error": "forbidden", "detail": "host is outside run scope"}, False
                return client.get_host_baseline_summary(host_id), False
            if name == "propose_ephemeral_watch":
                if proposals_done >= self.budgets.max_proposals_per_run:
                    return (
                        {
                            "error": "budget",
                            "detail": f"proposal budget of {self.budgets.max_proposals_per_run} "
                            "for this run is exhausted",
                        },
                        False,
                    )
                spec = args.get("spec")
                rationale = str(args.get("rationale") or "")
                if not isinstance(spec, dict):
                    return {"error": "invalid", "detail": "spec must be an object"}, False
                try:
                    reply = client.propose_ephemeral_watch(
                        run_id,
                        args.get("idempotency_key")
                        or f"{run_id}-p{proposals_done + 1}-{uuid.uuid4().hex[:8]}",
                        spec,
                        rationale,
                    )
                except RpcError as exc:
                    # A deterministic policy rejection still consumes run budget:
                    # rejections are final and must not be retried by the model.
                    return (
                        {"error": exc.code, "detail": exc.message, "_proposal_attempted": True},
                        False,
                    )
                decision = reply.get("decision") or {}
                result = {
                    "decision": decision,
                    "watch_id": reply.get("watch_id"),
                    "bundle_version": reply.get("bundle_version"),
                    "_proposal_attempted": True,
                }
                if decision.get("allowed"):
                    result["_accepted_proposal"] = True
                return result, False
            if name == "record_hypothesis_or_finding":
                kind = str(args.get("kind") or "hypothesis")
                evidence = args.get("evidence_observation_ids") or []
                if not isinstance(evidence, list):
                    return {"error": "invalid", "detail": "evidence must be an array of IDs"}, False
                reply = client.record_hypothesis_or_finding(
                    run_id,
                    incident_id,
                    kind=kind,
                    severity=str(args.get("severity") or "low"),
                    summary=str(args.get("summary") or ""),
                    uncertainty=str(args.get("uncertainty") or ""),
                    evidence_observation_ids=[int(i) for i in evidence],
                    escalation_requested=bool(args.get("escalation_requested", False)),
                )
                return {"_finding_recorded": True, **reply}, False
            if name == "finish":
                return {"finished": True, "summary": str(args.get("summary") or "")}, True
            return {"error": "unknown_tool", "detail": f"tool '{name}' is not on the run surface"}, False
        except RpcError as exc:
            # A deterministic policy rejection: report verbatim to the model.
            return {"error": exc.code, "detail": exc.message}, False

    @staticmethod
    def _tool_message(result: dict[str, Any]) -> str:
        """Render a tool result as an untrusted provenance envelope."""
        from defsec_reasoner.provenance import wrap_tool_result

        return wrap_tool_result("investigation_rpc", result, max_content_bytes=8192)

    def _compact_messages(self, messages: list[dict[str, Any]]) -> None:
        """Keep the conversation under ``max_context_bytes`` deterministically."""
        budget = self.budgets.max_context_bytes
        tool_indexes = [i for i, m in enumerate(messages) if m.get("role") == "tool"]
        while self._messages_bytes(messages) > budget and len(tool_indexes) > 1:
            idx = tool_indexes.pop(0)
            messages[idx]["content"] = "[older tool results compacted for context budget]"
        if self._messages_bytes(messages) > budget and tool_indexes:
            idx = tool_indexes[-1]
            others = self._messages_bytes([m for j, m in enumerate(messages) if j != idx])
            room = max(budget - others, 256)
            messages[idx]["content"] = clip_utf8(str(messages[idx]["content"]), room)
        if self._messages_bytes(messages) > budget:
            last_user = max((i for i, m in enumerate(messages) if m.get("role") == "user"), default=0)
            others = self._messages_bytes([m for j, m in enumerate(messages) if j != last_user])
            room = max(budget - others, 256)
            messages[last_user]["content"] = clip_utf8(str(messages[last_user]["content"]), room)

    @staticmethod
    def _messages_bytes(messages: list[dict[str, Any]]) -> int:
        return len(json.dumps(messages, ensure_ascii=False, default=str).encode("utf-8"))

    # ------------------------------------------------------------ lease policy

    def _fail_lease(
        self,
        client: ControlRpcClient,
        outcome: WorkerOutcome,
        lease_token: str,
        error: str,
        *,
        retryable: bool,
    ) -> WorkerOutcome:
        assert outcome.event_id is not None
        try:
            reply = client.fail_trigger_lease(
                outcome.event_id, lease_token, error, retryable=retryable
            )
            status = str(reply.get("status") or ("pending" if retryable else "dead_letter"))
        except RpcError as exc:
            # Lease expired and was reclaimed (fencing): nothing to commit.
            logger.warning("lease %s could not be failed (fencing): %s", outcome.event_id, exc)
            outcome.status = "lease_stale"
            outcome.error = str(exc)
            return outcome
        outcome.status = "requeued" if status == "pending" else "dead_letter"
        outcome.error = clip_utf8(error, 512)
        logger.warning(
            "event %s failed (retryable=%s) -> %s", outcome.event_id, retryable, status
        )
        return outcome

    def next_backoff_seconds(self, retry_count: int) -> float:
        """Bounded exponential backoff for requeued triggers."""
        raw = self.backoff_base_seconds * (2 ** max(int(retry_count) - 1, 0))
        return min(raw, self.max_backoff_seconds)

    # ------------------------------------------------------------------- loop

    def run_loop(
        self,
        poll_interval_seconds: float = 5.0,
        stop_event: threading.Event | None = None,
    ) -> int:
        """Continuous dormant-until-triggered loop with graceful shutdown.

        Returns the number of processed (non-dormant) runs.
        """
        stop_event = stop_event or threading.Event()
        processed = 0
        last_retry_count = 0
        logger.info("reasoner-d worker loop started (poll=%ss)", poll_interval_seconds)
        try:
            while not stop_event.is_set():
                try:
                    outcome = self.run_once()
                except RpcTransportError as exc:
                    logger.warning("control-d unreachable; backing off: %s", exc)
                    stop_event.wait(self.next_backoff_seconds(1))
                    continue
                if outcome is None:
                    last_retry_count = 0
                    stop_event.wait(poll_interval_seconds)
                    continue
                processed += 1
                if outcome.status == "requeued":
                    # Bounded backoff before the next attempt on this trigger.
                    stop_event.wait(self.next_backoff_seconds(last_retry_count + 1))
                    last_retry_count += 1
                else:
                    last_retry_count = 0
                    stop_event.wait(min(poll_interval_seconds, 1.0))
        except KeyboardInterrupt:  # graceful ^C
            logger.info("worker loop interrupted; shutting down")
        finally:
            logger.info("worker loop stopped after %s run(s)", processed)
        return processed
