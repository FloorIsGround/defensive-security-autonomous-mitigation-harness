"""The automated episodic reasoning worker (`reasoner-d`, Design §7.4).

Lifecycle of one run:

1. Lease the next pending trigger (dormant when the queue is empty).
2. Mint/obtain short-lived run-scoped authority and start a durable
   investigation run bound to the incident.
3. Fetch bounded incident context + collector capabilities and render all
   monitored data inside provenance envelopes (never raw).
4. Execute a bounded tool-calling loop through the Investigation RPC only —
   no shell, no filesystem, no direct database access.
5. Commit findings/proposals, persist the run outcome, then complete the
   trigger lease. Retryable provider failures requeue the trigger with bounded
   backoff. Non-retryable failures dead-letter the trigger. Lease completion
   is fenced by control-d.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from queue import Full, Queue
from typing import Any, Callable

from defsec_reasoner import PROMPT_SCHEMA_VERSION
from defsec_reasoner.canonical import (
    CanonicalizationError,
    canonical_json,
    sha256_hex,
)
from defsec_reasoner.context import (
    compact_for_prompt,
    has_set_items,
    select_observations,
    trigger_diff,
)
from defsec_reasoner.models import BudgetExhausted, ModelAdapter, ProviderError, ToolCall, TurnBudget
from defsec_reasoner.provenance import (
    build_system_prompt,
    clip_utf8,
    render_context_block,
    wrap_json,
    wrap_observation,
)
from defsec_reasoner.rpc_client import (
    ACTION_VERB_KINDS,
    ControlRpcClient,
    RpcError,
    RpcTransportError,
    normalize_action_verb,
)

__all__ = [
    "RunBudgets",
    "ReasonerWorker",
    "WorkerOutcome",
    "INVESTIGATION_TOOLS",
    "ACTION_TOOLS",
    "ACTION_TOOL_NAMES",
]

logger = logging.getLogger("defsec.reasoner.worker")


@dataclass
class RunBudgets:
    """Hard, worker-enforced limits for one investigation run."""

    max_turns: int = 6
    max_wall_seconds: float = 45.0
    max_total_tokens: int = 48000
    max_cost_usd: float = 0.25
    max_proposals_per_run: int = 3
    max_rule_proposals_per_run: int = 3
    max_action_proposals_per_run: int = 1
    enable_action_proposals: bool = False
    max_context_bytes: int = 32768
    lease_seconds: int = 120
    max_completion_tokens: int = 4096
    onboarding_max_total_tokens: int = 24_000
    onboarding_max_wall_seconds: float = 15.0


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
    cached_input_tokens: int = 0
    reasoning_tokens: int = 0
    cache_creation_input_tokens: int = 0
    estimated_cost_usd: float = 0.0
    findings: int = 0
    proposals: int = 0
    proposals_accepted: int = 0
    rule_proposals_submitted: int = 0
    rule_proposals_accepted: int = 0
    action_proposals_submitted: int = 0
    action_proposals_accepted: int = 0
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
            "watch_id (string), optional limit (integer <= 100), and optional focus_keys "
            "(array of set identities to retrieve, including keys omitted from the initial context)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host_id": {"type": "string"},
                "watch_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "focus_keys": {"type": "array", "items": {"type": "string"}},
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
            "policy gate validates it deterministically; unknown fields are rejected. "
            "Exact WatchSpec JSON shape: "
            "{id: str, version: 1, host_id: str, class: 'ephemeral', incident_id: str, "
            "collector: {type: 'systemd.unit_state', parameters: {unit: 'name.service', hash_unit_files: true}} "
            "| {type: 'journal.unit_events', parameters: {unit: 'name.service', min_priority: 6, max_events_per_batch: 50, max_message_bytes: 512}} "
            "| {type: 'files.metadata', parameters: {paths: ['/etc/...'], compute_hash: true, max_file_bytes: 65536}} "
            "| {type: 'sockets.listening', parameters: {include_tcp: true, include_udp: false, include_ipv6: true, resolve_process: true}}, "
            "schedule: {interval_seconds: >=15, timeout_seconds: 5}, "
            "trigger: {type: 'field_changed', compare_against: 'last_observed', fields: ['active_state']} "
            "| {type: 'set_diff', compare_against: 'last_observed', set_field: 'sockets', identity_key: 'socket_key'}, "
            "wake_policy: {cooldown_seconds: 120, max_wakeups_per_hour: 4}, "
            "lifecycle: {enabled: true, expires_at: '<RFC3339 UTC within 4h>', max_runs: 120}}. "
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
        "name": "propose_expectation_rule",
        "description": (
            "Propose ONE closed-schema expectation rule telling control-d that "
            "benign recurring set-diff noise from a known service is expected "
            "(e.g. a unit that may open and close its own bounded listener "
            "ports). Use ONLY for benign recurring noise with a clear service "
            "anchor (systemd_unit/comm/uid plus a bounded local_port); NEVER "
            "for suspicious or unexplained activity. Rules are INERT until an "
            "operator approves them on the admin interface; a proposal only "
            "records an auditable expectation with a backtest. The central "
            "gate is deterministic and a rejection is final. Exact "
            "ExpectationRuleSpec JSON shape: "
            "{scope: {host_id: str (the run host), collector: 'sockets.listening', "
            "watch_id: str (optional)}, "
            "matches: [1..8 of {op: 'eq', field: str, value: str|int} "
            "| {op: 'in', field: str, values: [str|int, ...max 32]} "
            "| {op: 'range', field: str, min: int, max: int} "
            "| {op: 'prefix', field: str, value: str}], "
            "effect: 'allow_optional' | 'require_present' | 'ignore_modified', "
            "rationale: str (<=1024 bytes), "
            "expires_at: '<RFC3339 UTC within 30 days, required>'}. Sockets fields: "
            "protocol, local_addr, local_port, uid, comm, systemd_unit, bind_scope. "
            "Proposals are idempotent per (run_id, idempotency_key): omit the key "
            "and an identical resubmission of the same rule replays the stored "
            "decision instead of proposing twice. "
            "Arguments: rule (object), optional idempotency_key (string)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "idempotency_key": {"type": "string"},
                "rule": {"type": "object"},
            },
            "required": ["rule"],
            "additionalProperties": False,
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

#: Phase 8 typed mitigation tools. Only exposed when
#: ``RunBudgets.enable_action_proposals`` is explicitly True (safe opt-in).
ACTION_TOOLS: list[dict[str, Any]] = [
    {
        "name": "propose_action",
        "description": (
            "Submit ONE typed mitigation action from a closed catalog. There is no "
            "shell, script, or free-form remediation: the only verbs are "
            "nft_block_ip, systemd_stop_unit, and host_isolate. Every action must "
            "cite at least one verified observation_id and include a concrete "
            "rollback_plan; the central policy gate may auto-authorize reversible "
            "low-blast verbs under human-owned policy, or require an independent "
            "operator dual-signature for high-blast verbs (status pending_approval). "
            "A rejection is final. Arguments: verb (closed-catalog object with a "
            "'verb' tag), evidence_observation_ids (array of integers), "
            "expected_effect, blast_radius, rollback_plan."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "verb": {
                    "type": "object",
                    "properties": {
                        "verb": {"type": "string", "enum": list(ACTION_VERB_KINDS)},
                        "ip": {"type": "string"},
                        "direction": {"type": "string", "enum": ["inbound", "outbound", "both"]},
                        "unit": {"type": "string"},
                        "preserve_mgmt_cidrs": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "ttl_seconds": {"type": "integer", "minimum": 1},
                    },
                    "required": ["verb"],
                    "additionalProperties": False,
                },
                "evidence_observation_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "minItems": 1,
                },
                "expected_effect": {"type": "string"},
                "blast_radius": {"type": "string"},
                "rollback_plan": {"type": "string"},
            },
            "required": [
                "verb",
                "evidence_observation_ids",
                "expected_effect",
                "blast_radius",
                "rollback_plan",
            ],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_actions",
        "description": (
            "List action proposal summaries for this run's host and incident "
            "(proposal/intent IDs, auth mode, status). Read-only; no arguments."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
]

ACTION_TOOL_NAMES = frozenset(tool["name"] for tool in ACTION_TOOLS)

#: Top-level keys that are not fields of the tagged ``ActionVerb`` object.
_ACTION_METADATA_KEYS = frozenset(
    {
        "verb",
        "evidence_observation_ids",
        "expected_effect",
        "blast_radius",
        "rollback_plan",
        "idempotency_key",
    }
)


class _RunProgress:
    """Send bounded progress snapshots off the investigation's critical path."""

    def __init__(self, client: ControlRpcClient, run_id: str) -> None:
        self._queue: Queue[tuple[str, dict[str, Any]] | None] = Queue(maxsize=256)
        self._stopped = threading.Event()
        self._thread = threading.Thread(target=self._send, args=(client, run_id), daemon=True)
        self._thread.start()

    def record(self, kind: str, **detail: Any) -> None:
        if not self._stopped.is_set():
            try:
                self._queue.put_nowait((kind, detail))
            except Full:
                pass

    def close(self) -> None:
        try:
            self._queue.put_nowait(None)
        except Full:
            self._stopped.set()
            return
        # Allow local, already queued events to land before the terminal write.
        self._thread.join(timeout=0.05)
        self._stopped.set()

    def _send(self, client: ControlRpcClient, run_id: str) -> None:
        while not self._stopped.is_set():
            item = self._queue.get()
            if item is None or self._stopped.is_set():
                break
            kind, detail = item
            try:
                client.report_run_progress(run_id, kind, detail)
            except RpcError as exc:
                logger.debug("run progress rejected: %s", exc.code)
                if exc.code == "run_event_quota":
                    break
            except (RpcTransportError, OSError):
                logger.debug("run progress transport failed")
                break
        self._stopped.set()


def _tool_preview(call: ToolCall) -> tuple[str, str]:
    for tool in INVESTIGATION_TOOLS + ACTION_TOOLS:
        if call.name == tool["name"]:
            args = call.arguments if isinstance(call.arguments, dict) else {}
            fields = tool["parameters"]["properties"]
            # Preview only trusted parameter names and types. Free-form strings
            # and nested arguments may contain sensitive telemetry.
            preview = ", ".join(f"{key}={fields[key]['type']}" for key in fields if key in args)
            return call.name, clip_utf8(preview, 160)
    return "unknown_tool", ""


def _redact_credentials(text: str, client: ControlRpcClient, lease_token: str) -> str:
    for credential in (lease_token, getattr(client, "capability_token", "")):
        if credential:
            text = text.replace(credential, "[redacted]")
    return text


def _auto_idempotency_key(run_id: str, payload: Any) -> str:
    """Deterministic default idempotency key for one typed proposal.

    control-d stores a receipt per ``(run_id, idempotency_key)``: replaying
    the same key with the same canonical spec returns the original response,
    and reusing it with a different spec is a structured ``conflict``.
    Deriving the key from the run plus an RFC 8785 canonical serialization
    of the proposal payload means a proposal whose response was lost can be
    resubmitted verbatim and replay instead of storing a duplicate: identical
    proposals in the same run share a key, distinct proposals get distinct
    keys, and the key is stable across worker restarts because it contains
    no process-local randomness and no attempt counter.

    A payload outside the canonical JSON subset (e.g. a non-integral float
    smuggled in by a model) falls back to sorted deterministic JSON: the
    key stays a pure function of the payload, and control-d's typed boundary
    still rejects the spec itself.
    """
    try:
        payload_material = canonical_json(payload)
    except CanonicalizationError:
        payload_material = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
        )
    material = canonical_json(str(run_id)) + payload_material
    return "auto-" + sha256_hex(material.encode("utf-8"))[:32]


def _outcome_unknown(tool_noun: str, exc: RpcTransportError) -> dict[str, Any]:
    """A proposal tool result for a transport-level failure (timeout/EOF).

    The call was sent but no structured reply arrived: the proposal may have
    committed before the connection died, or may never have been parsed.
    That ambiguity is reported to the model explicitly instead of aborting
    the run or guessing a schema rejection; the deterministic auto key (or
    the model's own key) makes an identical resubmission replay the receipt.
    Callers add their ``_*_attempted`` flag so the attempt is charged
    against the per-run proposal cap.
    """
    return {
        "error": "outcome_unknown",
        "detail": clip_utf8(
            "control-d transport failure while submitting the "
            f"{tool_noun} (a commit may or may not have landed): {exc}",
            256,
        ),
        "retry_hint": f"re-submitting the identical {tool_noun} is safe; it will replay",
    }


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
        followups_only: bool = False,
        discovery_only: bool = False,
    ) -> None:
        self.discovery_only = discovery_only
        self.followups_only = followups_only
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
        if self.followups_only:
            from defsec_reasoner.followups import reassess

            return reassess(self, client)
        try:
            lease = None if self.discovery_only else client.lease_next_trigger(self.lease_owner, self.budgets.lease_seconds)
        except (RpcError, RpcTransportError) as exc:
            logger.warning("lease attempt rejected: %s", exc)
            return None
        if not lease:
            from defsec_reasoner.discovery import interpret_next_host

            interpret_next_host(self.adapter, client, self.budgets)
            return None
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
        except (RpcError, RpcTransportError) as exc:
            logger.warning(
                "run setup failed for event %s incident %s: %s", event_id, incident_id, exc
            )
            return self._fail_lease(
                client, outcome, lease_token, f"run setup failed: {exc}",
                retryable=isinstance(exc, RpcTransportError),
            )

        try:
            return self._investigate(
                client, lease, outcome, lease_token, context, capabilities
            )
        except Exception as exc:  # noqa: BLE001 - never strand a leased trigger or an active run
            logger.exception("run %s crashed for event %s", outcome.run_id, event_id)
            return self._fail_lease(
                client, outcome, lease_token,
                f"internal error: {type(exc).__name__}: {exc}", retryable=True,
            )

    def _investigate(
        self,
        client: ControlRpcClient,
        lease: dict[str, Any],
        outcome: WorkerOutcome,
        lease_token: str,
        context: dict[str, Any],
        capabilities: list[dict[str, Any]],
    ) -> WorkerOutcome:
        """Run the bounded model loop for a leased trigger with a started run."""
        event_id = int(lease["event_id"])
        incident_id = str(lease["incident_id"])
        host_id = str(lease["host_id"])
        run_id = str(outcome.run_id)
        # A fresh capability is bound to the run by control-d; keep using the
        # same client (same token) for the rest of the run.
        diff = trigger_diff(lease.get("outcome") or {})
        focus_keys = {key for keys in diff.values() for key in keys}
        evidence_ids = set(lease.get("evidence_observation_ids") or [])
        run_header = {
            "run_id": run_id,
            "incident_id": incident_id,
            "host_id": host_id,
            "trigger": {
                "watch_id": lease.get("watch_id"),
                "spec_version": lease.get("spec_version"),
                "retry_count": lease.get("retry_count"),
                "evidence_observation_ids": lease.get("evidence_observation_ids", []),
            },
            "trigger_diff": {name: keys[:50] for name, keys in diff.items()},
            "budgets": {
                "max_turns": self.budgets.max_turns,
                "max_proposals_per_run": self.budgets.max_proposals_per_run,
                "max_rule_proposals_per_run": self.budgets.max_rule_proposals_per_run,
                "max_action_proposals_per_run": self.budgets.max_action_proposals_per_run,
                "enable_action_proposals": self.budgets.enable_action_proposals,
                "max_total_tokens": self.budgets.max_total_tokens,
                "max_cost_usd": self.budgets.max_cost_usd,
            },
        }
        observations = select_observations(context.get("recent_observations") or [], evidence_ids)
        compacted = [compact_for_prompt(row, focus_keys) for row in observations]
        if focus_keys:
            compacted.sort(key=lambda row: not has_set_items(row))
        envelopes = [wrap_observation(row) for row in compacted]
        incident_metadata = {key: value for key, value in context.items() if key != "recent_observations"}
        envelopes.append(wrap_json("trigger:outcome", lease.get("outcome")))
        envelopes.append(wrap_json("rpc:get_incident_context", incident_metadata))
        context_block = render_context_block(
            run_header, envelopes, capabilities,
            max_block_bytes=min(self.budgets.max_context_bytes, 24 * 1024),
        )
        tools = (
            INVESTIGATION_TOOLS + ACTION_TOOLS
            if self.budgets.enable_action_proposals
            else INVESTIGATION_TOOLS
        )
        system_prompt = build_system_prompt(
            self.backend_id,
            self.model_id,
            self.budgets,
            [tool["name"] for tool in tools],
            self.prompt_schema_version,
            enable_action_proposals=self.budgets.enable_action_proposals,
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": context_block},
        ]

        # ------------------------------------------------------- bounded loop
        deadline = time.monotonic() + self.budgets.max_wall_seconds
        final_text: str | None = None
        finish_summary = ""
        budget_warning_sent = False
        progress = _RunProgress(client, run_id)
        failure: tuple[str, bool] | None = None

        try:
            for _turn in range(self.budgets.max_turns):
                if time.monotonic() >= deadline:
                    outcome.budget_stop_reason = "max_wall_seconds"
                    break
                if outcome.input_tokens + outcome.output_tokens >= self.budgets.max_total_tokens:
                    outcome.budget_stop_reason = "max_total_tokens"
                    break
                if outcome.estimated_cost_usd > self.budgets.max_cost_usd:
                    outcome.budget_stop_reason = "max_cost_usd"
                    break
                progress.record(
                    "turn_started", turn=_turn + 1,
                    input_tokens=outcome.input_tokens, output_tokens=outcome.output_tokens,
                )
                remaining_tokens = (
                    self.budgets.max_total_tokens - outcome.input_tokens - outcome.output_tokens
                )
                budget = TurnBudget(
                    remaining_tokens, deadline, self.budgets.max_completion_tokens,
                    session_id=f"trigger/{incident_id}/{event_id}",
                )
                turn = self.adapter.chat_with_budget(messages, tools, budget)
                outcome.turns += 1
                outcome.input_tokens += turn.input_tokens
                outcome.output_tokens += turn.output_tokens
                outcome.cached_input_tokens += turn.cached_input_tokens
                outcome.reasoning_tokens += turn.reasoning_tokens
                outcome.cache_creation_input_tokens += turn.cache_creation_input_tokens
                outcome.estimated_cost_usd += turn.estimated_cost_usd

                tokens_used = outcome.input_tokens + outcome.output_tokens
                if not budget_warning_sent and tokens_used * 5 >= self.budgets.max_total_tokens * 4:
                    progress.record(
                        "budget_warning", total_tokens=tokens_used,
                        max_total_tokens=self.budgets.max_total_tokens,
                    )
                    budget_warning_sent = True
                if turn.finish_reason == "budget_exhausted":
                    outcome.budget_stop_reason = "provider_token_limit"
                    break
                if tokens_used >= self.budgets.max_total_tokens:
                    outcome.budget_stop_reason = "max_total_tokens"
                    break
                if outcome.estimated_cost_usd > self.budgets.max_cost_usd:
                    outcome.budget_stop_reason = "max_cost_usd"
                    break
                if time.monotonic() >= deadline:
                    outcome.budget_stop_reason = "max_wall_seconds"
                    break
                if turn.final_text:
                    text = _redact_credentials(turn.final_text, client, lease_token)
                    progress.record("model_text", text=text[:300])

                if turn.tool_calls:
                    assistant_msg: dict[str, Any] = {
                        "role": "assistant",
                        "content": turn.final_text or "",
                        "tool_calls": [
                            {"id": call.id, "name": call.name, "arguments": call.arguments}
                            for call in turn.tool_calls
                        ],
                    }
                    if turn.response_items:
                        assistant_msg["response_items"] = turn.response_items
                    if turn.reasoning_content is not None:
                        assistant_msg["reasoning_content"] = turn.reasoning_content
                    messages.append(assistant_msg)
                    stop = False
                    for call in turn.tool_calls:
                        if time.monotonic() >= deadline:
                            outcome.budget_stop_reason = "max_wall_seconds"
                            break
                        outcome.tool_calls += 1
                        tool_name, preview = _tool_preview(call)
                        progress.record("tool_call", tool=tool_name, arguments_preview=preview)
                        result, stop = self._execute_tool(
                            client,
                            call,
                            run_id=run_id,
                            incident_id=incident_id,
                            host_id=host_id,
                            proposals_done=outcome.proposals,
                            rule_proposals_done=outcome.rule_proposals_submitted,
                            action_proposals_done=outcome.action_proposals_submitted,
                            findings_done=outcome.findings,
                        )
                        proposal_accepted = bool(result.pop("_accepted_proposal", None))
                        proposal_attempted = result.pop("_proposal_attempted", None)
                        rule_accepted = bool(result.pop("_accepted_rule_proposal", None))
                        rule_attempted = result.pop("_rule_proposal_attempted", None)
                        action_accepted = bool(result.pop("_action_proposal_accepted", None))
                        action_attempted = result.pop("_action_proposal_attempted", None)
                        outcome.proposals += int(bool(proposal_attempted) or proposal_accepted)
                        outcome.proposals_accepted += int(proposal_accepted)
                        outcome.rule_proposals_submitted += int(
                            bool(rule_attempted) or rule_accepted
                        )
                        outcome.rule_proposals_accepted += int(rule_accepted)
                        outcome.action_proposals_submitted += int(
                            bool(action_attempted) or action_accepted
                        )
                        outcome.action_proposals_accepted += int(action_accepted)
                        outcome.findings += int(bool(result.pop("_finding_recorded", None)))

                        error = result.get("error")
                        detail: dict[str, Any] = {"tool": tool_name, "ok": error is None}
                        if error is not None:
                            detail["error_code"] = clip_utf8(str(error), 64)
                        if tool_name in (
                            "propose_ephemeral_watch",
                            "propose_expectation_rule",
                            "propose_action",
                        ):
                            detail["accepted"] = (
                                proposal_accepted or rule_accepted or action_accepted
                            )
                        progress.record("tool_result", **detail)
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": call.id,
                                "name": call.name,
                                "content": self._tool_message(result),
                            }
                        )
                        if stop:
                            finish_summary = result["summary"]
                            break
                    self._compact_messages(messages)
                    if time.monotonic() >= deadline:
                        outcome.budget_stop_reason = "max_wall_seconds"
                        break
                    if not stop:
                        continue
                final_text = turn.final_text
                break
            else:
                outcome.budget_stop_reason = "max_turns"
        except BudgetExhausted as exc:
            outcome.budget_stop_reason = str(exc)
            if outcome.budget_stop_reason == "max_total_tokens" and not budget_warning_sent:
                progress.record(
                    "budget_warning", total_tokens=outcome.input_tokens + outcome.output_tokens,
                    max_total_tokens=self.budgets.max_total_tokens,
                )
        except ProviderError as exc:
            if time.monotonic() >= deadline:
                outcome.budget_stop_reason = "max_wall_seconds"
            else:
                failure = (f"provider failure: {exc}", exc.retryable)
        except RpcTransportError as exc:
            failure = (f"control-d transport failure: {exc}", True)
        finally:
            progress.close()

        if failure is not None:
            error, retryable = failure
            return self._fail_lease(client, outcome, lease_token, error, retryable=retryable)
        summary = final_text or finish_summary or "investigation run finished without a final model summary"
        outcome.summary = clip_utf8(_redact_credentials(summary, client, lease_token), 2048)
        self.last_messages = messages

        # Finish is a durable write between the evidence writes and lease completion.
        terminal = "budget_exhausted" if outcome.budget_stop_reason else "completed"
        try:
            self._finish_run(client, outcome, terminal)
        except (RpcError, RpcTransportError) as exc:
            return self._fail_lease(client, outcome, lease_token, f"run finish failed: {exc}", retryable=True)

        try:
            client.complete_trigger_lease(
                event_id, lease_token, run_id=run_id, summary=outcome.summary
            )
        except (RpcError, RpcTransportError) as exc:
            logger.warning("lease %s could not be completed: %s", event_id, exc)
            outcome.status = "lease_stale"
            outcome.error = str(exc)
            return outcome
        logger.info(
            "event %s completed: turns=%s findings=%s proposals=%s (accepted=%s) "
            "rule_proposals=%s (accepted=%s) action_proposals=%s (accepted=%s)",
            event_id, outcome.turns, outcome.findings, outcome.proposals, outcome.proposals_accepted,
            outcome.rule_proposals_submitted, outcome.rule_proposals_accepted,
            outcome.action_proposals_submitted, outcome.action_proposals_accepted,
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
        rule_proposals_done: int,
        action_proposals_done: int,
        findings_done: int,
    ) -> tuple[dict[str, Any], bool]:
        """Execute ONE allowed investigation tool via the RPC. No shell ever.

        Returns ``(result_dict, stop_loop)`` where the result dict is what the
        model sees (enveloped upstream) plus private bookkeeping flags.
        """
        name = call.name
        args = call.arguments if isinstance(call.arguments, dict) else {}
        try:
            if name in ACTION_TOOL_NAMES and not self.budgets.enable_action_proposals:
                # Safe default: the tools are not advertised, and a hijacked
                # model that emits them anyway is refused before any RPC.
                return (
                    {
                        "error": "forbidden",
                        "detail": "typed action proposals are disabled for this worker run",
                    },
                    False,
                )
            if name == "propose_action":
                if action_proposals_done >= self.budgets.max_action_proposals_per_run:
                    return (
                        {
                            "error": "budget",
                            "detail": "action proposal budget of "
                            f"{self.budgets.max_action_proposals_per_run} for this run is exhausted",
                        },
                        False,
                    )
                raw_verb = args.get("verb")
                if isinstance(raw_verb, dict):
                    verb_payload: Any = raw_verb
                elif isinstance(raw_verb, str):
                    # Tolerate the flat form while still validating strictly.
                    verb_payload = {
                        key: value
                        for key, value in args.items()
                        if key not in _ACTION_METADATA_KEYS
                    }
                    verb_payload["verb"] = raw_verb
                else:
                    return (
                        {"error": "invalid", "detail": "verb must be a closed-catalog object"},
                        False,
                    )
                try:
                    verb = normalize_action_verb(verb_payload)
                    evidence = args.get("evidence_observation_ids")
                    if not isinstance(evidence, list) or not evidence:
                        raise ValueError(
                            "evidence_observation_ids must cite at least one verified observation"
                        )
                    if not all(
                        isinstance(i, int) and not isinstance(i, bool) for i in evidence
                    ):
                        raise ValueError("evidence_observation_ids must be integers")
                    expected_effect = str(args.get("expected_effect") or "").strip()
                    blast_radius = str(args.get("blast_radius") or "").strip()
                    rollback_plan = str(args.get("rollback_plan") or "").strip()
                    for field, value in (
                        ("expected_effect", expected_effect),
                        ("blast_radius", blast_radius),
                        ("rollback_plan", rollback_plan),
                    ):
                        if not value:
                            raise ValueError(f"{field} must be a non-empty string")
                except ValueError as exc:
                    return {"error": "invalid", "detail": str(exc)}, False
                try:
                    reply = client.propose_action(
                        run_id,
                        incident_id,
                        args.get("idempotency_key")
                        or _auto_idempotency_key(
                            run_id,
                            {
                                "verb": verb,
                                "evidence_observation_ids": sorted({int(i) for i in evidence}),
                                "expected_effect": expected_effect,
                                "blast_radius": blast_radius,
                                "rollback_plan": rollback_plan,
                            },
                        ),
                        verb,
                        [int(i) for i in evidence],
                        expected_effect,
                        blast_radius,
                        rollback_plan,
                    )
                except RpcError as exc:
                    return (
                        {
                            "error": exc.code,
                            "detail": exc.message,
                            "_action_proposal_attempted": True,
                        },
                        False,
                    )
                except RpcTransportError as exc:
                    return (
                        {
                            **_outcome_unknown("action proposal", exc),
                            "_action_proposal_attempted": True,
                        },
                        False,
                    )
                decision = reply.get("decision") or {}
                result = {
                    "decision": decision,
                    "proposal_id": reply.get("proposal_id"),
                    "intent_id": reply.get("intent_id"),
                    "auth_mode": reply.get("auth_mode"),
                    "status": reply.get("status"),
                    "authorized_intent": reply.get("authorized_intent"),
                    "_action_proposal_attempted": True,
                }
                if decision.get("allowed"):
                    result["_action_proposal_accepted"] = True
                return result, False
            if name == "list_actions":
                if args.get("host_id") is not None and str(args.get("host_id")) != host_id:
                    return {"error": "forbidden", "detail": "host is outside run scope"}, False
                if (
                    args.get("incident_id") is not None
                    and str(args.get("incident_id")) != incident_id
                ):
                    return {"error": "forbidden", "detail": "incident is outside run scope"}, False
                return (
                    {
                        "actions": client.list_actions(
                            host_id=host_id, incident_id=incident_id
                        )
                    },
                    False,
                )
            if name == "query_observations":
                target_host = str(args.get("host_id") or host_id)
                if target_host != host_id:
                    return {"error": "forbidden", "detail": "host is outside run scope"}, False
                focus = args.get("focus_keys", [])
                if not isinstance(focus, list) or not all(isinstance(key, str) for key in focus):
                    return {"error": "invalid", "detail": "focus_keys must be an array of strings"}, False
                limit = args.get("limit", 50)
                if not isinstance(limit, int) or isinstance(limit, bool):
                    return {"error": "invalid", "detail": "limit must be an integer"}, False
                observations = client.query_observations(
                    host_id, watch_id=args.get("watch_id"), limit=max(1, min(100, limit)),
                )
                keys = set(focus)
                compacted = [compact_for_prompt(row, keys) for row in observations]
                if keys:
                    compacted.sort(key=lambda row: not has_set_items(row))
                return {"observations": compacted}, False
            if name == "get_incident_context":
                if str(args.get("incident_id") or incident_id) != incident_id:
                    return {"error": "forbidden", "detail": "incident is outside run scope"}, False
                context = client.get_incident_context(incident_id)
                return {
                    **context,
                    "recent_observations": [
                        compact_for_prompt(row, set())
                        for row in select_observations(context.get("recent_observations") or [], set())
                    ],
                }, False
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
                        or _auto_idempotency_key(
                            run_id, {"spec": spec, "rationale": rationale}
                        ),
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
                except RpcTransportError as exc:
                    # The proposal may have committed before the connection died,
                    # or never have been parsed. Report the ambiguity to the model
                    # (the deterministic key makes an identical resubmission
                    # replay), charge the attempt, and keep the run going.
                    return (
                        {
                            **_outcome_unknown("ephemeral watch proposal", exc),
                            "_proposal_attempted": True,
                        },
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
            if name == "propose_expectation_rule":
                if rule_proposals_done >= self.budgets.max_rule_proposals_per_run:
                    return (
                        {
                            "error": "budget",
                            "detail": "expectation rule proposal budget of "
                            f"{self.budgets.max_rule_proposals_per_run} "
                            "for this run is exhausted",
                        },
                        False,
                    )
                rule = args.get("rule")
                if not isinstance(rule, dict):
                    return (
                        {"error": "invalid", "detail": "rule must be an ExpectationRuleSpec object"},
                        False,
                    )
                try:
                    reply = client.propose_expectation_rule(
                        run_id,
                        args.get("idempotency_key")
                        or _auto_idempotency_key(run_id, rule),
                        rule,
                    )
                except RpcError as exc:
                    # A deterministic policy rejection still consumes the call
                    # budget: rejections are final and must not be retried.
                    return (
                        {"error": exc.code, "detail": exc.message, "_rule_proposal_attempted": True},
                        False,
                    )
                except RpcTransportError as exc:
                    # A read timeout or EOF means the outcome is genuinely
                    # unknown: the rule may have committed before the response
                    # was lost, or may never have been parsed (control-d closes
                    # the socket on a schema violation). Report that to the
                    # model — never abort the run and never guess a rejection —
                    # and charge the attempt. The deterministic key makes an
                    # identical resubmission replay the original receipt.
                    return (
                        {
                            **_outcome_unknown("rule", exc),
                            "_rule_proposal_attempted": True,
                        },
                        False,
                    )
                decision = reply.get("decision") or {}
                result = {
                    "decision": decision,
                    "rule_id": reply.get("rule_id"),
                    "backtest": reply.get("backtest"),
                    "_rule_proposal_attempted": True,
                }
                if decision.get("allowed"):
                    result["_accepted_rule_proposal"] = True
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

        max_bytes = 8192
        observations = result.get("observations")
        if isinstance(observations, list):
            # Keep whole JSON rows so one large query cannot invalidate every
            # observation in the envelope.
            shown = []
            remaining = max_bytes - 128  # room for the wrapper object and omitted count
            for row in observations:
                size = len(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1
                if size <= remaining:
                    shown.append(row)
                    remaining -= size
            result = {"observations": shown}
            if len(shown) < len(observations):
                result["omitted_observations"] = len(observations) - len(shown)
        return wrap_tool_result("investigation_rpc", result, max_content_bytes=max_bytes)

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

    @staticmethod
    def _finish_run(client: ControlRpcClient, outcome: WorkerOutcome, status: str) -> None:
        assert outcome.run_id is not None
        client.finish_investigation_run(outcome.run_id, {
            "status": status,
            "summary": outcome.summary,
            "budget_stop_reason": outcome.budget_stop_reason,
            "turns": outcome.turns,
            "tool_calls": outcome.tool_calls,
            "input_tokens": outcome.input_tokens,
            "output_tokens": outcome.output_tokens,
            "findings": outcome.findings,
            "proposals": outcome.proposals + outcome.action_proposals_submitted,
            "proposals_accepted": outcome.proposals_accepted + outcome.action_proposals_accepted,
        })

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
        error = _redact_credentials(error, client, lease_token)
        outcome.summary = clip_utf8(error, 2048)
        if outcome.run_id is not None:
            try:
                self._finish_run(client, outcome, "failed")
            except (RpcError, RpcTransportError):
                logger.debug("failed to persist outcome for run %s", outcome.run_id)
        try:
            reply = client.fail_trigger_lease(
                outcome.event_id, lease_token, outcome.summary, retryable=retryable
            )
            status = str(reply.get("status") or ("pending" if retryable else "dead_letter"))
        except (RpcError, RpcTransportError) as exc:
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
