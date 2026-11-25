"""Phase 10 expectation-rule proposal tests.

Covers the ``propose_expectation_rule`` worker surface: enabled by default,
client-side hard cap of 3 calls per run (the server independently enforces
its own quotas), system-prompt guidance, exact
``propose_expectation_rule`` wire shape, and denial handling — a denied gate
decision, a structured RPC error, and a schema rejection after control-d
closes the connection on a malformed rule.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path
from typing import Any

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))
TESTS_ROOT = Path(__file__).resolve().parent
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

import unittest  # noqa: E402

from defsec_reasoner.models import ScriptedMockAdapter  # noqa: E402
from defsec_reasoner.provenance import build_system_prompt, envelope_contents  # noqa: E402
from defsec_reasoner.rpc_client import (  # noqa: E402
    ControlRpcClient,
    RpcTransportError,
)
from defsec_reasoner.worker import (  # noqa: E402
    INVESTIGATION_TOOLS,
    ReasonerWorker,
    RunBudgets,
)

from support import FakeControlServer  # noqa: E402

TOKEN = "rule-test-token"


def rule_spec(**overrides: Any) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "scope": {"host_id": "edge-01", "collector": "sockets.listening"},
        "matches": [
            {"op": "eq", "field": "systemd_unit", "value": "nxserver.service"},
            {"op": "eq", "field": "bind_scope", "value": "loopback"},
            {"op": "range", "field": "local_port", "min": 4000, "max": 4100},
        ],
        "effect": "allow_optional",
        "rationale": "expected local service listener",
        "expires_at": "2026-12-24T14:00:00Z",
    }
    spec.update(overrides)
    return spec


def tool_results(worker: ReasonerWorker) -> list[Any]:
    assert worker.last_messages is not None
    return [
        envelope_contents(message["content"])[0]
        for message in worker.last_messages
        if message.get("role") == "tool"
    ]


class RuleTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.sock_path = str(Path(tempfile.mkdtemp(prefix="rule-t-")) / "i.sock")
        self.server = FakeControlServer(self.sock_path).start()
        self.client = ControlRpcClient(self.sock_path, TOKEN)

    def tearDown(self) -> None:
        self.server.stop()

    def make_worker(
        self, script: list, budgets: RunBudgets | None = None, client: ControlRpcClient | None = None
    ) -> ReasonerWorker:
        return ReasonerWorker(
            client or (lambda: ControlRpcClient(self.sock_path, TOKEN)),
            ScriptedMockAdapter(script),
            backend_id="test-worker",
            model_id="scripted-mock",
            budgets=budgets or RunBudgets(),
            backoff_base_seconds=0.01,
        )


class TestRuleToolSurface(RuleTestBase):
    def test_tool_is_enabled_by_default_with_hard_cap(self) -> None:
        budgets = RunBudgets()
        self.assertEqual(budgets.max_rule_proposals_per_run, 3)
        seen_tools: list[str] = []

        def first_turn(_messages: list[dict], tools: list[dict]) -> dict[str, Any]:
            seen_tools.extend(tool["name"] for tool in tools)
            return {"final_text": "done"}

        worker = self.make_worker([first_turn])
        outcome = worker.run_once()

        self.assertIsNotNone(outcome)
        self.assertIn("propose_expectation_rule", seen_tools)
        self.assertEqual(seen_tools, [tool["name"] for tool in INVESTIGATION_TOOLS])
        self.assertEqual(outcome.rule_proposals_submitted, 0)
        self.assertEqual(outcome.rule_proposals_accepted, 0)
        self.assertEqual(self.server.rule_proposals, [])

    def test_system_prompt_states_rule_guidance(self) -> None:
        prompt = build_system_prompt(
            "reasoner-d", "m", RunBudgets(),
            [tool["name"] for tool in INVESTIGATION_TOOLS], "v1",
        )
        self.assertIn("EXPECTATION RULES", prompt)
        self.assertIn("benign recurring", prompt)
        self.assertIn("systemd_unit, comm, or uid", prompt)
        self.assertIn("NEVER propose a rule", prompt)
        self.assertIn("suspicious, unexpected, or unexplained", prompt)
        self.assertIn("operator must review and approve", prompt)
        self.assertIn("3 expectation rule proposals", prompt)
        # Trusted system text never embeds host telemetry.
        self.assertNotIn('source="', prompt)


class TestRuleRpcClient(RuleTestBase):
    def test_proposal_serializes_with_exact_wire_shape(self) -> None:
        spec = rule_spec()
        reply = self.client.propose_expectation_rule("run-1", "key-1", spec)

        self.assertEqual(
            self.server.last_envelope["request"],
            {"op": "propose_expectation_rule", "run_id": "run-1",
             "idempotency_key": "key-1", "rule": spec},
        )
        self.assertTrue(reply["decision"]["allowed"])
        self.assertEqual(reply["rule_id"], "rule-1")
        self.assertEqual(reply["backtest"]["observations_scanned"], 2)

    def test_rule_result_tag_is_accepted_by_the_client(self) -> None:
        reply = self.client.propose_expectation_rule("run-1", "key-1", rule_spec())
        self.assertIn("decision", reply)
        self.assertEqual(self.server.requests[-1]["op"], "propose_expectation_rule")


class TestRuleProposals(RuleTestBase):
    def test_proposal_flows_through_the_worker_and_records_progress(self) -> None:
        worker = self.make_worker([
            {"tool_calls": [
                {"name": "propose_expectation_rule", "arguments": {"rule": rule_spec()}}
            ]},
            {"final_text": "proposed; awaiting operator"},
        ])
        outcome = worker.run_once()

        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.rule_proposals_submitted, 1)
        self.assertEqual(outcome.rule_proposals_accepted, 1)
        self.assertEqual(len(self.server.rule_proposals), 1)

        request = next(
            r for r in self.server.requests if r["op"] == "propose_expectation_rule"
        )
        self.assertEqual(request["run_id"], outcome.run_id)
        self.assertEqual(request["rule"], rule_spec())
        # The idempotency key is auto-generated per attempt when omitted.
        self.assertRegex(request["idempotency_key"], rf"^{outcome.run_id}-r1-[0-9a-f]{{8}}$")

        # Each proposal lands as P9 run-progress tool events.
        progress = [r for r in self.server.requests if r["op"] == "report_run_progress"]
        self.assertIn(
            {"tool": "propose_expectation_rule", "ok": True, "accepted": True},
            [r["detail"] for r in progress if r["kind"] == "tool_result"],
        )
        calls = [
            r for r in progress
            if r["kind"] == "tool_call" and r["detail"]["tool"] == "propose_expectation_rule"
        ]
        self.assertEqual(len(calls), 1)

        result = tool_results(worker)[0]
        self.assertTrue(result["decision"]["allowed"])
        self.assertEqual(result["rule_id"], "rule-1")
        self.assertEqual(result["backtest"]["triggered_before"], 1)

    def test_client_cap_blocks_the_fourth_call_without_rpc(self) -> None:
        script: list[Any] = [
            {"tool_calls": [
                {"name": "propose_expectation_rule", "arguments": {"rule": rule_spec()}}
            ]}
        ] * 4
        script.append({"final_text": "capped"})
        worker = self.make_worker(script)
        outcome = worker.run_once()

        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.rule_proposals_submitted, 3)
        self.assertEqual(outcome.rule_proposals_accepted, 3)
        self.assertEqual(
            [r["op"] for r in self.server.requests].count("propose_expectation_rule"), 3
        )
        results = tool_results(worker)
        self.assertEqual(len(results), 4)
        self.assertEqual(results[3]["error"], "budget")
        self.assertIn("exhausted", results[3]["detail"])
        self.assertEqual(self.server.completed_events, [1])

    def test_non_object_rule_is_rejected_without_rpc(self) -> None:
        worker = self.make_worker([
            {"tool_calls": [
                {"name": "propose_expectation_rule", "arguments": {"rule": "not-an-object"}}
            ]},
            {"final_text": "done"},
        ])
        outcome = worker.run_once()

        self.assertEqual(outcome.rule_proposals_submitted, 0)
        self.assertEqual(self.server.rule_proposals, [])
        result = tool_results(worker)[0]
        self.assertEqual(result["error"], "invalid")

    def test_denied_gate_decision_is_final_and_counted(self) -> None:
        self.server.rule_policy = lambda rule: (
            False,
            "rule-gate/port-bounds",
            "socket rule must constrain local_port within the allowed bounds",
        )
        worker = self.make_worker([
            {"tool_calls": [
                {"name": "propose_expectation_rule", "arguments": {"rule": rule_spec()}}
            ]},
            {"final_text": "denied; done"},
        ])
        outcome = worker.run_once()

        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.rule_proposals_submitted, 1)
        self.assertEqual(outcome.rule_proposals_accepted, 0)
        result = tool_results(worker)[0]
        self.assertFalse(result["decision"]["allowed"])
        self.assertEqual(result["decision"]["rule_id"], "rule-gate/port-bounds")
        self.assertIsNone(result["rule_id"])
        self.assertIsNone(result["backtest"])
        # The denial is recorded as a run-progress event with accepted=False.
        progress = [r for r in self.server.requests if r["op"] == "report_run_progress"]
        self.assertIn(
            {"tool": "propose_expectation_rule", "ok": True, "accepted": False},
            [r["detail"] for r in progress if r["kind"] == "tool_result"],
        )

    def test_structured_rpc_error_is_reported_verbatim(self) -> None:
        self.server.rule_error = {"code": "forbidden", "message": "run is outside capability scope"}
        worker = self.make_worker([
            {"tool_calls": [
                {"name": "propose_expectation_rule", "arguments": {"rule": rule_spec()}}
            ]},
            {"final_text": "refused"},
        ])
        outcome = worker.run_once()

        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.rule_proposals_submitted, 1)
        self.assertEqual(outcome.rule_proposals_accepted, 0)
        result = tool_results(worker)[0]
        self.assertEqual(result["error"], "forbidden")
        self.assertIn("outside capability scope", result["detail"])

    def test_schema_rejection_after_connection_close_is_not_a_crash(self) -> None:
        class SchemaRejectingClient(ControlRpcClient):
            def propose_expectation_rule(self, run_id, idempotency_key, rule):
                raise RpcTransportError("unexpected EOF while reading a frame")

        worker = self.make_worker(
            [
                {"tool_calls": [
                    {"name": "propose_expectation_rule", "arguments": {"rule": rule_spec()}}
                ]},
                {"final_text": "schema rejected"},
            ],
            client=SchemaRejectingClient(self.sock_path, TOKEN),
        )
        outcome = worker.run_once()

        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.rule_proposals_submitted, 1)
        self.assertEqual(outcome.rule_proposals_accepted, 0)
        result = tool_results(worker)[0]
        self.assertEqual(result["error"], "schema_rejected")
        self.assertIn("ExpectationRuleSpec", result["detail"])


if __name__ == "__main__":
    unittest.main()
