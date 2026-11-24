"""Phase 8 typed mitigation action proposal tests.

Covers the exact ``ActionVerb`` / ``ProposeAction`` / ``ListActions`` wire
shapes from ``crates/protocol/src/action.rs`` and ``rpc.rs``, the safe
opt-in default (tools hidden + locally rejected), per-run action proposal
budgets, policy-bounded vs. dual-signed responses, and adversarial model
behavior that tries to exceed the cap or smuggle a shell command.
"""

from __future__ import annotations

import json
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
from defsec_reasoner.rpc_client import ControlRpcClient  # noqa: E402
from defsec_reasoner.worker import (  # noqa: E402
    ACTION_TOOLS,
    INVESTIGATION_TOOLS,
    ReasonerWorker,
    RunBudgets,
)

from support import FakeControlServer  # noqa: E402

TOKEN = "action-test-token"


def nft_verb(**overrides: Any) -> dict[str, Any]:
    verb = {
        "verb": "nft_block_ip",
        "ip": "203.0.113.7",
        "direction": "inbound",
        "ttl_seconds": 900,
    }
    verb.update(overrides)
    return verb


def systemd_verb(**overrides: Any) -> dict[str, Any]:
    verb = {"verb": "systemd_stop_unit", "unit": "ghost.service", "ttl_seconds": 600}
    verb.update(overrides)
    return verb


def isolate_verb(**overrides: Any) -> dict[str, Any]:
    verb = {
        "verb": "host_isolate",
        "preserve_mgmt_cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
        "ttl_seconds": 600,
    }
    verb.update(overrides)
    return verb


def action_arguments(verb: dict[str, Any], evidence: list[int] | None = None) -> dict[str, Any]:
    return {
        "verb": verb,
        "evidence_observation_ids": evidence if evidence is not None else [11],
        "expected_effect": "contain the confirmed malicious source",
        "blast_radius": "one source IP, inbound only, short TTL",
        "rollback_plan": "delete the ephemeral nft rule; no persistent config written",
    }


def tool_results(worker: ReasonerWorker) -> list[Any]:
    assert worker.last_messages is not None
    return [
        envelope_contents(message["content"])[0]
        for message in worker.last_messages
        if message.get("role") == "tool"
    ]


class ActionTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.sock_path = str(Path(tempfile.mkdtemp(prefix="action-t-")) / "i.sock")
        self.server = FakeControlServer(self.sock_path).start()
        self.client = ControlRpcClient(self.sock_path, TOKEN)

    def tearDown(self) -> None:
        self.server.stop()

    def make_worker(
        self, script: list, budgets: RunBudgets | None = None
    ) -> ReasonerWorker:
        return ReasonerWorker(
            lambda: ControlRpcClient(self.sock_path, TOKEN),
            ScriptedMockAdapter(script),
            backend_id="test-worker",
            model_id="scripted-mock",
            budgets=budgets or RunBudgets(),
            backoff_base_seconds=0.01,
        )


class TestActionWireShapes(ActionTestBase):
    def test_nft_block_ip_serializes_exactly(self) -> None:
        self.client.propose_action(
            "run-1",
            "inc-1",
            "key-1",
            nft_verb(),
            [11, 12],
            "drop inbound traffic from the brute-force source",
            "single source IP, inbound only, 15 minute TTL",
            "nft delete rule after TTL; no persistent config written",
        )
        self.assertEqual(
            self.server.requests[-1],
            {
                "op": "propose_action",
                "run_id": "run-1",
                "incident_id": "inc-1",
                "idempotency_key": "key-1",
                "verb": {
                    "verb": "nft_block_ip",
                    "ip": "203.0.113.7",
                    "direction": "inbound",
                    "ttl_seconds": 900,
                },
                "evidence_observation_ids": [11, 12],
                "expected_effect": "drop inbound traffic from the brute-force source",
                "blast_radius": "single source IP, inbound only, 15 minute TTL",
                "rollback_plan": "nft delete rule after TTL; no persistent config written",
            },
        )

    def test_systemd_stop_unit_serializes_exactly_including_null_ttl(self) -> None:
        self.client.propose_action(
            "run-1", "inc-1", "key-1", systemd_verb(ttl_seconds=None), [11],
            "stop the unwanted unit", "one unit", "start the unit again",
        )
        self.assertEqual(
            self.server.requests[-1]["verb"],
            {"verb": "systemd_stop_unit", "unit": "ghost.service", "ttl_seconds": None},
        )
        self.client.propose_action(
            "run-1", "inc-1", "key-2", systemd_verb(ttl_seconds=300), [11],
            "stop the unwanted unit", "one unit", "start the unit again",
        )
        self.assertEqual(
            self.server.requests[-1]["verb"],
            {"verb": "systemd_stop_unit", "unit": "ghost.service", "ttl_seconds": 300},
        )

    def test_host_isolate_serializes_exactly(self) -> None:
        self.client.propose_action(
            "run-1", "inc-1", "key-1", isolate_verb(), [11, 12],
            "isolate compromised host", "host-wide network isolation",
            "lift isolation after operator review",
        )
        self.assertEqual(
            self.server.requests[-1]["verb"],
            {
                "verb": "host_isolate",
                "preserve_mgmt_cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
                "ttl_seconds": 600,
            },
        )

    def test_list_actions_omits_absent_filters(self) -> None:
        self.assertEqual(self.client.list_actions(), [])
        self.assertEqual(self.server.requests[-1], {"op": "list_actions"})
        self.client.list_actions(host_id="edge-01", incident_id="inc-1")
        self.assertEqual(
            self.server.requests[-1],
            {"op": "list_actions", "host_id": "edge-01", "incident_id": "inc-1"},
        )

    def test_invalid_verbs_are_rejected_locally_before_rpc(self) -> None:
        before = len(self.server.requests)
        bad_verbs = [
            {"verb": "run_shell", "cmd": "cat /etc/shadow"},
            {"verb": "nft_block_ip", "ip": "203.0.113.7", "direction": "sideways", "ttl_seconds": 900},
            {"verb": "nft_block_ip", "ip": "203.0.113.7", "direction": "inbound"},
            {"verb": "nft_block_ip", "ip": "203.0.113.7", "direction": "inbound",
             "ttl_seconds": 900, "cmd": "rm -rf /"},
            {"verb": "systemd_stop_unit", "unit": "", "ttl_seconds": None},
            {"verb": "host_isolate", "preserve_mgmt_cidrs": [], "ttl_seconds": 600},
        ]
        for verb in bad_verbs:
            with self.assertRaises(ValueError, msg=str(verb)):
                self.client.propose_action(
                    "run-1", "inc-1", "key", verb, [11],
                    "effect", "blast", "rollback",
                )
        with self.assertRaises(ValueError):
            self.client.propose_action(
                "run-1", "inc-1", "key", nft_verb(), [],
                "effect", "blast", "rollback",
            )
        with self.assertRaises(ValueError):
            self.client.propose_action(
                "run-1", "inc-1", "key", nft_verb(), ["11"],
                "effect", "blast", "rollback",
            )
        with self.assertRaises(ValueError):
            self.client.propose_action(
                "run-1", "inc-1", "key", nft_verb(), [11],
                "effect", "blast", "",
            )
        self.assertEqual(len(self.server.requests), before)


class TestActionProposalsDisabledByDefault(ActionTestBase):
    def test_budget_defaults_are_safe_opt_in(self) -> None:
        budgets = RunBudgets()
        self.assertFalse(budgets.enable_action_proposals)
        self.assertEqual(budgets.max_action_proposals_per_run, 1)

    def test_tools_hidden_and_attempts_rejected_without_rpc(self) -> None:
        seen_tools: list[str] = []

        def attempt(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
            seen_tools.extend(tool["name"] for tool in tools)
            return {
                "tool_calls": [
                    {"name": "propose_action", "arguments": action_arguments(nft_verb())},
                    {"name": "list_actions", "arguments": {}},
                ]
            }

        worker = self.make_worker([attempt, {"final_text": "blocked"}])
        outcome = worker.run_once()

        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.status, "completed")
        self.assertNotIn("propose_action", seen_tools)
        self.assertNotIn("list_actions", seen_tools)
        self.assertEqual(seen_tools, [tool["name"] for tool in INVESTIGATION_TOOLS])
        self.assertEqual(
            [request["op"] for request in self.server.requests].count("propose_action"), 0
        )
        self.assertEqual(
            [request["op"] for request in self.server.requests].count("list_actions"), 0
        )
        self.assertEqual(outcome.action_proposals_submitted, 0)
        self.assertEqual(outcome.action_proposals_accepted, 0)
        self.assertEqual(self.server.action_proposals, [])
        self.assertEqual(self.server.completed_events, [1])
        details = tool_results(worker)
        self.assertEqual(details[0]["error"], "forbidden")
        self.assertIn("disabled", details[0]["detail"])
        self.assertEqual(details[1]["error"], "forbidden")

    def test_prompt_has_no_action_guidance_when_disabled(self) -> None:
        prompt = build_system_prompt(
            "reasoner-d", "m", RunBudgets(), ["query_observations", "finish"], "v1"
        )
        self.assertNotIn("TYPED MITIGATION ACTIONS", prompt)
        self.assertNotIn("nft_block_ip", prompt)
        self.assertIn("remediation do not exist", prompt)


class TestActionProposalsEnabled(ActionTestBase):
    def enabled_budgets(self, **overrides: Any) -> RunBudgets:
        return RunBudgets(enable_action_proposals=True, **overrides)

    def test_policy_bounded_nft_block_ip_is_submitted_and_authorized(self) -> None:
        worker = self.make_worker(
            [
                {"tool_calls": [
                    {"name": "propose_action",
                     "arguments": action_arguments(nft_verb(), [11, 12])}
                ]},
                {"final_text": "contained"},
            ],
            budgets=self.enabled_budgets(),
        )
        outcome = worker.run_once()

        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.action_proposals_submitted, 1)
        self.assertEqual(outcome.action_proposals_accepted, 1)
        self.assertEqual(self.server.completed_events, [1])

        request = self.server.requests[-2]  # propose_action precedes completion
        self.assertEqual(request["op"], "propose_action")
        self.assertEqual(
            request["verb"],
            {"verb": "nft_block_ip", "ip": "203.0.113.7", "direction": "inbound", "ttl_seconds": 900},
        )
        self.assertEqual(request["evidence_observation_ids"], [11, 12])
        self.assertEqual(request["run_id"], outcome.run_id)
        self.assertEqual(request["incident_id"], "inc-1")
        self.assertIn("nft rule", request["rollback_plan"].lower())
        self.assertEqual(
            request["rollback_plan"],
            action_arguments(nft_verb())["rollback_plan"],
        )
        self.assertNotIn("cmd", json.dumps(request))

        self.assertEqual(len(self.server.action_proposals), 1)
        proposal = self.server.action_proposals[0]
        self.assertEqual(proposal["auth_mode"], "policy_bounded_autonomous")
        self.assertEqual(proposal["status"], "authorized")
        self.assertIsNotNone(proposal["intent_id"])

        result = tool_results(worker)[0]
        self.assertTrue(result["decision"]["allowed"])
        self.assertEqual(result["auth_mode"], "policy_bounded_autonomous")
        self.assertEqual(result["status"], "authorized")
        self.assertIsNotNone(result["authorized_intent"])
        self.assertNotIn("_action_proposal_attempted", result)

    def test_second_proposal_in_same_run_is_blocked_by_budget(self) -> None:
        worker = self.make_worker(
            [
                {"tool_calls": [
                    {"name": "propose_action",
                     "arguments": action_arguments(nft_verb(ip="203.0.113.7"))},
                    {"name": "propose_action",
                     "arguments": action_arguments(nft_verb(ip="203.0.113.8"))},
                ]},
                {"final_text": "done"},
            ],
            budgets=self.enabled_budgets(max_action_proposals_per_run=1),
        )
        outcome = worker.run_once()

        self.assertEqual(outcome.action_proposals_submitted, 1)
        self.assertEqual(outcome.action_proposals_accepted, 1)
        self.assertEqual(len(self.server.action_proposals), 1)
        self.assertEqual(
            [r["op"] for r in self.server.requests].count("propose_action"), 1
        )
        results = tool_results(worker)
        self.assertEqual(results[0]["status"], "authorized")
        self.assertEqual(results[1]["error"], "budget")
        self.assertIn("exhausted", results[1]["detail"])
        self.assertEqual(self.server.completed_events, [1])

    def test_dual_signed_host_isolate_stays_pending_approval(self) -> None:
        worker = self.make_worker(
            [
                {"tool_calls": [
                    {"name": "propose_action",
                     "arguments": action_arguments(isolate_verb(), [11])}
                ]},
                {"final_text": "awaiting operator"},
            ],
            budgets=self.enabled_budgets(),
        )
        outcome = worker.run_once()

        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.action_proposals_submitted, 1)
        self.assertEqual(outcome.action_proposals_accepted, 1)
        proposal = self.server.action_proposals[0]
        self.assertEqual(proposal["auth_mode"], "dual_signed_operator")
        self.assertEqual(proposal["status"], "pending_approval")
        self.assertIsNone(proposal["intent_id"])
        result = tool_results(worker)[0]
        self.assertEqual(result["auth_mode"], "dual_signed_operator")
        self.assertEqual(result["status"], "pending_approval")
        self.assertIsNone(result["authorized_intent"])
        self.assertEqual(self.server.completed_events, [1])

    def test_policy_rejection_counts_as_submitted_not_accepted(self) -> None:
        self.server.action_policy = lambda verb: (
            False,
            "action.denied",
            "verb not permitted for this incident",
        )
        worker = self.make_worker(
            [
                {"tool_calls": [
                    {"name": "propose_action",
                     "arguments": action_arguments(nft_verb())}
                ]},
                {"final_text": "rejected"},
            ],
            budgets=self.enabled_budgets(),
        )
        outcome = worker.run_once()

        self.assertEqual(outcome.action_proposals_submitted, 1)
        self.assertEqual(outcome.action_proposals_accepted, 0)
        self.assertEqual(self.server.action_proposals[0]["status"], "rejected")
        result = tool_results(worker)[0]
        self.assertFalse(result["decision"]["allowed"])
        self.assertEqual(result["decision"]["rule_id"], "action.denied")

    def test_list_actions_is_scoped_to_run_host_and_incident(self) -> None:
        worker = self.make_worker(
            [
                {"tool_calls": [
                    {"name": "propose_action",
                     "arguments": action_arguments(nft_verb())}
                ]},
                {"tool_calls": [{"name": "list_actions", "arguments": {}}]},
                {"tool_calls": [
                    {"name": "list_actions", "arguments": {"host_id": "other-host"}}
                ]},
                {"final_text": "done"},
            ],
            budgets=self.enabled_budgets(),
        )
        outcome = worker.run_once()

        self.assertEqual(outcome.status, "completed")
        results = tool_results(worker)
        self.assertEqual(len(results[1]["actions"]), 1)
        self.assertEqual(results[1]["actions"][0]["host_id"], "edge-01")
        self.assertEqual(results[2]["error"], "forbidden")
        list_requests = [r for r in self.server.requests if r["op"] == "list_actions"]
        self.assertEqual(len(list_requests), 1)
        self.assertEqual(list_requests[0]["host_id"], "edge-01")
        self.assertEqual(list_requests[0]["incident_id"], "inc-1")

    def test_prompt_guidance_is_explicit_when_enabled(self) -> None:
        prompt = build_system_prompt(
            "reasoner-d", "m", self.enabled_budgets(max_action_proposals_per_run=2),
            [tool["name"] for tool in INVESTIGATION_TOOLS + ACTION_TOOLS], "v1",
            enable_action_proposals=True,
        )
        self.assertIn("TYPED MITIGATION ACTIONS", prompt)
        self.assertIn("human-owned", prompt)
        self.assertIn("dual-signature", prompt)
        self.assertIn("pending_approval", prompt)
        self.assertIn("observation_id", prompt)
        self.assertIn("rollback_plan", prompt)
        self.assertIn("nft_block_ip", prompt)
        self.assertIn("host_isolate", prompt)
        self.assertIn("no shell", prompt.lower())
        self.assertIn("2 mitigation action proposal(s)", prompt)
        # No host data leaked into trusted system text.
        self.assertNotIn('source="', prompt)


class TestAdversarialActionBounding(ActionTestBase):
    def test_hijacked_model_cannot_exceed_cap_or_smuggle_shell(self) -> None:
        worker = self.make_worker(
            [
                {"tool_calls": [
                    # Arbitrary shell intent: never a valid verb.
                    {"name": "propose_action",
                     "arguments": {**action_arguments({"verb": "run_shell"}),
                                   "cmd": "cat /etc/shadow"}},
                    # High-blast verb missing mandatory management CIDRs.
                    {"name": "propose_action",
                     "arguments": action_arguments({"verb": "host_isolate", "ttl_seconds": 600})},
                    # Valid bounded reversible proposal (consumes the cap).
                    {"name": "propose_action",
                     "arguments": action_arguments(nft_verb())},
                    # Over-cap valid proposal must be blocked locally.
                    {"name": "propose_action",
                     "arguments": action_arguments(nft_verb(ip="198.51.100.9"))},
                    # Scope escape attempt on the read surface.
                    {"name": "list_actions",
                     "arguments": {"incident_id": "inc-other"}},
                ]},
                {"final_text": "bounded"},
            ],
            budgets=RunBudgets(enable_action_proposals=True, max_action_proposals_per_run=1),
        )
        outcome = worker.run_once()

        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.action_proposals_submitted, 1)
        self.assertEqual(outcome.action_proposals_accepted, 1)
        self.assertEqual(len(self.server.action_proposals), 1)
        propose_requests = [r for r in self.server.requests if r["op"] == "propose_action"]
        self.assertEqual(len(propose_requests), 1)
        self.assertEqual(propose_requests[0]["verb"]["verb"], "nft_block_ip")
        self.assertEqual(
            [r["op"] for r in self.server.requests].count("list_actions"), 0
        )

        results = tool_results(worker)
        self.assertEqual(results[0]["error"], "invalid")
        self.assertEqual(results[1]["error"], "invalid")
        self.assertEqual(results[2]["status"], "authorized")
        self.assertEqual(results[3]["error"], "budget")
        self.assertEqual(results[4]["error"], "forbidden")
        self.assertEqual(self.server.completed_events, [1])


if __name__ == "__main__":
    unittest.main()
