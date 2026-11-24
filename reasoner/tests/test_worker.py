"""ReasonerWorker bounded tool-loop tests against the fake control server."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from pathlib import Path

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))
TESTS_ROOT = Path(__file__).resolve().parent
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

import unittest  # noqa: E402

from defsec_reasoner.models import ProviderError, ScriptedMockAdapter  # noqa: E402
from defsec_reasoner.rpc_client import ControlRpcClient  # noqa: E402
from defsec_reasoner.worker import ReasonerWorker, RunBudgets  # noqa: E402

from support import FakeControlServer  # noqa: E402

TOKEN = "worker-test-token"


def _spec(incident: str = "inc-1", unit: str = "ghost.service") -> dict:
    return {
        "id": "eph-1",
        "version": 1,
        "host_id": "edge-01",
        "class": "ephemeral",
        "incident_id": incident,
        "collector": {"type": "systemd.unit_state", "parameters": {"unit": unit, "hash_unit_files": True}},
        "schedule": {"interval_seconds": 30, "timeout_seconds": 5},
        "trigger": {"type": "field_changed", "compare_against": "last_observed", "fields": ["active_state"]},
        "wake_policy": {"cooldown_seconds": 60, "max_wakeups_per_hour": 4},
        "lifecycle": {"enabled": True, "expires_at": "2026-11-24T14:00:00Z", "max_runs": 120},
    }


class WorkerTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.sock_path = str(Path(tempfile.mkdtemp(prefix="worker-t-")) / "i.sock")
        self.server = FakeControlServer(self.sock_path).start()

    def tearDown(self) -> None:
        self.server.stop()

    def make_worker(
        self, script: list, budgets: RunBudgets | None = None, price_per_mtok: float = 0.0
    ) -> ReasonerWorker:
        client = ControlRpcClient(self.sock_path, TOKEN)
        return ReasonerWorker(
            lambda: ControlRpcClient(self.sock_path, TOKEN),
            ScriptedMockAdapter(script, price_per_mtok=price_per_mtok),
            backend_id="test-worker",
            model_id="scripted-mock",
            budgets=budgets or RunBudgets(),
            backoff_base_seconds=0.01,
        )


class TestWorkerHappyPath(WorkerTestBase):
    def test_dormant_when_no_trigger(self) -> None:
        self.server.triggers[0]["status"] = "done"
        worker = self.make_worker([{"final_text": "nothing to do"}])
        self.assertIsNone(worker.run_once())

    def test_full_investigation_completes_lease(self) -> None:
        script = [
            {"tool_calls": [{"name": "query_observations",
                             "arguments": {"host_id": "edge-01", "watch_id": "w-sockets"}}]},
            {"tool_calls": [{"name": "propose_ephemeral_watch",
                             "arguments": {"spec": _spec(), "rationale": "follow-up"}}]},
            {"tool_calls": [{"name": "record_hypothesis_or_finding",
                             "arguments": {"kind": "verified_finding", "severity": "medium",
                                           "summary": "s", "uncertainty": "u",
                                           "evidence_observation_ids": [11, 12],
                                           "escalation_requested": True}}]},
            {"tool_calls": [{"name": "finish", "arguments": {"summary": "done"}}]},
        ]
        worker = self.make_worker(script)
        outcome = worker.run_once()
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.turns, 4)
        self.assertEqual(outcome.proposals, 1)
        self.assertEqual(outcome.proposals_accepted, 1)
        self.assertEqual(outcome.findings, 1)
        self.assertEqual(self.server.completed_events, [1])
        self.assertEqual(len(self.server.proposals), 1)
        self.assertEqual(len(self.server.findings), 1)
        self.assertGreater(outcome.input_tokens, 0)

    def test_findings_and_proposals_submit_before_completion(self) -> None:
        # The complete op must be the LAST investigation request issued.
        script = [
            {"tool_calls": [{"name": "record_hypothesis_or_finding",
                             "arguments": {"kind": "hypothesis", "severity": "low",
                                           "summary": "s", "uncertainty": "u",
                                           "evidence_observation_ids": [11],
                                           "escalation_requested": False}}]},
        ]
        worker = self.make_worker(script)
        outcome = worker.run_once()
        self.assertEqual(outcome.status, "completed")
        last_op = self.server.requests[-1]["op"]
        self.assertEqual(last_op, "complete_trigger_lease")
        ops = [r["op"] for r in self.server.requests]
        self.assertLess(ops.index("record_hypothesis_or_finding"), ops.index("complete_trigger_lease"))


class TestWorkerBudgets(WorkerTestBase):
    def test_turn_cap_stops_loop_and_still_completes(self) -> None:
        def query_again(_messages: list, _tools: list) -> dict:
            return {"tool_calls": [{"name": "query_observations",
                                    "arguments": {"host_id": "edge-01"}}]}

        script = [query_again] * 10
        worker = self.make_worker(script, budgets=RunBudgets(max_turns=3))
        outcome = worker.run_once()
        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.turns, 3)
        self.assertEqual(outcome.budget_stop_reason, "max_turns")
        self.assertEqual(self.server.completed_events, [1])

    def test_proposal_cap_blocks_excess_proposals(self) -> None:
        def propose(n: int):
            def step(_messages: list, _tools: list) -> dict:
                return {"tool_calls": [{"name": "propose_ephemeral_watch",
                                        "arguments": {"spec": _spec(unit=f"u{n}.service"), "rationale": "r"}}]}
            return step

        script = [propose(n) for n in range(4)] + [{"final_text": "done"}]
        worker = self.make_worker(script, budgets=RunBudgets(max_proposals_per_run=2))
        outcome = worker.run_once()
        self.assertEqual(outcome.proposals, 2)  # server saw exactly 2 proposals
        self.assertEqual(len(self.server.proposals), 2)
        self.assertEqual(outcome.status, "completed")

    def test_token_budget_stops_loop(self) -> None:
        script = [
            {"tool_calls": [{"name": "query_observations", "arguments": {"host_id": "edge-01"}}]},
        ]
        worker = self.make_worker(script, budgets=RunBudgets(max_total_tokens=10))
        outcome = worker.run_once()
        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.budget_stop_reason, "max_total_tokens")
        self.assertEqual(outcome.turns, 1)

    def test_cost_budget_stops_loop(self) -> None:
        script = [{"tool_calls": [{"name": "query_observations", "arguments": {"host_id": "edge-01"}}]}]
        worker = self.make_worker(
            script,
            budgets=RunBudgets(max_total_tokens=10_000_000, max_cost_usd=0.001),
            price_per_mtok=1000.0,
        )
        outcome = worker.run_once()
        # First turn accumulates > $0.001 cost; loop must stop before turn 2.
        self.assertEqual(outcome.budget_stop_reason, "max_cost_usd")
        self.assertEqual(outcome.turns, 1)

    def test_context_byte_budget_compacts_conversation(self) -> None:
        big_payload = {"observations": [{"observation_id": i, "payload": {"blob": "z" * 3000}} for i in range(20)]}

        def big_query(_messages: list, _tools: list) -> dict:
            return {"tool_calls": [{"name": "query_observations", "arguments": {"host_id": "edge-01"}}]}

        self.server.observations = [
            {"observation_id": i, "host_id": "edge-01", "watch_id": "w-sockets", "spec_version": 1,
             "observed_at": "2026-11-24T12:00:00Z", "status": "ok", "state_hash": "ff" * 32,
             "payload": big_payload} for i in range(1, 21)
        ]
        script = [big_query] * 6
        worker = self.make_worker(script, budgets=RunBudgets(max_turns=6, max_context_bytes=4096))
        outcome = worker.run_once()
        self.assertEqual(outcome.status, "completed")
        assert worker.last_messages is not None
        self.assertLessEqual(worker._messages_bytes(worker.last_messages), 4096 + 2048)

    def test_wall_clock_budget(self) -> None:
        def slow_step(_messages: list, _tools: list) -> dict:
            time.sleep(0.3)
            return {"tool_calls": [{"name": "query_observations", "arguments": {"host_id": "edge-01"}}]}

        script = [slow_step] * 10
        worker = self.make_worker(script, budgets=RunBudgets(max_wall_seconds=0.5, max_turns=10))
        outcome = worker.run_once()
        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.budget_stop_reason, "max_wall_seconds")
        self.assertLess(outcome.turns, 10)


class TestWorkerFailurePaths(WorkerTestBase):
    def test_retryable_provider_failure_requeues(self) -> None:
        script = [ProviderError("simulated 503", retryable=True)]
        worker = self.make_worker(script)
        outcome = worker.run_once()
        self.assertEqual(outcome.status, "requeued")
        self.assertEqual(self.server.triggers[0]["status"], "pending")
        self.assertEqual(self.server.triggers[0]["retry_count"], 1)
        self.assertEqual(self.server.completed_events, [])

    def test_nonretryable_provider_failure_dead_letters(self) -> None:
        script = [ProviderError("401 unauthorized", retryable=False)]
        worker = self.make_worker(script)
        outcome = worker.run_once()
        self.assertEqual(outcome.status, "dead_letter")
        self.assertEqual(self.server.triggers[0]["status"], "dead_letter")

    def test_repeated_outage_requeues_then_dead_letters(self) -> None:
        script = [ProviderError("simulated 503", retryable=True)]
        statuses = []
        for _attempt in range(5):
            worker = self.make_worker(script)
            outcome = worker.run_once()
            statuses.append(outcome.status)
        self.assertEqual(statuses, ["requeued", "requeued", "requeued", "requeued", "dead_letter"])

    def test_expired_lease_rejection_is_reported_as_lease_stale(self) -> None:
        # The fake issues already-expired leases; complete must be fenced off.
        self.server.expire_leases = True
        self.server.triggers[0]["status"] = "pending"
        self.server.triggers[0]["lease_expires_at"] = None
        script = [
            {"tool_calls": [{"name": "record_hypothesis_or_finding",
                             "arguments": {"kind": "hypothesis", "severity": "low",
                                           "summary": "s", "uncertainty": "u",
                                           "evidence_observation_ids": [11],
                                           "escalation_requested": False}}]},
        ]
        worker = self.make_worker(script)
        outcome = worker.run_once()
        self.assertEqual(outcome.status, "lease_stale")
        self.assertEqual(outcome.findings, 1)
        self.assertEqual(self.server.completed_events, [])

    def test_policy_rejection_is_reported_not_retried(self) -> None:
        self.server.proposal_policy = lambda spec: (False, "scope.host_denied", "outside scope")
        script = [
            {"tool_calls": [{"name": "propose_ephemeral_watch",
                             "arguments": {"spec": _spec(), "rationale": "r"}}]},
            {"final_text": "rejected; done"},
        ]
        worker = self.make_worker(script)
        outcome = worker.run_once()
        self.assertEqual(outcome.proposals, 1)
        self.assertEqual(outcome.proposals_accepted, 0)
        self.assertEqual(outcome.status, "completed")

    def test_fabricated_evidence_rejected_by_control(self) -> None:
        script = [
            {"tool_calls": [{"name": "record_hypothesis_or_finding",
                             "arguments": {"kind": "verified_finding", "severity": "high",
                                           "summary": "s", "uncertainty": "u",
                                           "evidence_observation_ids": [999999],
                                           "escalation_requested": True}}]},
            {"final_text": "recording failed"},
        ]
        worker = self.make_worker(script)
        outcome = worker.run_once()
        self.assertEqual(outcome.findings, 0)
        self.assertEqual(outcome.status, "completed")

    def test_unknown_tool_is_refused_without_rpc(self) -> None:
        script = [
            {"tool_calls": [{"name": "run_shell", "arguments": {"cmd": "cat /etc/shadow"}}]},
            {"final_text": "no shell available; done"},
        ]
        worker = self.make_worker(script)
        outcome = worker.run_once()
        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.tool_calls, 1)
        ops = {r["op"] for r in self.server.requests}
        self.assertNotIn("run_shell", ops)

    def test_cross_host_tool_call_refused(self) -> None:
        script = [
            {"tool_calls": [{"name": "query_observations",
                             "arguments": {"host_id": "other-host"}}]},
            {"final_text": "done"},
        ]
        worker = self.make_worker(script)
        outcome = worker.run_once()
        self.assertEqual(outcome.status, "completed")
        # The only observation query stayed on the run host.
        queries = [r for r in self.server.requests if r["op"] == "query_observations"]
        self.assertTrue(all(q["host_id"] == "edge-01" for q in queries))


class TestWorkerLoop(WorkerTestBase):
    def test_run_loop_processes_then_sleeps_and_stops(self) -> None:
        script = [
            {"tool_calls": [{"name": "query_observations", "arguments": {"host_id": "edge-01"}}]},
            {"final_text": "done"},
        ]
        worker = self.make_worker(script)
        stop = threading.Event()

        def stopper() -> None:
            time.sleep(0.4)
            stop.set()

        threading.Thread(target=stopper, daemon=True).start()
        processed = worker.run_loop(poll_interval_seconds=0.05, stop_event=stop)
        self.assertEqual(processed, 1)
        self.assertEqual(self.server.completed_events, [1])

    def test_backoff_is_bounded(self) -> None:
        worker = self.make_worker([{"final_text": "x"}])
        self.assertLessEqual(worker.next_backoff_seconds(1), 0.01)
        self.assertLessEqual(worker.next_backoff_seconds(10), worker.max_backoff_seconds)


if __name__ == "__main__":
    unittest.main()
