"""LIVE integration tests against the compiled ``target/debug/control-d``.

Covers the full Phase-5 loop: synthetic agent feed -> trigger -> lease ->
durable run -> typed ephemeral watch proposal -> evidence-bound finding ->
lease completion -> audit chain verification, plus expired-lease fencing.
Skipped automatically when no compiled binary is present.
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))

import unittest  # noqa: E402
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from defsec_reasoner.admin_client import AdminClient  # noqa: E402
from defsec_reasoner.control_harness import (  # noqa: E402
    COLLECTORS,
    ControlDaemon,
    SyntheticAgent,
    find_control_binary,
    rfc3339_now,
    socket_entry,
    sockets_snapshot,
    sockets_watch_spec,
    systemd_snapshot,
    systemd_unit_watch_spec,
    unit_file_hash,
)
from defsec_reasoner.host_review import ReviewLimits, review_once
from defsec_reasoner.models import ProviderError, ScriptedMockAdapter  # noqa: E402
from defsec_reasoner.rpc_client import ControlRpcClient, RpcError  # noqa: E402
from defsec_reasoner.worker import ReasonerWorker, RunBudgets  # noqa: E402

BINARY = find_control_binary()
HOST = "edge-01"


def _base_sockets() -> list[dict]:
    return [
        socket_entry("tcp:0.0.0.0:22:uid=0", port=22, inode=1001, pid=101, comm="sshd", systemd_unit="sshd.service"),
        socket_entry("tcp:0.0.0.0:80:uid=0", port=80, inode=2002, pid=202, comm="nginx", systemd_unit="nginx.service"),
    ]


def _changed_sockets() -> list[dict]:
    return _base_sockets()[:1] + [
        socket_entry("tcp:0.0.0.0:4444:uid=0", port=4444, inode=4404, pid=444, comm="ghost", systemd_unit="ghost.service")
    ]


@unittest.skipUnless(BINARY, "compiled control-d binary not found (cargo build -p control-d)")
class LiveIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.daemon = ControlDaemon(BINARY)
        self.addCleanup(self.daemon.stop)
        self.daemon.start()
        self.admin = AdminClient(self.daemon.admin_sock)
        self.admin.enroll_host(HOST)
        self.admin.apply_baseline_watch(
            sockets_watch_spec(HOST), "operator-setup", "baseline sockets inventory"
        )
        self.agent = SyntheticAgent(self.daemon.agent_sock, HOST)
        self.agent.connect()
        self.token = self.admin.mint_capability_token(
            "live-integration", "investigator", [HOST], COLLECTORS
        )["token"]

    def tearDown(self) -> None:
        self.agent.close()

    def _client(self, token: str | None = None) -> ControlRpcClient:
        return ControlRpcClient(self.daemon.investigate_sock, token or self.token)

    def _fire_sockets_trigger(self) -> float:
        assert self.agent.push_snapshot("w-sockets", 1, sockets_snapshot(_base_sockets()))
        t_trigger = time.monotonic()
        assert self.agent.push_snapshot("w-sockets", 1, sockets_snapshot(_changed_sockets()))
        return t_trigger

    def _ephemeral_spec(self, incident_id: str) -> dict:
        expires = (
            datetime.now(timezone.utc).replace(microsecond=0) + timedelta(hours=2)
        ).isoformat().replace("+00:00", "Z")
        return systemd_unit_watch_spec(
            HOST, "ghost.service", "eph-ghost",
            klass="ephemeral", incident_id=incident_id,
            interval_seconds=30, expires_at=expires, max_runs=120,
        )

    def _rule_spec(self) -> dict:
        """A benign expectation rule: sshd.service may re-listen on port 22."""
        expires = (
            datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=3)
        ).isoformat().replace("+00:00", "Z")
        return {
            "scope": {"host_id": HOST, "collector": "sockets.listening", "watch_id": "w-sockets"},
            "matches": [
                {"op": "eq", "field": "systemd_unit", "value": "sshd.service"},
                {"op": "eq", "field": "local_port", "value": 22},
            ],
            "effect": "allow_optional",
            "rationale": "sshd.service legitimately re-listens on its pinned port after restarts",
            "expires_at": expires,
        }

    def test_periodic_host_review_rpc(self) -> None:
        self.admin.call({
            "admin_op": "set_host_review_schedule",
            "schedule": {
                "host_id": HOST,
                "interval_seconds": 120,
                "route": "supervisory",
                "question": "Which evidence is still missing?",
                "collectors": ["sockets.listening"],
            },
        })
        token = self.admin.mint_capability_token(
            "review-worker", "investigator", [HOST], ["sockets.listening"],
            may_spawn_runs=True,
        )["token"]
        client = self._client(token)
        lease = client.claim_host_review("supervisory", 60)
        assert lease is not None
        self.assertEqual(lease["assessment"]["host_id"], HOST)
        client.complete_host_review(
            lease["review_id"], lease["lease_token"], "unresolved", "Awaiting discovery."
        )
        review = self.admin.call({"admin_op": "get_latest_host_review", "host_id": HOST})["review"]
        self.assertEqual(review["review_id"], lease["review_id"])
        self.assertIsNone(client.claim_host_review("supervisory", 60))

    def test_host_review_refresh_survives_provider_outage(self) -> None:
        self.agent.close()
        self.agent = SyntheticAgent(
            self.daemon.agent_sock, HOST, agent_version="synthetic+host-discovery-v1"
        )
        self.agent.connect()
        question = "Does the socket sample establish which service is running?"
        route = "supervisory"
        self.admin.call({
            "admin_op": "set_host_review_schedule",
            "schedule": {
                "host_id": HOST, "interval_seconds": 120, "route": route,
                "question": question, "collectors": ["sockets.listening"],
            },
        })

        def scoped(name, collectors):
            return self._client(self.admin.mint_capability_token(
                name, "investigator", [HOST], collectors, may_spawn_runs=True,
            )["token"])

        first = scoped("provider-a", ["sockets.listening"])
        second = scoped("provider-b", COLLECTORS)
        narrow = scoped("narrow", ["packages.inventory"])
        self.assertIsNone(narrow.claim_host_review(route, 10))

        barrier = Barrier(2)

        def claim(client):
            barrier.wait(timeout=5)
            return client.claim_host_review(route, 10)

        with ThreadPoolExecutor(max_workers=2) as pool:
            contenders = [pool.submit(claim, client) for client in (first, second)]
            claims = [task.result() for task in contenders]
        ((winner, lease),) = [(client, lease) for client, lease in zip((first, second), claims) if lease]
        self.assertTrue(lease["needs_fresh_evidence"])
        self.assertTrue(winner.refresh_host_review(lease["review_id"], lease["lease_token"]))
        with self.assertRaises(RpcError):
            winner.complete_host_review(lease["review_id"], lease["lease_token"], "unresolved", "Old lease")
        self.agent.drain()
        discovery_watches = [w for w in self.agent.watches() if w["id"].startswith("discovery-")]
        self.assertEqual(len(discovery_watches), 1, first.get_host_assessment(HOST))
        watch = discovery_watches[0]
        self.assertTrue(self.agent.push_snapshot(watch["id"], watch["version"], sockets_snapshot([
            socket_entry("tcp:0.0.0.0:5432:uid=0", port=5432),
        ])))

        # The reactive worker can finish a trigger during the review's refresh window.
        self._fire_sockets_trigger()
        reactive = ReasonerWorker(self._client(), ScriptedMockAdapter(["Baseline trigger reviewed."]))
        self.assertIsNotNone(reactive.run_once())
        time.sleep(2.1)

        failed = ScriptedMockAdapter([ProviderError("simulated outage", True)], name="provider-a")
        with self.assertRaises(ProviderError):
            review_once(first, failed, route, ReviewLimits(seconds=0.8, lease_seconds=1))
        time.sleep(1.1)

        def assess(messages, tools):
            self.assertEqual(tools, [])
            self.assertEqual(len(messages), 2)
            self.assertIn("A socket does not identify its process", messages[0]["content"])
            prompt = json.loads(messages[1]["content"])
            self.assertEqual(prompt["question"], question)
            (sample,) = prompt["samples"]
            self.assertEqual(sample["collector"], "sockets.listening")
            self.assertEqual(sample["sample"]["sockets"][0]["local_port"], 5432)
            return json.dumps({
                "interpretation": "unresolved",
                "summary": "The listener does not identify the service.",
                "citations": [sample["observation_id"]],
            })

        successor = ScriptedMockAdapter([assess], name="provider-b")
        review_once(second, successor, route, ReviewLimits())
        self.assertEqual(successor.turns_used, 1)
        self.assertEqual(second.get_host_discovery_samples(HOST), [])
        review = self.admin.call({"admin_op": "get_latest_host_review", "host_id": HOST})["review"]
        self.assertEqual(review["review_id"], lease["review_id"])
        self.assertEqual(review["interpretation"], "unresolved")
        self.assertGreater(review["assessment_version"], lease["assessment"]["version"])
        self.assertEqual(len(review["citations"]), 1)
        self.assertEqual(second.query_observations(HOST, watch_id=watch["id"]), [])

    def test_lease_run_propose_finding_complete_and_audit_chain(self) -> None:
        self._fire_sockets_trigger()

        # Scripted model: query evidence -> propose follow-up unit watch ->
        # collect it via the synthetic agent -> record an evidence-bound
        # verified finding -> finish.
        agent = self.agent

        def propose_followup(messages: list[dict], _tools: list) -> dict:
            header = {}
            for message in messages:
                if message.get("role") == "user":
                    content = str(message.get("content") or "")
                    marker = "RUN CONTEXT (trusted, generated by reasoner-d):"
                    start = content.find(marker)
                    rest = content[start + len(marker):].lstrip()
                    header = json.JSONDecoder().raw_decode(rest)[0]
                    break
            return {"tool_calls": [{
                "name": "propose_ephemeral_watch",
                "arguments": {
                    "spec": self._ephemeral_spec(header["incident_id"]),
                    "rationale": "corroborate the new 4444 listener with unit state",
                },
            }]}

        def collect_followup(messages: list[dict], _tools: list) -> dict:
            agent.drain(2.0)
            watch = agent.find_watch("eph-ghost")
            self.assertIsNotNone(watch, "ephemeral watch was not synced to the agent bundle")
            assert agent.push_snapshot(
                "eph-ghost", 1,
                systemd_snapshot(
                    "ghost.service", active_state="active", sub_state="running",
                    unit_files=[unit_file_hash("/etc/systemd/system/ghost.service", "ab" * 32, size=289)],
                ),
                collector="systemd.unit_state",
            )
            return {"tool_calls": [{
                "name": "query_observations",
                "arguments": {"host_id": HOST, "watch_id": "eph-ghost", "limit": 50},
            }]}

        def record_finding(messages: list[dict], _tools: list) -> dict:
            from defsec_reasoner.provenance import envelope_contents

            ids: set[int] = set()
            for message in messages:
                if message.get("role") != "tool":
                    continue
                for payload in envelope_contents(str(message.get("content") or "")):
                    if isinstance(payload, dict) and isinstance(payload.get("observations"), list):
                        ids.update(o["observation_id"] for o in payload["observations"] if "observation_id" in o)
            return {"tool_calls": [{
                "name": "record_hypothesis_or_finding",
                "arguments": {
                    "kind": "verified_finding", "severity": "high",
                    "summary": "Unexpected listener on 4444 belongs to ghost.service; "
                               "follow-up unit watch shows active/running with a hashed unit file.",
                    "uncertainty": "Deployment channel is outside collector scope.",
                    "evidence_observation_ids": sorted(ids),
                    "escalation_requested": True,
                },
            }]}

        def inspect_initial_context(messages, _tools):
            from defsec_reasoner.provenance import envelope_contents

            sockets = [
                item for payload in envelope_contents(messages[1]["content"])
                if isinstance(payload, dict) and payload.get("kind") == "snapshot"
                for item in payload["data"]["sockets"]["items"]
            ]
            self.assertIn(_base_sockets()[1], sockets)
            self.assertIn(_changed_sockets()[-1], sockets)
            return {"tool_calls": [{"name": "query_observations", "arguments": {
                "host_id": HOST, "watch_id": "w-sockets", "limit": 50,
            }}]}

        def propose_rule(messages: list[dict], _tools: list) -> dict:
            return {"tool_calls": [{
                "name": "propose_expectation_rule",
                "arguments": {
                    "idempotency_key": "sshd-22",
                    "rule": self._rule_spec(),
                },
            }]}

        script = [
            inspect_initial_context,
            propose_followup,
            collect_followup,
            record_finding,
            propose_rule,
            {"final_text": "investigation complete"},
        ]

        def factory() -> ControlRpcClient:
            fresh = self.admin.mint_capability_token(
                "live-run", "investigator", [HOST], COLLECTORS
            )["token"]
            return ControlRpcClient(self.daemon.investigate_sock, fresh)

        worker = ReasonerWorker(
            factory, ScriptedMockAdapter(script), backend_id="live-test",
            budgets=RunBudgets(max_turns=8),
        )
        outcome = worker.run_once()
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.status, "completed", f"worker outcome: {outcome}")
        self.assertEqual(outcome.proposals, 1)
        self.assertEqual(outcome.proposals_accepted, 1)
        self.assertEqual(outcome.rule_proposals_submitted, 1)
        self.assertEqual(outcome.rule_proposals_accepted, 1)
        self.assertEqual(outcome.findings, 1)
        self.assertGreaterEqual(outcome.tool_calls, 5)

        # The trigger is done and cannot be double-processed.
        client = self._client(self.admin.mint_capability_token(
            "verify", "investigator", [HOST], COLLECTORS)["token"])
        self.assertIsNone(client.lease_next_trigger("verify-worker", 60))

        runs = client.list_investigation_runs(host_id=HOST, limit=1)
        self.assertEqual(runs[0]["run_id"], outcome.run_id)
        self.assertEqual(runs[0]["status"], "completed")
        self.assertEqual(runs[0]["outcome"]["summary"], "investigation complete")
        self.assertEqual(runs[0]["findings_count"], 1)
        self.assertEqual(runs[0]["proposals_count"], 1)
        events = client.get_run_events(outcome.run_id)
        self.assertEqual(len(events), runs[0]["event_count"])
        self.assertEqual(events[0]["kind"], "turn_started")
        self.assertIn("model_text", {event["kind"] for event in events})
        self.assertEqual(events[-1], runs[0]["last_event"])
        self.assertEqual(client.get_run_events(outcome.run_id, after_seq=events[0]["event_seq"]), events[1:])
        queue = client.list_trigger_queue(statuses=["done"])
        self.assertEqual(queue[0]["event_id"], outcome.event_id)
        self.assertNotIn("lease_token", queue[0])
        self.assertIn("diff", queue[0]["reason"])

        # The rule proposal was recorded as run progress and stays inert (proposed).
        rule_results = [
            event for event in events
            if event["kind"] == "tool_result"
            and (event.get("detail") or {}).get("tool") == "propose_expectation_rule"
        ]
        self.assertEqual(len(rule_results), 1)
        self.assertTrue(rule_results[0]["detail"]["accepted"])
        rules = self.admin.call({
            "admin_op": "list_expectation_rules",
            "host_id": HOST,
            "statuses": ["proposed"],
            "limit": 10,
        })["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["status"], "proposed")
        self.assertEqual(rules[0]["origin"], "investigator")
        self.assertEqual(rules[0]["run_id"], outcome.run_id)
        self.assertEqual(rules[0]["spec"]["scope"]["watch_id"], "w-sockets")
        self.assertEqual(rules[0]["spec"]["matches"][0]["value"], "sshd.service")
        self.assertGreater(rules[0]["backtest"]["observations_scanned"], 0)
        self.assertEqual(rules[0]["hit_count"], 0)

        # Findings are durable and evidence-bound in the incident context.
        incidents = [i for i in self.admin.list_incidents() if i["status"] == "open"]
        self.assertEqual(len(incidents), 1)
        context = client.get_incident_context(incidents[0]["incident_id"])
        self.assertEqual(len(context["findings"]), 1)
        finding = context["findings"][0]["finding"]
        self.assertEqual(finding["kind"], "verified_finding")
        self.assertGreaterEqual(len(finding["evidence_observation_ids"]), 3)  # 2 socket + 1 unit obs
        watch_ids = {o["watch_id"] for o in context["recent_observations"]}
        self.assertIn("w-sockets", watch_ids)
        self.assertIn("eph-ghost", watch_ids)

        # The proposal produced a signed bundle the agent actually received.
        self.assertEqual(len(self.agent.bundles), 2)
        eph = [w for w in self.agent.bundles[-1]["watches"] if w["id"] == "eph-ghost"]
        self.assertEqual(len(eph), 1)
        self.assertEqual(eph[0]["class"], "ephemeral")

        # The durable policy decision for the accepted proposal exists.
        decisions = self.admin.list_policy_decisions(50)
        allowed = [d for d in decisions if (d.get("decision") or {}).get("allowed")]
        self.assertGreaterEqual(len(allowed), 1)

        # End-to-end tamper-evidence: the audit chain verifies over the whole run.
        chain = self.admin.verify_audit_chain()
        self.assertTrue(chain["valid"], f"audit chain broken: {chain}")
        self.assertGreaterEqual(chain["entries_checked"], 8)

    def _check_resumed_followup(self, active_state: str, expected: str) -> None:
        from defsec_reasoner.provenance import envelope_contents

        self._fire_sockets_trigger()
        origin = self._client()
        incident = self.admin.list_incidents()[0]["incident_id"]
        run_id = origin.start_investigation_run(incident, "test", "original", "v1")["run_id"]
        question = "Does the service still appear active at the time of the new sample?"
        proposal = origin.propose_ephemeral_watch(run_id, "question-1", self._ephemeral_spec(incident), question)
        self.assertTrue(proposal["decision"]["allowed"])
        origin.finish_investigation_run(run_id, {
            "status": "budget_exhausted", "budget_stop_reason": "max_turns",
            "summary": "Awaiting unit state", "turns": 1, "tool_calls": 1, "input_tokens": 100,
            "output_tokens": 50, "findings": 0, "proposals": 1, "proposals_accepted": 1,
        })
        token = self.admin.mint_capability_token(
            "followup-service", "investigator", [HOST], COLLECTORS, may_spawn_runs=True,
        )["token"]
        claimant = self._client(token)
        query = {"op": "list_watch_followups", "incident_id": incident}
        self.assertEqual(claimant.call(query)["followups"][0]["status"], "awaiting_evidence")
        self.agent.close()
        self.daemon.keep_data = True
        self.daemon.stop()
        for socket in (self.daemon.agent_sock, self.daemon.investigate_sock, self.daemon.admin_sock):
            socket.unlink(missing_ok=True)
        self.daemon.start()
        self.daemon.keep_data = False
        self.agent = SyntheticAgent(self.daemon.agent_sock, HOST)
        self.agent.connect()
        sample = systemd_snapshot("ghost.service", active_state=active_state)
        for _ in range(2):
            self.assertTrue(self.agent.push_snapshot("eph-ghost", 1, sample, collector="systemd.unit_state"))
        job = claimant.call(query)["followups"][0]
        self.assertEqual(job["status"], "ready")

        restricted = self._client(self.admin.mint_capability_token(
            "restricted", "investigator", [HOST], ["systemd.unit_state"], may_spawn_runs=True,
        )["token"])
        self.assertEqual(restricted.call(query)["followups"], [])
        self.assertIsNone(restricted.call({
            "op": "claim_watch_followup", "backend_id": "test", "model_id": "test", "lease_seconds": 30,
        })["task"])

        self.assertIsNone(claimant.call({
            "op": "claim_watch_followup", "backend_id": "test", "model_id": "test", "lease_seconds": 30,
            "allowed_sources": [{"host_id": HOST, "collectors": ["systemd.unit_state"]}],
        })["task"])
        self.assertEqual(claimant.call(query)["followups"][0]["status"], "ready")

        def interpret(messages, tools):
            self.assertEqual([t["name"] for t in tools], ["assess_observation"])
            text = messages[-1]["content"]
            self.assertNotIn(token, text)
            rationale, payload = envelope_contents(text)
            self.assertEqual(rationale, question)
            state = payload["data"]["active_state"]
            evidence = re.search(r'observation_id="(\d+)"', text)
            return {"tool_calls": [{"name": "assess_observation", "arguments": {
                "summary": f"The service was {state} when observed.",
                "interpretation": "supports" if state == "active" else "contradicts",
                "observation_id": int(evidence[1]),
            }}]}

        worker = ReasonerWorker(claimant, ScriptedMockAdapter([interpret]), followups_only=True)
        result = worker.run_once()
        self.assertEqual(result.findings, 1)
        self.assertNotEqual(result.run_id, run_id)
        self.assertIsNone(worker.run_once())
        finding = claimant.get_incident_context(incident)["findings"][0]["finding"]
        self.assertEqual(restricted.get_incident_context(incident)["findings"], [])
        self.assertEqual(finding["interpretation"], expected)
        self.assertEqual(finding["evidence_observation_ids"], [job["observation_id"]])
        self.assertEqual(claimant.call(query)["followups"][0]["status"], "answered")
        self.assertTrue(self.admin.verify_audit_chain()["valid"])

    def test_unanswered_followup_expires_and_refuses_late_evidence(self):
        self._fire_sockets_trigger()
        origin = self._client()
        incident = self.admin.list_incidents()[0]["incident_id"]
        run_id = origin.start_investigation_run(incident, "test", "origin", "v1")["run_id"]
        proposal = origin.propose_ephemeral_watch(run_id, "missing-sample", self._ephemeral_spec(incident),
                                                   "Was the service active?")
        token = self.admin.mint_capability_token(
            "review", "investigator", [HOST], COLLECTORS, may_spawn_runs=True,
        )["token"]
        client = self._client(token)
        query = {"op": "list_watch_followups", "incident_id": incident}
        self.assertTrue(proposal["decision"]["allowed"])
        pending, = client.call(query)["followups"]
        self.assertEqual(pending["status"], "awaiting_evidence")
        # Advance only the fixture's deadline so the test needs no wall-clock delay.
        with sqlite3.connect(self.daemon.data_dir / "ledger.sqlite3") as db:
            db.execute("UPDATE watch_followups SET deadline='2000-01-01T00:00:00Z' WHERE proposal_id=?",
                       (pending["proposal_id"],))
        self.assertTrue(self.agent.push_snapshot("eph-ghost", 1, systemd_snapshot("ghost.service"),
                                                 collector="systemd.unit_state"))
        question, = client.call(query)["followups"]
        self.assertEqual(question["status"], "expired")
        self.assertIsNone(question["observation_id"])
        self.assertIsNone(question["finding_id"])
        self.assertIsNone(client.call({"op": "claim_watch_followup", "backend_id": "test", "model_id": "test",
                                       "lease_seconds": 30})["task"])

    def test_followup_supports_after_restart(self):
        self._check_resumed_followup("active", "supports")

    def test_followup_contradicts_after_restart(self):
        self._check_resumed_followup("inactive", "contradicts")

    def test_expired_lease_is_fenced_and_requeued_by_control(self) -> None:
        self._fire_sockets_trigger()
        client = self._client()
        lease = client.lease_next_trigger("fence-test", 1)  # 1-second lease
        self.assertIsNotNone(lease)
        run = client.start_investigation_run(lease["incident_id"], "fence", "mock", "v1")
        time.sleep(1.4)  # lease expires
        with self.assertRaises(RpcError) as ctx:
            client.complete_trigger_lease(lease["event_id"], lease["lease_token"], run_id=run["run_id"])
        self.assertIn(ctx.exception.code, ("forbidden", "lease_fenced"))
        self.assertIn("lease expired", ctx.exception.message)
        # A new lease attempt reclaims the expired lease (bounded requeue).
        next_client = self._client(self.admin.mint_capability_token(
            "fence-2", "investigator", [HOST], COLLECTORS)["token"])
        reclaimed = next_client.lease_next_trigger("fence-test-2", 60)
        self.assertIsNotNone(reclaimed)
        self.assertEqual(reclaimed["event_id"], lease["event_id"])
        self.assertEqual(reclaimed["retry_count"], 1)
        # The stale fencing token can no longer fail or complete the lease.
        with self.assertRaises(RpcError):
            client.fail_trigger_lease(lease["event_id"], lease["lease_token"], "stale", True)

    def test_worker_reports_lease_stale_on_expired_lease(self) -> None:
        self._fire_sockets_trigger()

        def slow_query(_messages: list, _tools: list) -> dict:
            time.sleep(1.4)  # outlive the 1-second lease
            return {"tool_calls": [{"name": "query_observations",
                                    "arguments": {"host_id": HOST, "watch_id": "w-sockets"}}]}

        script = [slow_query, {"final_text": "done too late"}]

        def factory() -> ControlRpcClient:
            fresh = self.admin.mint_capability_token(
                "stale-run", "investigator", [HOST], COLLECTORS)["token"]
            return ControlRpcClient(self.daemon.investigate_sock, fresh)

        worker = ReasonerWorker(
            factory, ScriptedMockAdapter(script), budgets=RunBudgets(lease_seconds=1)
        )
        outcome = worker.run_once()
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.status, "lease_stale")

    def test_observer_role_cannot_propose(self) -> None:
        self._fire_sockets_trigger()
        observer_token = self.admin.mint_capability_token(
            "obs", "observer", [HOST], COLLECTORS
        )["token"]
        observer = self._client(observer_token)
        with self.assertRaises(RpcError) as lease_error:
            observer.lease_next_trigger("observer", 60)
        self.assertIn("investigator role required", lease_error.exception.message)
        with self.assertRaises(RpcError) as ctx:
            observer.propose_ephemeral_watch("run-x", "key", self._ephemeral_spec("inc"), "nope")
        self.assertEqual(ctx.exception.code, "forbidden")
        with self.assertRaises(RpcError) as rule_ctx:
            observer.propose_expectation_rule("run-x", "key", self._rule_spec())
        self.assertEqual(rule_ctx.exception.code, "forbidden")


if __name__ == "__main__":
    unittest.main()
