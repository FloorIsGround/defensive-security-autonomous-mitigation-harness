"""Exercise quiet-host discovery through the real control and agent RPCs."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import json
import sqlite3
import tempfile
import time
import unittest
from threading import Barrier
from unittest.mock import patch

from defsec_reasoner.admin_client import AdminClient
from defsec_reasoner.control_harness import (
    ControlDaemon, SyntheticAgent, find_control_binary, socket_entry, sockets_snapshot,
)
from defsec_reasoner.discovery import _may_export, export_scopes, interpret_next_host
from defsec_reasoner.models import OpenAICompatibleAdapter, ScriptedMockAdapter
from defsec_reasoner.rpc_client import ControlRpcClient, RpcError
from defsec_reasoner.worker import ReasonerWorker, RunBudgets

BINARY = find_control_binary()
SOCKETS = "sockets.listening"
PACKAGES = "packages.inventory"
SYSTEMD = "systemd.unit_state"


class DiscoveryExportTests(unittest.TestCase):
    def test_external_grant_binds_endpoint_host_and_every_collector(self):
        endpoint = "https://provider.example/v1"
        adapter = OpenAICompatibleAdapter(base_url=endpoint, model_id="fixture")
        with patch.dict("os.environ", {"DEFSEC_DISCOVERY_EXPORT_GRANTS": "[]"}):
            self.assertFalse(_may_export(adapter, "node-01", {SOCKETS}))
        grant = {"endpoint": endpoint, "host_id": "node-01", "collectors": [SOCKETS]}
        with patch.dict("os.environ", {"DEFSEC_DISCOVERY_EXPORT_GRANTS": json.dumps([grant])}):
            self.assertTrue(_may_export(adapter, "node-01", {SOCKETS}))
            with patch.dict("os.environ", {"DEFSEC_REVIEW_EXPORT_GRANTS": json.dumps([{**grant, "purpose":"routine"}])}):
                self.assertEqual(export_scopes(adapter, "supervisory"), [])
                self.assertEqual(export_scopes(adapter, "routine"), [{"host_id":"node-01", "collectors":[SOCKETS]}])
            self.assertFalse(_may_export(adapter, "node-01", {SOCKETS}, local_only=True))
            self.assertFalse(_may_export(adapter, "node-01", {SOCKETS, PACKAGES}))
            self.assertFalse(_may_export(adapter, "node-02", {SOCKETS}))
            adapter.base_url = "https://other.example/v1"
            self.assertFalse(_may_export(adapter, "node-01", {SOCKETS}))
            adapter.base_url = "http://127.0.0.1:11434/v1"
            self.assertTrue(_may_export(adapter, "node-01", {SOCKETS, PACKAGES}))


@unittest.skipUnless(BINARY, "build control-d before running the live discovery test")
class DiscoveryOnboardingTests(unittest.TestCase):
    def test_quiet_host_interpretation_is_evidence_bound_and_durable(self):
        host = "node-01"
        with tempfile.TemporaryDirectory(prefix="dsam-discovery-") as root:
            daemon = ControlDaemon(BINARY, base_dir=root, keep_data=True).start()
            self.addCleanup(daemon.stop)
            admin = AdminClient(daemon.admin_sock)
            admin.enroll_host(host)
            admin.enroll_host("node-02")

            def scoped_client(principal, collectors):
                token = admin.mint_capability_token(principal, "investigator", [host], collectors)["token"]
                return ControlRpcClient(daemon.investigate_sock, token)

            broad = scoped_client("worker", [SOCKETS, PACKAGES, SYSTEMD])
            narrow = scoped_client("reader", [SOCKETS])
            agent = SyntheticAgent(daemon.agent_sock, host, agent_version="test+host-discovery-v1")
            agent.connect()
            self.addCleanup(agent.close)

            def infer(messages, tools):
                self.assertEqual(tools, [])
                self.assertNotIn(host, json.dumps(messages))
                samples = {item["collector"]: item for item in json.loads(messages[1]["content"])}
                ports = {entry["local_port"] for entry in samples[SOCKETS]["sample"]["sockets"]}
                packages = {entry["name"] for entry in samples[PACKAGES]["sample"]["packages"]}
                if 5432 not in ports or "postgresql-16" not in packages:
                    return {"final_text": "{}"}
                return {"final_text": json.dumps({
                    "purpose": "Likely PostgreSQL database host",
                    "dependencies": ["PostgreSQL 16 package"],
                    "uncertainty": "Package and port agree, but the owning process is unknown.",
                    "visibility_gaps": ["A single snapshot does not establish uptime or clients."],
                    "proposed_watch": {
                        "collector": SOCKETS,
                        "service_unit": "postgresql.service",
                        "rationale": "Track the likely PostgreSQL service behind TCP 5432.",
                    },
                    "citations": [samples[SOCKETS]["observation_id"]],
                })}

            adapter = ScriptedMockAdapter([infer])
            worker = ReasonerWorker(broad, adapter)
            self.assertIsNone(worker.run_once())
            agent.drain()
            watches = {watch["collector"]["type"]: watch for watch in agent.watches()}
            self.assertEqual(set(watches), {SOCKETS, PACKAGES})
            fixture = {
                SOCKETS: sockets_snapshot([socket_entry("tcp:0.0.0.0:5432:uid=0", port=5432)]),
                PACKAGES: {
                    "packages": [{
                        "package_key": "postgresql-16:amd64", "name": "postgresql-16",
                        "arch": "amd64", "version": "16.1",
                    }],
                    "total_packages": 1, "status_file_sha256": "0" * 64,
                },
            }
            for collector, watch in watches.items():
                self.assertTrue(agent.push_snapshot(
                    watch["id"], watch["version"], fixture[collector], collector=collector,
                ))

            broad.advance_host_discovery(host)
            broad_ids = [s["evidence"]["observation_id"] for s in broad.get_host_discovery_samples(host)]
            socket_ids = [s["evidence"]["observation_id"] for s in narrow.get_host_discovery_samples(host)]
            self.assertEqual(len(broad_ids), 2)
            self.assertIsNone(narrow.claim_host_interpretation(host, broad_ids, [SOCKETS], 30))
            self.assertIsNone(broad.claim_host_interpretation(host, broad_ids, [SOCKETS], 30))
            self.assertEqual(broad.list_host_interpretation_attempts(host, broad_ids), [])
            cancelled = broad.claim_host_interpretation(host, broad_ids, [SOCKETS, PACKAGES], 30)
            self.assertIsNotNone(cancelled)
            broad.finish_host_interpretation(host, cancelled, error="export_revoked")
            self.assertEqual(broad.list_host_interpretation_attempts(host, broad_ids), [])

            replay = ControlRpcClient(
                daemon.investigate_sock, narrow.capability_token,
                _request_id_factory=lambda: "claim-race",
            )
            other = ControlRpcClient(
                daemon.investigate_sock, scoped_client("other", [SOCKETS]).capability_token,
                _request_id_factory=lambda: "other-claim-race",
            )
            barrier = Barrier(2)

            def race(client):
                barrier.wait(timeout=5)
                return client.claim_host_interpretation(host, socket_ids, [SOCKETS], 30)

            with ThreadPoolExecutor(max_workers=2) as pool:
                leases = list(pool.map(race, [replay, other]))
            self.assertEqual(sum(lease is not None for lease in leases), 1)
            owner = replay if leases[0] is not None else other
            lease = next(lease for lease in leases if lease is not None)
            with self.assertRaises(RpcError):
                broad.finish_host_interpretation(host, lease, error="provider_retryable")

            def age_attempt(*, expired=False):
                # Advance the persisted deadlines without making the test sleep through backoff.
                with closing(sqlite3.connect(daemon.data_dir / "ledger.sqlite3")) as db, db:
                    db.execute(
                        "UPDATE host_discovery_interpretation_attempts SET retry_at=:deadline"
                        + (", lease_until=:deadline" if expired else "") + " WHERE source_ids=:source",
                        {"deadline": "2000-01-01T00:00:00.000000000Z", "source": json.dumps(socket_ids)},
                    )

            agent.close()
            daemon.stop()
            for socket in (daemon.agent_sock, daemon.investigate_sock, daemon.admin_sock):
                socket.unlink(missing_ok=True)
            daemon.start()
            self.assertIsNone(owner.claim_host_interpretation(host, socket_ids, [SOCKETS], 30))
            age_attempt(expired=True)
            self.assertEqual(narrow.list_host_interpretation_attempts(host, socket_ids)[0]["error"],
                             "lease_expired")
            self.assertIsNone(owner.finish_host_interpretation(host, lease, error="provider_retryable"))
            self.assertIsNone(owner.claim_host_interpretation(host, socket_ids, [SOCKETS], 30))

            # Select the already collected host directly so the test does not wait on polling.
            with patch.object(narrow, "advance_host_discovery", return_value={"host_id": host}):
                denied = OpenAICompatibleAdapter(base_url="https://provider.example/v1", model_id="test")
                with patch.dict("os.environ", {"DEFSEC_DISCOVERY_EXPORT_GRANTS": "[]"}):
                    interpret_next_host(denied, narrow, RunBudgets())
                self.assertEqual(len(narrow.list_host_interpretation_attempts(host, socket_ids)), 1)
                malformed = ScriptedMockAdapter(["{broken", "{}"])
                original_turn = malformed.chat_with_budget

                def metered_turn(*args):
                    return replace(original_turn(*args), input_tokens=42, output_tokens=9,
                                   cached_input_tokens=11, reasoning_tokens=3)

                with patch.object(malformed, "chat_with_budget", side_effect=metered_turn):
                    interpret_next_host(malformed, narrow, RunBudgets())
                    interpret_next_host(malformed, narrow, RunBudgets())
                self.assertEqual(malformed.turns_used, 1)
                age_attempt()
                interpret_next_host(malformed, narrow, RunBudgets())
                age_attempt()
                interpret_next_host(malformed, narrow, RunBudgets())
                self.assertEqual(malformed.turns_used, 2)
            attempts = narrow.list_host_interpretation_attempts(host, socket_ids)
            self.assertEqual([a["error"] for a in attempts],
                             ["lease_expired", "malformed_response", "malformed_response"])
            self.assertEqual(attempts[1]["usage"]["input_tokens"], 42)
            self.assertEqual(attempts[1]["usage"]["output_tokens"], 9)
            self.assertEqual(attempts[1]["usage"]["cached_input_tokens"], 11)
            self.assertEqual(attempts[1]["usage"]["reasoning_tokens"], 3)
            agent = SyntheticAgent(daemon.agent_sock, host, agent_version="test+host-discovery-v1")
            agent.connect()
            self.addCleanup(agent.close)

            deadline = time.monotonic() + 8
            while adapter.turns_used == 0 and time.monotonic() < deadline:
                self.assertIsNone(worker.run_once())
                time.sleep(0.1)
            self.assertEqual(adapter.turns_used, 1)
            saved = broad.get_host_assessment(host)["assessment"]
            interpretation, = saved["interpretations"]
            self.assertEqual(interpretation["proposal"]["purpose"], "Likely PostgreSQL database host")
            attempt, = broad.list_host_interpretation_attempts(host, broad_ids)
            self.assertEqual(attempt["status"], "saved")
            self.assertEqual(attempt["assessment_version"], saved["version"])
            self.assertEqual(narrow.list_host_interpretation_attempts(host, broad_ids), [])
            self.assertEqual(narrow.get_host_assessment(host)["assessment"]["interpretations"], [])
            self.assertEqual([s["collector"] for s in narrow.get_host_discovery_samples(host)], [SOCKETS])
            with self.assertRaises(RpcError):
                narrow.submit_host_interpretation(host, interpretation["source_ids"], interpretation["proposal"])
            with self.assertRaises(RpcError):
                broad.submit_host_interpretation(host, interpretation["source_ids"], {
                    **interpretation["proposal"], "citations": [999999],
                })
            with self.assertRaises(RpcError):
                broad.get_host_discovery_samples("node-02")
            self.assertEqual(broad.list_active_incidents(host), [])
            agent.close()
            daemon.stop()
            for socket in (daemon.agent_sock, daemon.investigate_sock, daemon.admin_sock):
                socket.unlink(missing_ok=True)
            daemon.start()
            self.assertEqual(broad.get_host_assessment(host, saved["version"])["assessment"], saved)
            self.assertEqual(broad.get_host_assessment(host)["assessment"], saved)
            with patch.object(narrow, "advance_host_discovery", return_value={"host_id": host}):
                interpret_next_host(malformed, narrow, RunBudgets())
            self.assertEqual(malformed.turns_used, 2)

            agent = SyntheticAgent(daemon.agent_sock, host, agent_version="test+host-discovery-v1")
            agent.connect()
            self.addCleanup(agent.close)
            self.assertFalse(any(w["collector"]["type"] == SYSTEMD for w in agent.watches()))

            grant = admin.call({
                "admin_op": "set_monitoring_grant", "host_id": host,
                "principal_id": "worker", "max_watches": 1, "allow_promotion": False,
            })
            self.assertTrue(grant["result"]["allowed"])
            narrow_monitor = scoped_client("worker", [SOCKETS, SYSTEMD])
            missing_collector = scoped_client("worker", [SOCKETS, PACKAGES])
            # All sources are needed even when the proposed watch cites just one collector.
            self.assertEqual(narrow_monitor.get_host_assessment(host)["assessment"]["interpretations"], [])
            time.sleep(5.1)
            self.assertIsNone(ReasonerWorker(missing_collector, adapter).run_once())
            agent.drain()
            self.assertFalse(any(w["collector"]["type"] == SYSTEMD for w in agent.watches()))

            installed = []
            deadline = time.monotonic() + 10
            while not installed and time.monotonic() < deadline:
                self.assertIsNone(worker.run_once())
                agent.drain(timeout=0.2)
                installed = [watch for watch in agent.watches() if watch["collector"]["type"] == SYSTEMD]
            watch, = installed
            self.assertEqual(watch["collector"]["parameters"]["unit"], "postgresql.service")
            self.assertEqual(adapter.turns_used, 1)
            inspected = broad.monitoring(host, watch["id"], {"operation": "inspect"})
            self.assertEqual(inspected["revision"], 1)
            self.assertEqual(inspected["intent"]["evidence"], interpretation["source_ids"])
            self.assertFalse(narrow_monitor.monitoring(host, watch["id"], {"operation": "inspect"})["allowed"])

            # A restarted worker rediscovers the persisted intent without changing the bundle.
            version = agent.bundle_version
            time.sleep(5.1)
            self.assertIsNone(ReasonerWorker(broad, adapter).run_once())
            agent.drain()
            self.assertEqual(agent.bundle_version, version)
            self.assertEqual(adapter.turns_used, 1)
            def snapshot(spec, state, substate):
                self.assertTrue(agent.push_snapshot(spec["id"], spec["version"], {
                    "unit": "postgresql.service", "load_state": "loaded",
                    "active_state": state, "sub_state": substate,
                }, collector=SYSTEMD))

            snapshot(watch, "active", "running")
            stronger = {**watch, "version": 2, "schedule": {
                **watch["schedule"], "interval_seconds": 30,
            }}
            intent = inspected["intent"]
            apply = {"operation": "apply", "spec": stronger, "expected_revision": 1,
                     **{key: intent[key] for key in ("purpose", "expected_signal", "evidence", "review_at")}}
            self.assertFalse(missing_collector.monitoring(host, watch["id"], apply)["allowed"])
            self.assertFalse(broad.monitoring(host, watch["id"], {
                **apply, "spec": {**stronger, "schedule": {**watch["schedule"], "interval_seconds": 120}},
            })["allowed"])
            self.assertEqual(broad.monitoring(host, watch["id"], apply)["revision"], 2)
            self.assertFalse(broad.monitoring(host, watch["id"], apply)["allowed"])
            agent.drain()
            self.assertEqual(agent.find_watch(watch["id"])["version"], 2)
            snapshot(stronger, "inactive", "dead")
            incident, = broad.list_active_incidents(host)
            self.assertEqual(incident["host_id"], host)
