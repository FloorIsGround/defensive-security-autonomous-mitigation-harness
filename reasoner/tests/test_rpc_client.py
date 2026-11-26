"""ControlRpcClient tests: exact op shapes, error handling, token hygiene."""

from __future__ import annotations

import json
import socket
import sys
import threading
import uuid
from pathlib import Path

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))
TESTS_ROOT = Path(__file__).resolve().parent
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

import unittest  # noqa: E402

from defsec_reasoner.rpc_client import (  # noqa: E402
    ControlRpcClient,
    RpcError,
    RpcTransportError,
)
from defsec_reasoner.wire import MAX_FRAME_BYTES, read_frame, send_frame  # noqa: E402

from support import FakeControlServer, temporary_socket_path  # noqa: E402

TOKEN = "capability-token-do-not-log-0123456789abcdef"


class TestControlRpcClient(unittest.TestCase):
    def setUp(self) -> None:
        self.sock_path = temporary_socket_path(self, "rpc-t-")
        self.server = FakeControlServer(self.sock_path).start()
        self.client = ControlRpcClient(self.sock_path, TOKEN)

    def tearDown(self) -> None:
        self.server.stop()

    def test_envelope_shape_is_exact_investigation_call(self) -> None:
        self.client.list_hosts(limit=5)
        envelope = self.server.last_envelope
        self.assertEqual(set(envelope), {"request_id", "capability_token", "request"})
        self.assertEqual(envelope["capability_token"], TOKEN)
        self.assertRegex(envelope["request_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(envelope["request"], {"op": "list_hosts", "limit": 5})
        self.client.list_hosts(tag="region:west")
        self.assertEqual(self.server.last_envelope["request"], {"op": "list_hosts", "tag": "region:west"})

    def test_omitted_optional_fields_are_absent(self) -> None:
        self.client.query_observations("edge-01")
        self.assertEqual(self.server.last_envelope["request"], {"op": "query_observations", "host_id": "edge-01"})

    def test_delegated_run_fencing_fields_are_optional(self) -> None:
        self.server.register_token(TOKEN, principal_id="test-parent", may_spawn_runs=True)
        self.client.start_delegated_run("inc-1", "test", "model", "v1")
        base = self.server.last_envelope["request"]
        self.assertNotIn("trigger_event_id", base)
        self.assertNotIn("lease_token", base)
        self.client.start_delegated_run("inc-1", "test", "model", "v1",
                                        trigger_event_id=0, lease_token="test-lease")
        self.assertEqual(self.server.last_envelope["request"],
                         {**base, "trigger_event_id": 0, "lease_token": "test-lease"})

    def test_all_typed_ops_serialize_with_exact_tags(self) -> None:
        c = self.client
        c.list_active_incidents(host_id="edge-01")
        c.list_active_watches("edge-01")
        c.list_collector_capabilities("edge-01")
        c.get_incident_context("inc-1")
        c.get_host_baseline_summary("edge-01")
        c.start_investigation_run("inc-1", "b", "m", "v1")
        c.propose_ephemeral_watch("run-1", "key-1", {"id": "w"}, "why")
        c.record_hypothesis_or_finding(
            "run-1", "inc-1", kind="hypothesis", severity="low",
            summary="s", uncertainty="u", evidence_observation_ids=[11],
            escalation_requested=False,
        )
        c.lease_next_trigger("worker", 60)
        ops = [r["op"] for r in self.server.requests]
        self.assertEqual(
            ops,
            [
                "list_active_incidents",
                "list_active_watches",
                "list_collector_capabilities",
                "get_incident_context",
                "get_host_baseline_summary",
                "start_investigation_run",
                "propose_ephemeral_watch",
                "record_hypothesis_or_finding",
                "lease_next_trigger",
            ],
        )
        self.assertEqual(self.server.requests[-1], {"op": "lease_next_trigger", "lease_owner": "worker", "lease_seconds": 60})

    def test_dormant_lease_returns_none(self) -> None:
        self.server.triggers[0]["status"] = "done"
        self.assertIsNone(self.client.lease_next_trigger("worker", 60))

    def test_server_error_raises_rpc_error(self) -> None:
        with self.assertRaises(RpcError) as ctx:
            self.client.get_incident_context("inc-nope")
        self.assertEqual(ctx.exception.code, "forbidden")
        self.assertIn("capability scope", ctx.exception.message)

    def test_unknown_result_tag_is_transport_error(self) -> None:
        sock_path = temporary_socket_path(self, "rpc-t2-")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(sock_path)
        listener.listen(1)

        def serve() -> None:
            conn, _ = listener.accept()
            envelope = read_frame(conn, MAX_FRAME_BYTES, timeout=5.0)
            send_frame(conn, {"result": "mystery"})
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        client = ControlRpcClient(sock_path, TOKEN)
        with self.assertRaises(RpcTransportError):
            client.list_hosts()
        listener.close()

    def test_connect_failure_is_transport_error(self) -> None:
        client = ControlRpcClient(str(uuid.uuid4()) + ".sock", TOKEN)
        with self.assertRaises(RpcTransportError):
            client.list_hosts()

    def test_outgoing_oversize_frame_is_rejected_client_side(self) -> None:
        client = ControlRpcClient(self.sock_path, TOKEN, max_frame_bytes=64)
        with self.assertRaises(RpcTransportError):
            client.query_observations("edge-01", limit=100)

    def test_repr_and_error_paths_never_expose_token(self) -> None:
        representation = repr(self.client)
        self.assertNotIn(TOKEN, representation)
        self.assertIn("tok-", representation)
        # Transport errors must not embed the token either.
        bad = ControlRpcClient("/nonexistent/sock", TOKEN)
        try:
            bad.list_hosts()
        except RpcTransportError as exc:
            self.assertNotIn(TOKEN, str(exc))
        else:  # pragma: no cover
            self.fail("expected RpcTransportError")

    def test_query_observations_returns_slices(self) -> None:
        observations = self.client.query_observations("edge-01", watch_id="w-sockets")
        self.assertEqual([o["observation_id"] for o in observations], [11, 12])

    def test_invalid_enum_arguments_rejected_locally(self) -> None:
        with self.assertRaises(ValueError):
            self.client.record_hypothesis_or_finding(
                "run", "inc-1", kind="guess", severity="low",
                summary="s", uncertainty="u", evidence_observation_ids=[],
                escalation_requested=False,
            )
        with self.assertRaises(ValueError):
            self.client.record_hypothesis_or_finding(
                "run", "inc-1", kind="hypothesis", severity="extreme",
                summary="s", uncertainty="u", evidence_observation_ids=[],
                escalation_requested=False,
            )


if __name__ == "__main__":
    unittest.main()
