"""Client for ``control-d``'s bounded Investigation RPC (``investigate.sock``).

Wire contract (mirrors ``crates/protocol/src/rpc.rs`` exactly):

* every frame is an ``InvestigationCall``::

      {"request_id": <str>, "capability_token": <str>, "request": {"op": ...}}

* every reply is an internally tagged ``InvestigationResponse`` keyed on
  ``"result"``; server-side failures arrive as
  ``{"result": "error", "code": ..., "message": ...}``.

The client is deliberately conservative: it opens a fresh ``AF_UNIX``
connection per call, enforces a socket timeout and the 2 MiB frame bound, and
never logs or exposes the capability token.
"""

from __future__ import annotations

import json
import logging
import socket
import uuid
from pathlib import Path
from typing import Any, Callable

from defsec_reasoner.canonical import sha256_hex
from defsec_reasoner.wire import MAX_FRAME_BYTES, FrameError, FrameTooLargeError, read_frame, send_frame

__all__ = ["ControlRpcClient", "RpcError", "RpcTransportError", "PROBE_OP"]

logger = logging.getLogger("defsec.reasoner.rpc")

#: The closed set of ``InvestigationResponse`` result tags (snake_case, from
#: ``crates/protocol/src/rpc.rs``). Anything else is a protocol violation.
_KNOWN_RESULTS = frozenset(
    {
        "hosts",
        "incidents",
        "watches",
        "capabilities",
        "incident_context",
        "observations",
        "baseline_summary",
        "run_started",
        "proposal_evaluated",
        "finding_recorded",
        "trigger_leased",
        "lease_updated",
    }
)

#: The investigation interface exposes exactly this closed operation set.
PROBE_OP = "list_hosts"


class RpcError(Exception):
    """A structured ``{"result": "error"}`` reply from ``control-d``."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"control-d rejected the call: {code}: {message}")


class RpcTransportError(Exception):
    """The socket was unreachable, timed out, or spoke invalid framing."""


class ControlRpcClient:
    """Typed client for the shared bounded Investigation RPC.

    Each public method maps 1:1 onto an ``InvestigationRequest`` variant.
    Responses are returned as plain dictionaries in the exact wire shape
    (minus the ``"result"`` tag) so callers keep full fidelity.
    """

    def __init__(
        self,
        socket_path: str | Path,
        capability_token: str,
        request_timeout: float = 10.0,
        max_frame_bytes: int = MAX_FRAME_BYTES,
        _request_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.socket_path = str(socket_path)
        self.capability_token = capability_token
        self.request_timeout = request_timeout
        self.max_frame_bytes = max_frame_bytes
        self._request_id_factory = _request_id_factory or (lambda: uuid.uuid4().hex)

    # ------------------------------------------------------------------ core

    def _redacted_token(self) -> str:
        """Short non-reversible fingerprint, safe for logs."""
        return "tok-" + sha256_hex(self.capability_token.encode())[:8]

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return (
            f"ControlRpcClient(socket={self.socket_path!r}, "
            f"token={self._redacted_token()}, timeout={self.request_timeout})"
        )

    def _open_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.request_timeout)
        try:
            sock.connect(self.socket_path)
        except OSError as exc:
            sock.close()
            raise RpcTransportError(
                f"cannot connect to control-d investigation socket {self.socket_path}: {exc}"
            ) from exc
        return sock

    def call(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send one ``InvestigationRequest`` and return the response fields.

        ``request`` must already contain the ``"op"`` tag. Server errors raise
        :class:`RpcError`.
        """
        if "op" not in request:
            raise ValueError("InvestigationRequest must carry an 'op' tag")
        envelope = {
            "request_id": self._request_id_factory(),
            "capability_token": self.capability_token,
            "request": request,
        }
        sock = self._open_socket()
        try:
            try:
                send_frame(sock, envelope, self.max_frame_bytes)
            except FrameTooLargeError as exc:
                raise RpcTransportError(
                    f"outgoing frame exceeds the {self.max_frame_bytes}-byte limit: {exc}"
                ) from exc
            try:
                reply = read_frame(sock, self.max_frame_bytes, timeout=self.request_timeout)
            except FrameTooLargeError as exc:
                raise RpcTransportError(
                    f"control-d sent an oversized frame: {exc}"
                ) from exc
            except FrameError as exc:
                raise RpcTransportError(str(exc)) from exc
        finally:
            sock.close()
        if not isinstance(reply, dict) or "result" not in reply:
            raise RpcTransportError(f"malformed investigation response: {json.dumps(reply)[:200]}")
        result = reply.pop("result")
        if result == "error":
            raise RpcError(str(reply.get("code", "unknown")), str(reply.get("message", "")))
        if result not in _KNOWN_RESULTS:
            raise RpcTransportError(f"unknown investigation result tag: {result!r}")
        # Non-error variants: tag stripped, payload fields returned verbatim.
        return reply

    # ------------------------------------------------------- discovery tools

    def list_hosts(self, limit: int | None = None) -> list[dict[str, Any]]:
        request: dict[str, Any] = {"op": "list_hosts"}
        if limit is not None:
            request["limit"] = int(limit)
        return self.call(request)["hosts"]

    def list_active_incidents(
        self, host_id: str | None = None, limit: int | None = None
    ) -> list[dict[str, Any]]:
        request: dict[str, Any] = {"op": "list_active_incidents"}
        if host_id is not None:
            request["host_id"] = host_id
        if limit is not None:
            request["limit"] = int(limit)
        return self.call(request)["incidents"]

    def list_active_watches(self, host_id: str) -> list[dict[str, Any]]:
        return self.call({"op": "list_active_watches", "host_id": host_id})["watches"]

    def list_collector_capabilities(self, host_id: str) -> list[dict[str, Any]]:
        return self.call({"op": "list_collector_capabilities", "host_id": host_id})["capabilities"]

    def get_incident_context(self, incident_id: str) -> dict[str, Any]:
        return self.call({"op": "get_incident_context", "incident_id": incident_id})

    def query_observations(
        self,
        host_id: str,
        watch_id: str | None = None,
        since: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        request: dict[str, Any] = {"op": "query_observations", "host_id": host_id}
        if watch_id is not None:
            request["watch_id"] = watch_id
        if since is not None:
            request["since"] = since
        if limit is not None:
            request["limit"] = int(limit)
        return self.call(request)["observations"]

    def get_host_baseline_summary(self, host_id: str) -> dict[str, Any]:
        return self.call({"op": "get_host_baseline_summary", "host_id": host_id})

    # ------------------------------------------------------------ run + write

    def start_investigation_run(
        self,
        incident_id: str,
        backend_id: str,
        model_id: str,
        prompt_schema_version: str,
    ) -> dict[str, Any]:
        return self.call(
            {
                "op": "start_investigation_run",
                "incident_id": incident_id,
                "backend_id": backend_id,
                "model_id": model_id,
                "prompt_schema_version": prompt_schema_version,
            }
        )

    def propose_ephemeral_watch(
        self, run_id: str, idempotency_key: str, spec: dict[str, Any], rationale: str
    ) -> dict[str, Any]:
        return self.call(
            {
                "op": "propose_ephemeral_watch",
                "run_id": run_id,
                "idempotency_key": idempotency_key,
                "spec": spec,
                "rationale": rationale,
            }
        )

    def record_hypothesis_or_finding(
        self,
        run_id: str,
        incident_id: str,
        *,
        kind: str,
        severity: str,
        summary: str,
        uncertainty: str,
        evidence_observation_ids: list[int],
        escalation_requested: bool,
    ) -> dict[str, Any]:
        if kind not in ("hypothesis", "verified_finding"):
            raise ValueError("kind must be 'hypothesis' or 'verified_finding'")
        if severity not in ("info", "low", "medium", "high", "critical"):
            raise ValueError("severity must be one of info/low/medium/high/critical")
        return self.call(
            {
                "op": "record_hypothesis_or_finding",
                "run_id": run_id,
                "incident_id": incident_id,
                "kind": kind,
                "severity": severity,
                "summary": summary,
                "uncertainty": uncertainty,
                "evidence_observation_ids": [int(i) for i in evidence_observation_ids],
                "escalation_requested": bool(escalation_requested),
            }
        )

    # --------------------------------------------------------- trigger leases

    def lease_next_trigger(self, lease_owner: str, lease_seconds: int) -> dict[str, Any] | None:
        lease = self.call(
            {
                "op": "lease_next_trigger",
                "lease_owner": lease_owner,
                "lease_seconds": int(lease_seconds),
            }
        )["lease"]
        return lease

    def complete_trigger_lease(
        self,
        event_id: int,
        lease_token: str,
        run_id: str | None = None,
        summary: str | None = None,
    ) -> dict[str, Any]:
        request: dict[str, Any] = {
            "op": "complete_trigger_lease",
            "event_id": int(event_id),
            "lease_token": lease_token,
        }
        if run_id is not None:
            request["run_id"] = run_id
        if summary is not None:
            request["summary"] = summary
        return self.call(request)

    def fail_trigger_lease(
        self, event_id: int, lease_token: str, error: str, retryable: bool
    ) -> dict[str, Any]:
        return self.call(
            {
                "op": "fail_trigger_lease",
                "event_id": int(event_id),
                "lease_token": lease_token,
                "error": error[:2048],
                "retryable": bool(retryable),
            }
        )
