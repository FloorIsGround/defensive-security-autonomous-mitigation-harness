"""Client for ``control-d``'s strictly separate Admin RPC (``admin.sock``).

The reasoning plane never uses this interface at runtime; the benchmark
harness and integration tests use it as the *operator* side-channel to
enroll hosts, apply baseline watches, mint short-lived scoped capability
tokens, and verify the append-only audit chain. Wire contract mirrors
``AdminRequest``/``AdminResponse`` in ``crates/protocol/src/rpc.rs``
(internally tagged on ``"admin_op"`` / ``"admin_result"``).
"""

from __future__ import annotations

import json
import socket
import uuid
from pathlib import Path
from typing import Any

from defsec_reasoner.wire import MAX_FRAME_BYTES, FrameError, FrameTooLargeError, read_frame, send_frame

__all__ = ["AdminClient", "AdminRpcError"]


class AdminRpcError(Exception):
    """A structured ``{"admin_result": "error"}`` reply from ``control-d``."""


class AdminClient:
    """Minimal operator client for the administrative socket."""

    def __init__(self, socket_path: str | Path, request_timeout: float = 10.0) -> None:
        self.socket_path = str(socket_path)
        self.request_timeout = request_timeout

    def call(self, request: dict[str, Any]) -> dict[str, Any]:
        if "admin_op" not in request:
            raise ValueError("AdminRequest must carry an 'admin_op' tag")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.request_timeout)
        try:
            try:
                sock.connect(self.socket_path)
            except OSError as exc:
                raise AdminRpcError("transport", f"cannot connect to admin socket: {exc}") from exc
            try:
                send_frame(sock, request, MAX_FRAME_BYTES)
                reply = read_frame(sock, MAX_FRAME_BYTES, timeout=self.request_timeout)
            except FrameTooLargeError as exc:
                raise AdminRpcError("transport", f"admin frame bound violated: {exc}") from exc
            except FrameError as exc:
                raise AdminRpcError("transport", str(exc)) from exc
        finally:
            sock.close()
        if not isinstance(reply, dict) or "admin_result" not in reply:
            raise AdminRpcError("transport", f"malformed admin response: {json.dumps(reply)[:200]}")
        result = reply.pop("admin_result")
        if result == "error":
            raise AdminRpcError(str(reply.get("code", "unknown")), str(reply.get("message", "")))
        reply["admin_result"] = result
        return reply

    # --------------------------------------------------------------- lifecycle

    def enroll_host(self, host_id: str, agent_public_key_hex: str | None = None) -> dict[str, Any]:
        return self.call(
            {
                "admin_op": "enroll_host",
                "host_id": host_id,
                "agent_public_key_hex": agent_public_key_hex,
            }
        )

    def apply_baseline_watch(
        self, spec: dict[str, Any], actor: str, rationale: str
    ) -> dict[str, Any]:
        return self.call(
            {"admin_op": "apply_baseline_watch", "spec": spec, "actor": actor, "rationale": rationale}
        )

    def promote_baseline(
        self,
        host_id: str,
        watch_id: str,
        observation_id: int,
        approver: str,
        rationale: str,
        ticket_ref: str | None = None,
    ) -> dict[str, Any]:
        request: dict[str, Any] = {
            "admin_op": "promote_baseline",
            "host_id": host_id,
            "watch_id": watch_id,
            "observation_id": int(observation_id),
            "approver": approver,
            "rationale": rationale,
        }
        if ticket_ref is not None:
            request["ticket_ref"] = ticket_ref
        return self.call(request)

    def mint_capability_token(
        self,
        principal_id: str,
        role: str,
        allowed_hosts: list[str],
        allowed_collectors: list[str],
        incident_id: str | None = None,
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        if role not in ("observer", "investigator"):
            raise ValueError("role must be 'observer' or 'investigator'")
        return self.call(
            {
                "admin_op": "mint_capability_token",
                "principal_id": principal_id,
                "role": role,
                "allowed_hosts": list(allowed_hosts),
                "allowed_collectors": list(allowed_collectors),
                "incident_id": incident_id,
                "ttl_seconds": int(ttl_seconds),
            }
        )

    def close_incident(self, incident_id: str, actor: str, resolution: str) -> dict[str, Any]:
        return self.call(
            {
                "admin_op": "close_incident",
                "incident_id": incident_id,
                "actor": actor,
                "resolution": resolution,
            }
        )

    # ------------------------------------------------------------------- reads

    def list_hosts(self) -> list[dict[str, Any]]:
        return self.call({"admin_op": "list_hosts"})["hosts"]

    def list_incidents(self) -> list[dict[str, Any]]:
        return self.call({"admin_op": "list_incidents"})["incidents"]

    def verify_audit_chain(self) -> dict[str, Any]:
        reply = self.call({"admin_op": "verify_audit_chain"})
        reply.pop("admin_result", None)
        return reply

    def list_audit_entries(self, limit: int | None = None) -> list[dict[str, Any]]:
        request: dict[str, Any] = {"admin_op": "list_audit_entries"}
        if limit is not None:
            request["limit"] = int(limit)
        return self.call(request)["entries"]

    def list_policy_decisions(self, limit: int | None = None) -> list[dict[str, Any]]:
        request: dict[str, Any] = {"admin_op": "list_policy_decisions"}
        if limit is not None:
            request["limit"] = int(limit)
        return self.call(request)["decisions"]
