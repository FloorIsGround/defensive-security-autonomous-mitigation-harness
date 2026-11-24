"""Shared test support: an in-process fake ``control-d`` investigation server.

Implements the exact wire framing and the semantics of the investigation ops
the worker relies on (lease/requeue/dead-letter, fencing tokens, run starts,
typed proposals with a configurable deterministic policy, evidence-checked
findings) so the worker's bounded loop is testable without the Rust binary.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))

from defsec_reasoner.wire import MAX_FRAME_BYTES, read_frame, send_frame  # noqa: E402

CAPABILITIES = [
    {
        "collector_type": "sockets.listening",
        "schema_version": 1,
        "is_stream": False,
        "sensitivity": "metadata_sensitive",
        "min_interval_seconds": 15,
        "description": "Listening socket and process metadata",
        "declared_privileges": [],
    },
    {
        "collector_type": "systemd.unit_state",
        "schema_version": 1,
        "is_stream": False,
        "sensitivity": "metadata_low",
        "min_interval_seconds": 15,
        "description": "Systemd unit status and configuration hashes",
        "declared_privileges": [],
    },
]

MAX_RETRIES = 5


class FakeControlServer:
    """Threaded AF_UNIX server speaking the Investigation RPC contract."""

    def __init__(
        self,
        socket_path: str,
        *,
        lease_seconds: int = 120,
        expire_leases: bool = False,
        complete_error: dict[str, str] | None = None,
        proposal_policy: Callable[[dict[str, Any]], tuple[bool, str, str]] | None = None,
        action_policy: Callable[[dict[str, Any]], tuple[bool, str, str]] | None = None,
        action_auth_modes: dict[str, str] | None = None,
        triggers: list[dict[str, Any]] | None = None,
    ) -> None:
        self.socket_path = str(socket_path)
        self.lease_seconds = lease_seconds
        self.expire_leases = expire_leases
        self.complete_error = complete_error
        self.proposal_policy = proposal_policy or (lambda spec: (True, "policy.accepted", "ok"))
        self.action_policy = action_policy or (lambda verb: (True, "policy.action_ok", "ok"))
        #: Per-verb authorization tier, mirroring Phase 8's policy engine.
        self.action_auth_modes = dict(
            action_auth_modes
            or {
                "nft_block_ip": "policy_bounded_autonomous",
                "systemd_stop_unit": "policy_bounded_autonomous",
                "host_isolate": "dual_signed_operator",
            }
        )
        self.triggers = triggers or [
            self._default_trigger(),
        ]
        self.observations = [
            {
                "observation_id": 11,
                "host_id": "edge-01",
                "watch_id": "w-sockets",
                "spec_version": 1,
                "observed_at": "2026-11-24T12:00:00.000000Z",
                "status": "ok",
                "state_hash": "aa" * 32,
                "payload": {"kind": "snapshot", "data": {"count": 1, "sockets": []}},
            },
            {
                "observation_id": 12,
                "host_id": "edge-01",
                "watch_id": "w-sockets",
                "spec_version": 1,
                "observed_at": "2026-11-24T12:01:00.000000Z",
                "status": "ok",
                "state_hash": "bb" * 32,
                "payload": {"kind": "snapshot", "data": {"count": 2, "sockets": []}},
            },
        ]
        self.findings: list[dict[str, Any]] = []
        self.proposals: list[dict[str, Any]] = []
        self.action_proposals: list[dict[str, Any]] = []
        self.runs: list[dict[str, Any]] = []
        self.requests: list[dict[str, Any]] = []
        self.completed_events: list[int] = []
        self.last_envelope: dict[str, Any] | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(self.socket_path)
        self._listener.listen(16)
        self._listener.settimeout(0.2)

    @staticmethod
    def _default_trigger() -> dict[str, Any]:
        return {
            "event_id": 1,
            "incident_id": "inc-1",
            "host_id": "edge-01",
            "watch_id": "w-sockets",
            "spec_version": 1,
            "status": "pending",
            "lease_token": None,
            "lease_expires_at": None,
            "retry_count": 0,
            "outcome": {"predicate": {"outcome": "triggered", "reason": "set diff", "details": {}}},
            "evidence_observation_ids": [11, 12],
        }

    # ------------------------------------------------------------- lifecycle

    def start(self) -> "FakeControlServer":
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        try:
            self._listener.close()
        except OSError:
            pass
        Path(self.socket_path).unlink(missing_ok=True)

    def __enter__(self) -> "FakeControlServer":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()

    def _serve_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            while True:
                try:
                    envelope = read_frame(conn, MAX_FRAME_BYTES, timeout=5.0)
                except Exception:
                    break
                if envelope is None:
                    break
                self.last_envelope = envelope
                request = envelope.get("request") or {}
                self.requests.append(request)
                reply = self.dispatch(request)
                try:
                    send_frame(conn, reply, MAX_FRAME_BYTES)
                except Exception:
                    break
        finally:
            conn.close()

    # -------------------------------------------------------------- dispatch

    @staticmethod
    def _error(code: str, message: str) -> dict[str, Any]:
        return {"result": "error", "code": code, "message": message}

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        op = request.get("op")
        handler = getattr(self, f"_op_{op}", None)
        if handler is None:
            return self._error("invalid_request", f"unknown op {op}")
        try:
            return handler(request)
        except KeyError as exc:
            return self._error("invalid_request", f"missing field {exc}")

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _op_list_hosts(self, _req: dict[str, Any]) -> dict[str, Any]:
        return {"result": "hosts", "hosts": [{"host_id": "edge-01", "agent_version": "fake", "liveness_status": "online", "active_bundle_version": 1}]}

    def _op_list_active_incidents(self, _req: dict[str, Any]) -> dict[str, Any]:
        return {
            "result": "incidents",
            "incidents": [{"incident_id": "inc-1", "host_id": "edge-01", "status": "open", "priority": "medium", "summary": "set diff", "created_at": "2026-11-24T12:00:00Z", "updated_at": "2026-11-24T12:00:00Z"}],
        }

    def _op_list_active_watches(self, _req: dict[str, Any]) -> dict[str, Any]:
        return {"result": "watches", "watches": []}

    def _op_list_collector_capabilities(self, _req: dict[str, Any]) -> dict[str, Any]:
        return {"result": "capabilities", "capabilities": CAPABILITIES}

    def _op_get_incident_context(self, req: dict[str, Any]) -> dict[str, Any]:
        if req["incident_id"] != "inc-1":
            return self._error("forbidden", "incident is outside capability scope")
        return {
            "result": "incident_context",
            "incident": {"incident_id": "inc-1", "host_id": "edge-01", "status": "open", "priority": "medium", "summary": "set diff", "created_at": "2026-11-24T12:00:00Z", "updated_at": "2026-11-24T12:00:00Z"},
            "active_watches": [],
            "recent_observations": self.observations,
            "findings": [{"finding_id": f["finding_id"], "finding": f} for f in self.findings],
        }

    def _op_query_observations(self, req: dict[str, Any]) -> dict[str, Any]:
        matched = [o for o in self.observations if o["host_id"] == req["host_id"]]
        if req.get("watch_id") is not None:
            matched = [o for o in matched if o["watch_id"] == req["watch_id"]]
        matched = matched[: int(req.get("limit") or 50)]
        return {"result": "observations", "observations": matched}

    def _op_get_host_baseline_summary(self, req: dict[str, Any]) -> dict[str, Any]:
        return {"result": "baseline_summary", "host_id": req["host_id"], "baselines": []}

    def _op_start_investigation_run(self, _req: dict[str, Any]) -> dict[str, Any]:
        run = {"run_id": str(uuid.uuid4()), "incident_id": "inc-1", "expires_at": "2026-11-24T13:00:00Z"}
        self.runs.append(run)
        return {"result": "run_started", **run}

    def _op_propose_ephemeral_watch(self, req: dict[str, Any]) -> dict[str, Any]:
        spec = req["spec"]
        allowed, rule_id, reason = self.proposal_policy(spec)
        self.proposals.append({"spec": spec, "allowed": allowed, "rule_id": rule_id})
        if not allowed:
            return {
                "result": "proposal_evaluated",
                "decision": {"allowed": False, "rule_id": rule_id, "reason": reason, "policy_version": 1},
                "watch_id": None,
                "bundle_version": None,
            }
        return {
            "result": "proposal_evaluated",
            "decision": {"allowed": True, "rule_id": rule_id, "reason": "ok", "policy_version": 1},
            "watch_id": spec.get("id"),
            "bundle_version": 2,
        }

    def _op_record_hypothesis_or_finding(self, req: dict[str, Any]) -> dict[str, Any]:
        known = {o["observation_id"] for o in self.observations}
        for evidence_id in req.get("evidence_observation_ids", []):
            if int(evidence_id) not in known:
                return self._error("invalid_request", "observation evidence is missing or outside incident scope")
        finding = {
            "finding_id": len(self.findings) + 1,
            "kind": req["kind"],
            "severity": req["severity"],
            "summary": req["summary"],
            "uncertainty": req["uncertainty"],
            "evidence_observation_ids": req.get("evidence_observation_ids", []),
            "escalation_requested": req.get("escalation_requested", False),
        }
        self.findings.append(finding)
        return {
            "result": "finding_recorded",
            "finding_id": finding["finding_id"],
            "verified_evidence_count": len(finding["evidence_observation_ids"]),
        }

    def _op_propose_action(self, req: dict[str, Any]) -> dict[str, Any]:
        verb = req.get("verb") or {}
        kind = verb.get("verb")
        if kind not in ("nft_block_ip", "systemd_stop_unit", "host_isolate"):
            return self._error("invalid_request", f"unknown action verb {kind!r}")
        known = {o["observation_id"] for o in self.observations}
        evidence = req.get("evidence_observation_ids") or []
        if not evidence:
            return self._error("invalid_request", "action must cite verified evidence")
        for evidence_id in evidence:
            if int(evidence_id) not in known:
                return self._error(
                    "invalid_request", "action evidence is missing or outside incident scope"
                )
        allowed, rule_id, reason = self.action_policy(verb)
        auth_mode = self.action_auth_modes.get(kind, "dual_signed_operator")
        proposal_id = len(self.action_proposals) + 1
        if not allowed:
            status = "rejected"
        elif auth_mode == "policy_bounded_autonomous":
            status = "authorized"
        else:
            status = "pending_approval"
        intent_id = f"intent-{proposal_id}" if status == "authorized" else None
        summary = {
            "proposal_id": proposal_id,
            "intent_id": intent_id,
            "host_id": "edge-01",
            "incident_id": req.get("incident_id", "inc-1"),
            "auth_mode": auth_mode,
            "status": status,
            "verb": verb,
            "expected_effect": req.get("expected_effect", ""),
            "blast_radius": req.get("blast_radius", ""),
            "rollback_plan": req.get("rollback_plan", ""),
            "created_at": "2026-11-24T12:00:00Z",
            "approver": None,
        }
        self.action_proposals.append(summary)
        authorized_intent = None
        if status == "authorized":
            authorized_intent = {
                "control_envelope": {
                    "domain": "defsecautmit.action_intent.v1",
                    "signing_key_id": "fake-control",
                    "raw_payload": json.dumps(
                        {"intent_id": intent_id, "proposal_id": proposal_id},
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    "signature_hex": "00" * 64,
                },
                "operator_approval": None,
            }
        return {
            "result": "action_proposal_evaluated",
            "decision": {
                "allowed": allowed,
                "rule_id": rule_id,
                "reason": reason,
                "policy_version": 1,
            },
            "proposal_id": proposal_id,
            "intent_id": intent_id,
            "auth_mode": auth_mode,
            "status": status,
            "authorized_intent": authorized_intent,
        }

    def _op_list_actions(self, req: dict[str, Any]) -> dict[str, Any]:
        actions = list(self.action_proposals)
        if req.get("host_id") is not None:
            actions = [a for a in actions if a["host_id"] == req["host_id"]]
        if req.get("incident_id") is not None:
            actions = [a for a in actions if a["incident_id"] == req["incident_id"]]
        return {"result": "actions", "actions": actions}

    def _op_lease_next_trigger(self, req: dict[str, Any]) -> dict[str, Any]:
        now = self._now()
        # Reclaim expired leases first (mirrors control-d).
        for trigger in self.triggers:
            if trigger["status"] == "leased" and trigger["lease_expires_at"] <= now:
                next_retry = trigger["retry_count"] + 1
                trigger["retry_count"] = next_retry
                trigger["status"] = "dead_letter" if next_retry >= MAX_RETRIES else "pending"
                trigger["lease_token"] = None
                trigger["lease_expires_at"] = None
        for trigger in self.triggers:
            if trigger["status"] != "pending":
                continue
            trigger["status"] = "leased"
            trigger["lease_token"] = uuid.uuid4().hex
            delta = timedelta(seconds=-1) if self.expire_leases else timedelta(seconds=int(req["lease_seconds"]))
            trigger["lease_expires_at"] = now + delta
            return {
                "result": "trigger_leased",
                "lease": {
                    "event_id": trigger["event_id"],
                    "incident_id": trigger["incident_id"],
                    "host_id": trigger["host_id"],
                    "watch_id": trigger["watch_id"],
                    "spec_version": trigger["spec_version"],
                    "lease_token": trigger["lease_token"],
                    "lease_expires_at": trigger["lease_expires_at"].isoformat().replace("+00:00", "Z"),
                    "retry_count": trigger["retry_count"],
                    "outcome": trigger["outcome"],
                    "evidence_observation_ids": trigger["evidence_observation_ids"],
                },
            }
        return {"result": "trigger_leased", "lease": None}

    def _leased(self, req: dict[str, Any]) -> dict[str, Any] | None:
        for trigger in self.triggers:
            if trigger["event_id"] == int(req["event_id"]) and trigger["status"] == "leased" and trigger["lease_token"] == req["lease_token"]:
                return trigger
        return None

    def _op_complete_trigger_lease(self, req: dict[str, Any]) -> dict[str, Any]:
        trigger = self._leased(req)
        if trigger is None:
            return self._error("forbidden", "lease expired, already completed, or fencing token mismatch")
        if trigger["lease_expires_at"] <= self._now():
            return self._error("forbidden", "lease expired, already completed, or fencing token mismatch")
        if self.complete_error is not None:
            return self._error(self.complete_error["code"], self.complete_error["message"])
        trigger["status"] = "done"
        self.completed_events.append(trigger["event_id"])
        return {"result": "lease_updated", "event_id": trigger["event_id"], "status": "done"}

    def _op_fail_trigger_lease(self, req: dict[str, Any]) -> dict[str, Any]:
        trigger = self._leased(req)
        if trigger is None:
            return self._error("forbidden", "lease not found or fencing token mismatch")
        next_retry = trigger["retry_count"] + 1
        trigger["retry_count"] = next_retry
        status = "pending" if req.get("retryable") and next_retry < MAX_RETRIES else "dead_letter"
        trigger["status"] = status
        trigger["lease_token"] = None
        trigger["lease_expires_at"] = None
        return {"result": "lease_updated", "event_id": trigger["event_id"], "status": status}
