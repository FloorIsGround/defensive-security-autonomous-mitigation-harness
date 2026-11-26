"""Test/benchmark harness driving a REAL ``control-d`` daemon subprocess.

Owns three pieces:

* :class:`ControlDaemon` — spawns ``target/debug/control-d`` (or release) with
  short-lived temp sockets (paths kept far below the 108-byte ``sun_path``
  limit), waits for readiness, and shuts it down cleanly.
* :class:`SyntheticAgent` — a deterministic in-process edge agent speaking the
  exact ``AgentToControl``/``ControlToAgent`` wire protocol so scripted ground
  truth (snapshots, journal batches, bundle syncs) can be fed to the real
  control plane.
* Spec/payload builders producing byte-exact ``WatchSpec`` and observation
  JSON, including the RFC 8785 ``state_hash`` values control-d verifies.

Operator-side setup (enrollment, baseline watches, token minting) uses
:class:`defsec_reasoner.admin_client.AdminClient`.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from defsec_reasoner.canonical import canonical_sha256_hex
from defsec_reasoner.wire import FrameError, read_frame, send_frame

__all__ = [
    "ControlDaemon",
    "SyntheticAgent",
    "find_control_binary",
    "rfc3339_now",
    "parse_rfc3339",
    "sockets_snapshot",
    "socket_entry",
    "systemd_snapshot",
    "unit_file_hash",
    "journal_event",
    "journal_batch",
    "sockets_watch_spec",
    "systemd_unit_watch_spec",
    "journal_watch_spec",
    "files_watch_spec",
    "COLLECTORS",
]

logger = logging.getLogger("defsec.reasoner.harness")

REPO_ROOT = Path(__file__).resolve().parents[2]
WIRE_PROTOCOL_VERSION = 1
_MAX_SOCKET_PATH_BYTES = 90

#: The closed collector catalog.
COLLECTORS = [
    "sockets.listening",
    "systemd.unit_state",
    "files.metadata",
    "journal.unit_events",
]


def find_control_binary(explicit: str | os.PathLike[str] | None = None) -> Path | None:
    """Locate a compiled ``control-d`` binary (debug, then release)."""
    if explicit:
        path = Path(explicit)
        return path if path.is_file() else None
    env = os.environ.get("DEFSEC_CONTROL_BIN")
    if env:
        path = Path(env)
        return path if path.is_file() else None
    for candidate in (REPO_ROOT / "target/debug/control-d", REPO_ROOT / "target/release/control-d"):
        if candidate.is_file():
            return candidate
    return None


def rfc3339_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_rfc3339(value: str) -> datetime:
    """Parse an RFC3339 timestamp (chrono emits up to 9 fractional digits)."""
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    # Trim any fraction beyond microseconds.
    if "." in text:
        head, _, rest = text.partition(".")
        digits, sign, tail = rest.partition("+") if "+" in rest else rest.partition("-")
        if digits.isdigit():
            text = f"{head}.{digits[:6].ljust(6, '0')}{sign}{tail}"
    return datetime.fromisoformat(text)


def _socket_path_fits(directory: Path) -> bool:
    return len(os.fsencode(directory.resolve() / "i.sock")) <= _MAX_SOCKET_PATH_BYTES


def make_socket_temp_dir(prefix: str) -> Path:
    """Create a private temporary directory with room for a short socket name."""
    directory = Path(tempfile.mkdtemp(prefix=prefix))
    if _socket_path_fits(directory):
        return directory
    directory.rmdir()
    short_in_tmp = Path(tempfile.mkdtemp(prefix="d"))
    if _socket_path_fits(short_in_tmp):
        return short_in_tmp
    short_in_tmp.rmdir()
    return Path(tempfile.mkdtemp(prefix="ds-", dir="/tmp"))


class ControlDaemon:
    """A real ``control-d`` subprocess with isolated temp state and sockets."""

    def __init__(
        self,
        binary: str | os.PathLike[str],
        *,
        base_dir: str | os.PathLike[str] | None = None,
        key_id: str = "control-key-01",
        policy_version: int = 1,
        keep_data: bool = False,
        startup_timeout: float = 15.0,
    ) -> None:
        self.binary = str(binary)
        self.keep_data = keep_data
        self.startup_timeout = startup_timeout
        self.key_id = key_id
        self.policy_version = policy_version
        root = Path(base_dir) if base_dir else make_socket_temp_dir("dsam-")
        self.base_dir = root
        self.data_dir = root / "data"
        socket_dir = root if _socket_path_fits(root) else make_socket_temp_dir("d")
        self._separate_socket_dir = socket_dir if socket_dir != root else None
        self._recreate_socket_dir = False
        self.agent_sock = socket_dir / "a.sock"
        self.admin_sock = socket_dir / "m.sock"
        self.investigate_sock = socket_dir / "i.sock"
        self.log_path = root / "control-d.log"
        self._proc: subprocess.Popen[bytes] | None = None

    def start(self) -> "ControlDaemon":
        sockets = [self.agent_sock, self.admin_sock, self.investigate_sock]
        if self._separate_socket_dir is not None and self._recreate_socket_dir:
            self._separate_socket_dir.mkdir(mode=0o700)
            self._recreate_socket_dir = False
        with self.log_path.open("wb") as log:
            self._proc = subprocess.Popen(
                [
                    self.binary,
                    "--data-dir", str(self.data_dir),
                    "--agent-sock", str(self.agent_sock),
                    "--admin-sock", str(self.admin_sock),
                    "--investigate-sock", str(self.investigate_sock),
                    "--key-id", self.key_id,
                    "--policy-version", str(self.policy_version),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(
                    f"control-d exited during startup (code {self._proc.returncode}); "
                    f"log: {self.log_path.read_text(errors='replace')[:2000]}"
                )
            if all(p.exists() for p in sockets):
                return self
            time.sleep(0.05)
        raise TimeoutError(f"control-d sockets did not appear within {self.startup_timeout}s")

    def stop(self, timeout: float = 5.0) -> None:
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:  # pragma: no cover
                proc.kill()
                proc.wait(timeout=timeout)
        self._proc = None
        if self._separate_socket_dir is not None and not self._recreate_socket_dir:
            shutil.rmtree(self._separate_socket_dir, ignore_errors=True)
            self._recreate_socket_dir = True
        if not self.keep_data:
            shutil.rmtree(self.base_dir, ignore_errors=True)

    def __enter__(self) -> "ControlDaemon":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


class SyntheticAgent:
    """Deterministic edge agent speaking the real agent wire protocol."""

    def __init__(
        self,
        socket_path: str | os.PathLike[str],
        host_id: str,
        *,
        agent_version: str = "synthetic-agent-1.0",
        session_id: str | None = None,
        boot_id: str | None = None,
        drain_timeout: float = 0.75,
    ) -> None:
        self.socket_path = str(socket_path)
        self.host_id = host_id
        self.agent_version = agent_version
        self.session_id = session_id or f"sess-{uuid.uuid4().hex[:12]}"
        self.boot_id = boot_id or f"boot-{uuid.uuid4().hex[:12]}"
        self.drain_timeout = drain_timeout
        self.seq_no = 0
        self.bundle_version = 0
        self.bundle_digest: str | None = None
        self.bundles: list[dict[str, Any]] = []
        self.reconciliations: list[str] = []
        self.observation_ids: list[int] = []
        self._sock: socket.socket | None = None

    # ------------------------------------------------------------- connection

    def connect(self) -> None:
        assert self._sock is None, "agent already connected"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect(self.socket_path)
        self._sock = sock
        self._send(
            {
                "msg": "register",
                "protocol_version": WIRE_PROTOCOL_VERSION,
                "host_id": self.host_id,
                "agent_version": self.agent_version,
                "boot_id": self.boot_id,
                "session_id": self.session_id,
                "active_bundle_version": self.bundle_version,
                "active_bundle_digest": self.bundle_digest,
                "sent_at": rfc3339_now(),
            }
        )
        acked = False
        for frame in self._read_until_timeout(5.0):
            if frame.get("msg") == "register_ack":
                if not frame.get("accepted"):
                    raise RuntimeError(f"control-d rejected agent registration: {frame.get('reason')}")
                acked = True
            else:
                self._handle_server_frame(frame)
        if not acked:
            raise RuntimeError("no register_ack from control-d")

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "SyntheticAgent":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ wire

    def _send(self, message: dict[str, Any]) -> None:
        assert self._sock is not None, "agent not connected"
        send_frame(self._sock, message)

    def _read_one(self, timeout: float) -> dict[str, Any] | None:
        assert self._sock is not None
        try:
            return read_frame(self._sock, timeout=timeout)
        except (FrameError, socket.timeout, TimeoutError, OSError):
            return None

    def _read_until_timeout(self, timeout: float) -> list[dict[str, Any]]:
        frames: list[dict[str, Any]] = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = max(deadline - time.monotonic(), 0.01)
            frame = self._read_one(remaining)
            if frame is None:
                return frames
            frames.append(frame)

    def _handle_server_frame(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        msg = frame.get("msg")
        if msg == "sync_watch_bundle":
            envelope = frame["envelope"]
            payload = json.loads(envelope["raw_payload"])
            digest = canonical_sha256_hex(envelope["raw_payload"])
            self.bundle_version = payload["bundle_version"]
            self.bundle_digest = digest
            self.bundles.append(payload)
            self.ack_bundle(payload, envelope)
            return payload
        if msg == "request_reconciliation":
            self.reconciliations.append(str(frame.get("reason")))
        return None

    def ack_bundle(self, payload: dict[str, Any], envelope: dict[str, Any]) -> None:
        self._send(
            {
                "msg": "bundle_ack",
                "host_id": self.host_id,
                "bundle_id": payload["bundle_id"],
                "bundle_version": payload["bundle_version"],
                "payload_digest": canonical_sha256_hex(envelope["raw_payload"]),
                "status": "accepted",
                "reason": None,
                "acked_at": rfc3339_now(),
            }
        )

    def drain(self, timeout: float | None = None) -> list[dict[str, Any]]:
        """Read everything the server has queued (acks, bundles, reconciles)."""
        frames = self._read_until_timeout(timeout if timeout is not None else self.drain_timeout)
        for frame in frames:
            self._handle_server_frame(frame)
        return frames

    # ------------------------------------------------------------ observation

    def push_snapshot(
        self,
        watch_id: str,
        spec_version: int,
        data: dict[str, Any],
        *,
        status: str = "ok",
        collector: str = "sockets.listening",
    ) -> dict[str, Any] | None:
        payload = {"kind": "snapshot", "data": data}
        return self._push(watch_id, spec_version, collector, payload, status)

    def push_stream_batch(
        self,
        watch_id: str,
        spec_version: int,
        events: list[dict[str, Any]],
        *,
        cursor_before: str | None = None,
        cursor_after: str | None = None,
        gap_detected: bool = False,
    ) -> dict[str, Any] | None:
        payload = {
            "kind": "stream_batch",
            "events": events,
            "cursor_before": cursor_before,
            "cursor_after": cursor_after,
            "gap_detected": gap_detected,
        }
        return self._push(watch_id, spec_version, "journal.unit_events", payload, "ok")

    def _push(
        self,
        watch_id: str,
        spec_version: int,
        collector: str,
        payload: dict[str, Any],
        status: str,
    ) -> dict[str, Any] | None:
        self.seq_no += 1
        if payload.get("kind") == "snapshot":
            state_hash = canonical_sha256_hex(payload["data"])
        elif payload.get("kind") == "stream_batch":
            state_hash = canonical_sha256_hex(payload["events"])
        else:
            state_hash = canonical_sha256_hex(payload)
        record = {
            "host_id": self.host_id,
            "session_id": self.session_id,
            "seq_no": self.seq_no,
            "watch_id": watch_id,
            "spec_version": spec_version,
            "collector_type": collector,
            "observed_at": rfc3339_now(),
            "status": status,
            "state_hash": state_hash,
            "payload": payload,
        }
        self._send({"msg": "push_observation_delta", "observation": record})
        # Consume the observation ack (plus anything piggybacked).
        ack: dict[str, Any] | None = None
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            frame = self._read_one(max(deadline - time.monotonic(), 0.05))
            if frame is None:
                break
            if frame.get("msg") == "observation_ack":
                ack = frame
                # Brief extra drain for piggybacked bundles, then stop.
                for extra in self._read_until_timeout(0.15):
                    self._handle_server_frame(extra)
                break
            self._handle_server_frame(frame)
        if ack is not None and ack.get("acked_seq_no", 0) >= record["seq_no"]:
            self.observation_ids.append(int(ack["acked_seq_no"]))
        return ack

    # ------------------------------------------------------------------ utils

    def watches(self) -> list[dict[str, Any]]:
        """Watches from the latest synced bundle."""
        return list(self.bundles[-1]["watches"]) if self.bundles else []

    def find_watch(self, watch_id: str) -> dict[str, Any] | None:
        for watch in self.watches():
            if watch.get("id") == watch_id:
                return watch
        return None


# ------------------------------------------------------------------ builders


def socket_entry(
    key: str,
    *,
    protocol: str = "tcp",
    local_addr: str = "0.0.0.0",
    port: int = 22,
    uid: int = 0,
    inode: int = 12345,
    pid: int | None = None,
    comm: str | None = None,
    systemd_unit: str | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "socket_key": key,
        "protocol": protocol,
        "local_addr": local_addr,
        "local_port": port,
        "uid": uid,
        "inode": inode,
    }
    if pid is not None:
        entry["pid"] = pid
        entry["pid_start_time_ticks"] = 999
    if comm is not None:
        entry["comm"] = comm
    if systemd_unit is not None:
        entry["systemd_unit"] = systemd_unit
    return entry


def sockets_snapshot(entries: list[dict[str, Any]], *, partial: bool = False) -> dict[str, Any]:
    return {"count": len(entries), "partial_attribution": partial, "sockets": entries}


def unit_file_hash(path: str, sha256: str, *, size: int = 512, status: str = "ok") -> dict[str, Any]:
    return {"path": path, "status": status, "sha256": sha256, "size_bytes": size}


def systemd_snapshot(
    unit: str,
    *,
    load_state: str = "loaded",
    active_state: str = "active",
    sub_state: str = "running",
    unit_files: list[dict[str, Any]] | None = None,
    exec_start_hash: str | None = None,
) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "unit": unit,
        "load_state": load_state,
        "active_state": active_state,
        "sub_state": sub_state,
        "unit_files": unit_files or [],
    }
    if exec_start_hash is not None:
        snapshot["exec_start_hash"] = exec_start_hash
    return snapshot


def journal_event(
    cursor: str,
    unit: str,
    message: str,
    *,
    priority: int = 6,
    timestamp_us: int | None = None,
    pid: int | None = None,
    uid: int | None = None,
    truncated: bool = False,
) -> dict[str, Any]:
    # NOTE: `pid`/`uid` must always be present (null when absent): control-d
    # canonicalizes the TYPED JournalEventRecord, where Option fields
    # serialize as JSON null, into the observation state hash.
    return {
        "cursor": cursor,
        "timestamp_us": timestamp_us or int(time.time() * 1_000_000),
        "unit": unit,
        "priority": priority,
        "pid": pid,
        "uid": uid,
        "message_redacted": message,
        "truncated": truncated,
        "redaction_applied": True,
        "classification": "bounded_redacted_text",
    }


def journal_batch(events: list[dict[str, Any]], cursor_after: str) -> dict[str, Any]:
    return {
        "kind": "stream_batch",
        "events": events,
        "cursor_before": None,
        "cursor_after": cursor_after,
        "gap_detected": False,
    }


def _spec(
    *,
    watch_id: str,
    host_id: str,
    klass: str,
    collector: dict[str, Any],
    trigger: dict[str, Any],
    incident_id: str | None,
    interval_seconds: int,
    timeout_seconds: int,
    expires_at: str | None,
    max_runs: int | None,
    cooldown_seconds: int = 60,
    max_wakeups_per_hour: int = 30,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "id": watch_id,
        "version": 1,
        "host_id": host_id,
        "class": klass,
        "collector": collector,
        "schedule": {"interval_seconds": interval_seconds, "timeout_seconds": timeout_seconds},
        "trigger": trigger,
        "wake_policy": {
            "cooldown_seconds": cooldown_seconds,
            "max_wakeups_per_hour": max_wakeups_per_hour,
        },
        "lifecycle": {"enabled": True},
    }
    if incident_id is not None:
        spec["incident_id"] = incident_id
    if expires_at is not None:
        spec["lifecycle"]["expires_at"] = expires_at
    if max_runs is not None:
        spec["lifecycle"]["max_runs"] = max_runs
    return spec


def sockets_watch_spec(
    host_id: str,
    watch_id: str = "w-sockets",
    *,
    klass: str = "baseline",
    incident_id: str | None = None,
    interval_seconds: int = 30,
    expires_at: str | None = None,
    max_runs: int | None = None,
) -> dict[str, Any]:
    return _spec(
        watch_id=watch_id,
        host_id=host_id,
        klass=klass,
        incident_id=incident_id,
        collector={
            "type": "sockets.listening",
            "parameters": {
                "include_tcp": True,
                "include_udp": True,
                "include_ipv6": True,
                "resolve_process": True,
            },
        },
        trigger={
            "type": "set_diff",
            "compare_against": "last_observed",
            "set_field": "sockets",
            "identity_key": "socket_key",
        },
        interval_seconds=interval_seconds,
        timeout_seconds=5,
        expires_at=expires_at,
        max_runs=max_runs,
        cooldown_seconds=0,
    )


def systemd_unit_watch_spec(
    host_id: str,
    unit: str,
    watch_id: str,
    *,
    klass: str = "ephemeral",
    incident_id: str | None = None,
    interval_seconds: int = 30,
    expires_at: str | None = None,
    max_runs: int | None = None,
) -> dict[str, Any]:
    return _spec(
        watch_id=watch_id,
        host_id=host_id,
        klass=klass,
        incident_id=incident_id,
        collector={
            "type": "systemd.unit_state",
            "parameters": {"unit": unit, "hash_unit_files": True},
        },
        trigger={
            "type": "field_changed",
            "compare_against": "last_observed",
            "fields": ["active_state"],
        },
        interval_seconds=interval_seconds,
        timeout_seconds=5,
        expires_at=expires_at,
        max_runs=max_runs,
    )


def journal_watch_spec(
    host_id: str,
    unit: str,
    watch_id: str = "w-journal",
    *,
    interval_seconds: int = 30,
) -> dict[str, Any]:
    return _spec(
        watch_id=watch_id,
        host_id=host_id,
        klass="baseline",
        incident_id=None,
        collector={"type": "journal.unit_events", "parameters": {"unit": unit}},
        trigger={
            "type": "field_changed",
            "compare_against": "last_observed",
            "fields": ["cursor_after"],
        },
        interval_seconds=interval_seconds,
        timeout_seconds=5,
        expires_at=None,
        max_runs=None,
        cooldown_seconds=0,
    )


def files_watch_spec(
    host_id: str,
    paths: list[str],
    watch_id: str,
    *,
    klass: str = "ephemeral",
    incident_id: str | None = None,
    interval_seconds: int = 30,
    expires_at: str | None = None,
    max_runs: int | None = None,
) -> dict[str, Any]:
    return _spec(
        watch_id=watch_id,
        host_id=host_id,
        klass=klass,
        incident_id=incident_id,
        collector={
            "type": "files.metadata",
            "parameters": {"paths": list(paths), "compute_hash": True},
        },
        trigger={
            "type": "field_changed",
            "compare_against": "last_observed",
            "fields": ["files"],
        },
        interval_seconds=interval_seconds,
        timeout_seconds=5,
        expires_at=expires_at,
        max_runs=max_runs,
    )
