"""Codex-worker tests: hygiene contract, failure classes, delegated runs.

Runs against the in-process fake control server plus the **real** compiled
``mcp-adapter`` binary, with a fake ``codex`` executable (``fixtures/
fake_codex.py``) standing in for the Codex CLI. The fake makes real MCP calls
into the adapter, so the delegated-run path is exercised end-to-end above a
faked control plane. A separate live-test class repeats the key paths against
the compiled ``control-d``.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
import time
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))
TESTS_ROOT = Path(__file__).resolve().parent
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

import unittest  # noqa: E402

from defsec_reasoner.codex_worker import (  # noqa: E402
    CodexBudgets,
    CodexWorker,
    CodexWorkerStartupError,
    build_codex_prompt,
    find_mcp_adapter_binary,
)
from defsec_reasoner.control_harness import (  # noqa: E402
    COLLECTORS,
    ControlDaemon,
    SyntheticAgent,
    find_control_binary,
    socket_entry,
    sockets_snapshot,
    sockets_watch_spec,
)
from defsec_reasoner.admin_client import AdminClient  # noqa: E402
from defsec_reasoner.rpc_client import ControlRpcClient, RpcError  # noqa: E402

from support import DropConnection, FakeControlServer, temporary_socket_path  # noqa: E402

FAKE_CODEX = TESTS_ROOT / "fixtures" / "fake_codex.py"
ADAPTER_BIN = find_mcp_adapter_binary()
CONTROL_BIN = find_control_binary()
PARENT_TOKEN = "codex-worker-parent-token"


def _pid_alive(pid: int) -> bool:
    """A live (running) process check: zombies count as gone."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - process exists, keep waiting
        return True
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
            fields = handle.read().rsplit(")", 1)
        state = fields[1].split()[0] if len(fields) == 2 else ""
    except (OSError, IndexError):
        return True  # cannot inspect: keep polling
    return state != "Z"


def _wait_pid_gone(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.05)
    return not _pid_alive(pid)


def _trigger(event_id: int) -> dict:
    return {
        "event_id": event_id,
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


class PrimaryEntryPointTests(unittest.TestCase):
    def test_worker_routes_to_adapter_and_codex_has_explicit_commands(self):
        from defsec_reasoner import cli
        with mock.patch.object(cli, "_cmd_codex_worker", return_value=0) as codex, \
                mock.patch.object(cli, "_cmd_worker", return_value=0) as adapter:
            for command in ("investigator", "codex-worker"):
                self.assertEqual(cli.main([command, "--socket", "test.sock"]), 0)
            self.assertEqual(cli.main(["worker", "--socket", "/unused", "--max-turns", "1", "--once"]), 0)
            options = adapter.call_args.args[0]
            self.assertEqual(options.backend, "mock")
            self.assertEqual(options.max_turns, 1)
            self.assertTrue(options.once)
            for mode in ("--discovery-only", "--followups-only"):
                self.assertEqual(cli.main(["worker", "--backend", "chatgpt", mode, "--socket", "test.sock"]), 0)
            self.assertEqual(codex.call_count, 2)
            self.assertEqual(adapter.call_count, 3)
            with redirect_stderr(io.StringIO()) as error, self.assertRaises(SystemExit) as exc:
                cli.main(["worker", "--socket", "test.sock", "--backend=codex"])
            self.assertEqual(exc.exception.code, 2)
            self.assertIn("use the codex-worker command", error.getvalue())

    def test_codex_session_persistence_is_opt_in(self):
        from defsec_reasoner import cli
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            socket = root / "i.sock"
            socket.touch()
            command = ["codex-worker", "--socket", str(socket), "--token", PARENT_TOKEN,
                       "--mcp-adapter-bin", "unused"]
            with mock.patch("defsec_reasoner.codex_worker.CodexWorker") as worker, \
                    mock.patch.dict(os.environ, XDG_STATE_HOME=tmp), \
                    mock.patch("signal.signal"):
                cases = (
                    ([], None),
                    (["--ephemeral"], None),
                    (["--persist-sessions"], root / "defsec-reasoner/codex-sessions"),
                    (["--session-dir", str(root)], root),
                )
                for flags, expected in cases:
                    with self.subTest(flags=flags):
                        self.assertEqual(cli.main(command + flags), 0)
                        self.assertEqual(worker.call_args.kwargs["session_dir"], expected)


class CodexWorkerTestBase(unittest.TestCase):
    """Fake control plane + real mcp-adapter + fake codex."""

    def setUp(self) -> None:
        self.sock_path = temporary_socket_path(self, "cw-t-")
        self.server = FakeControlServer(
            self.sock_path, triggers=[_trigger(1), _trigger(2)]
        ).start()
        self.server.register_token(PARENT_TOKEN, principal_id="codex-parent", may_spawn_runs=True)
        # A canary the fake codex must never see in its scrubbed environment.
        self._saved_env = {
            key: os.environ.get(key)
            for key in ("DEFSEC_CAPABILITY_TOKEN", "DEFSEC_TEST_CANARY", "CODEX_HOME")
        }
        os.environ["DEFSEC_CAPABILITY_TOKEN"] = PARENT_TOKEN
        os.environ["DEFSEC_TEST_CANARY"] = "leaky-secret"

    def tearDown(self) -> None:
        self.server.stop()
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def make_worker(
        self,
        behavior: str = "happy",
        budgets: CodexBudgets | None = None,
        codex_bin: str | None = None,
    ) -> CodexWorker:
        return CodexWorker(
            lambda: ControlRpcClient(self.sock_path, PARENT_TOKEN),
            socket_path=self.sock_path,
            codex_bin=str(codex_bin or FAKE_CODEX),
            mcp_adapter_bin=str(ADAPTER_BIN),
            model=behavior,
            budgets=budgets or CodexBudgets(max_wall_seconds=20.0),
        )

    def run_once(self, **kwargs: object) -> object:
        worker = self.make_worker(**kwargs)  # type: ignore[arg-type]
        return worker.run_once()

    def trigger(self, event_id: int) -> dict:
        for trigger in self.server.triggers:
            if trigger["event_id"] == event_id:
                return trigger
        raise AssertionError(f"no trigger {event_id}")

    def parse_fake_report(self, summary: str) -> dict:
        marker = "fake-codex-report: "
        start = summary.find(marker)
        self.assertGreaterEqual(start, 0, f"no fake report in summary: {summary!r}")
        report = json.JSONDecoder().raw_decode(summary[start + len(marker) :])[0]
        self.assertIsInstance(report, dict)
        return report


@unittest.skipIf(ADAPTER_BIN is None, "compiled mcp-adapter binary not found (cargo build -p mcp-adapter)")
class CodexWorkerFakeServerTests(CodexWorkerTestBase):
    # ------------------------------------------------------------- happy path

    def test_restart_resumes_same_incident_with_new_run_and_token_path(self):
        with tempfile.TemporaryDirectory() as folder:
            def wake():
                worker = self.make_worker()
                worker.session_dir = Path(folder)
                outcome = worker.run_once()
                self.assertEqual(outcome.status, "completed", outcome.error)
                return outcome
            first, second = wake(), wake()
            self.assertEqual(first.thread_id, second.thread_id)
            self.assertEqual(second.codex_argv[-3:], ["resume", first.thread_id, "-"])
            self.assertNotEqual(first.run_id, second.run_id)
            self.assertNotEqual(self.parse_fake_report(first.summary)["token_file"],
                                self.parse_fake_report(second.summary)["token_file"])

    def test_concurrent_wake_and_changed_authority_do_not_reuse_history(self):
        worker = self.make_worker()
        client = worker._new_client()
        with tempfile.TemporaryDirectory() as folder:
            worker.session_dir = Path(folder)
            lease = _trigger(1)
            with worker._session(client, lease, Path(folder)) as (_, pointer, _):
                pointer.write_text("e59853ad-5227-4485-9de0-9bcd43b70eed")
                with worker._session(client, lease, Path(folder)) as (_, busy, thread):
                    self.assertIsNone(busy)
                    self.assertIsNone(thread)
            for host, incident in [("other", "inc-1"), ("edge-01", "another")]:
                with worker._session(client, dict(lease, host_id=host, incident_id=incident), Path(folder)) as (_, new, thread):
                    self.assertNotEqual(pointer, new)
                    self.assertIsNone(thread)
            self.server.register_token("rotated", principal_id="codex-parent", may_spawn_runs=True)
            with worker._session(ControlRpcClient(self.sock_path, "rotated"), lease, Path(folder)) as (_, new, thread):
                self.assertNotEqual(pointer, new)
                self.assertIsNone(thread)

    def test_happy_path_finds_proposes_and_records_events(self) -> None:
        outcome = self.run_once()
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.status, "completed", f"outcome: {outcome}")
        self.assertEqual(outcome.turns, 1)
        self.assertEqual(outcome.tool_calls, 3)
        self.assertEqual(outcome.findings, 1)
        self.assertEqual(outcome.proposals, 1)
        self.assertEqual(outcome.proposals_accepted, 1)
        self.assertGreater(outcome.events_seen, 10)

        # The trigger lease completed; the delegated run finished completed.
        self.assertEqual(self.trigger(1)["status"], "done")
        run = self.server.delegated_runs[outcome.run_id]
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["outcome"]["status"], "completed")

        # Finding and rule proposal were recorded and are visible in run events.
        self.assertEqual(len(self.server.findings), 1)
        self.assertEqual(self.server.rule_proposals[0]["key"].startswith("fake-codex-"), True)
        kinds = [event["kind"] for event in self.server.run_events[outcome.run_id]]
        self.assertIn("turn_started", kinds)
        self.assertIn("model_text", kinds)
        self.assertIn("tool_call", kinds)
        self.assertIn("tool_result", kinds)
        tools_called = {
            event["detail"]["tool"]
            for event in self.server.run_events[outcome.run_id]
            if event["kind"] == "tool_call"
        }
        self.assertEqual(
            tools_called,
            {"query_observations", "record_hypothesis_or_finding", "propose_expectation_rule"},
        )

        # The summary is the fake's final agent message with its self-checks.
        report = self.parse_fake_report(outcome.summary)
        self.assertEqual(report["env_defsec_vars"], [])
        self.assertFalse(report["argv_token"], "run token leaked onto the codex argv")
        self.assertFalse(report["adapter_argv_token"], "run token leaked onto the adapter argv")
        self.assertEqual(report["token_mode"], "0o600")
        self.assertEqual(report["token_dir_mode"], "0o700")
        self.assertEqual(report["mcp_calls"], 3)
        self.assertIn("query_observations", report["tools_seen"])
        # The prompt arrived provenance-wrapped.
        self.assertGreater(report["prompt_bytes"], 400)

    def test_environment_and_argv_stay_secret_free(self) -> None:
        outcome = self.run_once()
        assert outcome is not None
        report = self.parse_fake_report(outcome.summary)
        # The codex child saw only the scrubbed allow-list of variables.
        allowed = {"PATH", "HOME", "LANG", "TERM", "CODEX_HOME"}
        self.assertTrue(set(report["env_keys"]) <= allowed, f"env leaked: {report['env_keys']}")
        self.assertIn("PATH", report["env_keys"])
        # No token value ever reached the argv the worker built.
        argv_text = " ".join(outcome.codex_argv)
        self.assertNotIn(PARENT_TOKEN, argv_text)
        self.assertNotIn("child-token-", argv_text)

    def test_parent_token_is_not_narrowed_and_leases_next_trigger(self) -> None:
        parent = ControlRpcClient(self.sock_path, PARENT_TOKEN)
        first = self.run_once()
        assert first is not None
        self.assertEqual(first.status, "completed")
        # The parent can still lease with the very same token.
        second = parent.lease_next_trigger("next-owner", 60)
        self.assertIsNotNone(second)
        self.assertEqual(second["event_id"], 2)
        capability = parent.get_capability()
        self.assertFalse(capability["delegated"])
        self.assertIsNone(capability["capability"]["run_id"])
        self.assertTrue(capability["capability"]["may_spawn_runs"])

    # ---------------------------------------------------------------- budgets

    def test_timeout_budget_exhausted_and_process_group_killed(self) -> None:
        outcome = self.run_once(behavior="timeout", budgets=CodexBudgets(max_wall_seconds=2.0))
        assert outcome is not None
        self.assertEqual(outcome.status, "budget_exhausted", f"outcome: {outcome}")
        self.assertEqual(outcome.budget_stop_reason, "max_wall_seconds")
        # The lease completed (timeout is a budget, not a failure).
        self.assertEqual(self.trigger(1)["status"], "done")
        run = self.server.delegated_runs[outcome.run_id]
        self.assertEqual(run["outcome"]["status"], "budget_exhausted")
        # thread_id carries "<pid>:<grandchild pid>" from the fake; the whole
        # process group must be dead with no orphan left behind.
        first_pid, second_pid = outcome.thread_id.split(":")
        self.assertTrue(_wait_pid_gone(int(first_pid)), "codex process survived the budget kill")
        self.assertTrue(
            _wait_pid_gone(int(second_pid)), "codex grandchild survived the process-group kill"
        )

    def test_max_events_budget_exhausted(self) -> None:
        outcome = self.run_once(behavior="flood", budgets=CodexBudgets(max_events=25))
        assert outcome is not None
        self.assertEqual(outcome.status, "budget_exhausted", f"outcome: {outcome}")
        self.assertEqual(outcome.budget_stop_reason, "max_events")
        self.assertEqual(self.trigger(1)["status"], "done")

    # --------------------------------------------------------- failure classes

    def test_missing_codex_binary_is_non_retryable_with_alert(self) -> None:
        with self.assertLogs("defsec.reasoner.codex_worker", level="CRITICAL") as logs:
            outcome = self.run_once(codex_bin="/nonexistent/codex-binary")
        assert outcome is not None
        self.assertEqual(outcome.status, "dead_letter", f"outcome: {outcome}")
        self.assertIn("ALERT", "\n".join(logs.output))
        self.assertIn("codex binary unusable", outcome.error or "")
        self.assertEqual(self.trigger(1)["status"], "dead_letter")
        run = self.server.delegated_runs[outcome.run_id]
        self.assertEqual(run["status"], "failed")

    def test_auth_failure_is_non_retryable_with_alert(self) -> None:
        with self.assertLogs("defsec.reasoner.codex_worker", level="CRITICAL") as logs:
            outcome = self.run_once(behavior="auth-error")
        assert outcome is not None
        self.assertEqual(outcome.status, "dead_letter", f"outcome: {outcome}")
        self.assertIn("ALERT", "\n".join(logs.output))
        self.assertIn("not logged in", outcome.error or "")
        run = self.server.delegated_runs[outcome.run_id]
        self.assertEqual(run["status"], "failed")
        self.assertEqual(self.trigger(1)["status"], "dead_letter")

    def test_crash_is_retryable_and_requeues(self) -> None:
        outcome = self.run_once(behavior="crash")
        assert outcome is not None
        self.assertEqual(outcome.status, "requeued", f"outcome: {outcome}")
        self.assertEqual(self.trigger(1)["status"], "pending")
        self.assertEqual(self.trigger(1)["retry_count"], 1)
        run = self.server.delegated_runs[outcome.run_id]
        self.assertEqual(run["status"], "failed")

    def test_no_events_is_retryable(self) -> None:
        outcome = self.run_once(behavior="no-events")
        assert outcome is not None
        self.assertEqual(outcome.status, "requeued", f"outcome: {outcome}")
        self.assertIn("no JSONL events", outcome.error or "")

    def test_incomplete_and_malformed_streams_requeue_even_with_zero_exit(self) -> None:
        outcome = self.run_once(behavior="incomplete")
        self.assertEqual(outcome.status, "requeued")
        self.assertEqual(outcome.unknown_events, 4)
        self.assertIn("no completed turn", outcome.error)
        self.assertEqual(self.server.delegated_runs[outcome.run_id]["status"], "failed")

    def test_transient_delegated_start_errors_requeue_without_fallback(self) -> None:
        for code in ("delegated_run_quota", "rate_limited", "busy", "temporarily_unavailable"):
            with self.subTest(code=code), mock.patch.object(
                self.server, "_op_start_delegated_run", return_value=self.server._error(code, "retry later")
            ) as start:
                outcome = self.run_once()
                self.assertEqual(outcome.status, "requeued")
                start.assert_called_once()
        self.assertFalse(self.server.delegated_runs)

    def test_lease_fencing_and_explicit_legacy_fallback(self) -> None:
        start_run = self.server._op_start_delegated_run

        def legacy_start(request):
            if "trigger_event_id" in request:
                return self.server._error("invalid_request", "unknown field `trigger_event_id`")
            return start_run(request)

        with mock.patch.object(self.server, "_op_start_delegated_run", side_effect=legacy_start) as start:
            outcome = self.run_once(budgets=CodexBudgets(lease_seconds=120, run_ttl_seconds=400))
        self.assertEqual(outcome.status, "completed")
        fenced, legacy = [call.args[0] for call in start.call_args_list]
        self.assertEqual(fenced["trigger_event_id"], 1)
        self.assertTrue(fenced["lease_token"])
        self.assertEqual(fenced["ttl_seconds"], 120)
        self.assertEqual(legacy, {k: v for k, v in fenced.items() if k not in ("trigger_event_id", "lease_token")})

    def test_start_request_validation_does_not_drop_lease_fields(self) -> None:
        message = "lease_token did not match the trigger"
        with mock.patch.object(
            self.server, "_op_start_delegated_run",
            return_value=self.server._error("invalid_request", message),
        ) as start:
            self.assertEqual(self.run_once().status, "dead_letter")
            start.assert_called_once()

    def test_lost_start_reply_requeues_without_creating_a_second_run(self) -> None:
        start_run = self.server._op_start_delegated_run

        def lose_reply(request):
            start_run(request)
            raise DropConnection

        with mock.patch.object(self.server, "_op_start_delegated_run", side_effect=lose_reply) as start:
            self.assertEqual(self.run_once().status, "requeued")
            start.assert_called_once()
        self.assertEqual(len(self.server.delegated_runs), 1)

    def test_watchdog_handles_prompt_larger_than_pipe_when_child_does_not_read(self) -> None:
        for shutdown in (False, True):
            with self.subTest(shutdown=shutdown), mock.patch(
                "defsec_reasoner.codex_worker.build_codex_prompt", return_value="x" * (2 * 1024 * 1024)
            ):
                worker = self.make_worker("stalled-input", CodexBudgets(max_wall_seconds=0.7))
                stop = threading.Event()
                timer = threading.Timer(0.25, stop.set)
                if shutdown:
                    timer.start()
                started = time.monotonic()
                try:
                    outcome = worker.run_once(stop_event=stop)
                finally:
                    timer.cancel()
                self.assertLess(time.monotonic() - started, 3.5)
                self.assertEqual(outcome.status, "requeued" if shutdown else "budget_exhausted")
                self.assertTrue(_wait_pid_gone(outcome.codex_pid))

    def test_watchdog_kills_term_resistant_descendant_after_leader_exits(self) -> None:
        outcome = self.run_once(behavior="orphan")
        self.assertEqual(outcome.status, "completed")
        pid = int(outcome.thread_id)
        self.addCleanup(self._kill_test_descendant, pid)
        self.assertTrue(_wait_pid_gone(pid))

    @staticmethod
    def _kill_test_descendant(pid: int) -> None:
        if _pid_alive(pid):
            os.kill(pid, 9)

    def test_auth_alert_and_summary_redact_both_tokens(self) -> None:
        worker = self.make_worker("auth-error")
        tokens = []
        handle_event = worker._handle_event

        def echo_tokens(line, state, progress, run_token, lease_token):
            if json.loads(line).get("type") == "error":
                tokens.extend((run_token, lease_token))
                line = json.dumps({"type": "error", "message": f"unauthorized {run_token} {lease_token}"}).encode()
            return handle_event(line, state, progress, run_token, lease_token)

        with mock.patch.object(worker, "_handle_event", side_effect=echo_tokens), \
                self.assertLogs("defsec.reasoner.codex_worker", level="CRITICAL") as logs:
            outcome = worker.run_once()
        self.assertEqual(outcome.status, "dead_letter")
        self.assertEqual(len(tokens), 2)
        report = "\n".join(logs.output + [outcome.summary, outcome.error])
        for token in tokens:
            self.assertNotIn(token, report)
        self.assertIn("unauthorized [redacted] [redacted]", report)

    # ----------------------------------------------------------- token hygiene

    def test_token_file_permissions_and_cleanup_on_success(self) -> None:
        outcome = self.run_once()
        assert outcome is not None
        report = self.parse_fake_report(outcome.summary)
        self.assertEqual(report["token_mode"], "0o600")
        self.assertEqual(report["token_dir_mode"], "0o700")
        self.assertFalse(Path(report["cwd"]).exists(), "work dir survived the run")
        self.assertFalse(Path(report["token_file"]).exists(), "token file survived the run")

    def test_temp_dirs_cleaned_up_after_internal_exception(self) -> None:
        cleaned: list[Path] = []
        original_cleanup = CodexWorker._cleanup

        def spy(_worker: CodexWorker, *dirs: Path) -> None:
            cleaned.extend(dirs)
            original_cleanup(*dirs)

        worker = self.make_worker()
        with mock.patch.object(CodexWorker, "_finish_run", side_effect=RuntimeError("boom")), \
                mock.patch.object(CodexWorker, "_cleanup", spy):
            outcome = worker.run_once()
        assert outcome is not None
        self.assertEqual(outcome.status, "requeued", f"outcome: {outcome}")
        self.assertIn("internal error", outcome.error or "")
        self.assertGreaterEqual(len(cleaned), 2)
        for directory in cleaned:
            self.assertFalse(directory.exists(), f"{directory} survived an internal exception")
        self.assertEqual(self.trigger(1)["status"], "pending")

    def test_sigterm_mid_run_requeues_and_cleans_up(self) -> None:
        import threading

        stop_event = threading.Event()
        stop_event.set()  # already shutting down when the run starts
        cleaned: list[Path] = []
        original_cleanup = CodexWorker._cleanup

        def spy(_worker: CodexWorker, *dirs: Path) -> None:
            cleaned.extend(dirs)
            original_cleanup(*dirs)

        worker = self.make_worker(behavior="timeout", budgets=CodexBudgets(max_wall_seconds=20.0))
        with mock.patch.object(CodexWorker, "_cleanup", spy):
            outcome = worker.run_once(stop_event=stop_event)
        assert outcome is not None
        self.assertEqual(outcome.status, "requeued", f"outcome: {outcome}")
        self.assertIn("shutdown", outcome.error or "")
        for directory in cleaned:
            self.assertFalse(directory.exists())
        run = self.server.delegated_runs[outcome.run_id]
        self.assertEqual(run["status"], "failed")

    # ------------------------------------------------------------ capability

    def test_startup_fails_closed_without_may_spawn_runs(self) -> None:
        plain = "plain-investigator-token"
        self.server.register_token(plain, principal_id="plain")
        worker = self.make_worker()
        worker._client_or_factory = lambda: ControlRpcClient(self.sock_path, plain)  # type: ignore[assignment]
        with self.assertRaises(CodexWorkerStartupError) as ctx:
            worker.verify_capability()
        self.assertIn("may_spawn_runs", str(ctx.exception))

    def test_delegated_child_token_cannot_manage_leases_or_spawn(self) -> None:
        outcome = self.run_once(behavior="crash")  # any behavior mints a child token
        assert outcome is not None
        child_token = self.server.delegated_runs[outcome.run_id]["run_token"]
        child = ControlRpcClient(self.sock_path, child_token)
        with self.assertRaises(RpcError) as lease_error:
            child.lease_next_trigger("child", 60)
        self.assertIn("delegated runs cannot manage trigger leases", lease_error.exception.message)
        capability = child.get_capability()
        self.assertTrue(capability["delegated"])
        self.assertFalse(capability["capability"]["may_spawn_runs"])
        with self.assertRaises(RpcError) as spawn_error:
            child.start_delegated_run("inc-1", "x", "y", "z")
        self.assertIn("cannot spawn delegated runs", spawn_error.exception.message)

    def test_only_child_token_can_finish_the_run(self) -> None:
        worker = self.make_worker()
        with mock.patch.object(
            CodexWorker, "_execute_run",
            side_effect=lambda *args, **kwargs: self._child_finish_attempt(),
        ):
            outcome = worker.run_once()
        assert outcome is not None
        self.assertEqual(outcome.status, "requeued")

    def _child_finish_attempt(self) -> object:
        child_token = next(
            run["run_token"] for run in self.server.delegated_runs.values()
            if run["status"] == "active"
        )
        parent = ControlRpcClient(self.sock_path, PARENT_TOKEN)
        run_id = next(
            run_id for run_id, run in self.server.delegated_runs.items()
            if run["run_token"] == child_token
        )
        with self.assertRaises(RpcError) as ctx:
            parent.finish_investigation_run(run_id, {"status": "completed", "summary": "parent"})
        self.assertIn("run is outside capability scope", ctx.exception.message)
        raise RuntimeError("finish probe complete")

    # ---------------------------------------------------------------- mapping

    def test_unknown_events_are_counted_and_ignored(self) -> None:
        fake_lines = [
            b'{"type":"thread.started","thread_id":"t-1"}\n',
            b'{"type":"turn.started"}\n',
            b'{"type":"todo_list","items":[]}\n',
            b'{"type":"shiny.new.event","payload":"??"}\n',
            b"not json at all\n",
            b'{"type":"item.completed","item":{"id":"i1","type":"agent_message","text":"done"}}\n',
            b'{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":5}}\n',
        ]
        from defsec_reasoner.codex_worker import _StreamState

        state = _StreamState()
        progress = recording_progress()
        worker = CodexWorker(lambda: None, socket_path="unused")
        for line in fake_lines:
            worker._handle_event(line, state, progress, "tok", "lease")
        self.assertEqual(state.turns, 1)
        self.assertEqual(state.model_texts, 1)
        self.assertEqual(state.last_message, "done")
        self.assertEqual(state.input_tokens, 10)
        self.assertEqual(state.unknown_events, 3)
        self.assertEqual(
            [item[0] for item in progress.events],
            ["turn_started", "model_text"],
        )

    def test_bare_turn_completed_without_turn_started_or_usage_is_rejected(self) -> None:
        from defsec_reasoner.codex_worker import _StreamState

        state = _StreamState()
        progress = recording_progress()
        worker = CodexWorker(lambda: None, socket_path="unused")
        worker._handle_event(b'{"type":"turn.completed"}\n', state, progress, "tok", "lease")
        self.assertFalse(state.completed_turn)
        self.assertEqual(state.turns, 0)
        self.assertEqual(state.unknown_events, 1)
        worker._handle_event(b'{"type":"turn.started"}\n', state, progress, "tok", "lease")
        worker._handle_event(b'{"type":"turn.completed"}\n', state, progress, "tok", "lease")
        self.assertFalse(state.completed_turn)
        self.assertEqual(state.unknown_events, 2)
        worker._handle_event(
            b'{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":2}}\n',
            state, progress, "tok", "lease",
        )
        self.assertTrue(state.completed_turn)
        self.assertEqual(state.turns, 1)
        # A subsequent malformed final turn must clear completed_turn.
        worker._handle_event(b'{"type":"turn.started"}\n', state, progress, "tok", "lease")
        worker._handle_event(b'{"type":"turn.completed"}\n', state, progress, "tok", "lease")
        self.assertFalse(state.completed_turn)
        self.assertEqual(state.turns, 2)

    def test_prompt_wraps_trigger_context_in_envelopes(self) -> None:
        from defsec_reasoner.provenance import envelope_contents, envelope_count

        lease = _trigger(1)
        context = {
            "incident": {"incident_id": "inc-1", "host_id": "edge-01", "status": "open"},
            "active_watches": [],
            "recent_observations": self.server.observations,
            "findings": [],
        }
        prompt = build_codex_prompt(
            backend_id="codex-worker",
            model_id="happy",
            lease=lease,
            context=context,
            capabilities=[],
            budgets=CodexBudgets(),
            run_id="run-x",
        )
        self.assertIn("INERT", prompt)
        self.assertIn("untrusted_telemetry", prompt)
        self.assertIn("finish by writing a concise final assessment", prompt.lower())
        self.assertGreater(envelope_count(prompt), 2)
        payloads = envelope_contents(prompt)
        kinds = [p.get("kind") for p in payloads if isinstance(p, dict)]
        self.assertIn("snapshot", kinds)


def recording_progress():
    class Recording:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict]] = []

        def record(self, kind: str, detail: dict) -> None:
            self.events.append((kind, detail))

    return Recording()


# ---------------------------------------------------------------------- live


@unittest.skipUnless(CONTROL_BIN, "compiled control-d binary not found (cargo build -p control-d)")
@unittest.skipIf(ADAPTER_BIN is None, "compiled mcp-adapter binary not found (cargo build -p mcp-adapter)")
class LiveCodexWorkerTests(unittest.TestCase):
    """End-to-end against real control-d + real mcp-adapter + fake codex."""

    HOST = "edge-01"

    def setUp(self) -> None:
        self.daemon = ControlDaemon(CONTROL_BIN).start()
        self.admin = AdminClient(self.daemon.admin_sock)
        self.admin.enroll_host(self.HOST)
        self.admin.apply_baseline_watch(
            sockets_watch_spec(self.HOST), "operator-setup", "baseline sockets inventory"
        )
        self.agent = SyntheticAgent(self.daemon.agent_sock, self.HOST)
        self.agent.connect()
        self.parent_token = self.admin.mint_capability_token(
            "codex-worker-live", "investigator", [self.HOST], COLLECTORS, may_spawn_runs=True
        )["token"]

    def tearDown(self) -> None:
        self.agent.close()
        self.daemon.stop()

    def _base_sockets(self) -> list[dict]:
        return [
            socket_entry("tcp:0.0.0.0:22:uid=0", port=22, inode=1001, pid=101, comm="sshd", systemd_unit="sshd.service"),
            socket_entry("tcp:0.0.0.0:80:uid=0", port=80, inode=2002, pid=202, comm="nginx", systemd_unit="nginx.service"),
        ]

    def _fire_sockets_trigger(self) -> None:
        changed = self._base_sockets()[:1] + [
            socket_entry("tcp:0.0.0.0:4444:uid=0", port=4444, inode=4404, pid=444, comm="ghost", systemd_unit="ghost.service")
        ]
        assert self.agent.push_snapshot("w-sockets", 1, sockets_snapshot(self._base_sockets()))
        assert self.agent.push_snapshot("w-sockets", 1, sockets_snapshot(changed))

    def make_worker(self, behavior: str, **budget_fields: object) -> CodexWorker:
        budgets = CodexBudgets(max_wall_seconds=20.0)
        for key, value in budget_fields.items():
            setattr(budgets, key, value)
        return CodexWorker(
            lambda: ControlRpcClient(self.daemon.investigate_sock, self.parent_token),
            socket_path=str(self.daemon.investigate_sock),
            codex_bin=str(FAKE_CODEX),
            mcp_adapter_bin=str(ADAPTER_BIN),
            model=behavior,
            lease_owner="codex-worker-live",
            budgets=budgets,
        )

    def test_live_delegated_run_end_to_end(self) -> None:
        self._fire_sockets_trigger()
        worker = self.make_worker("happy")
        worker.verify_capability()
        outcome = worker.run_once()
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.status, "completed", f"outcome: {outcome}")
        self.assertEqual(outcome.findings, 1)
        self.assertEqual(outcome.proposals, 1)
        self.assertEqual(outcome.proposals_accepted, 1)

        parent = ControlRpcClient(self.daemon.investigate_sock, self.parent_token)
        runs = parent.list_investigation_runs(incident_id=outcome.incident_id)
        run = next(run for run in runs if run["run_id"] == outcome.run_id)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["findings_count"], 1)
        # NB: control-d's RunSummary.proposals_count counts watch/action
        # proposals only; the fake's expectation rule lands in the rule
        # registry, asserted below.
        self.assertIn("fake-codex-report:", run["outcome"]["summary"])
        events = parent.get_run_events(outcome.run_id)
        kinds = {event["kind"] for event in events}
        self.assertEqual(
            {"turn_started", "tool_call", "tool_result", "model_text", "note"}, kinds
        )
        cached, = [event["detail"]["cached_input_tokens"] for event in events if event["kind"] == "note"]
        self.assertEqual(cached, 24448)
        self.assertEqual(outcome.cached_input_tokens, cached)
        # The rule proposal is durable and inert until an operator approves it.
        rules = self.admin.call({
            "admin_op": "list_expectation_rules",
            "host_id": self.HOST,
            "statuses": ["proposed"],
            "limit": 10,
        })["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["status"], "proposed")
        self.assertEqual(rules[0]["origin"], "investigator")
        self.assertEqual(rules[0]["run_id"], outcome.run_id)
        # The finding is durable and evidence-bound.
        context = parent.get_incident_context(outcome.incident_id)
        self.assertEqual(len(context["findings"]), 1)
        finding = context["findings"][0]["finding"]
        self.assertGreaterEqual(len(finding["evidence_observation_ids"]), 1)
        # The trigger is done and the audit chain holds end to end.
        queue = parent.list_trigger_queue(statuses=["done"])
        self.assertEqual(queue[0]["event_id"], outcome.event_id)
        self.assertEqual(queue[0]["lease_owner"], "codex-worker-live")
        chain = self.admin.verify_audit_chain()
        self.assertTrue(chain["valid"], f"audit chain broken: {chain}")

        # The parent token was never narrowed: it can lease the next trigger.
        self._fire_sockets_trigger()
        self.assertIsNotNone(parent.lease_next_trigger("codex-worker-live-2", 60))

    def test_live_timeout_finishes_budget_exhausted_and_completes_lease(self) -> None:
        self._fire_sockets_trigger()
        worker = self.make_worker("timeout", max_wall_seconds=2.0)
        outcome = worker.run_once()
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.status, "budget_exhausted", f"outcome: {outcome}")
        self.assertEqual(outcome.budget_stop_reason, "max_wall_seconds")
        parent = ControlRpcClient(self.daemon.investigate_sock, self.parent_token)
        runs = parent.list_investigation_runs(incident_id=outcome.incident_id)
        run = next(run for run in runs if run["run_id"] == outcome.run_id)
        self.assertEqual(run["status"], "budget_exhausted")
        self.assertEqual(run["outcome"]["budget_stop_reason"], "max_wall_seconds")
        queue = parent.list_trigger_queue(statuses=["done"])
        self.assertEqual(queue[0]["event_id"], outcome.event_id)
        # No orphaned codex process group.
        first_pid, second_pid = outcome.thread_id.split(":")
        self.assertTrue(_wait_pid_gone(int(first_pid)))
        self.assertTrue(_wait_pid_gone(int(second_pid)))

    def test_live_missing_binary_dead_letters_with_alert(self) -> None:
        self._fire_sockets_trigger()
        worker = self.make_worker("happy")
        worker.codex_bin = "/nonexistent/codex-binary"
        with self.assertLogs("defsec.reasoner.codex_worker", level="CRITICAL") as logs:
            outcome = worker.run_once()
        assert outcome is not None
        self.assertEqual(outcome.status, "dead_letter", f"outcome: {outcome}")
        self.assertIn("ALERT", "\n".join(logs.output))
        parent = ControlRpcClient(self.daemon.investigate_sock, self.parent_token)
        queue = parent.list_trigger_queue(statuses=["dead_letter"])
        self.assertEqual(queue[0]["event_id"], outcome.event_id)


@unittest.skipUnless(
    os.environ.get("DEFSEC_LIVE_CODEX") == "1",
    "opt-in live smoke test: set DEFSEC_LIVE_CODEX=1 (needs a logged-in Codex CLI)",
)
@unittest.skipUnless(CONTROL_BIN, "compiled control-d binary not found (cargo build -p control-d)")
@unittest.skipIf(ADAPTER_BIN is None, "compiled mcp-adapter binary not found (cargo build -p mcp-adapter)")
class LiveRealCodexSmokeTests(unittest.TestCase):
    """Manual smoke test against the real Codex CLI (ChatGPT OAuth login).

    Gated behind ``DEFSEC_LIVE_CODEX=1``; never run in CI. Assumes ``codex``
    on PATH with a completed ``codex login`` (dedicated OS user recommended).
    """

    HOST = "edge-01"

    def setUp(self) -> None:
        self.daemon = ControlDaemon(CONTROL_BIN).start()
        self.admin = AdminClient(self.daemon.admin_sock)
        self.admin.enroll_host(self.HOST)
        self.admin.apply_baseline_watch(
            sockets_watch_spec(self.HOST), "operator-setup", "baseline sockets inventory"
        )
        self.agent = SyntheticAgent(self.daemon.agent_sock, self.HOST)
        self.agent.connect()
        self.parent_token = self.admin.mint_capability_token(
            "codex-smoke", "investigator", [self.HOST], COLLECTORS, may_spawn_runs=True
        )["token"]

    def tearDown(self) -> None:
        self.agent.close()
        self.daemon.stop()

    def test_real_codex_smoke(self) -> None:
        base = [
            socket_entry("tcp:0.0.0.0:22:uid=0", port=22, inode=1001, pid=101, comm="sshd", systemd_unit="sshd.service"),
        ]
        changed = base + [
            socket_entry("tcp:0.0.0.0:4444:uid=0", port=4444, inode=4404, pid=444, comm="ghost", systemd_unit="ghost.service")
        ]
        assert self.agent.push_snapshot("w-sockets", 1, sockets_snapshot(base))
        assert self.agent.push_snapshot("w-sockets", 1, sockets_snapshot(changed))
        parent = ControlRpcClient(self.daemon.investigate_sock, self.parent_token)
        with tempfile.TemporaryDirectory() as folder:
            def wake():
                worker = CodexWorker(
                    parent, socket_path=str(self.daemon.investigate_sock), session_dir=Path(folder),
                    codex_bin="codex", model=os.environ.get("DEFSEC_LIVE_CODEX_MODEL"),
                    mcp_adapter_bin=str(ADAPTER_BIN),
                    budgets=CodexBudgets(max_wall_seconds=300.0, lease_seconds=900),
                )
                outcome = worker.run_once()
                self.assertIsNotNone(outcome)
                self.assertEqual(outcome.status, "completed", outcome.error)
                events = parent.get_run_events(outcome.run_id)
                self.assertTrue(any(e["kind"] == "tool_result" and e["detail"].get("ok") for e in events))
                return outcome
            first = wake()
            latest = base + [socket_entry("tcp:0.0.0.0:8043:uid=0", port=8043, pid=320,
                                          comm="other", systemd_unit="other.service")]
            self.assertTrue(self.agent.push_snapshot("w-sockets", 1, sockets_snapshot(latest)))
            second = wake()
            self.assertIsNotNone(first.thread_id)
            self.assertEqual(first.thread_id, second.thread_id)
            self.assertNotEqual(first.run_id, second.run_id)
            self.assertEqual(second.codex_argv[-3:], ["resume", first.thread_id, "-"])


if __name__ == "__main__":
    unittest.main()
