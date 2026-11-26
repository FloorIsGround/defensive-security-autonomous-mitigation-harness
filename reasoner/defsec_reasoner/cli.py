"""Command-line entrypoints for ``reasoner-d`` and the Codex worker.

Usage::

    python3 -m defsec_reasoner worker   --socket ./control-data/investigate.sock \
                                       --token "$DEFSEC_CAPABILITY_TOKEN" \
                                       --backend openai --base-url http://localhost:11434/v1 \
                                       --model llama3.1 --poll-interval 5

    python3 -m defsec_reasoner codex-worker --socket ./control-data/investigate.sock \
                                            --codex-bin codex --model gpt-5-codex \
                                            --mcp-adapter-bin ./target/debug/mcp-adapter

    python3 -m defsec_reasoner benchmark --json-out bench.json --markdown-out bench.md
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Sequence

from defsec_reasoner import __version__
from defsec_reasoner.models import (
    AnthropicAdapter,
    OpenAICompatibleAdapter,
    ProviderError,
    ScriptedMockAdapter,
)


def _build_adapter(args: argparse.Namespace) -> tuple[Any, str]:
    if args.backend == "mock":
        script: list[Any] = []
        if args.script_file:
            raw = json.loads(Path(args.script_file).read_text())
            for step in raw:
                if isinstance(step, dict) and "provider_error" in step:
                    err = step["provider_error"]
                    script.append(ProviderError(str(err.get("message", "scripted failure")), bool(err.get("retryable", True))))
                else:
                    script.append(step)
        else:
            script = [
                {"tool_calls": [{"name": "query_observations", "arguments": {"host_id": args.host or ""}}]}
                if args.host
                else {"final_text": "no host scope configured; nothing to do"},
            ]
        return ScriptedMockAdapter(script), args.model or "scripted-mock"
    if args.backend in ("chatgpt", "opencode-go"):
        from defsec_reasoner.subscriptions import ChatGPTPlanAdapter, OpenCodeGoAdapter
        if not args.model or args.base_url:
            raise ValueError("subscription backends require --model and use a fixed provider endpoint")
        if args.backend == "chatgpt":
            return ChatGPTPlanAdapter(args.model, args.chatgpt_profile, args.effort), args.model
        return OpenCodeGoAdapter(args.model, args.effort), args.model
    if getattr(args, "command", "") == "worker" and getattr(args, "effort", None):
        raise ValueError("worker --effort is supported for subscription backends")
    if args.backend == "openai":
        return (
            OpenAICompatibleAdapter(
                base_url=args.base_url or "http://localhost:11434/v1",
                model_id=args.model or "local-model",
                completion_token_field=os.environ.get(
                    "DEFSEC_OPENAI_COMPLETION_TOKEN_FIELD", "max_completion_tokens"
                ),
            ),
            args.model or "local-model",
        )
    if args.backend == "anthropic":
        options = {"base_url": args.base_url} if getattr(args, "command", None) == "host-review-worker" and args.base_url else {}
        model_id = args.model or "claude-sonnet-4-20250514"
        return AnthropicAdapter(model_id=model_id, **options), args.model
    raise ValueError(f"unknown backend: {args.backend}")


def _cmd_worker(args: argparse.Namespace) -> int:
    from defsec_reasoner.rpc_client import ControlRpcClient
    from defsec_reasoner.worker import ReasonerWorker, RunBudgets

    token = args.token or os.environ.get("DEFSEC_CAPABILITY_TOKEN")
    if not token:
        print("error: --token or DEFSEC_CAPABILITY_TOKEN is required", file=sys.stderr)
        return 2
    adapter, model_id = _build_adapter(args)
    budgets = RunBudgets(
        max_turns=args.max_turns,
        max_wall_seconds=args.max_wall_seconds,
        max_total_tokens=args.max_total_tokens,
        max_completion_tokens=args.max_completion_tokens,
        onboarding_max_total_tokens=args.onboarding_max_total_tokens,
        onboarding_max_wall_seconds=args.onboarding_max_wall_seconds,
        max_cost_usd=args.max_cost_usd,
        max_proposals_per_run=args.max_proposals,
        enable_action_proposals=args.enable_action_proposals,
        max_context_bytes=args.max_context_bytes,
        lease_seconds=args.lease_seconds,
    )
    socket_path = args.socket
    if not Path(socket_path).exists():
        print(f"error: investigation socket {socket_path} does not exist", file=sys.stderr)
        return 2

    def client_factory() -> ControlRpcClient:
        # The operator/queue layer mints short-lived scoped capability tokens;
        # the worker refreshes authority for every run through this hook.
        return ControlRpcClient(
            socket_path, os.environ.get("DEFSEC_CAPABILITY_TOKEN") or token, request_timeout=args.rpc_timeout
        )

    worker = ReasonerWorker(
        client_factory,
        adapter,
        backend_id=args.backend_id,
        model_id=model_id,
        lease_owner=args.lease_owner,
        budgets=budgets,
        followups_only=args.followups_only,
        discovery_only=args.discovery_only,
    )
    if args.once:
        worker.run_once()
        return 0
    stop_event = threading.Event()

    def _stop(signum: int, _frame: Any) -> None:
        stop_event.set()

    import signal

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):  # pragma: no cover - non-main thread
            pass
    worker.run_loop(poll_interval_seconds=args.poll_interval, stop_event=stop_event)
    return 0


def _cmd_host_review_worker(args: argparse.Namespace) -> int:
    import math
    import signal
    from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor, wait

    from defsec_reasoner.discovery import export_scopes
    from defsec_reasoner.host_review import ReviewLimits, run_reviews
    from defsec_reasoner.rpc_client import ControlRpcClient

    token = args.token or os.environ.get("DEFSEC_CAPABILITY_TOKEN")
    if not token or not Path(args.socket).exists():
        print("error: a capability token and existing investigation socket are required", file=sys.stderr)
        return 2
    if not (1 <= args.concurrency <= 16 and 1 <= args.lease_seconds <= 900
            and args.max_total_tokens > 0 and args.max_completion_tokens > 0
            and 0 < args.max_wall_seconds < args.lease_seconds
            and math.isfinite(args.poll_interval) and args.poll_interval > 0
            and math.isfinite(args.rpc_timeout) and args.rpc_timeout > 0):
        print("error: invalid host review limits", file=sys.stderr)
        return 2
    if args.effort and args.backend == "anthropic":
        print("error: this Anthropic adapter does not support review effort", file=sys.stderr)
        return 2
    adapters = [_build_adapter(args)[0] for _ in range(args.concurrency)]
    if export_scopes(adapters[0], args.purpose) == []:
        print("error: host review requires a local endpoint or a grant for this endpoint and purpose", file=sys.stderr)
        return 2
    limits = ReviewLimits(args.max_total_tokens, args.max_wall_seconds, args.lease_seconds, args.effort, args.max_completion_tokens)
    stop = threading.Event()

    def client_factory() -> ControlRpcClient:
        return ControlRpcClient(
            args.socket, os.environ.get("DEFSEC_CAPABILITY_TOKEN") or token,
            request_timeout=args.rpc_timeout,
        )

    def stop_worker(_signum: int, _frame: Any) -> None:
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, stop_worker)
    with ThreadPoolExecutor(max_workers=args.concurrency) as workers:
        futures = [
            workers.submit(run_reviews, client_factory, adapter, args.purpose, limits, args.poll_interval, stop)
            for adapter in adapters
        ]
        try:
            done, _ = wait(futures, return_when=FIRST_EXCEPTION)
            for future in done:
                future.result()
        finally:
            stop.set()
    return 0


def _cmd_codex_worker(args: argparse.Namespace) -> int:
    from defsec_reasoner.codex_worker import (
        CodexBudgets,
        CodexWorker,
        CodexWorkerStartupError,
        find_mcp_adapter_binary,
    )
    from defsec_reasoner.rpc_client import ControlRpcClient, RpcError, RpcTransportError

    token = args.token or os.environ.get("DEFSEC_CAPABILITY_TOKEN")
    if not token:
        print("error: --token or DEFSEC_CAPABILITY_TOKEN is required", file=sys.stderr)
        return 2
    socket_path = args.socket
    if not Path(socket_path).exists():
        print(f"error: investigation socket {socket_path} does not exist", file=sys.stderr)
        return 2
    adapter_bin = args.mcp_adapter_bin or find_mcp_adapter_binary()
    if adapter_bin is None:
        print(
            "error: no mcp-adapter binary found; pass --mcp-adapter-bin "
            "(or build the workspace: cargo build -p mcp-adapter)",
            file=sys.stderr,
        )
        return 2

    def client_factory() -> ControlRpcClient:
        return ControlRpcClient(socket_path, token, request_timeout=args.rpc_timeout)

    budgets = CodexBudgets(
        max_wall_seconds=args.max_wall_seconds,
        max_events=args.max_events,
        max_context_bytes=args.max_context_bytes,
        run_ttl_seconds=args.run_ttl_seconds,
        lease_seconds=args.lease_seconds,
    )
    session_dir = args.session_dir
    if args.persist_sessions and session_dir is None:
        state_root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
        session_dir = state_root / "defsec-reasoner/codex-sessions"
    worker = CodexWorker(
        client_factory,
        socket_path=socket_path,
        codex_bin=args.codex_bin,
        mcp_adapter_bin=str(adapter_bin),
        model=args.model,
        session_dir=None if args.ephemeral else session_dir,
        backend_id=args.backend_id,
        lease_owner=args.lease_owner,
        budgets=budgets,
    )
    # Fail closed at startup unless the parent token can spawn delegated runs.
    try:
        worker.verify_capability()
    except (CodexWorkerStartupError, RpcError, RpcTransportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    stop_event = threading.Event()

    def _stop(signum: int, _frame: Any) -> None:
        stop_event.set()

    import signal

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):  # pragma: no cover - non-main thread
            pass
    worker.run_loop(poll_interval_seconds=args.poll_interval, stop_event=stop_event)
    return 0


def _cmd_benchmark(args: argparse.Namespace) -> int:
    from defsec_reasoner.benchmark import BenchmarkRunner

    runner = BenchmarkRunner(args.binary, keep_data=args.keep_data, quiet=args.quiet)
    scenarios = args.scenario or None
    report = runner.run_all(scenarios)
    text = report.to_json()
    if args.json_out:
        Path(args.json_out).write_text(text)
        print(f"wrote JSON metrics to {args.json_out}")
    else:
        print(text)
    if args.markdown_out:
        Path(args.markdown_out).write_text(report.to_markdown())
        print(f"wrote Markdown summary to {args.markdown_out}")
    if not args.quiet:
        print("\n" + report.to_markdown())
    return 0 if report.all_assertions_pass else 1


def _cmd_chatgpt(args: argparse.Namespace) -> int:
    from defsec_reasoner import chatgpt_auth as auth

    if args.operation == "login":
        auth.login(args.profile)
    elif args.operation == "logout":
        auth.logout(args.profile)
    elif args.operation == "models":
        catalog = auth.fetch(auth.RESOURCE + "/models", token=auth.bearer(args.profile))
        for model in catalog["models"]:
            if model.get("visibility") == "list":
                print(model["slug"], model["display_name"], sep="\t")
    else:
        with auth.registry() as state:
            for profile, record in state["accounts"].items():
                print(profile, "plan authorized" if auth.PLAN_SCOPE in record.get("scopes", []) else "disconnected")
    return 0


def _cmd_go_models(args: argparse.Namespace) -> int:
    from defsec_reasoner.subscriptions import OpenCodeGoAdapter

    models = OpenCodeGoAdapter.available_models()
    if not models:
        print("This workspace lists no tool-capable Go chat models.", file=sys.stderr)
    for model_id, name in models:
        print(model_id, name, sep="\t")
    return 0


def _worker_backend(value: str) -> str:
    if value == "codex":
        raise argparse.ArgumentTypeError("use the codex-worker command to run the Codex CLI")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defsec_reasoner",
        description="DefSecAutMit reasoning plane: episodic worker and benchmark harness",
    )
    parser.add_argument("--version", action="version", version=f"defsec-reasoner {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    go = sub.add_parser("opencode-go", help="inspect the authenticated Go workspace catalog")
    go.add_argument("operation", choices=("models",))
    go.set_defaults(func=_cmd_go_models)

    account = sub.add_parser("chatgpt", help="manage direct ChatGPT subscription profiles")
    account.add_argument("operation", choices=("login", "logout", "profiles", "models"))
    account.add_argument("--profile", default="default")
    account.set_defaults(func=_cmd_chatgpt)

    worker = sub.add_parser(
        "worker", help="run the custom model-adapter worker",
        description="Run the custom model-adapter worker with the mock backend by default.",
        epilog="For the Codex CLI backend, use codex-worker.",
    )
    worker.add_argument("--socket", required=True, help="path to control-d investigate.sock")
    worker.add_argument("--token", default=None, help="scoped capability token (or DEFSEC_CAPABILITY_TOKEN)")
    worker.add_argument("--backend", type=_worker_backend,
                        choices=("mock", "openai", "anthropic", "chatgpt", "opencode-go"), default="mock")
    worker.add_argument("--backend-id", default="reasoner-d")
    worker.add_argument("--chatgpt-profile", default="default")
    worker.add_argument("--effort", choices=("none", "low", "medium", "high", "xhigh", "max"))
    worker.add_argument("--model", default=None)
    worker.add_argument("--base-url", default=None, help="OpenAI-compatible base URL incl. /v1")
    worker.add_argument("--script-file", default=None, help="JSON script for the mock backend")
    worker.add_argument("--host", default=None, help="host scope hint for the default mock script")
    worker.add_argument("--lease-owner", default="reasoner-d")
    worker.add_argument("--poll-interval", type=float, default=5.0)
    worker.add_argument("--rpc-timeout", type=float, default=10.0)
    worker.add_argument("--max-turns", type=int, default=6)
    worker.add_argument("--max-wall-seconds", type=float, default=45.0)
    worker.add_argument("--max-total-tokens", type=int, default=48000)
    worker.add_argument("--max-completion-tokens", type=int, default=4096)
    worker.add_argument("--onboarding-max-total-tokens", type=int, default=24000)
    worker.add_argument("--onboarding-max-wall-seconds", type=float, default=15.0)
    worker.add_argument(
        "--enable-action-proposals", action="store_true",
        help="allow the model to submit typed mitigation proposals for policy evaluation",
    )
    worker.add_argument("--max-cost-usd", type=float, default=0.25)
    worker.add_argument("--max-proposals", type=int, default=3)
    worker.add_argument("--max-context-bytes", type=int, default=32768)
    worker.add_argument("--lease-seconds", type=int, default=120)
    worker.add_argument("--once", action="store_true", help="poll for work once and exit")
    jobs = worker.add_mutually_exclusive_group()
    jobs.add_argument("--discovery-only", action="store_true", help="advance host discovery without leasing incident triggers")
    jobs.add_argument("--followups-only", action="store_true", help="lease ready evidence questions using a run-spawn grant")
    worker.set_defaults(func=_cmd_worker)

    codex = sub.add_parser(
        "codex-worker", aliases=["investigator"],
        help="run the Codex CLI investigator",
        description="Run the Codex CLI investigator with ephemeral sessions by default.",
    )
    sessions = codex.add_mutually_exclusive_group()
    sessions.add_argument("--ephemeral", action="store_true", help="use a temporary session for each trigger (default)")
    sessions.add_argument("--persist-sessions", action="store_true",
                          help="save sessions under ${XDG_STATE_HOME:-~/.local/state}/defsec-reasoner/codex-sessions")
    codex.add_argument("--session-dir", type=Path,
                       help="private directory for incident session references and work directories")
    codex.add_argument("--socket", required=True, help="path to control-d investigate.sock")
    codex.add_argument("--token", default=None, help="parent capability token (or DEFSEC_CAPABILITY_TOKEN)")
    codex.add_argument("--codex-bin", default="codex", help="Codex CLI binary (codex exec)")
    codex.add_argument("--model", default=None, help="model id passed to codex (-m)")
    codex.add_argument("--mcp-adapter-bin", default=None, help="mcp-adapter binary (default: auto-detect)")
    codex.add_argument("--backend-id", default="codex-worker")
    codex.add_argument("--lease-owner", default="codex-worker")
    codex.add_argument("--poll-interval", type=float, default=5.0)
    codex.add_argument("--rpc-timeout", type=float, default=10.0)
    codex.add_argument("--max-wall-seconds", type=float, default=600.0)
    codex.add_argument("--max-events", type=int, default=2000)
    codex.add_argument("--max-context-bytes", type=int, default=32768)
    codex.add_argument("--lease-seconds", type=int, default=900)
    codex.add_argument("--run-ttl-seconds", type=int, default=900, help="delegated token TTL, capped by --lease-seconds")
    codex.set_defaults(func=_cmd_codex_worker)

    review = sub.add_parser("host-review-worker", help="assess scheduled host questions using a local model")
    review.add_argument("--socket", required=True)
    review.add_argument("--token")
    review.add_argument("--purpose", required=True, help="schedule route this worker may claim")
    review.add_argument("--backend", choices=("mock", "openai", "anthropic", "chatgpt", "opencode-go"), default="openai")
    review.add_argument("--chatgpt-profile", default="default")
    review.add_argument("--model")
    review.add_argument("--base-url")
    review.add_argument("--script-file")
    review.add_argument("--effort", choices=("none", "low", "medium", "high", "xhigh", "max"))
    review.add_argument("--max-total-tokens", type=int, default=4096)
    review.add_argument("--max-completion-tokens", type=int, default=4096)
    review.add_argument("--max-wall-seconds", type=float, default=15)
    review.add_argument("--lease-seconds", type=int, default=30)
    review.add_argument("--concurrency", type=int, default=1)
    review.add_argument("--poll-interval", type=float, default=2)
    review.add_argument("--rpc-timeout", type=float, default=10)
    review.set_defaults(func=_cmd_host_review_worker, host=None)

    bench = sub.add_parser("benchmark", help="run the synthetic adaptive-vs-static benchmark suite")
    bench.add_argument("--binary", default=None, help="path to a compiled control-d binary")
    bench.add_argument("--scenario", action="append", default=None, help="run a single scenario (repeatable)")
    bench.add_argument("--json-out", default=None, help="write structured JSON metrics to this path")
    bench.add_argument("--markdown-out", default=None, help="write the Markdown summary to this path")
    bench.add_argument("--keep-data", action="store_true", help="keep control-d temp state for debugging")
    bench.add_argument("--quiet", action="store_true")
    bench.set_defaults(func=_cmd_benchmark)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        return args.func(args)
    except (ValueError, ProviderError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
