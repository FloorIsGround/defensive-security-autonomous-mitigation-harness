"""Command-line entrypoints for ``reasoner-d``.

Usage::

    python3 -m defsec_reasoner worker   --socket ./control-data/investigate.sock \
                                       --token "$DEFSEC_CAPABILITY_TOKEN" \
                                       --backend openai --base-url http://localhost:11434/v1 \
                                       --model llama3.1 --poll-interval 5

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
    if args.backend == "openai":
        return (
            OpenAICompatibleAdapter(
                base_url=args.base_url or "http://localhost:11434/v1",
                model_id=args.model or "local-model",
            ),
            args.model or "local-model",
        )
    if args.backend == "anthropic":
        return AnthropicAdapter(model_id=args.model or "claude-sonnet-4-20250514"), args.model
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
    )
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defsec_reasoner",
        description="DefSecAutMit reasoning plane: episodic worker and benchmark harness",
    )
    parser.add_argument("--version", action="version", version=f"defsec-reasoner {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    worker = sub.add_parser("worker", help="run the episodic reasoning worker (reasoner-d)")
    worker.add_argument("--socket", required=True, help="path to control-d investigate.sock")
    worker.add_argument("--token", default=None, help="scoped capability token (or DEFSEC_CAPABILITY_TOKEN)")
    worker.add_argument("--backend", choices=("mock", "openai", "anthropic"), default="mock")
    worker.add_argument("--backend-id", default="reasoner-d")
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
    worker.add_argument(
        "--enable-action-proposals", action="store_true",
        help="allow the model to submit typed mitigation proposals for policy evaluation",
    )
    worker.add_argument("--max-cost-usd", type=float, default=0.25)
    worker.add_argument("--max-proposals", type=int, default=3)
    worker.add_argument("--max-context-bytes", type=int, default=32768)
    worker.add_argument("--lease-seconds", type=int, default=120)
    worker.set_defaults(func=_cmd_worker)

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
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
