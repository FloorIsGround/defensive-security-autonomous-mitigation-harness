"""Run Beam in the disposable fleet and the existing two-stage benchmark lab."""
import dataclasses
from functools import partial
import json
import os
import re
import subprocess
import sys
import time
from unittest.mock import patch

from defsec_reasoner import cli, worker
from defsec_reasoner.benchmark import BenchmarkRunner, GHOST_UNIT, HOST_ID, _base_sockets, _changed_sockets
from defsec_reasoner.control_harness import (
    sockets_snapshot, sockets_watch_spec, systemd_snapshot, unit_file_hash,
)
from defsec_reasoner.models import OpenAICompatibleAdapter, ProviderError
from defsec_reasoner.worker import ReasonerWorker, RunBudgets
from scenarios import COLLECTORS, Fleet, wait_for, write_json
from guests import BIN, RESULTS, STATE

MODEL = "Beam-1.0-501B-A23B"
BASE_URL = "https://api.reflection.ai/openai/v1"
MAX_TURNS = 6
MAX_TOKENS = 48000
MAX_WALL_SECONDS = 110
LEASE_SECONDS = 150


class BeamAdapter(OpenAICompatibleAdapter):
    def __init__(self, *args, **kwargs):
        super().__init__(base_url=BASE_URL, model_id=MODEL, timeout=45)
        self.effort = os.environ.get("DEFSEC_BENCH_BEAM_EFFORT", "high") or None
        self.throttles = 0

    def _chat(self, messages, tools, budget):
        try:
            return super()._chat(messages, tools, budget)
        except ProviderError as error:
            # Provider bodies can echo request fields. Preserve only the status.
            code = re.search(r"^provider HTTP (\d+):", str(error))
            if code:
                self.throttles += code[1] == "429"
            detail = f"provider HTTP {code[1]}" if code else "provider transport or decode error"
            raise ProviderError(detail, retryable=error.retryable) from None


def safe_tools(*, adaptive=False):
    allowed = {"propose_ephemeral_watch"} if adaptive else set()
    return [tool for tool in worker.INVESTIGATION_TOOLS
            if not tool["name"].startswith("propose_") or tool["name"] in allowed]


def safe_result(result, *tokens):
    text = json.dumps(result)
    for secret in (os.environ["DEFSEC_OPENAI_API_KEY"], *tokens):
        text = text.replace(json.dumps(secret)[1:-1], "[redacted]")
    return json.loads(text)


def worker_entry():
    # Use the actual worker CLI with fleet-only overrides for proposal kinds
    # that Phase 11 does not expose as switches.
    with (patch.object(worker, "RunBudgets", partial(
              RunBudgets, max_rule_proposals_per_run=0, max_action_proposals_per_run=0)),
          patch.object(worker, "INVESTIGATION_TOOLS", safe_tools()),
          patch.object(cli, "OpenAICompatibleAdapter", BeamAdapter)):
        return cli.main([
            "worker", "--socket", str(STATE / "control/investigate.sock"),
            "--backend", "openai", "--base-url", BASE_URL, "--model", MODEL,
            "--backend-id", "fleet-p13-beam", "--max-turns", str(MAX_TURNS),
            "--max-wall-seconds", str(MAX_WALL_SECONDS), "--max-total-tokens", str(MAX_TOKENS),
            "--max-proposals", "0", "--lease-seconds", str(LEASE_SECONDS),
            "--poll-interval", "15",
        ])


def worker_run(fleet, name, incident):
    result = {"scenario": name, "incident_id": incident["incident_id"]}
    cap = fleet.admin.mint_capability_token(
        f"fleet-beam-{name}", "investigator", [incident["host_id"]], COLLECTORS,
        incident_id=incident["incident_id"], ttl_seconds=360,
    )["token"]
    cmd = [sys.executable, __file__, "worker"]
    with subprocess.Popen(cmd, env={**os.environ, "DEFSEC_CAPABILITY_TOKEN": cap},
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as proc:
        def finished():
            if proc.poll() is not None:
                raise RuntimeError(f"Worker exited with code {proc.returncode}")
            runs = fleet.rpc.list_investigation_runs(incident_id=incident["incident_id"])
            return next((r for r in runs if r["status"] != "active"), None)

        try:
            result["run"] = wait_for(f"{name} terminal reasoner run", finished, 145)
        except (AssertionError, RuntimeError) as error:
            result["error"] = str(error)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
    if summary := result.get("run"):
        result["events"] = [event for event in fleet.rpc.get_run_events(summary["run_id"], limit=100)
                            if event["kind"] != "model_text"]
        finding = next((e for e in result["events"] if e["kind"] == "tool_result"
                        and e["detail"].get("tool") == "record_hypothesis_or_finding"
                        and e["detail"].get("ok")), None)
        if finding:
            result["first_finding_at"] = finding["created_at"]
        outcome = summary.get("outcome") or {}
        result["http_429s"] = int("provider HTTP 429" in outcome.get("summary", ""))
    return safe_result(result, cap)


class BenchmarkBeam(BeamAdapter):
    def __init__(self, agent, adaptive):
        super().__init__()
        self.agent = agent
        self.adaptive = adaptive
        self.followup_at = None
        self.watch_id = None

    def _chat(self, messages, tools, budget):
        # The scripted benchmark simulates a second agent observation after
        # an admitted follow-up watch. Feed the same fixture for actual Beam
        # proposals, using the ID Beam chose.
        if self.adaptive and self.followup_at is None:
            self.agent.drain(.25)
            for watch in self.agent.watches():
                if (watch["class"] == "ephemeral"
                    and watch["collector"]["type"] == "systemd.unit_state"
                    and watch["collector"]["parameters"]["unit"] == GHOST_UNIT):
                    watch_id = watch["id"]
                    snapshot = systemd_snapshot(
                        GHOST_UNIT, active_state="active", sub_state="running",
                        unit_files=[unit_file_hash("/etc/systemd/system/ghost.service",
                                                   "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", size=289)],
                    )
                    if self.agent.push_snapshot(watch_id, watch["version"], snapshot,
                                                collector="systemd.unit_state"):
                        self.watch_id = watch_id
                        self.followup_at = time.monotonic()
                    break
        return super()._chat(messages, tools, budget)


def two_stage(strategy):
    adaptive = strategy == "adaptive"
    runner = BenchmarkRunner(str(BIN / "control-d"), quiet=True)
    lab = runner._lab(f"beam-{strategy}")
    try:
        lab.apply(sockets_watch_spec(HOST_ID), "baseline sockets inventory")
        agent = lab.agent()
        assert agent.push_snapshot("w-sockets", 1, sockets_snapshot(_base_sockets()))
        trigger_at = time.monotonic()
        assert agent.push_snapshot("w-sockets", 1, sockets_snapshot(_changed_sockets()))
        adapter = BenchmarkBeam(agent, adaptive)
        budgets = RunBudgets(
            max_turns=MAX_TURNS, max_wall_seconds=MAX_WALL_SECONDS, max_total_tokens=MAX_TOKENS,
            max_proposals_per_run=int(adaptive), max_rule_proposals_per_run=0,
            max_action_proposals_per_run=0, lease_seconds=LEASE_SECONDS,
        )
        reasoner = ReasonerWorker(
            lambda: lab.client("investigator"), adapter,
            backend_id=f"fleet-benchmark-{strategy}", model_id=MODEL, budgets=budgets,
        )
        with patch.object(worker, "INVESTIGATION_TOOLS", safe_tools(adaptive=adaptive)):
            outcome = reasoner.run_once()
        observer = lab.client("observer")
        observations = observer.query_observations(HOST_ID, limit=100)
        return safe_result({
            "requested_effort": adapter.effort,
            "outcome": dataclasses.asdict(outcome) if outcome else None,
            "coverage": runner._coverage(observer),
            "followup_evidence_observations": sum(
                o["watch_id"] == adapter.watch_id and o["status"] == "ok" for o in observations
            ),
            "followup_seconds": round(adapter.followup_at - trigger_at, 3) if adapter.followup_at else None,
            "http_429s": adapter.throttles,
            "audit_valid": lab.admin.verify_audit_chain()["valid"],
        })
    finally:
        if "agent" in locals():
            agent.close()
        lab.close()


def benchmark_trials():
    results = {}
    for strategy in ("static", "adaptive"):
        try:
            results[strategy] = two_stage(strategy)
        except Exception as error:
            results[strategy] = {"error": type(error).__name__}
    return results


def main():
    if sys.argv[1:] == ["worker"]:
        return worker_entry()

    result = {"status": "skipped", "model": MODEL, "max_total_tokens_per_run": MAX_TOKENS,
              "max_turns_per_run": MAX_TURNS, "max_wall_seconds": MAX_WALL_SECONDS}
    if not os.environ.get("REFLECTION_API_KEY"):
        result["note"] = "REFLECTION_API_KEY is unset."
        write_json("beam.json", result)
        return 0

    os.environ["DEFSEC_OPENAI_API_KEY"] = os.environ["REFLECTION_API_KEY"]
    if sys.argv[1:] == ["benchmark"]:
        write_json("beam-benchmark.json", benchmark_trials())
        return 0

    result["status"] = "attempted"
    result["worker_runs"] = []
    result["benchmark"] = {}
    write_json("beam.json", result)
    raw = json.loads((RESULTS / "scenarios.json").read_text())
    fleet = Fleet()
    for name in ("rogue_listener", "config_tamper", "outbound_beacon"):
        incident = raw.get(name, {}).get("incident")
        if incident and any(trigger["status"] == "pending" for trigger in
                            fleet.rpc.list_trigger_queue(incident_id=incident["incident_id"])):
            result["worker_runs"].append(worker_run(fleet, name, incident))
            write_json("beam.json", result)
            break
    comparison = RESULTS / "beam-benchmark.json"
    result["benchmark"] = json.loads(comparison.read_text()) if comparison.is_file() else benchmark_trials()
    result["benchmark_summary"] = (
        f"Worker budget {MAX_TOKENS:,} tokens, {MAX_TURNS} turns and {MAX_WALL_SECONDS} seconds per run. "
        "The scripted benchmark has no provider switch. The Beam comparison used its two-stage "
        "fixtures, lab and coverage calculation, with separate static and adaptive tool sets."
    )
    observed = result["benchmark"]
    comparisons = all((row.get("outcome") or {}).get("status") == "completed"
                      and row["audit_valid"] for row in observed.values())
    followup = observed["adaptive"].get("followup_evidence_observations", 0)
    static = observed["static"].get("followup_evidence_observations", 0)
    fleet_complete = False
    for row in result["worker_runs"]:
        outcome = row.get("run", {}).get("outcome") or {}
        usage = outcome.get("input_tokens", 0) + outcome.get("output_tokens", 0)
        fleet_complete |= "first_finding_at" in row and usage <= MAX_TOKENS
    result["status"] = "pass" if comparisons and followup > static and fleet_complete else "fail"
    if result["status"] == "fail":
        result["note"] = ("The Beam comparison or fleet finding and token-budget assertion failed. "
                          "See the per-run outcomes, budget and follow-up sample counts.")
    write_json("beam.json", result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
