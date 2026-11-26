"""Collect service resource counters and render the fleet run report."""
import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import statistics
import sys
import time


def footprint():
    from guests import HOSTS, STATE, UNIT, guest
    pid = os.environ["FLEET_CONTROL_PID"]
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    agents = {}
    for role in HOSTS:
        response = guest(role, f"systemctl show {UNIT} -p MainPID -p InvocationID "
                         "-p MemoryCurrent -p MemoryPeak -p CPUUsageNSec -p MemoryMax -p NRestarts")
        agents[role] = dict(line.split("=", 1) for line in response.stdout.splitlines())
        # MemoryPeak is a counter for the current cgroup lifetime.
        agents[role]["memory_peak_cgroup"] = guest(
            role, f"cat /sys/fs/cgroup/system.slice/{UNIT}/memory.peak", check=False,
        ).stdout.strip() or None
    files = {p.name: p.stat().st_size for p in (STATE / "control").iterdir()
             if p.is_file() and not p.name.endswith((".key", ".hex"))}
    return {
        "sampled_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "monotonic_seconds": time.monotonic(),
        "control_rss_kib": int(next(line for line in status if line.startswith("VmRSS:")).split()[1]),
        "ledger_files_bytes": {k: v for k, v in files.items() if k.startswith("ledger")},
        "agents": agents,
    }


def read(path, default=""):
    return path.read_text() if path.is_file() else default


def load(path, default=None):
    return json.loads(path.read_text()) if path.is_file() else default


def read_inventory(path):
    lines = read(path).strip().splitlines()
    return json.loads(lines[-1]) if lines else None


def delta(end, start):
    if not end or not start:
        return None
    return (dt.datetime.fromisoformat(end) - dt.datetime.fromisoformat(start)).total_seconds()


def format_seconds(value):
    return f"{value:.3f}" if value is not None else "—"


def report(results, teardown_rc):
    provision = results / "provision.log"
    if provision.is_file():
        provision.write_text(re.sub(r"(defsec-p13-|fleet-run-)[0-9a-f]{24}",
                                    r"\1[run]", provision.read_text()))
    before_resources = read_inventory(results / "before.txt")
    after_resources = read_inventory(results / "after.txt")
    low, high = (int(os.environ[name]) for name in ("PVE_VMID_MIN", "PVE_VMID_MAX"))
    before = {row["vmid"]: row for row in before_resources or []}
    after = {row["vmid"]: row for row in after_resources or []}
    confirmed = (teardown_rc == 0 and before_resources is not None and after_resources is not None
                 and not any(low <= vmid <= high for vmid in after))
    for vmid, initial in before.items():
        final = after.get(vmid, {})
        confirmed &= all(initial[key] == final.get(key) for key in ("node", "type", "status"))
        if initial["status"] == "running":
            uptimes = initial["uptime"], final.get("uptime")
            confirmed &= all(type(value) is int for value in uptimes) and uptimes[1] >= uptimes[0]
    rows = load(results / "scenarios.json", {})
    guests = load(results / "guests.json", {})
    phase, exit_status = read(results / "exit-status.txt", "unknown\n1").splitlines()
    out = [
        "# Phase 13 fleet validation", "",
        "| Setting | Value |",
        "| --- | --- |",
        f"| Checkout at launch | `{read(results / 'base.txt').strip()}` |",
        f"| Workstation | {', '.join(read(results / 'workstation.txt').splitlines())} |",
        "| Hypervisor | Configured Proxmox node, bridge and storage |",
        "| Guest image | cached Ubuntu 24.04 cloud image, 1024 MiB, 2 vCPU each |",
        "| Fleet settings | 15 s watch interval, 8 s heartbeat, 36 s grace, 12 s sweep |",
        "| Agent service | unprivileged user, empty capability sets, 64 MiB cap, 20% CPU quota |",
        f"| Harness phase and exit | {phase}, {exit_status} |", "",
        "| Role | VMID | Address |", "| --- | ---: | --- |",
    ]
    for role, data in guests.items():
        out.append(f"| {role} | {data['vmid']} | {data['address']} |")
    out += ["", "| Scenario | Outcome | Action → observation (s) | Observation → trigger (s) | Observation → incident (s) |",
            "| --- | --- | ---: | ---: | ---: |"]
    latency = []
    for name, row in rows.items():
        observed = row.get("observation", {}).get("observed_at")
        triggered = row.get("trigger", {}).get("created_at")
        incident = row.get("incident", {}).get("updated_at" if row.get("reused_incident") else "created_at")
        lag = delta(incident, observed)
        if lag is not None:
            latency.append(lag)
        out.append(f"| {name} | {row['status']} | {format_seconds(delta(observed, row.get('action_at')))} "
                   f"| {format_seconds(delta(triggered, observed))} | {format_seconds(lag)} |")
    if latency:
        p95 = sorted(latency)[math.ceil(len(latency) * .95) - 1]
        out += ["", f"Observation-to-incident timing across {len(latency)} paired events (seconds, "
                f"guest and controller UTC clocks) had a minimum of {min(latency):.3f}, "
                f"median of {statistics.median(latency):.3f}, nearest-rank p95 of {p95:.3f}, "
                f"and maximum of {max(latency):.3f}."]
    for name, row in rows.items():
        for field in ("error", "note"):
            if row.get(field):
                out += ["", f"- **{name}** — {str(row[field]).strip()}"]
    if "maintenance_noise" in rows:
        row = rows["maintenance_noise"]
        if row.get("package_method"):
            out += ["", f"Maintenance fixture used {row['package_method']}."]
        if "rule_after" in row:
            out += [f"Rule hits increased from {row['rule_before']['hit_count']} "
                    f"to {row['rule_after']['hit_count']}."]
    truncation = rows.get("forced_truncation", {})
    if truncation.get("status") == "observed":
        out += ["", "The socket collector returns `truncated_rejected` at its hard cap "
                "(`crates/agent-d/src/collectors/sockets.rs:387`). The role's set-diff "
                "predicate rejects invalid samples (`crates/policy/src/predicate.rs:183`), "
                "so this signal is visible in observations and does not open a role incident."]
    if "heartbeat_to_incident_seconds" in rows.get("agent_liveness", {}):
        row = rows["agent_liveness"]
        out += ["", f"Liveness incident opened {row['heartbeat_to_incident_seconds']:.3f} s "
                f"after the last heartbeat and {delta(row['incident']['created_at'], row['action_at']):.3f} s "
                "after the stop command. Liveness was recorded directly in the audit chain."]
    start = rows.get("role_profiles", {}).get("footprint_before")
    final = rows.get("footprint", {}).get("final")
    if start and final:
        out += ["", "## Footprint", "",
                "| Agent | Current MiB | cgroup peak MiB | CPU seconds |",
                "| --- | ---: | ---: | ---: |"]
        for role, data in final["agents"].items():
            initial = start["agents"][role]
            if initial["InvocationID"] != data["InvocationID"]:
                if role == "desktop":
                    initial = rows.get("agent_liveness", {}).get("footprint_before_stop", initial)
                out.append(f"| {role} (before restart) | {agent_stats(initial)} |")
                role += " (after restart)"
            out.append(f"| {role} | {agent_stats(data)} |")
        initial_bytes = sum(start["ledger_files_bytes"].values())
        final_bytes = sum(final["ledger_files_bytes"].values())
        out += ["", f"Control RSS was {start['control_rss_kib']} KiB at baseline and "
                f"{final['control_rss_kib']} KiB at the final sample. Ledger files including SQLite "
                f"sidecars grew from {initial_bytes} to {final_bytes} bytes "
                f"over {final['monotonic_seconds'] - start['monotonic_seconds']:.1f} s."]
    beam = load(results / "beam.json", {})
    out += ["", "## Reasoner and adaptive vs static", ""]
    if beam:
        out.append(f"Beam {beam['status']}. {beam.get('note', '')}")
        for item in beam.get("worker_runs", []):
            summary = item.get("run", {})
            outcome = summary.get("outcome") or {}
            out.append(f"- {item['scenario']} yielded {summary.get('status', 'no run')}, "
                       f"{outcome.get('turns', 0)} turns, {outcome.get('tool_calls', 0)} tool calls, "
                       f"{outcome.get('input_tokens', 0)} input and {outcome.get('output_tokens', 0)} output tokens, "
                       f"{summary.get('findings_count', 0)} findings, {summary.get('proposals_count', 0)} proposals. "
                       f"Run start → first finding {format_seconds(delta(item.get('first_finding_at'), summary.get('started_at')))} s. "
                       f"Provider HTTP 429 count {item.get('http_429s', 0)}.")
        if "benchmark" in beam:
            out += ["", beam.get("benchmark_summary", ""), "",
                    "| Beam strategy | Coverage | Follow-up samples | Seconds to follow-up | Turns | Input / output tokens | HTTP 429s |",
                    "| --- | --- | ---: | ---: | ---: | ---: | ---: |"]
            for strategy, row in beam["benchmark"].items():
                if "error" in row:
                    out.append(f"| {strategy} | Error: {row['error']} | — | — | — | — | — |")
                    continue
                outcome = row["outcome"] or {}
                out.append(f"| {strategy} | {', '.join(row['coverage'])} | "
                           f"{row['followup_evidence_observations']} | "
                           f"{format_seconds(row['followup_seconds'])} | {outcome.get('turns', '—')} | "
                           f"{outcome.get('input_tokens', 0)} / {outcome.get('output_tokens', 0)} | "
                           f"{row['http_429s']} |")
    else:
        out.append("Beam was unavailable or the fleet stopped before the live-model step.")
    synthetic = read(results / "benchmark.md")
    if synthetic:
        out += ["", "### Existing scripted benchmark", "", synthetic]
    out += ["", "## Teardown", "",
            f"Confirmed: **{'yes' if confirmed else 'no'}**. "
            "The guarded cleanup checked the configured disposable range cluster-wide. "
            "The before/after snapshots record guest placement, status and uptime on the test node.",
            "", "Raw results are in `scenarios.json`, `beam.json` when present, and the adjacent logs.", ""]
    (results / "report.md").write_text("\n".join(out))
    (results / "teardown.json").write_text(json.dumps(
        {"confirmed": confirmed, "before": before_resources, "after": after_resources}, indent=2) + "\n")
    return int(not confirmed)


def agent_stats(agent):
    peak = agent["memory_peak_cgroup"] or agent["MemoryPeak"]
    return (f"{int(agent['MemoryCurrent']) / 2**20:.2f} | "
            f"{int(peak) / 2**20:.2f} | {int(agent['CPUUsageNSec']) / 1e9:.3f}")


if __name__ == "__main__":
    if sys.argv[1] == "report":
        sys.exit(report(Path(sys.argv[2]), int(sys.argv[3])))
    print(json.dumps(footprint(), indent=2))
