"""OpenAI evidence selection on independently scoped synthetic incidents."""
import argparse
import json
import os
import time
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from run_openai_investigator import ENDPOINT, PROFILES, ResponsesTransport
from run_phase18 import COLLECTORS, HOST, UNIT, LiveIntegrationTests, _base_sockets, models, worker
from test_live_integration import socket_entry, sockets_snapshot, systemd_snapshot

CASES = {
    "archive": (7124, "archive-export.service", "active"),
    "index": (6328, "index-reader.service", "inactive"),
    "mail": (7413, "mail-spool.service", "unknown"),
    "ledger": (6247, "ledger-copy.service", "missing"),
    "media": (7529, "media-queue.service", "inactive"),
    "metrics": (6851, "metric-store.service", "active"),
}
MODEL = "gpt-6-luna"


def episode(case, row, adapter, model_id=MODEL, *, turns=4, tokens=24000, seconds=75,
            completion=4096, followup_tokens=4096, followup_seconds=60):
    port, unit, state = CASES[case]
    lab = LiveIntegrationTests()
    lab.setUp()
    try:
        base = _base_sockets()
        target = socket_entry(f"tcp:0.0.0.0:{port}:uid=0", port=port, inode=8000 + port,
                              pid=602, comm="worker", systemd_unit=unit)
        distractor = socket_entry("tcp:0.0.0.0:8125:uid=0", port=8125, pid=583,
                                  comm="worker", systemd_unit="event-relay.service")
        additions = [target, distractor] if port % 2 else [distractor, target]
        assert lab.agent.push_snapshot("w-sockets", 1, sockets_snapshot(base))
        assert lab.agent.push_snapshot("w-sockets", 1, sockets_snapshot(base + additions))
        client = lab._client()
        incident = lab.admin.list_incidents()[0]["incident_id"]
        objective = (f"Determine whether the service associated with the newly observed TCP port {port} "
                     "was running when independently checked. Record what the evidence supports. "
                     "Further observations can arrive after this run returns.")
        trigger_token = lab.admin.mint_capability_token("selection-trigger", "investigator", [HOST], COLLECTORS)["token"]
        initial = worker.ReasonerWorker(lab._client(trigger_token), adapter, model_id=model_id, budgets=worker.RunBudgets(
            max_turns=turns, max_total_tokens=tokens, max_wall_seconds=seconds,
            lease_seconds=max(120, seconds + 30), max_completion_tokens=completion, max_proposals_per_run=1,
            max_rule_proposals_per_run=0))
        original = worker.build_system_prompt
        with patch.object(worker, "build_system_prompt",
                          lambda *a, **kw: original(*a, **kw) + "\nOperator objective: " + objective):
            row["initial"] = asdict(initial.run_once())
        def findings():
            return [e["finding"] for e in client.get_incident_context(incident)["findings"]]
        row["initial_findings"] = findings()
        lab.agent.drain(0.5)
        watches = [w for w in lab.agent.watches() if w.get("incident_id") == incident]
        row["watches"] = watches
        query = {"op": "list_watch_followups", "incident_id": incident}
        jobs = client.call(query)["followups"]
        selected = (len(watches) == 1 and watches[0]["host_id"] == HOST and
                    watches[0]["collector"]["type"] == UNIT and
                    watches[0]["collector"]["parameters"].get("unit") == unit)
        row["selected"] = selected
        durable = selected and len(jobs) == 1 and jobs[0]["watch_id"] == watches[0]["id"]
        if durable and state != "missing":
            sub = {"active": "running", "inactive": "dead", "unknown": "unknown"}[state]
            watch = watches[0]
            assert lab.agent.push_snapshot(watch["id"], watch["version"],
                                           systemd_snapshot(unit, active_state=state, sub_state=sub),
                                           collector=UNIT)
            ready, = client.call(query)["followups"]
            assert ready["status"] == "ready" and ready["observation_id"] is not None
            row["fresh_ref"] = ready["observation_id"]
            token = lab.admin.mint_capability_token("selection-followup", "investigator", [HOST],
                                                    COLLECTORS, may_spawn_runs=True)["token"]
            followup = worker.ReasonerWorker(lab._client(token), adapter, model_id=model_id,
                                            followups_only=True, budgets=worker.RunBudgets(
                                                max_turns=1, max_total_tokens=followup_tokens,
                                                max_wall_seconds=followup_seconds, max_completion_tokens=completion,
                                                lease_seconds=max(120, followup_seconds + 30)))
            result = followup.run_once()
            row["followup"] = asdict(result) if result else None
        row["jobs"] = client.call(query)["followups"]
        row["findings"] = findings()
        if state == "missing":
            verdict = durable and row["jobs"][0]["status"] == "awaiting_evidence" and not any(
                f.get("interpretation") in ("supports", "contradicts") for f in row["findings"])
        else:
            expected = {"active": "supports", "inactive": "contradicts", "unknown": "unresolved"}[state]
            verdict = durable and row["jobs"][0]["status"] == "answered" and any(
                f.get("interpretation") == expected and f["evidence_observation_ids"] == [row["fresh_ref"]]
                for f in row["findings"])
        row["audit_valid"] = lab.admin.verify_audit_chain()["valid"]
        row["pass"] = verdict and row["audit_valid"]
    finally:
        lab.tearDown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("cases", choices=CASES, nargs="+")
    parser.add_argument("--profile", choices=PROFILES, default="luna-max")
    parser.add_argument("--tier", choices=("flex", "default"), default="flex")
    parser.add_argument("--original-limits", action="store_true", help="replay the Luna High pilot's budgets and timeouts")
    args = parser.parse_args()
    key = os.environ.pop("OPENAI_API_KEY")
    model, effort = PROFILES[args.profile]
    limits = (dict(turns=4, tokens=24000, seconds=75, completion=4096, followup_tokens=4096, followup_seconds=60)
              if args.original_limits else
              dict(turns=4, tokens=192000, seconds=480, completion=8192, followup_tokens=16384, followup_seconds=240))
    adapter = models.OpenAICompatibleAdapter(base_url=ENDPOINT, model_id=model, timeout=25 if args.original_limits else 180)
    grant = [{"endpoint": ENDPOINT, "host_id": HOST, "collectors": COLLECTORS}]
    failed = False
    with args.output.open("x") as output, patch.dict(os.environ, DEFSEC_DISCOVERY_EXPORT_GRANTS=json.dumps(grant)):
        for case in args.cases:
            transport = ResponsesTransport(args.tier)
            row = dict(case=case, requests=[], profile=args.profile, model=model, effort=effort,
                       requested_tier=args.tier, limits=limits, request_timeout=adapter.timeout)
            row["pass"] = False

            def observe(url, body, headers, timeout):
                assert url == ENDPOINT + "/chat/completions" and body["model"] == model
                request = {}
                row["requests"].append(request)
                start = time.monotonic()
                try:
                    reply = transport.send(body, key, timeout, effort)
                    request.update(model=reply["model"], effort=reply["reported_effort"],
                                   tier=reply["service_tier"], usage=reply["usage"],
                                   tools=reply["choices"][0]["message"].get("tool_calls", []))
                    return reply
                except Exception as exc:
                    request["error"] = str(exc).replace(key, "[redacted]")
                    raise
                finally:
                    request["ms"] = round(1000 * (time.monotonic() - start))
                    request["flex_capacity_rejections"] = transport.capacity_rejections
            try:
                with patch.object(models, "_http_json", observe):
                    episode(case, row, adapter, model_id=model, **limits)
            except Exception as exc:
                row["pass"] = False
                row["harness_error"] = f"{type(exc).__name__}: {exc}"
            failed |= not row["pass"]
            output.write(json.dumps(row).replace(key, "[redacted]") + "\n")
            output.flush()
            print(case, row["pass"], row.get("harness_error", ""), flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
