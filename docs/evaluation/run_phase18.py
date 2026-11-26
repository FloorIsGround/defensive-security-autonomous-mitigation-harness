"""Run the frozen Phase 18 synthetic episode pilot against disposable control-d."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import time
from unittest.mock import patch

from run_followup_pilot import OPENROUTER, record_wire, redact
from test_live_integration import (
    BINARY, COLLECTORS, HOST, LiveIntegrationTests, _base_sockets,
    socket_entry, sockets_snapshot, systemd_snapshot,
)

from defsec_reasoner import models, worker
from defsec_reasoner.control_harness import (
    ControlDaemon, SyntheticAgent, sockets_watch_spec,
)
from defsec_reasoner.admin_client import AdminClient

SOCKETS = "sockets.listening"
PACKAGES = "packages.inventory"
UNIT = "systemd.unit_state"
MODEL = "z-ai/glm-5.3-flash"
CASES = ("quiet", "maintenance", "new-service", "missing")
LANES = ("static", "reactive-script", "adaptive-script", "reactive-live", "adaptive-live")
QUESTION = "Does ghost.service appear active/running in a fresh unit-state sample?"


def call(name, **arguments):
    return {"tool_calls": [{"name": name, "arguments": arguments}]}


def discovery(messages, _tools):
    samples = json.loads(messages[1]["content"])
    return {"final_text": json.dumps({
        "purpose": "Likely PostgreSQL host", "dependencies": ["PostgreSQL 16"],
        "uncertainty": "The package and listener do not establish process ownership.",
        "visibility_gaps": ["One sample does not establish continuity."],
        "proposed_watch": {"collector": SOCKETS, "rationale": "Track TCP 5432."},
        "citations": [sample["observation_id"] for sample in samples],
    })}


def assessment(messages, _tools):
    from defsec_reasoner.provenance import envelope_contents

    evidence = messages[-1]["content"]
    state = envelope_contents(evidence)[1]["data"]
    active = state.get("active_state") == "active" and state.get("sub_state") == "running"
    return call("assess_observation", interpretation="supports" if active else "unresolved",
                observation_id=int(re.search(r'observation_id="(\d+)"', evidence)[1]),
                summary="ghost.service was active/running." if active else "Unit state remains unknown.")


def quiet(lab, client, initial, row):
    if initial is None:
        client.advance_host_discovery(HOST)
    else:
        assert initial.run_once() is None
    scheduled = time.monotonic()
    lab.agent.drain(0.5)
    watches = {watch["collector"]["type"]: watch for watch in lab.agent.watches()
               if watch["id"] != "w-sockets"}
    assert set(watches) == {SOCKETS, PACKAGES}, list(watches)
    samples = {
        SOCKETS: sockets_snapshot([socket_entry("tcp:0.0.0.0:5432:uid=0", port=5432)]),
        PACKAGES: {"packages": [{"package_key": "postgresql-16:amd64", "name": "postgresql-16",
                                "arch": "amd64", "version": "16.1"}],
                   "total_packages": 1, "status_file_sha256": "0" * 64},
    }
    for collector, watch in watches.items():
        assert lab.agent.push_snapshot(watch["id"], watch["version"], samples[collector], collector=collector)
    if initial is None:
        client.advance_host_discovery(HOST)
    else:
        # The unpinned production discovery poll has a five-second debounce.
        time.sleep(max(0, scheduled + 5.1 - time.monotonic()))
        assert initial.run_once() is None
    observed = client.get_host_discovery_samples(HOST)
    saved = client.get_host_assessment(HOST).get("assessment") or {}
    row["discovery_refs"] = [sample["evidence"]["observation_id"] for sample in observed]
    row["discovery"] = saved.get("interpretations", [])
    row["verified_claims"] = sum(
        sorted(result["proposal"]["citations"]) == sorted(row["discovery_refs"])
        and len(row["discovery_refs"]) == 2
        and "postgresql" in result["proposal"]["purpose"].lower()
        and "likely" in result["proposal"]["purpose"].lower()
        for result in row["discovery"]
    )


def episode(case, lane, live, row):
    lab = LiveIntegrationTests()
    lab.daemon = ControlDaemon(BINARY).start()
    lab.agent = SyntheticAgent(
        lab.daemon.agent_sock, HOST,
        agent_version="test+host-discovery-v1" if case == "quiet" else "test",
    )
    try:
        lab.admin = AdminClient(lab.daemon.admin_sock)
        lab.admin.enroll_host(HOST)
        lab.admin.apply_baseline_watch(sockets_watch_spec(HOST), "phase18", "socket baseline")
        lab.agent.connect()
        client = lab._client(lab.admin.mint_capability_token(
            "phase18", "investigator", [HOST], [*COLLECTORS, PACKAGES],
        )["token"])
        adaptive = lane.startswith("adaptive")
        if case == "quiet":
            snapshot = sockets_snapshot([socket_entry("tcp:0.0.0.0:5432:uid=0", port=5432)])
            assert lab.agent.push_snapshot("w-sockets", 1, snapshot)
            initial = worker.ReasonerWorker(
                client, live or models.ScriptedMockAdapter([discovery]),
                model_id=MODEL if live else "scripted",
            ) if adaptive else None
            quiet(lab, client, initial, row)
        elif case == "maintenance":
            lab.admin.call({"admin_op": "create_expectation_rule", "actor": "phase18-operator",
                            "rule": lab._rule_spec()})
            row["operator_interventions"] = 1
            for sockets in (_base_sockets()[1:], _base_sockets()):
                assert lab.agent.push_snapshot("w-sockets", 1, sockets_snapshot(sockets))
            rules = lab.admin.call({"admin_op": "list_expectation_rules"})["rules"]
            row["rule_hits"] = sum(rule["hit_count"] for rule in rules)
        else:
            lab._fire_sockets_trigger()
            incident = lab.admin.list_incidents()[0]["incident_id"]
            row["incident_id"] = incident
            spec = lab._ephemeral_spec(incident)
            if lane != "static":
                investigator = lab._client(lab.admin.mint_capability_token(
                    "phase18-trigger", "investigator", [HOST], [*COLLECTORS, PACKAGES],
                )["token"])
                initial = worker.ReasonerWorker(
                    investigator, live or models.ScriptedMockAdapter([
                        call("propose_ephemeral_watch", spec=spec, rationale=QUESTION),
                        call("finish", summary="Awaiting asynchronous unit-state evidence."),
                    ]), model_id=MODEL if live else "scripted",
                    budgets=worker.RunBudgets(max_turns=3, max_wall_seconds=60,
                                              max_total_tokens=24000, max_proposals_per_run=1,
                                              max_rule_proposals_per_run=0))
                original_prompt = worker.build_system_prompt

                def prompt(*args, **kwargs):
                    return original_prompt(*args, **kwargs) + (
                        "\nOperator objective for this synthetic episode: ask whether ghost.service "
                        "is active/running using a fresh unit-state sample. Propose the following "
                        "scoped watch with the question as its rationale, then finish. "
                        "The sample can arrive only after the initial run returns. "
                        f"WatchSpec: {json.dumps(spec)}"
                    )

                with patch.object(worker, "build_system_prompt", prompt):
                    outcome = initial.run_once()
                row["initial"] = asdict(outcome) if outcome else None
                if outcome is not None and getattr(outcome, "error", None):
                    row["initial"]["error"] = redact(outcome.error)
            query = {"op": "list_watch_followups", "incident_id": incident}
            lab.agent.drain(0.5)
            watch = lab.agent.find_watch("eph-ghost")
            if watch and case == "new-service":
                sample = systemd_snapshot("ghost.service", active_state="active", sub_state="running")
                assert lab.agent.push_snapshot(watch["id"], watch["version"], sample, collector=UNIT)
            jobs = client.call(query)["followups"]
            row["manual_followup_required"] = not jobs
            row["fixture_delivery"] = ("withheld" if case == "missing"
                                       else "delivered" if watch else "no_watch")
            if adaptive:
                claimant = lab._client(lab.admin.mint_capability_token(
                    "phase18-followup", "investigator", [HOST], [*COLLECTORS, PACKAGES],
                    may_spawn_runs=True,
                )["token"])
                followup = worker.ReasonerWorker(
                    claimant, live or models.ScriptedMockAdapter([assessment]), followups_only=True,
                    model_id=MODEL if live else "scripted", budgets=worker.RunBudgets(
                        max_turns=1, max_total_tokens=4096, max_wall_seconds=60))
                result = followup.run_once()
                row["assessment_status"] = result.status if result else "no_ready_question"
            row["followups"] = client.call(query)["followups"]
            row["findings"] = [entry["finding"] for entry in client.get_incident_context(incident)["findings"]]
            fresh = [job["observation_id"] for job in jobs if job["observation_id"] is not None]
            row["fresh_refs"] = fresh
            row["verified_claims"] = sum(
                len(fresh) == 1 and finding.get("interpretation") == "supports"
                and finding["evidence_observation_ids"] == fresh
                and "active" in finding["summary"].lower() and "running" in finding["summary"].lower()
                for finding in row["findings"]
            )
        row["triggers"] = len(client.list_trigger_queue())
        row["audit_valid"] = lab.admin.verify_audit_chain()["valid"]
        row["pass"] = row["audit_valid"] and {
            "quiet": row["triggers"] == 0 and row["verified_claims"] == 1,
            "maintenance": row["triggers"] == 0 and row.get("rule_hits", 0) > 0,
            "new-service": row["triggers"] == 1 and row["verified_claims"] == 1,
            "missing": row["triggers"] == 1 and any(
                job["status"] == "awaiting_evidence" for job in row.get("followups", [])
            ) and not any(
                finding.get("kind") == "verified_finding" for finding in row.get("findings", [])
            ),
        }[case]
    finally:
        lab.tearDown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    if not BINARY:
        parser.error("build control-d first")
    grant = json.dumps([{"endpoint": OPENROUTER, "host_id": HOST, "collectors": [*COLLECTORS, PACKAGES]}])
    failed = False
    with args.output.open("x") as output, patch.dict(os.environ, DEFSEC_DISCOVERY_EXPORT_GRANTS=grant):
        for lane in LANES:
            for case in CASES:
                row = {"lane": lane, "case": case, "requests": [], "pass": False,
                       "verified_claims": 0, "operator_interventions": 0}
                start = time.monotonic()
                live = None
                if lane.endswith("-live") and args.live and os.environ.get("OPENROUTER_API_KEY"):
                    live = models.OpenAICompatibleAdapter(
                        base_url=OPENROUTER, model_id=MODEL, api_key_env="OPENROUTER_API_KEY",
                        timeout=25, completion_token_field="max_tokens")
                if lane.endswith("-live") and live is None:
                    row["availability"] = "credential_unavailable" if args.live else "live_disabled"
                else:
                    row["availability"] = "executed"
                    try:
                        with patch.object(models, "_http_json", record_wire(row["requests"], False)):
                            episode(case, lane, live, row)
                    except Exception as error:
                        row["pass"] = False
                        row["harness_error"] = redact(f"{type(error).__name__}: {error}")
                failed |= row["availability"] != "live_disabled" and not row["pass"]
                row["episode_ms"] = round(1000 * (time.monotonic() - start))
                output.write(json.dumps(row) + "\n")
                output.flush()
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
