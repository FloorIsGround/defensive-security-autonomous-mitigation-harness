"""Serial Phase 14 model pilot against a disposable control-d per case."""
import argparse
import json
import os
import time
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from test_live_integration import BINARY, COLLECTORS, HOST, LiveIntegrationTests, systemd_snapshot

from defsec_reasoner import models
from defsec_reasoner.worker import ReasonerWorker, RunBudgets

GO = "https://opencode.ai/inference/go/openai/v1"
REFLECTION = "https://api.reflection.ai/openai/v1"
OPENROUTER = "https://openrouter.ai/api/v1"
HTTP_JSON = models._http_json
FIXTURE = Path(__file__).with_name("followup-cases-v1.json")


def run_case(case, question, adapter, row):
    lab = LiveIntegrationTests()
    lab.setUp()
    try:
        lab._fire_sockets_trigger()
        origin = lab._client()
        incident = lab.admin.list_incidents()[0]["incident_id"]
        run = origin.start_investigation_run(incident, "pilot", "script", "v1")["run_id"]
        proposal = origin.propose_ephemeral_watch(run, "question-1", lab._ephemeral_spec(incident), question)
        assert proposal["decision"]["allowed"]
        origin.finish_investigation_run(run, {
            "status": "budget_exhausted", "budget_stop_reason": "max_turns",
            "summary": "Awaiting unit state", "turns": 1, "tool_calls": 1,
            "input_tokens": 0, "output_tokens": 0, "findings": 0,
            "proposals": 1, "proposals_accepted": 1,
        })
        token = lab.admin.mint_capability_token(
            "pilot", "investigator", [HOST], COLLECTORS, may_spawn_runs=True,
        )["token"]
        client = lab._client(token)
        query = {"op": "list_watch_followups", "incident_id": incident}
        sample = systemd_snapshot(
            "ghost.service", active_state=case["active_state"], sub_state=case["sub_state"],
        )
        assert lab.agent.push_snapshot("eph-ghost", 1, sample, collector="systemd.unit_state")
        job = client.call(query)["followups"][0]
        assert job["status"] == "ready"
        row["expected_observation_id"] = job["observation_id"]
        worker = ReasonerWorker(client, adapter, followups_only=True, budgets=RunBudgets(
            max_turns=1, max_total_tokens=4096, max_wall_seconds=60,
        ))
        start = time.monotonic()
        result = worker.run_once()
        row.update(worker_status=result.status, worker_ms=round(1000 * (time.monotonic() - start)))
        findings = client.get_incident_context(incident)["findings"]
        if len(findings) == 1:
            finding = findings[0]["finding"]
            row["interpretation"] = finding["interpretation"]
            row["citations"] = finding["evidence_observation_ids"]
            row["summary"] = redact(result.summary)
            row["decision_pass"] = row["interpretation"] == case["expected"]
            row["citation_pass"] = row["citations"] == [job["observation_id"]]
        row["audit_valid"] = lab.admin.verify_audit_chain()["valid"]
    finally:
        lab.tearDown()


def redact(value):
    for name in ("REFLECTION_API_KEY", "OPENCODE_GO_API_KEY", "OPENROUTER_API_KEY"):
        if os.environ.get(name):
            value = value.replace(os.environ[name], "[redacted]")
    return value


def record_wire(requests, go):
    def observe(url, body, headers, timeout):
        if go:
            headers = {**headers, "User-Agent": "defsec-followup-pilot/1.0",
                       "x-opencode-session": str(uuid4())}
        wire = {"url": url, "requested_model": body["model"]}
        wire.update({k: body[k] for k in ("max_tokens", "max_completion_tokens", "reasoning_effort") if k in body})
        requests.append(wire)
        start = time.monotonic()
        try:
            reply = HTTP_JSON(url, body, headers, timeout)
        except models.ProviderError as exc:
            wire["error"] = redact(str(exc))
            raise
        finally:
            wire["ms"] = round(1000 * (time.monotonic() - start))
        choice = (reply.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        wire.update(
            returned_model=reply.get("model"), provider=reply.get("provider"), finish_reason=choice.get("finish_reason"),
            usage=reply.get("usage"), allowance=(reply.get("opencode") or {}).get("allowance"),
            reasoning_characters=len(message.get("reasoning_content") or ""),
            tool_calls=json.loads(redact(json.dumps(message.get("tool_calls") or []))),
        )
        return reply

    return observe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--openrouter", action="store_true", help="use the configured OpenRouter route")
    parser.add_argument("--beam-effort", choices=("high", "default"), default="high",
                        help="use 'default' to replay the original pilot with no effort field")
    args = parser.parse_args()
    if not BINARY:
        parser.error("build control-d first with cargo build -p control-d")
    fixture = json.loads(FIXTURE.read_text())
    go_key = "OPENCODE_GO_API_KEY"
    beam = (REFLECTION, "Beam-1.0-501B-A23B", "REFLECTION_API_KEY")
    if not os.environ.get(beam[2]):
        beam = (GO, "beam-free", go_key)
    routes = (beam, (GO, "glm-5.3", go_key), (GO, "glm-5.3-flash", go_key))
    if args.openrouter:
        routes = tuple((OPENROUTER, model, "OPENROUTER_API_KEY") for model in (
            "reflection/beam-1.0-501b-a23b", "z-ai/glm-5.3", "z-ai/glm-5.3-flash",
        ))
    failed = False
    with args.output.open("x") as output:
        for url, model, key in routes:
            for case in fixture["cases"]:
                row = {"model": model, "base_url": url, "case": case["id"],
                       "expected": case["expected"], "requests": [],
                       "decision_pass": False, "citation_pass": False}
                if os.environ.get(key):
                    adapter = models.OpenAICompatibleAdapter(
                        base_url=url, model_id=model, api_key_env=key, timeout=60,
                        completion_token_field="max_tokens",
                    )
                    if model in ("beam-free", "Beam-1.0-501B-A23B", "reflection/beam-1.0-501b-a23b"):
                        adapter.effort = args.beam_effort if args.beam_effort != "default" else None
                    try:
                        grant = {"host_id": HOST, "collectors": COLLECTORS, "endpoint": url}
                        with patch.dict(os.environ, {"DEFSEC_DISCOVERY_EXPORT_GRANTS": json.dumps([grant])}), \
                                patch.object(models, "_http_json", record_wire(row["requests"], url == GO)):
                            run_case(case, fixture["question"], adapter, row)
                    except Exception as exc:
                        row["harness_error"] = redact(str(exc))
                        row["worker_status"] = "harness_error"
                else:
                    row["worker_status"] = "credential_unavailable"
                row["verified_conclusion"] = (
                    row["decision_pass"] and row["citation_pass"] and case["expected"] != "unresolved"
                )
                failed |= not all(row.get(key) for key in ("decision_pass", "citation_pass", "audit_valid"))
                output.write(json.dumps(row) + "\n")
                output.flush()
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
