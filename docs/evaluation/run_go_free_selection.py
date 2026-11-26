"""Run port-only investigations and supplied-sample controls on a zero-priced Go model."""
import argparse
import json
import os
import time
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request

from defsec_reasoner import chatgpt_auth, models
from defsec_reasoner.subscriptions import GO, OpenCodeGoAdapter
from run_followup_pilot import FIXTURE, run_case
from run_luna_selection import CASES, COLLECTORS, HOST, episode

FREE_MODELS = ("beam-free", "hungerg-free")


def check_catalog(model, effort):
    req = Request("https://opencode.ai/console/api/v1/models", headers=OpenCodeGoAdapter._headers())
    with chatgpt_auth.opener().open(req, timeout=15) as response:
        entry = json.load(response)["opencode-go"]["models"][model]
    rates = entry["cost"]["text"]
    if (entry["type"] != "chat" or entry["capabilities"]["tools"]["supported"] is not True
            or rates["input"]["price"] != 0 or rates["output"]["price"] != 0):
        raise ValueError(f"{model} is no longer a zero-priced Go tool model")
    if effort and effort not in entry["capabilities"].get("reasoning", {}).get("effort", []):
        raise ValueError(f"{model} does not advertise {effort} reasoning effort")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", choices=FREE_MODELS)
    parser.add_argument("output", type=Path)
    parser.add_argument("--initial-turns", type=int, default=4)
    parser.add_argument("--initial-tokens", type=int, default=24000)
    parser.add_argument("--initial-seconds", type=int, default=75)
    parser.add_argument("--beam-effort", choices=("default", "low", "medium", "high", "xhigh", "max"),
                        default="high", help="Beam reasoning effort (default: high). Use 'default' to omit the field.")
    fixture = json.loads(FIXTURE.read_text())
    controls = {case["id"]: case for case in fixture["cases"]}
    parser.add_argument("cases", choices=[*CASES, *controls], nargs="+")
    args = parser.parse_args()
    if min(args.initial_turns, args.initial_tokens, args.initial_seconds) < 1 or args.initial_seconds > 870:
        parser.error("initial limits must be positive and the initial deadline must fit the 900-second lease")
    effort = args.beam_effort if args.model == "beam-free" and args.beam_effort != "default" else None
    check_catalog(args.model, effort)
    adapter = OpenCodeGoAdapter(args.model, effort=effort)
    adapter.timeout = 25
    grant = [{"endpoint": GO, "host_id": HOST, "collectors": COLLECTORS}]
    send = models._http_json
    failed = False
    with args.output.open("x") as out, patch.dict(os.environ, DEFSEC_DISCOVERY_EXPORT_GRANTS=json.dumps(grant)):
        for case in args.cases:
            row = {"model": args.model, "case": case, "requests": [], "pass": False}
            if case in CASES:
                row["initial_limits"] = dict(turns=args.initial_turns, tokens=args.initial_tokens,
                                             seconds=args.initial_seconds)
            sessions = []

            def observe(url, body, headers, timeout):
                assert url == GO + "/chat/completions" and body["model"] == args.model
                session = headers["x-opencode-session"]
                if session not in sessions:
                    sessions.append(session)
                request = {"session": sessions.index(session) + 1,
                           "requested_effort": body.get("reasoning_effort")}
                row["requests"].append(request)
                start = time.monotonic()
                try:
                    reply = send(url, body, headers, timeout)
                    choice = reply["choices"][0]
                    request.update(returned_model=reply.get("model"), usage=reply.get("usage"),
                                   finish=choice.get("finish_reason"),
                                   tools=[c["function"]["name"] for c in choice["message"].get("tool_calls") or []])
                    return reply
                except Exception as exc:
                    request["error"] = type(exc).__name__
                    raise
                finally:
                    request["ms"] = round(1000 * (time.monotonic() - start))

            try:
                with patch.object(models, "_http_json", observe):
                    if case in controls:
                        run_case(controls[case], fixture["question"], adapter, row)
                        row["pass"] = all(row.get(k) for k in ("decision_pass", "citation_pass", "audit_valid"))
                    else:
                        episode(case, row, adapter, args.model, turns=args.initial_turns,
                                tokens=args.initial_tokens, seconds=args.initial_seconds)
            except Exception as exc:
                row["pass"] = False
                row["harness_error"] = type(exc).__name__
            failed |= not row["pass"]
            out.write(json.dumps(row) + "\n")
            out.flush()
            print(args.model, case, row["pass"], len(row["requests"]), flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
