"""Run one OpenAI investigator configuration against the frozen P18 and P14 cases."""
import argparse
import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import run_followup_pilot as followup
import run_phase18 as episodes
from defsec_reasoner import models

ENDPOINT = "https://api.openai.com/v1"
FUNCTION_CALL = "function_call"
TOOL_ID = "_".join(("call", "id"))
PROFILES = {
    "luna-high": ("gpt-6-luna", "high"),
    "luna-max": ("gpt-6-luna", "max"),
    "terra-medium": ("gpt-6.1-terra", "medium"),
    "terra-high": ("gpt-6.1-terra", "high"),
    "sol-low": ("gpt-6.2-sol", "low"),
    "sol-medium": ("gpt-6.2-sol", "medium"),
}


class ResponsesTransport:
    """Replay the worker's tool history using the matching Responses output items."""

    def __init__(self, tier="flex"):
        self.history = {}
        self.tier = tier
        self.capacity_rejections = []

    def post(self, url, payload, key, timeout):
        self.capacity_rejections = []
        headers = {"Authorization": " ".join(("Bearer", key))}
        deadline = time.monotonic() + timeout
        for attempt in range(7):
            start = time.monotonic()
            try:
                return followup.HTTP_JSON(url, payload, headers,
                                          max(0.001, deadline - start))
            except models.ProviderError as exc:
                prefix = "provider HTTP 429: "
                if self.tier != "flex" or not str(exc).startswith(prefix):
                    raise
                try:
                    code = json.loads(str(exc)[len(prefix):]).get("error", {}).get("code")
                except (ValueError, AttributeError):
                    code = None
                if code != "flex_unavailable":
                    raise
                delay = min(16, 2 ** (attempt + 1))
                entry = {"ms": round((time.monotonic() - start) * 1000), "backoff_s": 0}
                self.capacity_rejections.append(entry)
                if attempt == 6 or time.monotonic() + delay + 1 >= deadline:
                    raise
                entry["backoff_s"] = delay
                time.sleep(delay)

    def send(self, body, key, timeout, effort):
        items = []
        for message in body["messages"]:
            if message.get("tool_calls"):
                items.extend(self.history[message["tool_calls"][0]["id"]])
            elif message["role"] == "tool":
                items.append({"type": f"{FUNCTION_CALL}_output", TOOL_ID: message[f"tool_{TOOL_ID}"],
                              "output": message["content"]})
            else:
                items.append({"role": message["role"], "content": message["content"]})
        request = dict(model=body["model"], input=items, reasoning={"effort": effort},
                       store=False, include=["reasoning.encrypted_content"], service_tier=self.tier,
                       max_output_tokens=body["max_completion_tokens"])
        if body.get("tools"):
            request["tools"] = [dict(type="function", strict=False, **tool["function"])
                                for tool in body["tools"]]
            request["tool_choice"] = body["tool_choice"]
        reply = self.post(ENDPOINT + "/responses", request, key, timeout)
        output = reply.get("output", [])
        calls = [{"id": item[TOOL_ID], "type": "function",
                  "function": {"name": item["name"], "arguments": item["arguments"]}}
                 for item in output if item["type"] == FUNCTION_CALL]
        if calls:
            self.history[calls[0]["id"]] = output
        content = "".join(part["text"] for item in output if item["type"] == "message"
                          for part in item["content"] if part["type"] == "output_text")
        usage = reply["usage"]
        normalized = dict(prompt_tokens=usage["input_tokens"], completion_tokens=usage["output_tokens"],
                          total_tokens=usage["total_tokens"], prompt_tokens_details=usage["input_tokens_details"],
                          completion_tokens_details=usage["output_tokens_details"])
        finish = ("length" if reply["status"] == "incomplete" else
                  "tool_calls" if calls else "stop")
        return dict(model=reply["model"], service_tier=reply.get("service_tier"),
                    reported_effort=reply["reasoning"]["effort"], usage=normalized,
                    choices=[dict(message=dict(content=content, tool_calls=calls), finish_reason=finish)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=PROFILES)
    parser.add_argument("output", type=Path)
    parser.add_argument("--transport", choices=("chat", "responses"), default="responses")
    parser.add_argument("--tier", choices=("flex", "default"), default="flex")
    args = parser.parse_args()
    if not episodes.BINARY:
        parser.error("build control-d first")
    key = os.environ.pop("OPENAI_API_KEY")
    model, effort = PROFILES[args.profile]
    adapter = models.OpenAICompatibleAdapter(base_url=ENDPOINT, model_id=model, timeout=25)
    fixture = json.loads(followup.FIXTURE.read_text())
    grant = [{"endpoint": ENDPOINT, "host_id": episodes.HOST,
              "collectors": [*episodes.COLLECTORS, episodes.PACKAGES]}]
    cases = [("episode", case, None) for case in episodes.CASES]
    cases.extend(("followup", case["id"], case) for case in fixture["cases"])
    failed = False
    with (args.output.open("x") as output, patch.object(episodes, "MODEL", model),
          patch.dict(os.environ, DEFSEC_DISCOVERY_EXPORT_GRANTS=json.dumps(grant))):
        for suite, case, sample in cases:
            transport = ResponsesTransport(args.tier)
            row = dict(transport=args.transport, requested_tier=args.tier, profile=args.profile, model=model, effort=effort, case=case, suite=suite,
                       requests=[], verified_claims=0, operator_interventions=0)
            row["pass"] = False
            started = time.monotonic()

            def observe(url, body, headers, timeout):
                assert url == ENDPOINT + "/chat/completions" and body["model"] == model
                wire = dict(timeout_s=timeout, limit=body.get("max_completion_tokens"))
                row["requests"].append(wire)
                start = time.monotonic()
                try:
                    if args.transport == "responses":
                        reply = transport.send(body, key, timeout, effort)
                    else:
                        reply = transport.post(url, {**body, "reasoning_effort": effort, "service_tier": args.tier},
                                               key, timeout)
                except Exception as error:
                    wire["error"] = str(error).replace(key, "[redacted]")
                    raise
                finally:
                    wire["ms"] = round((time.monotonic() - start) * 1000)
                    wire["flex_capacity_rejections"] = transport.capacity_rejections
                choice = reply["choices"][0]
                wire.update(returned_model=reply.get("model"), usage=reply.get("usage"),
                            tier=reply.get("service_tier"), reported_effort=reply.get("reported_effort"), finish=choice.get("finish_reason"),
                            tools=[c["function"]["name"] for c in choice["message"].get("tool_calls") or []])
                return reply

            try:
                with patch.object(models, "_http_json", observe):
                    if suite == "episode":
                        episodes.episode(case, "adaptive-live", adapter, row)
                    else:
                        followup.run_case(sample, fixture["question"], adapter, row)
                        row["pass"] = all(row.get(k) for k in ("audit_valid", "decision_pass", "citation_pass"))
            except Exception as error:
                row["pass"] = False
                row["harness_error"] = f"{type(error).__name__}: {error}".replace(key, "[redacted]")
            row["elapsed_ms"] = round((time.monotonic() - started) * 1000)
            failed |= not row["pass"]
            output.write(json.dumps(row).replace(key, "[redacted]") + "\n")
            output.flush()
            print(args.profile, suite, case, row["pass"], len(row["requests"]), flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
