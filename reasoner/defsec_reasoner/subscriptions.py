"""Subscription-backed transports for normalized investigator turns."""

from __future__ import annotations

import json
import os
import stat
import time
import uuid
from pathlib import Path
from urllib import error, request

from . import chatgpt_auth
from .models import (
    ModelAdapter,
    ModelTurnResult,
    OpenAICompatibleAdapter,
    ProviderError,
    ToolCall,
    TurnBudget,
    _discovery_transport,
    _estimate_payload,
)

GO = "https://opencode.ai/inference/go/openai/v1"
NAMESPACE = "investigator"
_MAX_KEY_FILE_BYTES = 4096


class OpenCodeGoAdapter(OpenAICompatibleAdapter):
    def __init__(self, model_id, effort=None):
        super().__init__(
            base_url=GO,
            model_id=model_id,
            completion_token_field="max_tokens",
            price_per_mtok_input=0,
            price_per_mtok_output=0,
        )
        self.effort = effort

    @staticmethod
    def _headers(budget=None):
        key = os.environ.get("OPENCODE_GO_API_KEY")
        if not key:
            path = os.environ.get("OPENCODE_GO_API_KEY_FILE") or auth_key_file()
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as source:
                    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                        raise ProviderError("OpenCode Go credential file must be a regular file", False)
                    data = source.read(_MAX_KEY_FILE_BYTES + 1)
                if len(data) > _MAX_KEY_FILE_BYTES:
                    raise ProviderError("OpenCode Go credential file exceeds the size limit", False)
                key = data.decode("utf-8").strip()
            except (OSError, ValueError):
                raise ProviderError("OpenCode Go credential file is unreadable", False) from None
        if not key:
            raise ProviderError("OpenCode Go requires OPENCODE_GO_API_KEY or OPENCODE_GO_API_KEY_FILE", False)
        conversation = budget.session_id if budget else None
        session = (
            uuid.uuid5(uuid.NAMESPACE_URL, "defsec-investigator/" + conversation)
            if conversation
            else uuid.uuid4()
        )
        return {
            "Authorization": "Bearer " + key,
            "User-Agent": "defsec-investigator/0.1",
            "x-opencode-session": "ses_" + session.hex,
        }

    @classmethod
    def available_models(cls):
        """List tool-capable chat models from this key's Go workspace catalog."""
        req = request.Request("https://opencode.ai/console/api/v1/models", headers=cls._headers())
        try:
            with chatgpt_auth.opener().open(req, timeout=15) as response:
                data = response.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024:
                raise ProviderError("OpenCode workspace catalog exceeds size limit", False)
            catalog = json.loads(data)
            entries = catalog.get("opencode-go", {}).get("models", {})
            return [
                (model_id, model.get("name", model_id))
                for model_id, model in entries.items()
                if model.get("type") == "chat"
                and model.get("capabilities", {}).get("tools", {}).get("supported") is True
            ]
        except error.HTTPError as exc:
            raise chatgpt_auth.http_failure("OpenCode workspace catalog", exc) from None
        except OSError as exc:
            raise ProviderError("OpenCode workspace catalog unavailable", True) from exc
        except (ValueError, TypeError, AttributeError) as exc:
            raise ProviderError("Invalid OpenCode workspace catalog", False) from exc

    def _chat(self, messages, tools, budget):
        guard = _discovery_transport.set(True)
        try:
            return super()._chat(messages, tools, budget)
        finally:
            _discovery_transport.reset(guard)


def auth_key_file():
    root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    return root / "defsec-reasoner" / "opencode-go.key"


def stream_response(body, token, budget):
    req = request.Request(
        chatgpt_auth.RESOURCE + "/responses",
        data=json.dumps(body).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
        },
    )
    try:
        with chatgpt_auth.opener().open(req, timeout=budget.request_timeout(60)) as response:
            # The direct plan endpoint can label its SSE frames as text/plain.
            if response.headers.get_content_type() not in {"text/event-stream", "text/plain"}:
                raise ProviderError("ChatGPT returned an unexpected response format", False)
            return completed_event(response, budget)
    except error.HTTPError as exc:
        raise chatgpt_auth.http_failure("ChatGPT Responses", exc) from None
    except (OSError, EOFError) as exc:
        raise ProviderError("ChatGPT stream interrupted", True) from exc


def completed_event(stream, budget):
    parts = []
    consumed = 0
    while True:
        budget.request_timeout(60)
        line = stream.readline(1024 * 1024 + 1)
        if not line:
            raise ProviderError("ChatGPT stream ended before completion", True)
        consumed += len(line)
        if len(line) > 1024 * 1024 or consumed > 8 * 1024 * 1024:
            raise ProviderError("ChatGPT stream exceeds size limit", False)
        if line.startswith(b"data:"):
            parts.append(line[5:].strip())
        elif not line.strip() and parts:
            try:
                event = json.loads(b"\n".join(parts))
                kind = event["type"]
                if kind == "response.completed" and event["response"]["status"] == "completed":
                    return event["response"]
                if kind in {"response.incomplete", "response.failed", "error"}:
                    raise ProviderError("ChatGPT stream returned " + kind, False)
            except (TypeError, ValueError, KeyError) as exc:
                raise ProviderError("Invalid ChatGPT stream event", False) from exc
            parts.clear()


class ChatGPTPlanAdapter(ModelAdapter):
    base_url = chatgpt_auth.RESOURCE

    def __init__(self, model_id, profile="default", effort=None):
        self.model_id = model_id
        self.profile = profile
        self.effort = effort

    def chat(self, messages, tools):
        return self.chat_with_budget(messages, tools, TurnBudget(100000, time.monotonic() + 60))

    def chat_with_budget(self, messages, tools, budget):
        items = []
        for msg in messages:
            if msg["role"] == "tool":
                items.append(
                    {"type": "function_call_output", "call_id": msg["tool_call_id"], "output": msg["content"]}
                )
                continue
            if msg.get("response_items"):
                items.extend(msg["response_items"])
                continue
            role = "developer" if msg["role"] == "system" else msg["role"]
            items.append({"role": role, "content": msg["content"]})
        body = {
            "model": self.model_id,
            "input": items,
            "store": False,
            "stream": True,
            "include": ["reasoning.encrypted_content"],
        }
        if budget.effort or self.effort:
            body["reasoning"] = {"effort": budget.effort or self.effort}
        if tools:
            body["tools"] = [
                {
                    "type": "namespace",
                    "name": NAMESPACE,
                    "description": "Scoped investigation tools",
                    "tools": [dict(t, type="function", strict=False) for t in tools],
                }
            ]
        limit = budget.completion_limit(_estimate_payload(body))
        budget.request_timeout(60)
        reply = stream_response(body, chatgpt_auth.bearer(self.profile), budget)
        budget.request_timeout(60)
        try:
            usage = reply["usage"]
            inp, out = usage["input_tokens"], usage["output_tokens"]
            if type(inp) is not int or type(out) is not int or min(inp, out) < 0:
                raise ValueError()
            # Direct plan requests have no server-side completion cap. Return usage
            # for accounting but discard any tool calls from an over-budget response.
            over = out > limit or inp + out >= budget.remaining_tokens
            calls, text = [], []
            for item in reply["output"] if not over else []:
                if item["type"] == "message":
                    text.extend(p["text"] for p in item["content"] if p["type"] == "output_text")
                elif item["type"] == "function_call":
                    if item.get("namespace") != NAMESPACE or item["name"] not in {t["name"] for t in tools}:
                        raise ValueError()
                    arguments = json.loads(item["arguments"])
                    if not isinstance(arguments, dict) or not item["call_id"]:
                        raise ValueError()
                    calls.append(ToolCall(item["name"], arguments, item["call_id"]))
            return ModelTurnResult(
                calls,
                "".join(text) or None,
                inp,
                out,
                0,
                "budget_exhausted" if over else "tool_calls" if calls else "stop",
                cached_input_tokens=(usage.get("input_tokens_details") or {}).get("cached_tokens", 0),
                cache_creation_input_tokens=(usage.get("input_tokens_details") or {}).get(
                    "cache_write_tokens", 0
                ),
                reasoning_tokens=(usage.get("output_tokens_details") or {}).get("reasoning_tokens", 0),
                response_items=reply["output"] if calls else None,
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise ProviderError("Invalid ChatGPT response or tool call", False) from exc
