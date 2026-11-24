"""Replaceable model adapters with a normalized tool-calling contract.

Design §7.1/7.2: the reasoning plane normalizes tool calls, errors, finish
states and usage across providers so the bounded worker loop is
provider-agnostic. Three adapters ship:

* :class:`OpenAICompatibleAdapter` — any OpenAI-compatible
  ``/v1/chat/completions`` endpoint (OpenAI, Ollama, vLLM, llama.cpp server).
* :class:`AnthropicAdapter` — Anthropic ``/v1/messages`` with tool use.
* :class:`ScriptedMockAdapter` — deterministic offline adapter for tests and
  the synthetic benchmark, including scripted provider outages and simulated
  prompt-injection hijacking attempts.

All adapters talk plain HTTP(S) via :mod:`urllib.request` from the standard
library — zero external dependencies — and never receive the capability
token, socket path, or any credential beyond their own provider API key.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = [
    "ModelAdapter",
    "ModelTurnResult",
    "ToolCall",
    "ProviderError",
    "OpenAICompatibleAdapter",
    "AnthropicAdapter",
    "ScriptedMockAdapter",
]


@dataclass(frozen=True)
class ToolCall:
    """One normalized tool invocation requested by the model."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    id: str | None = None


@dataclass(frozen=True)
class ModelTurnResult:
    """One normalized model turn."""

    tool_calls: list[ToolCall]
    final_text: str | None
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float
    finish_reason: str  # "tool_calls" | "stop" | "length" | "script_exhausted" | ...
    reasoning_content: str | None = None


class ProviderError(Exception):
    """A model-provider failure, classified for bounded retry policy."""

    def __init__(self, message: str, retryable: bool) -> None:
        self.retryable = retryable
        super().__init__(message)


class ModelAdapter(ABC):
    """Provider-agnostic bounded tool-calling contract."""

    @abstractmethod
    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurnResult:
        """Execute one model turn over the conversation so far.

        ``messages`` uses a common OpenAI-like shape:
        ``{"role": "system"|"user"|"assistant"|"tool", "content": str}``,
        assistant tool-call turns additionally carry ``tool_calls`` and tool
        replies carry ``tool_call_id``/``name``.

        ``tools`` is the normalized catalog:
        ``{"name", "description", "parameters"}`` where ``parameters`` is a
        JSON Schema object.

        Raises :class:`ProviderError` on provider failure; never retries
        internally (the worker owns bounded retry/backoff policy).
        """


# --------------------------------------------------------------------- helpers


def _http_json(
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    """POST JSON with urllib and decode a JSON reply, mapping errors."""
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        snippet = b""
        try:
            snippet = exc.read()[:512]
        except Exception:  # pragma: no cover - body already consumed
            pass
        retryable = exc.code in (408, 409, 429) or 500 <= exc.code < 600
        raise ProviderError(
            f"provider HTTP {exc.code}: {snippet.decode('utf-8', 'replace')}", retryable=retryable
        ) from exc
    except urllib.error.URLError as exc:
        raise ProviderError(f"provider unreachable: {exc.reason}", retryable=True) from exc
    except TimeoutError as exc:
        raise ProviderError("provider request timed out", retryable=True) from exc
    except json.JSONDecodeError as exc:
        raise ProviderError(f"provider returned invalid JSON: {exc}", retryable=False) from exc


def _estimate_tokens(messages: list[dict[str, Any]]) -> int:
    total = 0
    for message in messages:
        total += len(str(message.get("content") or "")) // 4 + 4
        for call in message.get("tool_calls") or []:
            total += len(json.dumps(call.get("function", {}))) // 4 + 8
    return max(total, 1)


# --------------------------------------------------------- OpenAI-compatible


class OpenAICompatibleAdapter(ModelAdapter):
    """Adapter for any OpenAI-compatible chat-completions endpoint.

    Works with OpenAI, Ollama (``http://localhost:11434/v1``), vLLM and the
    llama.cpp server. Native ``tools`` JSON schemas are passed through; the
    reply is normalized into :class:`ModelTurnResult`.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        model_id: str = "local-model",
        api_key_env: str = "DEFSEC_OPENAI_API_KEY",
        fallback_key_env: str = "OPENAI_API_KEY",
        timeout: float = 60.0,
        price_per_mtok_input: float = float(os.environ.get("DEFSEC_OPENAI_PRICE_IN_MTOK", "0.0")),
        price_per_mtok_output: float = float(os.environ.get("DEFSEC_OPENAI_PRICE_OUT_MTOK", "0.0")),
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self.timeout = timeout
        self.price_in = price_per_mtok_input
        self.price_out = price_per_mtok_output
        self._api_key_env = api_key_env
        self._fallback_key_env = fallback_key_env

    def _headers(self) -> dict[str, str]:
        key = os.environ.get(self._api_key_env) or os.environ.get(self._fallback_key_env)
        return {"Authorization": f"Bearer {key}"} if key else {}

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurnResult:
        body: dict[str, Any] = {
            "model": self.model_id,
            "messages": [self._encode_message(m) for m in messages],
        }
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool.get("description", ""),
                        "parameters": tool.get("parameters", {"type": "object", "properties": {}}),
                    },
                }
                for tool in tools
            ]
            body["tool_choice"] = "auto"
        reply = _http_json(
            f"{self.base_url}/chat/completions", body, self._headers(), self.timeout
        )
        choice = (reply.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        tool_calls: list[ToolCall] = []
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            raw_args = function.get("arguments") or "{}"
            try:
                arguments = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except json.JSONDecodeError:
                arguments = {"_malformed_arguments": str(raw_args)[:256]}
            tool_calls.append(
                ToolCall(name=str(function.get("name", "")), arguments=arguments, id=call.get("id"))
            )
        usage = reply.get("usage") or {}
        input_tokens = int(usage.get("prompt_tokens") or _estimate_tokens(messages))
        output_tokens = int(usage.get("completion_tokens") or 0)
        cost = (input_tokens * self.price_in + output_tokens * self.price_out) / 1_000_000
        finish = str(choice.get("finish_reason") or ("tool_calls" if tool_calls else "stop"))
        return ModelTurnResult(
            tool_calls=tool_calls,
            final_text=message.get("content"),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=cost,
            finish_reason=finish,
            reasoning_content=message.get("reasoning_content"),
        )

    @staticmethod
    def _encode_message(message: dict[str, Any]) -> dict[str, Any]:
        out = {"role": message.get("role", "user"), "content": message.get("content") or ""}
        if message.get("reasoning_content") is not None:
            out["reasoning_content"] = message["reasoning_content"]
        if message.get("tool_calls"):
            out["tool_calls"] = [
                {
                    "id": call.get("id") or f"call_{i}",
                    "type": "function",
                    "function": {
                        "name": call["name"],
                        "arguments": json.dumps(call.get("arguments", {}), separators=(",", ":")),
                    },
                }
                for i, call in enumerate(message["tool_calls"])
            ]
        if message.get("role") == "tool":
            out["tool_call_id"] = message.get("tool_call_id")
            out["content"] = message.get("content") or ""
        return {k: v for k, v in out.items() if v is not None}


# ------------------------------------------------------------------ Anthropic


class AnthropicAdapter(ModelAdapter):
    """Adapter for Anthropic ``/v1/messages`` with tool-use normalization."""

    DEFAULT_BASE_URL = "https://api.anthropic.com"

    def __init__(
        self,
        model_id: str = "claude-sonnet-4-20250514",
        base_url: str | None = None,
        api_key_env: str = "DEFSEC_ANTHROPIC_API_KEY",
        fallback_key_env: str = "ANTHROPIC_API_KEY",
        timeout: float = 60.0,
        price_per_mtok_input: float = 3.0,
        price_per_mtok_output: float = 15.0,
    ) -> None:
        self.model_id = model_id
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.price_in = price_per_mtok_input
        self.price_out = price_per_mtok_output
        self._api_key_env = api_key_env
        self._fallback_key_env = fallback_key_env

    def _headers(self) -> dict[str, str]:
        key = os.environ.get(self._api_key_env) or os.environ.get(self._fallback_key_env)
        if not key:
            raise ProviderError(
                f"no Anthropic API key in ${self._api_key_env}/${self._fallback_key_env}",
                retryable=False,
            )
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurnResult:
        system = "\n".join(m["content"] for m in messages if m.get("role") == "system")
        body: dict[str, Any] = {
            "model": self.model_id,
            "max_tokens": 4096,
            "messages": self._encode_messages([m for m in messages if m.get("role") != "system"]),
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = [
                {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "input_schema": tool.get("parameters", {"type": "object", "properties": {}}),
                }
                for tool in tools
            ]
        reply = _http_json(
            f"{self.base_url}/v1/messages", body, self._headers(), self.timeout
        )
        tool_calls: list[ToolCall] = []
        texts: list[str] = []
        for block in reply.get("content") or []:
            if block.get("type") == "tool_use":
                tool_calls.append(
                    ToolCall(
                        name=str(block.get("name", "")),
                        arguments=dict(block.get("input") or {}),
                        id=block.get("id"),
                    )
                )
            elif block.get("type") == "text":
                texts.append(str(block.get("text", "")))
        usage = reply.get("usage") or {}
        input_tokens = int(usage.get("input_tokens") or _estimate_tokens(messages))
        output_tokens = int(usage.get("output_tokens") or 0)
        cost = (input_tokens * self.price_in + output_tokens * self.price_out) / 1_000_000
        stop = str(reply.get("stop_reason") or "")
        finish = "tool_calls" if stop == "tool_use" or tool_calls else ("stop" if stop else "stop")
        return ModelTurnResult(
            tool_calls=tool_calls,
            final_text="\n".join(texts) or None,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=cost,
            finish_reason=finish,
        )

    @staticmethod
    def _encode_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        pending_results: list[dict[str, Any]] = []
        for message in messages:
            role = message.get("role", "user")
            if role == "tool":
                pending_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": message.get("tool_call_id"),
                        "content": str(message.get("content") or ""),
                    }
                )
                continue
            if pending_results:
                out.append({"role": "user", "content": pending_results})
                pending_results = []
            if role == "assistant":
                content: list[dict[str, Any]] = []
                if message.get("content"):
                    content.append({"type": "text", "text": str(message["content"])})
                for call in message.get("tool_calls") or []:
                    content.append(
                        {
                            "type": "tool_use",
                            "id": call.get("id") or "toolu_call",
                            "name": call["name"],
                            "input": call.get("arguments", {}),
                        }
                    )
                out.append({"role": "assistant", "content": content or [{"type": "text", "text": ""}]})
            else:
                out.append({"role": "user", "content": [{"type": "text", "text": str(message.get("content") or "")}]})
        if pending_results:
            out.append({"role": "user", "content": pending_results})
        return out


# ----------------------------------------------------------------- scripted


ScriptStep = (
    dict[str, Any]
    | str
    | ProviderError
    | Callable[[list[dict[str, Any]], list[dict[str, Any]]], dict[str, Any]]
)


class ScriptedMockAdapter(ModelAdapter):
    """Deterministic offline adapter for tests and synthetic benchmarks.

    A *script* is a list of steps; step ``i`` produces model turn ``i``:

    * ``{"tool_calls": [{"name": ..., "arguments": {...}}, ...]}`` — the model
      requests tool calls (use this to simulate a hijacked model emitting
      malicious-but-typed proposals: policy still gates everything).
    * ``"some final text"`` or ``{"final_text": ...}`` — the model finishes.
    * a :class:`ProviderError` instance — a simulated provider outage or hard
      provider failure (``retryable`` controls the worker's requeue policy).
    * a callable ``f(messages, tools) -> step`` — deterministic scripted
      behavior that may read previous (enveloped) tool results, e.g. to cite
      the exact observation IDs they contain.

    Token usage and cost are deterministic functions of the conversation so
    budget enforcement is testable offline.
    """

    def __init__(
        self,
        script: list[ScriptStep],
        *,
        price_per_mtok: float = 0.0,
        name: str = "scripted-mock",
    ) -> None:
        self.script = list(script)
        self.price_per_mtok = price_per_mtok
        self.name = name
        self._cursor = 0
        self.turns_used = 0

    def reset(self) -> None:
        self._cursor = 0
        self.turns_used = 0

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurnResult:
        self.turns_used += 1
        step: ScriptStep | None
        if self._cursor < len(self.script):
            step = self.script[self._cursor]
            self._cursor += 1
            if callable(step):
                step = step(messages, tools)
        else:
            step = None
        if isinstance(step, ProviderError):
            raise step
        if step is None:
            return ModelTurnResult(
                tool_calls=[],
                final_text="(script exhausted)",
                input_tokens=_estimate_tokens(messages),
                output_tokens=8,
                estimated_cost_usd=0.0,
                finish_reason="script_exhausted",
            )
        if isinstance(step, str):
            step = {"final_text": step}
        tool_calls = [
            ToolCall(
                name=str(call.get("name", "")),
                arguments=dict(call.get("arguments") or {}),
                id=call.get("id") or f"call_{self._cursor}_{i}",
            )
            for i, call in enumerate(step.get("tool_calls") or [])
        ]
        final_text = step.get("final_text")
        input_tokens = _estimate_tokens(messages) + 32
        output_tokens = 24 + 26 * len(tool_calls) + (len(str(final_text)) // 4 if final_text else 0)
        cost = (input_tokens + output_tokens) * self.price_per_mtok / 1_000_000
        finish = "tool_calls" if tool_calls else "stop"
        return ModelTurnResult(
            tool_calls=tool_calls,
            final_text=final_text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=cost,
            finish_reason=finish,
        )
