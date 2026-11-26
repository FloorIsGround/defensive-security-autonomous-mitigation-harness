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
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = [
    "ModelAdapter",
    "ModelTurnResult",
    "ToolCall",
    "ProviderError",
    "TurnBudget",
    "BudgetExhausted",
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
    cached_input_tokens: int = 0
    reasoning_tokens: int = 0
    cache_creation_input_tokens: int = 0
    response_items: list[dict[str, Any]] | None = None


class ProviderError(Exception):
    """A model-provider failure, classified for bounded retry policy."""

    def __init__(self, message: str, retryable: bool) -> None:
        self.retryable = retryable
        super().__init__(message)


@dataclass(frozen=True)
class TurnBudget:
    remaining_tokens: int
    deadline: float
    max_completion_tokens: int = 4096
    effort: str | None = None
    session_id: str | None = None

    def completion_limit(self, input_tokens: int) -> int:
        remaining = self.remaining_tokens - input_tokens
        if remaining <= 0:
            raise BudgetExhausted("max_total_tokens")
        if self.max_completion_tokens <= 0:
            raise BudgetExhausted("max_completion_tokens")
        return min(self.max_completion_tokens, remaining)

    def request_timeout(self, timeout: float) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BudgetExhausted("max_wall_seconds")
        return min(timeout, remaining)


class BudgetExhausted(Exception):
    """The turn cannot start within the supplied budget."""


def _estimate_payload(payload: Any) -> int:
    return (len(json.dumps(payload).encode("utf-8")) + 3) // 4


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


    def chat_with_budget(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], budget: TurnBudget
    ) -> ModelTurnResult:
        """Preflight legacy adapters; override to apply provider-side limits."""
        budget.completion_limit(_estimate_payload({"messages": messages, "tools": tools}))
        budget.request_timeout(float("inf"))
        return self.chat(messages, tools)


# --------------------------------------------------------------------- helpers


_discovery_transport: ContextVar[bool] = ContextVar("discovery_transport", default=False)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Only recognized machine identifiers may appear in persisted errors. Providers
# can echo arbitrary request data even in fields named "code" or "type".
_SAFE_PROVIDER_ERRORS = frozenset({
    "api_error", "authentication_error", "billing_error", "context_length_exceeded",
    "insufficient_quota", "invalid_api_key", "invalid_request_error", "model_not_found",
    "not_found_error", "overloaded_error", "permission_error", "rate_limit_error",
    "rate_limit_exceeded", "request_too_large", "server_error", "temporarily_unavailable",
})


def _provider_error_code(exc: urllib.error.HTTPError) -> str | None:
    try:
        with exc:
            reply = json.loads(exc.read(4096))
        detail = reply.get("error") if isinstance(reply, dict) else None
        if isinstance(detail, dict):
            for field in ("code", "type"):
                code = detail.get(field)
                if isinstance(code, str) and code in _SAFE_PROVIDER_ERRORS:
                    return code
    except (OSError, ValueError, RecursionError):
        pass
    return None


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
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    discovery = _discovery_transport.get()
    limit = 256 * 1024 if discovery else 8 * 1024 * 1024
    try:
        with opener.open(request, timeout=timeout) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            scope = "discovery" if discovery else "provider"
            raise ProviderError(f"{scope} response exceeds size limit", retryable=False)
        reply = json.loads(data)
        if not isinstance(reply, dict):
            raise ProviderError("provider returned an invalid JSON response", retryable=False)
        return reply
    except urllib.error.HTTPError as exc:
        code = _provider_error_code(exc)
        suffix = f" ({code})" if code else ""
        retryable = exc.code in (408, 409, 429) or 500 <= exc.code < 600
        raise ProviderError(f"provider HTTP {exc.code}{suffix}", retryable=retryable) from None
    except urllib.error.URLError:
        raise ProviderError("provider unreachable", retryable=True) from None
    except TimeoutError:
        raise ProviderError("provider request timed out", retryable=True) from None
    except (ValueError, RecursionError):
        raise ProviderError("provider returned invalid JSON", retryable=False) from None


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
        completion_token_field: str = "max_completion_tokens",
        price_per_mtok_input: float = float(os.environ.get("DEFSEC_OPENAI_PRICE_IN_MTOK", "0.0")),
        price_per_mtok_output: float = float(os.environ.get("DEFSEC_OPENAI_PRICE_OUT_MTOK", "0.0")),
    ) -> None:
        if completion_token_field not in ("max_completion_tokens", "max_tokens"):
            raise ValueError("unsupported OpenAI-compatible completion token field")
        self.completion_token_field = completion_token_field
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self.timeout = timeout
        self.price_in = price_per_mtok_input
        self.price_out = price_per_mtok_output
        self._api_key_env = api_key_env
        self._fallback_key_env = fallback_key_env

    def _headers(self, budget: TurnBudget | None = None) -> dict[str, str]:
        key = os.environ.get(self._api_key_env) or os.environ.get(self._fallback_key_env)
        return {"Authorization": f"Bearer {key}"} if key else {}

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurnResult:
        return self._chat(messages, tools, None)

    def chat_with_budget(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], budget: TurnBudget
    ) -> ModelTurnResult:
        return self._chat(messages, tools, budget)

    def _chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], budget: TurnBudget | None
    ) -> ModelTurnResult:
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
        effort = (budget.effort if budget else None) or getattr(self, "effort", None)
        if effort:
            body["reasoning_effort"] = effort
        input_estimate = _estimate_payload(body)
        if budget is not None:
            body[self.completion_token_field] = budget.completion_limit(input_estimate)
        headers = self._headers(budget)
        timeout = self.timeout if budget is None else budget.request_timeout(self.timeout)
        reply = _http_json(f"{self.base_url}/chat/completions", body, headers, timeout)
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
        input_tokens = int(usage.get("prompt_tokens", input_estimate))
        output_tokens = int(usage.get("completion_tokens", _estimate_payload(message)))
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
            cached_input_tokens=int((usage.get("prompt_tokens_details") or {}).get("cached_tokens") or 0),
            reasoning_tokens=int((usage.get("completion_tokens_details") or {}).get("reasoning_tokens") or 0),
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
        return self._chat(messages, tools, None)

    def chat_with_budget(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], budget: TurnBudget
    ) -> ModelTurnResult:
        return self._chat(messages, tools, budget)

    def _chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], budget: TurnBudget | None
    ) -> ModelTurnResult:
        system = "\n".join(m["content"] for m in messages if m.get("role") == "system")
        body: dict[str, Any] = {
            "model": self.model_id,
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
        input_estimate = _estimate_payload(body)
        body["max_tokens"] = 4096 if budget is None else budget.completion_limit(input_estimate)
        headers = self._headers()
        timeout = self.timeout if budget is None else budget.request_timeout(self.timeout)
        reply = _http_json(f"{self.base_url}/v1/messages", body, headers, timeout)
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
        cached_input = int(usage.get("cache_read_input_tokens") or 0)
        cache_creation = int(usage.get("cache_creation_input_tokens") or 0)
        input_tokens = int(usage.get("input_tokens", input_estimate))
        if "input_tokens" in usage:
            input_tokens += cached_input + cache_creation
        output_tokens = int(usage.get("output_tokens", _estimate_payload(reply.get("content") or [])))
        cost = (input_tokens * self.price_in + output_tokens * self.price_out) / 1_000_000
        stop = str(reply.get("stop_reason") or "")
        finish = "tool_calls" if stop == "tool_use" else stop or "stop"
        return ModelTurnResult(
            tool_calls=tool_calls,
            final_text="\n".join(texts) or None,
            cached_input_tokens=cached_input,
            cache_creation_input_tokens=cache_creation,
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
