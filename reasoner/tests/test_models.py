"""Model adapter tests: scripted mock, OpenAI-compatible, and Anthropic."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))

import unittest  # noqa: E402

from defsec_reasoner.models import (  # noqa: E402
    AnthropicAdapter,
    BudgetExhausted,
    TurnBudget,
    ModelTurnResult,
    OpenAICompatibleAdapter,
    ProviderError,
    ScriptedMockAdapter,
    ToolCall,
)

TOOLS = [
    {
        "name": "query_observations",
        "description": "query",
        "parameters": {"type": "object", "properties": {"host_id": {"type": "string"}}},
    }
]

MESSAGES = [
    {"role": "system", "content": "be safe"},
    {"role": "user", "content": "investigate"},
    {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"id": "call_1", "name": "query_observations", "arguments": {"host_id": "edge-01"}}],
    },
    {"role": "tool", "tool_call_id": "call_1", "name": "query_observations", "content": "result"},
]


class _StubHTTPServer(ThreadingHTTPServer):
    """Canned HTTP responder: replies from a queue of (status, body)."""

    def __init__(self) -> None:
        self.replies: list[tuple[int, str]] = []
        self.requests: list[dict] = []
        self.redirect_target: str | None = None
        super().__init__(("127.0.0.1", 0), _StubHandler)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"


class _StubHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        server = self.server  # type: ignore[assignment]
        length = int(self.headers.get("Content-Length", 0))
        server.requests.append(json.loads(self.rfile.read(length)))
        status, body = server.replies.pop(0)
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if server.redirect_target:
            self.send_header("Location", server.redirect_target)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        self.server.requests.append(dict(self.headers))
        self.send_error(400)

    def log_message(self, *_args: object) -> None:  # silence
        return


class TestScriptedMockAdapter(unittest.TestCase):
    def test_tool_calls_and_final(self) -> None:
        script = [
            {"tool_calls": [{"name": "query_observations", "arguments": {"host_id": "h"}}]},
            {"final_text": "done"},
        ]
        adapter = ScriptedMockAdapter(script)
        first = adapter.chat(MESSAGES, TOOLS)
        self.assertEqual(first.finish_reason, "tool_calls")
        self.assertEqual(len(first.tool_calls), 1)
        self.assertEqual(first.tool_calls[0].name, "query_observations")
        self.assertEqual(first.tool_calls[0].arguments, {"host_id": "h"})
        self.assertIsNotNone(first.tool_calls[0].id)
        self.assertGreater(first.input_tokens, 0)
        self.assertGreater(first.output_tokens, 0)
        second = adapter.chat(MESSAGES + [], TOOLS)
        self.assertEqual(second.finish_reason, "stop")
        self.assertEqual(second.final_text, "done")
        self.assertEqual(second.tool_calls, [])

    def test_string_step_is_final_text(self) -> None:
        adapter = ScriptedMockAdapter(["all done"])
        turn = adapter.chat(MESSAGES, TOOLS)
        self.assertEqual(turn.final_text, "all done")

    def test_provider_error_propagates(self) -> None:
        adapter = ScriptedMockAdapter([ProviderError("503 outage", retryable=True)])
        with self.assertRaises(ProviderError) as ctx:
            adapter.chat(MESSAGES, TOOLS)
        self.assertTrue(ctx.exception.retryable)

    def test_nonretryable_provider_error(self) -> None:
        adapter = ScriptedMockAdapter([ProviderError("401 unauthorized", retryable=False)])
        with self.assertRaises(ProviderError) as ctx:
            adapter.chat(MESSAGES, TOOLS)
        self.assertFalse(ctx.exception.retryable)

    def test_callable_step_reads_conversation(self) -> None:
        def step(messages: list[dict], tools: list[dict]) -> dict:
            tool_results = [m for m in messages if m.get("role") == "tool"]
            return {"final_text": f"saw {len(tool_results)} tool results"}

        adapter = ScriptedMockAdapter([step])
        turn = adapter.chat(MESSAGES, TOOLS)
        self.assertEqual(turn.final_text, "saw 1 tool results")

    def test_script_exhaustion_is_deterministic(self) -> None:
        adapter = ScriptedMockAdapter([])
        turn = adapter.chat(MESSAGES, TOOLS)
        self.assertEqual(turn.finish_reason, "script_exhausted")
        self.assertEqual(turn.final_text, "(script exhausted)")

    def test_cost_is_deterministic(self) -> None:
        script = [{"tool_calls": [{"name": "finish", "arguments": {}}]}]
        first = ScriptedMockAdapter(script, price_per_mtok=10.0).chat(MESSAGES, TOOLS)
        second = ScriptedMockAdapter(script, price_per_mtok=10.0).chat(MESSAGES, TOOLS)
        self.assertEqual(first.estimated_cost_usd, second.estimated_cost_usd)
        self.assertGreater(first.estimated_cost_usd, 0.0)


class TestOpenAICompatibleAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self.server = _StubHTTPServer()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.adapter = OpenAICompatibleAdapter(
            base_url=f"{self.server.url}/v1", model_id="test-model", timeout=10.0
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def test_normalizes_tool_calls_usage_and_cost(self) -> None:
        self.server.replies.append(
            (
                200,
                json.dumps(
                    {
                        "choices": [
                            {
                                "finish_reason": "tool_calls",
                                "message": {
                                    "content": None,
                                    "tool_calls": [
                                        {
                                            "id": "call_abc",
                                            "type": "function",
                                            "function": {
                                                "name": "query_observations",
                                                "arguments": '{"host_id": "edge-01"}',
                                            },
                                        }
                                    ],
                                },
                            }
                        ],
                        "usage": {"prompt_tokens": 120, "completion_tokens": 30},
                    }
                ),
            )
        )
        turn = self.adapter.chat(MESSAGES, TOOLS)
        self.assertEqual(turn.input_tokens, 120)
        self.assertEqual(turn.output_tokens, 30)
        self.assertEqual(turn.finish_reason, "tool_calls")
        self.assertEqual(turn.tool_calls[0].name, "query_observations")
        self.assertEqual(turn.tool_calls[0].arguments, {"host_id": "edge-01"})
        self.assertEqual(turn.tool_calls[0].id, "call_abc")
        self.assertEqual(self.server.requests[-1]["model"], "test-model")
        self.assertEqual(self.server.requests[-1]["tools"][0]["type"], "function")

    def test_malformed_arguments_do_not_crash(self) -> None:
        self.server.replies.append(
            (
                200,
                json.dumps(
                    {
                        "choices": [
                            {
                                "finish_reason": "tool_calls",
                                "message": {
                                    "tool_calls": [
                                        {"id": "c1", "type": "function",
                                         "function": {"name": "x", "arguments": "{not json"}}
                                    ]
                                },
                            }
                        ],
                        "usage": {},
                    }
                ),
            )
        )
        turn = self.adapter.chat(MESSAGES, TOOLS)
        self.assertIn("_malformed_arguments", turn.tool_calls[0].arguments)

    def test_http_503_is_retryable(self) -> None:
        self.server.replies.append((503, json.dumps({"error": "overloaded"})))
        with self.assertRaises(ProviderError) as ctx:
            self.adapter.chat(MESSAGES, TOOLS)
        self.assertTrue(ctx.exception.retryable)

    def test_http_401_is_not_retryable(self) -> None:
        self.server.replies.append((401, json.dumps({"error": "bad key"})))
        with self.assertRaises(ProviderError) as ctx:
            self.adapter.chat(MESSAGES, TOOLS)
        self.assertFalse(ctx.exception.retryable)

    def test_provider_error_only_keeps_status_and_recognized_machine_code(self) -> None:
        errors = [
            ({"code": "rate_limit_exceeded", "message": "sensitive telemetry"}, "provider HTTP 429 (rate_limit_exceeded)"),
            ({"type": "sensitive_telemetry", "message": "sensitive telemetry"}, "provider HTTP 429"),
        ]
        for error, expected in errors:
            with self.subTest(expected=expected):
                self.server.replies.append((429, json.dumps({"error": error})))
                with self.assertRaises(ProviderError) as ctx:
                    self.adapter.chat(MESSAGES, TOOLS)
                self.assertEqual(str(ctx.exception), expected)
                self.assertTrue(ctx.exception.retryable)

    def test_provider_rejects_responses_over_eight_mib(self) -> None:
        from io import BytesIO

        with patch("urllib.request.build_opener") as opener:
            response = BytesIO(b" " * (8 * 1024 * 1024 + 1))
            opener.return_value.open.return_value = response
            with self.assertRaisesRegex(ProviderError, "response exceeds size limit"):
                self.adapter.chat(MESSAGES, TOOLS)

    def test_both_providers_reject_redirects_without_using_ambient_proxies(self) -> None:
        with _StubHTTPServer() as destination:
            thread = threading.Thread(target=destination.serve_forever, daemon=True)
            thread.start()
            self.server.redirect_target = destination.url + "/collect"
            anthropic = AnthropicAdapter(base_url=self.server.url, model_id="test-model")
            try:
                with patch.dict(os.environ, DEFSEC_OPENAI_API_KEY="synthetic", DEFSEC_ANTHROPIC_API_KEY="synthetic"), \
                        patch("urllib.request.getproxies", side_effect=AssertionError("ambient proxy lookup")):
                    for adapter in (self.adapter, anthropic):
                        for status in (302, 307, 308):
                            with self.subTest(adapter=type(adapter).__name__, status=status):
                                self.server.replies.append((status, ""))
                                with self.assertRaisesRegex(ProviderError, f"HTTP {status}"):
                                    adapter.chat(MESSAGES, TOOLS)
                self.assertEqual(destination.requests, [])
            finally:
                destination.shutdown()

    def test_connection_refused_is_retryable(self) -> None:
        dead = OpenAICompatibleAdapter(base_url="http://127.0.0.1:9/v1", model_id="m", timeout=2.0)
        with self.assertRaises(ProviderError) as ctx:
            dead.chat(MESSAGES, TOOLS)
        self.assertTrue(ctx.exception.retryable)


class TestAnthropicAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self.server = _StubHTTPServer()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        os.environ["DEFSEC_ANTHROPIC_API_KEY"] = "test-key"

    def tearDown(self) -> None:
        os.environ.pop("DEFSEC_ANTHROPIC_API_KEY", None)
        self.server.shutdown()
        self.server.server_close()

    def test_normalizes_tool_use_blocks_and_system(self) -> None:
        self.server.replies.append(
            (
                200,
                json.dumps(
                    {
                        "content": [
                            {"type": "text", "text": "checking"},
                            {"type": "tool_use", "id": "tu_1", "name": "query_observations",
                             "input": {"host_id": "edge-01"}},
                        ],
                        "stop_reason": "tool_use",
                        "usage": {"input_tokens": 90, "output_tokens": 25},
                    }
                ),
            )
        )
        adapter = AnthropicAdapter(model_id="claude-test", base_url=self.server.url, timeout=10.0)
        turn = adapter.chat(MESSAGES, TOOLS)
        self.assertEqual(turn.finish_reason, "tool_calls")
        self.assertEqual(turn.tool_calls[0].name, "query_observations")
        self.assertEqual(turn.tool_calls[0].arguments, {"host_id": "edge-01"})
        self.assertEqual(turn.input_tokens, 90)
        # System prompt extracted to the dedicated field; tool results encoded
        # as a user turn of tool_result blocks immediately after the tool_use.
        request = self.server.requests[-1]
        self.assertEqual(request["system"], "be safe")
        self.assertEqual(request["messages"][0]["role"], "user")
        self.assertEqual(request["messages"][1]["content"][-1]["type"], "tool_use")
        self.assertEqual(request["messages"][2]["role"], "user")
        self.assertEqual(request["messages"][2]["content"][0]["type"], "tool_result")
        self.assertEqual(request["messages"][2]["content"][0]["tool_use_id"], "call_1")
        self.assertEqual(request["tools"][0]["name"], "query_observations")
        self.assertEqual(request["tools"][0]["input_schema"]["type"], "object")

    def test_missing_api_key_is_nonretryable(self) -> None:
        os.environ.pop("DEFSEC_ANTHROPIC_API_KEY", None)
        os.environ.pop("ANTHROPIC_API_KEY", None)
        adapter = AnthropicAdapter(model_id="m", base_url=self.server.url)
        with self.assertRaises(ProviderError) as ctx:
            adapter.chat(MESSAGES, TOOLS)
        self.assertFalse(ctx.exception.retryable)


class TestBudgetedRequests(unittest.TestCase):
    def test_preflight_counts_tools_and_history(self) -> None:
        adapters = [OpenAICompatibleAdapter(), AnthropicAdapter()]
        with patch("defsec_reasoner.models._http_json") as request:
            for adapter in adapters:
                with self.subTest(adapter=type(adapter).__name__):
                    budget = TurnBudget(500, time.monotonic() + 10)
                    for messages, tools in [
                        ([{"role": "user", "content": "x" * 3000}], []),
                        ([], [{"name": "lookup", "description": "x" * 3000}]),
                    ]:
                        with self.assertRaisesRegex(BudgetExhausted, "max_total_tokens"):
                            adapter.chat_with_budget(messages, tools, budget)
            request.assert_not_called()

    def test_completion_and_timeout_are_bounded_and_usage_is_retained(self) -> None:
        cases = [
            (
                OpenAICompatibleAdapter(), "max_completion_tokens",
                {"prompt_tokens": 900, "completion_tokens": 40,
                 "prompt_tokens_details": {"cached_tokens": 700},
                 "completion_tokens_details": {"reasoning_tokens": 25}},
                (900, 40, 700, 25, 0),
            ),
            (
                AnthropicAdapter(), "max_tokens",
                {"input_tokens": 100, "output_tokens": 40,
                 "cache_read_input_tokens": 700, "cache_creation_input_tokens": 100},
                (900, 40, 700, 0, 100),
            ),
        ]
        for adapter, cap_field, usage, expected in cases:
            with self.subTest(cap_field=cap_field), patch.object(adapter, "_headers", return_value={}):
                with patch("defsec_reasoner.models._http_json", return_value={"usage": usage}) as request:
                    result = adapter.chat_with_budget(MESSAGES, TOOLS, TurnBudget(500, time.monotonic() + 5))
                    _, body, _, timeout = request.call_args.args
                    cap = body.pop(cap_field)
                    self.assertEqual(cap, 500 - (len(json.dumps(body).encode("utf-8")) + 3) // 4)
                    self.assertGreater(timeout, 0)
                    self.assertLessEqual(timeout, 5)
                self.assertEqual(
                    (result.input_tokens, result.output_tokens, result.cached_input_tokens,
                     result.reasoning_tokens, result.cache_creation_input_tokens),
                    expected,
                )

if __name__ == "__main__":
    unittest.main()
