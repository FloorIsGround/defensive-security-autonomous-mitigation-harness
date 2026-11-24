"""Model adapter tests: scripted mock, OpenAI-compatible, and Anthropic."""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))

import unittest  # noqa: E402

from defsec_reasoner.models import (  # noqa: E402
    AnthropicAdapter,
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
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

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


if __name__ == "__main__":
    unittest.main()
