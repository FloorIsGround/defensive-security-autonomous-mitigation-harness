"""Subscription routes, credential isolation, OAuth rotation and worker tool history."""

import hashlib
import io
import json
import os
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from defsec_reasoner import chatgpt_auth as auth
from defsec_reasoner import models
from defsec_reasoner.cli import _build_adapter, build_parser
from defsec_reasoner.discovery import export_scopes
from defsec_reasoner.subscriptions import (
    GO,
    ChatGPTPlanAdapter,
    OpenCodeGoAdapter,
    completed_event,
)

MESSAGES = [
    {"role": "system", "content": "Assess service state."},
    {"role": "user", "content": "Synthetic sample."},
]
TOOLS = [{"name": "assess", "description": "Record assessment", "parameters": {"type": "object"}}]


def budget(session="conversation-a"):
    return models.TurnBudget(10000, time.monotonic() + 10, session_id=session)


class SubscriptionTests(unittest.TestCase):
    def test_cli_selects_fixed_provider_for_both_workers(self):
        for command in ("worker", "host-review-worker"):
            for backend, kind in (("chatgpt", ChatGPTPlanAdapter), ("opencode-go", OpenCodeGoAdapter)):
                args = [
                    command,
                    "--socket",
                    "unused",
                    "--backend",
                    backend,
                    "--model",
                    "example",
                    "--effort",
                    "high",
                ]
                if command == "host-review-worker":
                    args.extend(["--purpose", "routine"])
                opts = build_parser().parse_args(args)
                adapter, model = _build_adapter(opts)
                self.assertIs(type(adapter), kind)
                self.assertEqual((model, adapter.effort), ("example", "high"))
                self.assertEqual(export_scopes(adapter), [])
                opts.base_url = "https://invalid.example"
                with self.assertRaises(ValueError):
                    _build_adapter(opts)

    def test_go_catalog_filters_by_workspace_kind_and_tool_support(self):
        usable = {"name": "Example", "type": "chat", "capabilities": {"tools": {"supported": True}}}
        catalog = {
            "opencode": {"models": {"payg": usable}},
            "opencode-go": {
                "models": {
                    "chat-id": usable,
                    "vector": {**usable, "type": "embedding"},
                    "plain": {"type": "chat"},
                }
            },
        }
        with patch.object(auth, "opener") as opener, patch.dict(os.environ, OPENCODE_GO_API_KEY="test"):
            opener.return_value.open.return_value = io.BytesIO(json.dumps(catalog).encode())
            self.assertEqual(OpenCodeGoAdapter.available_models(), [("chat-id", "Example")])
            req = opener.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url, "https://opencode.ai/console/api/v1/models")
            self.assertEqual(req.get_header("Authorization"), "Bearer test")

    def test_go_keeps_sessions_separate_and_never_uses_openai_key(self):
        go = OpenCodeGoAdapter("beam-free")
        reply = {"choices": [{"message": {"content": "ok"}}]}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"XDG_STATE_HOME": tmp, "OPENAI_API_KEY": "wrong"}, clear=True),
        ):
            with self.assertRaises(models.ProviderError):
                go.chat_with_budget(MESSAGES, [], budget())
            with (
                patch.dict(os.environ, OPENCODE_GO_API_KEY="go-only"),
                patch.object(models, "_http_json", return_value=reply) as send,
            ):
                for session in ("a", "a", "b"):
                    go.chat_with_budget(MESSAGES, TOOLS, budget(session))
                headers = [c.args[2] for c in send.call_args_list]
                self.assertEqual(headers[0], headers[1])
                self.assertNotEqual(headers[1]["x-opencode-session"], headers[2]["x-opencode-session"])
                self.assertEqual(headers[0]["Authorization"], "Bearer go-only")
                self.assertEqual(send.call_args.args[0], GO + "/chat/completions")
                self.assertLessEqual(send.call_args.args[1]["max_tokens"], 4096)

    def test_go_credential_file_is_bounded_regular_and_not_a_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "key"
            with patch.dict(os.environ, OPENCODE_GO_API_KEY="", OPENCODE_GO_API_KEY_FILE=str(source)):
                source.write_bytes(b"x" * 4095 + b"\n")
                self.assertEqual(OpenCodeGoAdapter._headers()["Authorization"], "Bearer " + "x" * 4095)
                for data in (b"x" * 4097, b"\xff"):
                    source.write_bytes(data)
                    with self.assertRaises(models.ProviderError) as exc:
                        OpenCodeGoAdapter._headers()
                    self.assertFalse(exc.exception.retryable)
                target = source.rename(source.with_name("real-key"))
                target.write_bytes(b"synthetic")
                source.symlink_to(target)
                with self.assertRaises(models.ProviderError):
                    OpenCodeGoAdapter._headers()
                source.unlink()
                os.mkfifo(source)
                with self.assertRaisesRegex(models.ProviderError, "regular file"):
                    OpenCodeGoAdapter._headers()

    def test_logout_without_refresh_token_clears_local_state(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, XDG_STATE_HOME=tmp):
            with auth.registry() as state:
                state["accounts"]["fixture"] = {"access_token": "synthetic", "client_id": "test"}
            with patch.object(auth, "fetch") as fetch, redirect_stdout(io.StringIO()) as output:
                auth.logout("fixture")
            fetch.assert_not_called()
            self.assertIn("Local credentials cleared. Remote revocation was not attempted", output.getvalue())
            with auth.registry() as state:
                self.assertEqual(state["accounts"]["fixture"], {"client_id": "test"})

    def test_stream_requires_terminal_completed_event(self):
        def framed(obj):
            return b"data: " + json.dumps(obj).encode() + b"\n\n"

        event = framed({"type": "response.output_text.delta", "delta": "incomplete"})
        with self.assertRaises(models.ProviderError):
            completed_event(io.BytesIO(event), budget())
        with self.assertRaises(models.ProviderError):
            completed_event(io.BytesIO(event + framed({"type": "response.failed"})), budget())
        self.assertEqual(
            completed_event(
                io.BytesIO(
                    event + framed({"type": "response.completed", "response": {"status": "completed"}})
                ),
                budget(),
            ),
            {"status": "completed"},
        )

    def test_chatgpt_namespaced_tool_replay_and_budget(self):
        route = ChatGPTPlanAdapter("gpt-6-luna", "fixture", "high")
        usage = {"input_tokens": 120, "output_tokens": 65, "output_tokens_details": {"reasoning_tokens": 15}}
        output = [
            {"type": "reasoning", "encrypted_content": "opaque", "summary": []},
            {
                "type": "function_call",
                "namespace": "investigator",
                "name": "assess",
                "call_id": "call_a",
                "arguments": "{}",
            },
        ]
        with (
            patch.object(auth, "bearer", return_value="subscription"),
            patch(
                "defsec_reasoner.subscriptions.stream_response",
                return_value={"usage": usage, "output": output},
            ) as send,
        ):
            turn = route.chat_with_budget(MESSAGES, TOOLS, budget())
            body = send.call_args.args[0]
            self.assertFalse(body["store"])
            self.assertTrue(body["stream"])
            self.assertNotIn("max_output_tokens", body)
            self.assertEqual(body["input"][0]["role"], "developer")
            self.assertEqual(body["tools"][0]["type"], "namespace")
            self.assertEqual(turn.tool_calls[0].name, "assess")
            history = MESSAGES + [
                {"role": "assistant", "response_items": turn.response_items},
                {"role": "tool", "tool_call_id": "call_a", "content": "accepted"},
            ]
            route.chat_with_budget(history, TOOLS, budget())
            self.assertEqual(send.call_args.args[0]["input"][-3:-1], output)
            self.assertEqual(send.call_args.args[0]["input"][-1]["call_id"], "call_a")
            capped = route.chat_with_budget(MESSAGES, TOOLS, models.TurnBudget(4000, time.monotonic() + 5, 5))
            self.assertEqual(
                (capped.tool_calls, capped.output_tokens, capped.finish_reason), ([], 65, "budget_exhausted")
            )

    def test_saved_refresh_is_private_serialized_and_scope_checked(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, XDG_STATE_HOME=tmp):
            with auth.registry() as s:
                s["accounts"]["test"] = {
                    "subject": "me",
                    "client_id": "issued",
                    "refresh_token": "old",
                    "scopes": [auth.PLAN_SCOPE],
                    "expires": 0,
                }
            response = {
                "token_type": "Bearer",
                "expires_in": 3600,
                "access_token": "active",
                "refresh_token": "rotated",
            }
            with patch.object(auth, "fetch", return_value=response) as refresh, ThreadPoolExecutor(2) as pool:
                self.assertEqual(list(pool.map(auth.bearer, ["test", "test"])), ["active", "active"])
                self.assertEqual(refresh.call_count, 1)
            with auth.registry() as s:
                self.assertEqual(s["accounts"]["test"]["refresh_token"], "rotated")
                s["accounts"]["test"]["expires"] = 0
            self.assertEqual((auth.auth_dir() / "registrations.json").stat().st_mode & 0o777, 0o600)
            with (
                patch.object(auth, "fetch", return_value={**response, "scope": "openid"}),
                self.assertRaises(models.ProviderError),
            ):
                auth.bearer("test")
            with auth.registry() as s:
                self.assertEqual(s["accounts"]["test"]["scopes"], ["openid"])

    def test_identity_checks_signature_account_and_nonce(self):
        try:
            import jwt
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            self.skipTest("optional ChatGPT verification dependencies unavailable")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk["kid"] = "test"
        claims = {
            "sub": "user",
            "iss": auth.ISSUER,
            "aud": "client",
            "exp": time.time() + 120,
            "iat": time.time() - 1,
            "nonce": "nonce",
        }
        token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test"})
        uri = auth.ISSUER + "/jwks"
        responses = {
            auth.ISSUER + "/.well-known/openid-configuration": {"issuer": auth.ISSUER, "jwks_uri": uri},
            uri: {"keys": [jwk]},
        }
        with patch.object(auth, "fetch", side_effect=responses.__getitem__):
            self.assertEqual(auth.identity(token, "client", "nonce"), "user")
            for client, nonce in (("other", "nonce"), ("client", "wrong")):
                with self.assertRaises(models.ProviderError):
                    auth.identity(token, client, nonce)

    def test_loopback_sign_in_pkce_state_and_issued_client(self):
        import threading
        from urllib import parse, request

        callbacks = []
        connection_timeouts = []
        setup = auth.BaseHTTPRequestHandler.setup

        def observe_setup(handler):
            connection_timeouts.append(handler.request.gettimeout())
            setup(handler)

        def browser(url):
            def consent():
                try:
                    auth.opener().open(url, timeout=3)
                except request.HTTPError as redirect:
                    self.assertEqual(redirect.code, 303)
                    query = parse.parse_qs(parse.urlsplit(redirect.headers["Location"]).query)
                callbacks.append(query)
                uri = query["redirect_uri"][0]
                for state in ("incorrect", query["state"][0]):
                    try:
                        with request.urlopen(
                            uri
                            + "?"
                            + parse.urlencode({"state": state, "code": "code", "client_id": "issued"}),
                            timeout=3,
                        ):
                            pass
                    except request.HTTPError:
                        pass

            threading.Thread(target=consent, daemon=True).start()
            return True

        reply = {
            "access_token": "synthetic",
            "refresh_token": "refresh",
            "id_token": "id",
            "scope": auth.PLAN_SCOPE,
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, XDG_STATE_HOME=tmp),
            patch.object(auth.webbrowser, "open", side_effect=browser),
            patch.object(auth.BaseHTTPRequestHandler, "setup", observe_setup),
            patch.object(auth, "identity", return_value="verified") as identity,
            patch.object(auth, "fetch", return_value=reply) as exchange,
        ):
            auth.login("fixture")
            self.assertTrue(connection_timeouts)
            self.assertTrue(all(timeout is not None and 0 < timeout <= 5 for timeout in connection_timeouts))
            q = callbacks[0]
            form = exchange.call_args.kwargs["form"]
            self.assertEqual(q["client_id"], ["dynamic_agent_client"])
            self.assertEqual(form["client_id"], "issued")
            self.assertEqual(form["redirect_uri"], q["redirect_uri"][0])
            expected = (
                auth.base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest())
                .decode()
                .rstrip("=")
            )
            self.assertEqual(q["code_challenge"], [expected])
            identity.assert_called_once_with("id", "issued", q["nonce"][0])
            self.assertEqual(auth.bearer("fixture"), "synthetic")

    def test_http_failure_only_persists_allowlisted_error_codes(self) -> None:
        import io
        from urllib import error

        def make_err(code_val: str) -> error.HTTPError:
            body = json.dumps({"error": {"code": code_val}}).encode()
            return error.HTTPError("https://api.openai.com/v1/responses", 400, "Bad", {}, io.BytesIO(body))

        echoed = auth.http_failure("ChatGPT", make_err("secret_host_label_echo"))
        self.assertEqual(str(echoed), "ChatGPT returned HTTP 400")
        allowed = auth.http_failure("ChatGPT", make_err("rate_limit_exceeded"))
        self.assertEqual(str(allowed), "ChatGPT returned HTTP 400 (rate_limit_exceeded)")
