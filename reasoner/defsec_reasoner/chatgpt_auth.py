"""Direct Sign in with ChatGPT for the investigator's own local registrations."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import tempfile
import time
import uuid
import webbrowser
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib import error, parse, request

from .models import ProviderError, _NoRedirect, _SAFE_PROVIDER_ERRORS

ISSUER = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
PLAN_SCOPE = "chatgpt.tokens.use.direct"
TOKEN_URL = ISSUER + "/api/accounts/oauth/token"

_SAFE_OAUTH_ERRORS = _SAFE_PROVIDER_ERRORS | frozenset({
    "access_denied",
    "invalid_client",
    "invalid_grant",
    "invalid_request",
    "invalid_scope",
    "login_required",
    "unauthorized_client",
    "unsupported_grant_type",
})


def opener():
    return request.build_opener(request.ProxyHandler({}), _NoRedirect())


def http_failure(service, exc):
    # Provider messages can echo request content. Keep only allowlisted diagnostic codes.
    try:
        detail = json.loads(exc.read(4096)).get("error", {})
        code = detail.get("code") if isinstance(detail, dict) else detail
        suffix = f" ({code})" if isinstance(code, str) and code in _SAFE_OAUTH_ERRORS else ""
    except (OSError, ValueError, AttributeError):
        suffix = ""
    return ProviderError(
        f"{service} returned HTTP {exc.code}{suffix}", exc.code in (408, 429) or exc.code >= 500
    )


def fetch(url, *, form=None, token=None):
    headers = {"Authorization": "Bearer " + token} if token else {}
    req = request.Request(url, data=parse.urlencode(form).encode() if form else None, headers=headers)
    try:
        with opener().open(req, timeout=15) as response:
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise ProviderError("OAuth response exceeds limit", False)
            return json.loads(data) if data else {}
    except error.HTTPError as exc:
        raise http_failure("ChatGPT account endpoint", exc) from None
    except (OSError, ValueError) as exc:
        raise ProviderError("ChatGPT account endpoint unavailable or malformed", True) from exc


def auth_dir():
    root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    return root / "defsec-reasoner" / "chatgpt"


@contextmanager
def registry():
    directory = auth_dir()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077 or directory.stat().st_uid != os.getuid():
        raise ProviderError("ChatGPT state requires a private directory owned by the worker user", False)
    path = directory / "registrations.json"
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        original = path.read_bytes() if path.exists() else b""
        state = (
            json.loads(original) if original else {"accounts": {}, "host": "urn:uuid:" + str(uuid.uuid4())}
        )
        yield state
        data = json.dumps(state, separators=(",", ":")).encode()
        if data != original:
            with tempfile.NamedTemporaryFile(dir=directory, delete=False) as temp:
                try:
                    temp.write(data)
                    temp.flush()
                    os.fsync(temp.fileno())
                    os.replace(temp.name, path)
                finally:
                    Path(temp.name).unlink(missing_ok=True)


def identity(encoded, client_id, nonce=None):
    try:
        import jwt
    except ImportError:
        raise ProviderError("Install defsec-reasoner[chatgpt] for ChatGPT sign-in", False) from None
    metadata = fetch(ISSUER + "/.well-known/openid-configuration")
    uri = metadata["jwks_uri"]
    if metadata["issuer"] != ISSUER or parse.urlsplit(uri)[:2] != ("https", "auth.openai.com"):
        raise ProviderError("Unexpected ChatGPT identity metadata", False)
    try:
        header = jwt.get_unverified_header(encoded)
        if header["alg"] not in ("RS256", "ES256"):
            raise ValueError()
        (jwk,) = [
            k
            for k in fetch(uri)["keys"]
            if k.get("kid") == header.get("kid") and k.get("alg", header["alg"]) == header["alg"]
        ]
        claims = jwt.decode(
            encoded,
            jwt.PyJWK.from_dict(jwk).key,
            algorithms=[header["alg"]],
            issuer=ISSUER,
            audience=client_id,
            options={"require": ["sub", "iat", "exp", "iss", "aud"]},
        )
        if (
            not isinstance(claims["sub"], str)
            or not claims["sub"]
            or claims.get("azp", client_id) != client_id
            or isinstance(claims["aud"], list)
            and len(claims["aud"]) > 1
            and claims.get("azp") != client_id
            or nonce is not None
            and not secrets.compare_digest(claims.get("nonce", ""), nonce)
        ):
            raise ValueError()
        return claims["sub"]
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        raise ProviderError("ChatGPT identity verification failed", False) from None


def update_tokens(record, tokens):
    if (
        str(tokens.get("token_type", "")).lower() != "bearer"
        or not tokens.get("access_token")
        or not 0 < float(tokens.get("expires_in", 0)) <= 30 * 86400
    ):
        raise ProviderError("Invalid ChatGPT token response", False)
    for field in ("access_token", "refresh_token", "id_token"):
        if tokens.get(field):
            record[field] = tokens[field]
    if "scope" in tokens:
        record["scopes"] = tokens["scope"].split()
    record["expires"] = time.time() + float(tokens["expires_in"])


def bearer(profile):
    with registry() as state:
        record = state["accounts"].get(profile, {})
        if PLAN_SCOPE not in record.get("scopes", []):
            raise ProviderError("Continue with ChatGPT for this profile and authorize plan sharing", False)
        if record["expires"] <= time.time() + 60:
            if not record.get("refresh_token"):
                raise ProviderError("ChatGPT session expired. Sign in again.", False)
            tokens = fetch(
                TOKEN_URL,
                form={
                    "grant_type": "refresh_token",
                    "client_id": record["client_id"],
                    "refresh_token": record["refresh_token"],
                    "resource": RESOURCE,
                },
            )
            if (
                tokens.get("id_token")
                and identity(tokens["id_token"], record["client_id"]) != record["subject"]
            ):
                raise ProviderError("ChatGPT refresh identity mismatch", False)
            update_tokens(record, tokens)
        allowed = PLAN_SCOPE in record["scopes"]
        token = record["access_token"]
    if not allowed:
        raise ProviderError("ChatGPT plan sharing permission was removed", False)
    return token


def login(profile):
    with registry() as state:
        old = dict(state["accounts"].get(profile, {}))
        host = state["host"]
    if not profile.strip():
        raise ProviderError("Choose a nonempty ChatGPT profile label", False)
    nonce, verifier, state_id = (secrets.token_urlsafe(32) for _ in range(3))
    callback = {}
    launch_path = "/continue/" + secrets.token_urlsafe(24)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(max(0.001, min(5.0, deadline - time.monotonic())))
            super().setup()

        def log_message(self, *args):
            pass

        def do_GET(self):
            parts = parse.urlsplit(self.path)
            if parts.path == launch_path:
                self.send_response(303)
                self.send_header("Location", authorization_url)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                return
            params = parse.parse_qs(parts.query)
            valid = (
                parts.path == "/auth/callback"
                and all(len(v) == 1 for v in params.values())
                and secrets.compare_digest(params.get("state", [""])[0], state_id)
            )
            if valid:
                callback.update({k: v[0] for k, v in params.items()})
            self.send_response(200 if valid else 400)
            self.end_headers()
            self.wfile.write(b"Return to the investigator terminal.")

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        redirect = f"http://127.0.0.1:{server.server_port}/auth/callback"
        params = {
            "client_id": old.get("client_id", "dynamic_agent_client"),
            "response_type": "code",
            "ext_agent_host_id": host,
            "scope": "openid profile email offline_access resource.invoke " + PLAN_SCOPE,
            "resource": RESOURCE,
            "state": state_id,
            "nonce": nonce,
            "redirect_uri": redirect,
            "code_challenge_method": "S256",
            "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("="),
        }
        if not old:
            params["agent_name_hint"] = "DefSecAutMit Investigator"
        if old.get("id_token"):
            params["id_token_hint"] = old["id_token"]
        authorization_url = ISSUER + "/api/accounts/authorize?" + parse.urlencode(params)
        # Keep identity hints out of browser-launch arguments and terminal output.
        browser_url = f"http://127.0.0.1:{server.server_port}{launch_path}"
        print("Continue with ChatGPT in your browser. The callback returns to this machine.", flush=True)
        if not webbrowser.open(browser_url):
            print(browser_url, flush=True)
        deadline = time.monotonic() + 300
        while not callback and time.monotonic() < deadline:
            server.timeout = min(1.0, max(0.0, deadline - time.monotonic()))
            server.handle_request()
    client_id = callback.get("client_id", old.get("client_id"))
    if (
        "error" in callback
        or not callback.get("code")
        or not client_id
        or client_id == "dynamic_agent_client"
        or old
        and client_id != old["client_id"]
    ):
        raise ProviderError(
            "ChatGPT sign-in was declined, expired or returned an invalid registration", False
        )
    tokens = fetch(
        TOKEN_URL,
        form={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": callback["code"],
            "redirect_uri": redirect,
            "code_verifier": verifier,
            "resource": RESOURCE,
        },
    )
    subject = identity(tokens.get("id_token"), client_id, nonce)
    if old and subject != old["subject"]:
        raise ProviderError("Selected profile belongs to a different ChatGPT account", False)
    record = {"client_id": client_id, "subject": subject}
    update_tokens(record, tokens)
    with registry() as state:
        if state["accounts"].get(profile, {}) != old:
            raise ProviderError("ChatGPT profile changed during sign-in. Retry.", False)
        state["accounts"][profile] = record
    print(
        "ChatGPT connected." if PLAN_SCOPE in record.get("scopes", []) else "Signed in without plan sharing."
    )


def logout(profile):
    confirmed = False
    with registry() as state:
        record = state["accounts"].get(profile)
        if not record:
            return
        refresh_token = record.get("refresh_token")
        if refresh_token:
            try:
                endpoint = fetch(ISSUER + "/.well-known/openid-configuration")["revocation_endpoint"]
                if parse.urlsplit(endpoint)[:2] != ("https", "auth.openai.com"):
                    raise ProviderError("Unexpected revocation endpoint", False)
                fetch(
                    endpoint,
                    form={
                        "client_id": record["client_id"],
                        "token": refresh_token,
                        "token_type_hint": "refresh_token",
                    },
                )
                confirmed = True
            except (KeyError, ProviderError):
                pass
        for field in ("access_token", "refresh_token", "id_token", "scopes", "expires"):
            record.pop(field, None)
    if confirmed:
        print("Signed out.")
    elif refresh_token:
        print("Local credentials cleared. Remote revocation unconfirmed; see ChatGPT Settings.")
    else:
        print("Local credentials cleared. Remote revocation was not attempted (no refresh token).")
