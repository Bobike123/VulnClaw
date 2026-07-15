"""Tests for LLM credential resolution (static + OAuth / ChatGPT sign-in)."""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from vulnclaw.config import token_provider as tp
from vulnclaw.config.schema import LLMConfig


@pytest.fixture
def _config_dir(tmp_path, monkeypatch):
    """Isolate the OAuth token store in a temp config dir."""
    monkeypatch.setenv("VULNCLAW_CONFIG_DIR", str(tmp_path))
    yield tmp_path


# ── static mode ──────────────────────────────────────────────────────


def test_static_mode_returns_api_key():
    llm = LLMConfig(api_key="sk-static")
    assert tp.resolve_llm_token(llm) == "sk-static"
    assert tp.has_llm_credentials(llm) is True


def test_static_mode_without_key_is_not_credentialed():
    llm = LLMConfig()
    assert tp.resolve_llm_token(llm) == ""
    assert tp.has_llm_credentials(llm) is False


def test_unknown_mode_raises():
    with pytest.raises(tp.TokenResolutionError):
        tp.resolve_llm_token(LLMConfig(auth_mode="bogus"))


# ── oauth store + resolution ─────────────────────────────────────────


def test_oauth_has_credentials_reflects_store(_config_dir):
    llm = LLMConfig(auth_mode="oauth")
    assert tp.has_llm_credentials(llm) is False
    tp.save_oauth_tokens({"access_token": "a", "refresh_token": "r"})
    assert tp.has_llm_credentials(llm) is True


def test_oauth_resolve_uses_valid_access_token(_config_dir):
    tp.save_oauth_tokens({"access_token": "live", "expires_at": time.time() + 3600})
    assert tp.resolve_llm_token(LLMConfig(auth_mode="oauth")) == "live"


def test_oauth_resolve_without_tokens_raises(_config_dir):
    with pytest.raises(tp.OAuthError):
        tp.resolve_llm_token(LLMConfig(auth_mode="oauth"))


def test_logout_removes_store(_config_dir):
    tp.save_oauth_tokens({"access_token": "a"})
    assert tp.logout_oauth() is True
    assert tp.load_oauth_tokens() == {}


# ── inspect_llm_auth (read-only status, no refresh/network) ──────────


def test_inspect_llm_auth_static_mode_with_key(_config_dir):
    status = tp.inspect_llm_auth(LLMConfig(api_key="sk-static"))
    assert status.mode == "static"
    assert status.ready is True


def test_inspect_llm_auth_static_mode_without_key(_config_dir):
    status = tp.inspect_llm_auth(LLMConfig())
    assert status.mode == "static"
    assert status.ready is False


def test_inspect_llm_auth_oauth_mode_with_valid_token(_config_dir):
    tp.save_oauth_tokens({"access_token": "live", "expires_at": time.time() + 3600})
    status = tp.inspect_llm_auth(LLMConfig(auth_mode="oauth"))
    assert status.mode == "oauth"
    assert status.ready is True
    assert status.oauth_access_expired is False


def test_inspect_llm_auth_oauth_mode_expired_but_refreshable(_config_dir):
    tp.save_oauth_tokens(
        {"access_token": "stale", "refresh_token": "r", "expires_at": time.time() - 10}
    )
    status = tp.inspect_llm_auth(LLMConfig(auth_mode="oauth"))
    assert status.mode == "oauth"
    assert status.ready is True  # refreshable, so still usable
    assert status.oauth_access_expired is True
    assert status.oauth_refreshable is True


def test_inspect_llm_auth_oauth_mode_without_tokens(_config_dir):
    status = tp.inspect_llm_auth(LLMConfig(auth_mode="oauth"))
    assert status.mode == "oauth"
    assert status.ready is False
    assert status.oauth_tokens_stored is False


def test_inspect_llm_auth_never_refreshes_or_leaks_token(_config_dir, monkeypatch):
    """inspect_llm_auth must be side-effect-free: no refresh call, no token in the result."""

    def _boom(*args, **kwargs):
        raise AssertionError("inspect_llm_auth must not trigger a token refresh")

    monkeypatch.setattr(tp, "_resolve_oauth_token", _boom)
    tp.save_oauth_tokens({"access_token": "stale", "expires_at": time.time() - 10})
    status = tp.inspect_llm_auth(LLMConfig(auth_mode="oauth"))
    assert not hasattr(status, "access_token")
    assert "stale" not in repr(status)


def test_decode_jwt_claims_and_account_id():
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    claims = {"https://api.openai.com/auth": {"chatgpt_account_id": "acct-123"}}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    tok = f"{header}.{payload}.sig"
    assert tp._extract_account_id(tp._decode_jwt_claims(tok)) == "acct-123"
    assert tp._decode_jwt_claims("not-a-jwt") == {}


# ── Sign in with ChatGPT (Codex OAuth client) ────────────────────────


def _make_id_token(account_id: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    claims = {"https://api.openai.com/auth": {"chatgpt_account_id": account_id}}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_chatgpt_login_and_refresh(_config_dir, monkeypatch):
    refreshes = {"n": 0}

    class Provider(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - /authorize -> 302 to callback
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            assert q["client_id"][0] == tp.CHATGPT_CLIENT_ID
            assert q["code_challenge_method"][0] == "S256"
            assert q["id_token_add_organizations"][0] == "true"
            redirect = q["redirect_uri"][0]
            sep = "&" if "?" in redirect else "?"
            loc = redirect + sep + urllib.parse.urlencode(
                {"code": "cgpt-code", "state": q["state"][0]}
            )
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()

        def do_POST(self):  # noqa: N802 - /token
            n = int(self.headers.get("Content-Length", 0))
            form = urllib.parse.parse_qs(self.rfile.read(n).decode())
            if form["grant_type"][0] == "authorization_code":
                assert form["client_id"][0] == tp.CHATGPT_CLIENT_ID
                assert form["code_verifier"][0]
                body = {
                    "access_token": "cgpt-1",
                    "refresh_token": "cgpt-refresh",
                    "expires_in": 1,
                    "id_token": _make_id_token("acct-XYZ"),
                }
            else:
                refreshes["n"] += 1
                assert form["refresh_token"][0] == "cgpt-refresh"
                body = {"access_token": f"cgpt-{refreshes['n'] + 1}", "expires_in": 3600}
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Provider)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(tp, "CHATGPT_AUTHORIZE_URL", f"http://127.0.0.1:{port}/authorize")
        monkeypatch.setattr(tp, "CHATGPT_TOKEN_URL", f"http://127.0.0.1:{port}/token")

        def fake_open(url):
            def _go():
                time.sleep(0.2)
                try:
                    urllib.request.urlopen(url, timeout=5)
                except Exception:
                    pass

            threading.Thread(target=_go, daemon=True).start()
            return True

        monkeypatch.setattr(tp.webbrowser, "open", fake_open)

        bundle = tp.perform_chatgpt_login()
        assert bundle["access_token"] == "cgpt-1"
        assert bundle["account_id"] == "acct-XYZ"
        assert bundle["flow"] == "chatgpt"

        # config mirrors what `vulnclaw login` persists (Codex token endpoint).
        llm = LLMConfig(
            auth_mode="oauth",
            oauth_token_url=f"http://127.0.0.1:{port}/token",
            oauth_client_id=tp.CHATGPT_CLIENT_ID,
        )
        assert tp.has_llm_credentials(llm) is True
        time.sleep(1.1)  # force expiry → silent refresh
        tok = tp.resolve_llm_token(llm)
        assert tok.startswith("cgpt-")
        assert refreshes["n"] >= 1
        # account id survives the refresh
        assert tp.load_oauth_tokens().get("account_id") == "acct-XYZ"
    finally:
        srv.shutdown()
