"""Regression tests for the fetch tool's shared cookie-jar handling.

Covers the bug where brute_force_login synced session cookies into
MCPLifecycleManager._fetch_cookies, but _call_fetch created a fresh,
cookie-less httpx.AsyncClient per call and never read or wrote that jar.
"""

from __future__ import annotations

import httpx
import pytest

from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.mcp.lifecycle import MCPLifecycleManager


def _manager() -> MCPLifecycleManager:
    return MCPLifecycleManager(VulnClawConfig())


def _patch_fetch_transport(monkeypatch, handler):
    class _RecordingAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _RecordingAsyncClient)


@pytest.mark.asyncio
async def test_call_fetch_persists_response_cookies_into_shared_jar(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"set-cookie": "session=abc123; Path=/"},
            text="ok",
        )

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    await manager._call_fetch({"url": "https://example.com/login", "method": "GET"})

    jar = manager._fetch_cookies
    assert jar is not None
    assert jar.get("session") == "abc123"


@pytest.mark.asyncio
async def test_call_fetch_sends_previously_stored_cookies(monkeypatch):
    seen_cookie_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookie_headers.append(request.headers.get("cookie"))
        return httpx.Response(200, text="post-login content")

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    manager._fetch_cookies = httpx.Cookies()
    manager._fetch_cookies.set("session", "abc123", domain="example.com", path="/")

    await manager._call_fetch({"url": "https://example.com/dashboard", "method": "GET"})

    assert seen_cookie_headers == ["session=abc123"]


@pytest.mark.asyncio
async def test_call_fetch_with_no_prior_session_sends_no_cookie_header(monkeypatch):
    seen_cookie_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookie_headers.append(request.headers.get("cookie"))
        return httpx.Response(200, text="ok")

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    await manager._call_fetch({"url": "https://example.com/", "method": "GET"})

    assert seen_cookie_headers == [None]
