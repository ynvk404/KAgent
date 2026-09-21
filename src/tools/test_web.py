from __future__ import annotations

from typing import Any, Awaitable, Callable
from unittest.mock import AsyncMock

import httpx
import pytest

from src.permission.permission import Decision, PermissionRequest, AlwaysAllow, AlwaysDeny
from src.engagement.state import EngagementState, OutOfScopeError
from src.target.target import Target
from src.tools.web import WebFetchTool, WebSearchTool, clear_web_cache

class _Prompter:
    async def ask(
        self,
        request: PermissionRequest,
        signal=None,
    ) -> Decision:
        return Decision.ALLOW_ONCE

prompter = _Prompter()

class FakeSignal:
    def __init__(self, aborted: bool = False):
        self.aborted = aborted

class FakeResponse:
    def __init__(
        self,
        body: bytes = b"",
        status_code: int = 200,
        reason_phrase: str = "OK",
    ):
        self.body = body
        self.status_code = status_code
        self.reason_phrase = reason_phrase

    async def aiter_bytes(self):
        yield self.body

    async def aclose(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.aclose()

Handler = Callable[[httpx.Request], Awaitable[FakeResponse]]

class FakeAsyncClient:
    handler: Handler | None = None
    last_init_kwargs: dict[str, Any] | None = None
    call_count = 0

    def __init__(self, **kwargs: Any):
        type(self).last_init_kwargs = kwargs

    def build_request(self, method: str, url: str, headers: dict | None = None) -> httpx.Request:
        return httpx.Request(method, url, headers=headers)

    async def send(self, request: httpx.Request, stream: bool = False) -> FakeResponse:
        type(self).call_count += 1
        assert type(self).handler is not None, "no fake handler configured for this test"
        handler = type(self).handler
        assert handler is not None
        return await handler(request)

    async def aclose(self) -> None:
        pass

@pytest.fixture(autouse=True)
def fake_httpx_client(monkeypatch: pytest.MonkeyPatch):
    FakeAsyncClient.handler = None
    FakeAsyncClient.last_init_kwargs = None
    FakeAsyncClient.call_count = 0
    monkeypatch.setattr("src.tools.web.httpx.AsyncClient", FakeAsyncClient)
    yield
    clear_web_cache()

def set_handler(handler: Handler) -> None:
    FakeAsyncClient.handler = handler

def ok_handler(body: str, status: int = 200, reason: str = "OK") -> Handler:
    async def handler(_request: httpx.Request) -> FakeResponse:
        return FakeResponse(body.encode("utf-8"), status_code=status, reason_phrase=reason)

    return handler

def failing_handler(exc: Exception) -> Handler:
    async def handler(_request: httpx.Request) -> FakeResponse:
        raise exc

    return handler


def scoped_fetch(url: str = "https://example.com") -> WebFetchTool:
    engagement = EngagementState()
    engagement.initialize_target(url)
    return WebFetchTool(engagement)


def test_web_fetch_requires_engagement_state_at_construction():
    with pytest.raises(TypeError):
        WebFetchTool()  # type: ignore[call-arg]

@pytest.mark.asyncio
async def test_returns_readable_text_for_successful_fetches():
    set_handler(
        ok_handler("<html><body><h1>Hello</h1><script>x()</script></body></html>")
    )

    out = await scoped_fetch().run({"url": "https://example.com"}, None, prompter)

    assert "URL: https://example.com" in out
    assert "Status: 200" in out
    assert "Hello" in out
    assert "<h1>" not in out
    assert "x()" not in out

@pytest.mark.asyncio
async def test_explains_hackerone_platform_dns_failures_with_program_url_hint():
    set_handler(
        failing_handler(httpx.ConnectError("getaddrinfo ENOTFOUND platform.hackerone.com"))
    )

    out = await scoped_fetch("https://platform.hackerone.com").run(
        {"url": "https://platform.hackerone.com/hackerone/policy_scopes"},
        None,
        prompter,
    )

    assert "ERROR: fetch failed" in out
    assert "Code: ENOTFOUND" in out
    assert "platform.hackerone.com is not a public HackerOne program host" in out
    assert "https://hackerone.com/hackerone" in out

@pytest.mark.asyncio
async def test_rethrows_when_caller_aborts_the_request():
    signal = FakeSignal(aborted=True)
    set_handler(failing_handler(Exception("aborted")))

    with pytest.raises(Exception):
        await scoped_fetch().run({"url": "https://example.com"}, signal, prompter)

    assert FakeAsyncClient.call_count == 0

@pytest.mark.asyncio
async def test_prompts_before_fetching_private_or_local_urls():
    set_handler(ok_handler(""))

    with pytest.raises(Exception, match=r"private/internal URL denied"):
        await scoped_fetch("http://127.0.0.1:3000").run(
            {"url": "http://127.0.0.1:3000/status"},
            None,
            AlwaysDeny(),
        )

    assert FakeAsyncClient.call_count == 0

@pytest.mark.asyncio
async def test_does_not_automatically_follow_redirects():
    set_handler(ok_handler("", status=302, reason="Found"))

    await scoped_fetch().run(
        {"url": "https://example.com/redirect"},
        None,
        prompter,
    )

    assert FakeAsyncClient.last_init_kwargs == {"follow_redirects": False}

@pytest.mark.asyncio
async def test_prompts_before_fetching_ipv4_mapped_ipv6_private_urls():
    set_handler(ok_handler(""))

    with pytest.raises(Exception, match=r"private/internal URL denied"):
        await scoped_fetch("http://[::ffff:169.254.169.254]").run(
            {"url": "http://[::ffff:169.254.169.254]/latest/meta-data/"},
            None,
            AlwaysDeny(),
        )

    assert FakeAsyncClient.call_count == 0

@pytest.mark.asyncio
async def test_rejects_non_http_url_schemes():
    with pytest.raises(Exception, match="unsupported URL scheme"):
        await scoped_fetch().run(
            {"url": "file:///etc/passwd"},
            None,
            prompter,
        )


@pytest.mark.asyncio
async def test_fetch_scope_preflight_blocks_before_private_gate_or_network(monkeypatch):
    engagement = EngagementState()
    engagement.initialize_target("https://app.example")
    private_gate = AsyncMock()
    monkeypatch.setattr("src.tools.web.gate_private_request", private_gate)

    with pytest.raises(OutOfScopeError):
        await WebFetchTool(engagement).run(
            {"url": "https://other.example/page"}, None, prompter
        )

    private_gate.assert_not_awaited()
    assert FakeAsyncClient.call_count == 0


@pytest.mark.asyncio
async def test_private_fetch_passes_active_target_to_private_host_gate(monkeypatch):
    target = Target("http://juice.lab:3000")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    gate = AsyncMock(return_value="")
    monkeypatch.setattr("src.tools.web.gate_private_request", gate)
    set_handler(ok_handler("ok"))

    await WebFetchTool(engagement, target).run(
        {"url": "http://juice.lab:3000/status"}, None, prompter
    )

    assert gate.call_args.kwargs["target"] is target


@pytest.mark.asyncio
async def test_fetch_allows_explicit_additional_origin_and_blocks_unrelated():
    engagement = EngagementState()
    engagement.initialize_target("https://app.example")
    engagement.add_origin("https://docs.example:8443")
    set_handler(ok_handler("<p>allowed</p>"))

    out = await WebFetchTool(engagement).run(
        {"url": "https://docs.example:8443/page"}, None, prompter
    )
    assert "allowed" in out

    with pytest.raises(OutOfScopeError):
        await WebFetchTool(engagement).run(
            {"url": "https://other.example/page"}, None, prompter
        )

@pytest.mark.asyncio
async def test_serves_second_fetch_of_same_url_from_cache():
    set_handler(ok_handler("<p>cached body</p>"))

    first = await scoped_fetch().run(
        {"url": "https://example.com/advisory"}, None, prompter
    )
    second = await scoped_fetch().run(
        {"url": "https://example.com/advisory"}, None, prompter
    )

    assert second == first
    assert FakeAsyncClient.call_count == 1

@pytest.mark.asyncio
async def test_does_not_cache_failed_fetches():
    set_handler(failing_handler(httpx.ConnectError("fetch failed")))

    await scoped_fetch().run({"url": "https://example.com/down"}, None, prompter)
    await scoped_fetch().run({"url": "https://example.com/down"}, None, prompter)

    assert FakeAsyncClient.call_count == 2

@pytest.mark.asyncio
async def test_parses_structured_duckduckgo_results():
    html = """
      <a class="result__a" href="https://cve.example/CVE-1">Title One</a>
      <a class="result__snippet">Snippet one</a>"""
    set_handler(ok_handler(html))

    out = await WebSearchTool().run({"query": "CVE-1"}, None, prompter)

    assert "Title One" in out
    assert "https://cve.example/CVE-1" in out
    assert "Snippet one" in out

@pytest.mark.asyncio
async def test_falls_back_to_raw_anchor_extraction_when_markup_changes():
    html = """
      <div><a href="/internal">nav</a></div>
      <a href="https://example.org/post">Interesting Post</a>
      <a href="https://example.org/other">Another Result</a>"""
    set_handler(ok_handler(html))

    out = await WebSearchTool().run({"query": "anything"}, None, prompter)

    assert "degraded results" in out
    assert "https://example.org/post" in out
    assert "Interesting Post" in out
    assert "/internal" not in out

@pytest.mark.asyncio
async def test_returns_structured_failure_instead_of_throwing_when_search_fetch_fails():
    set_handler(
        failing_handler(httpx.ConnectError("getaddrinfo ENOTFOUND html.duckduckgo.com"))
    )

    out = await WebSearchTool().run({"query": "whatever"}, None, prompter)

    assert "ERROR: fetch failed" in out
    assert "Code: ENOTFOUND" in out
