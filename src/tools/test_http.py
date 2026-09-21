import pytest
from unittest.mock import AsyncMock, patch
from src.permission.permission import Decision, YoloPrompter
from src.engagement.state import EngagementState, OutOfScopeError
from src.target.target import Target
from src.tools.http import HTTPTool
from src.tools.registry import Registry


class FakeResponse:

    def __init__(
        self,
        text="ok",
        status=200,
        status_text="OK",
        headers=None,
    ):
        self.status_code = status
        self.reason_phrase = status_text
        self.headers = headers or {
            "content-type": "text/plain"
        }

        self._content = text.encode()

    async def aread(self):
        return self._content

    async def aiter_bytes(self):
        yield self._content

class FakeStream:

    async def __aenter__(self):
        return FakeResponse()

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakePrompter:

    def __init__(
        self,
        result=Decision.ALLOW_ONCE,
    ):
        self.ask = AsyncMock(
            return_value=result
        )


def make_stream_cm():
    stream_cm = AsyncMock()
    stream_cm.__aenter__.return_value = FakeResponse()
    stream_cm.__aexit__.return_value = None
    return stream_cm


def scoped_tool(
    url: str = "http://example.test",
    target: Target | None = None,
) -> HTTPTool:
    engagement = EngagementState()
    engagement.initialize_target(url)
    return HTTPTool(target or Target(), engagement)


def test_schema_not_require_method():

    tool = scoped_tool()

    assert tool.schema()["required"] == [
        "url"
    ]


def test_http_tool_requires_engagement_state_at_construction():
    with pytest.raises(TypeError):
        HTTPTool(Target())  # type: ignore[call-arg]

def test_summarize_default_get():

    tool = scoped_tool()

    result = tool.summarize(
        {
            "url": "http://example.test"
        }
    )

    assert result["summary"] == (
        "http: GET http://example.test"
    )

    assert result["detail"] == (
        "GET http://example.test"
    )


def test_summarize_ignores_malformed_headers():
    result = scoped_tool().summarize(
        {"url": "http://example.test", "headers": "not-an-object"}
    )

    assert result["detail"] == "GET http://example.test"

@pytest.mark.asyncio
async def test_default_get_runtime():

    tool = scoped_tool()

    response = FakeResponse()

    stream_cm = AsyncMock()
    stream_cm.__aenter__.return_value = response
    stream_cm.__aexit__.return_value = None

    with patch(
        "src.tools.http.httpx.AsyncClient.stream",
        return_value=stream_cm,
    ) as mock_stream:

        out = await tool.run(
            {
                "url": "http://example.test"
            },
            None,
            FakePrompter(),
        )

        mock_stream.assert_called_once()

        _, kwargs = mock_stream.call_args

        assert kwargs["method"] == "GET"

        assert "HTTP/1.1 200 OK" in out
        assert "ok" in out


@pytest.mark.asyncio
async def test_target_http_keeps_its_environment_proxy_policy(monkeypatch):
    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def stream(self, **kwargs):
            return FakeStream()

    monkeypatch.setattr("src.tools.http.httpx.AsyncClient", FakeClient)

    await scoped_tool().run(
        {"url": "http://example.test"},
        None,
        FakePrompter(),
    )

    # Target traffic still uses httpx's default trust_env=True behavior, so
    # intentional Burp/interception proxy environment settings keep working.
    assert "trust_env" not in captured

@pytest.mark.asyncio
async def test_require_url():

    tool = scoped_tool()

    with pytest.raises(
        Exception,
        match="url is required",
    ):

        await tool.run(
            {},
            None,
            FakePrompter(),
        )

@pytest.mark.asyncio
async def test_block_private_url():

    tool = scoped_tool("http://169.254.169.254")

    prompter = FakePrompter(
        Decision.DENY,
    )

    with pytest.raises(
        Exception,
        match="denied",
    ):

        await tool.run(
            {
                "url":
                "http://169.254.169.254/latest/meta-data/"
            },
            None,
            prompter,
        )

    prompter.ask.assert_called_once()

@pytest.mark.asyncio
async def test_allow_private_url():

    tool = scoped_tool("http://127.0.0.1:8080")

    prompter = FakePrompter(
        Decision.ALLOW_ONCE
    )

    response = FakeResponse()

    stream_cm = AsyncMock()
    stream_cm.__aenter__.return_value = response
    stream_cm.__aexit__.return_value = None

    with patch(
        "src.tools.http.httpx.AsyncClient.stream",
        return_value=stream_cm,
    ) as mock_stream:

        out = await tool.run(
            {
                "url": "http://127.0.0.1:8080/"
            },
            None,
            prompter,
        )

        prompter.ask.assert_called_once()
        mock_stream.assert_called_once()

        assert "HTTP/1.1 200 OK" in out

def test_permission_scope():

    tool = scoped_tool()

    assert tool.permission_hints(
        {
            "url":
            "https://app.example.com/a?x=1"
        }
    ) == {
        "cacheKey": "https://app.example.com",
        "sessionScopeDisplay": "HTTP requests to https://app.example.com",
    }

    assert tool.permission_hints(
        {
            "url":
            "http://169.254.169.254/"
        }
    ) == {
        "cacheKey": "http://169.254.169.254",
        "sessionScopeDisplay": "HTTP requests to http://169.254.169.254",
    }


@pytest.mark.asyncio
async def test_scope_preflight_precedes_permission_and_yolo_cannot_bypass():
    target = Target("https://app.example")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    registry = Registry()
    registry.register(HTTPTool(target, engagement))

    inner = FakePrompter()

    class CountingYolo(YoloPrompter):
        calls = 0

        async def ask(self, request, signal=None):
            self.calls += 1
            return await super().ask(request, signal)

    yolo = CountingYolo(inner, True)

    with pytest.raises(OutOfScopeError):
        await registry.execute(
            "http", {"url": "https://other.example/path"}, None, yolo
        )

    assert yolo.calls == 0
    inner.ask.assert_not_called()


def test_permission_cache_key_uses_canonical_origin():
    tool = scoped_tool()

    assert tool.permission_hints({"url": "HTTPS://App.Example:443/path"}) == {
        "cacheKey": "https://app.example",
        "sessionScopeDisplay": "HTTP requests to https://app.example",
    }


@pytest.mark.asyncio
async def test_http_allows_only_explicit_additional_origins():
    engagement = EngagementState()
    engagement.initialize_target("http://juice.lab:3000")
    engagement.add_origin("http://juice.lab:4000")
    tool = HTTPTool(Target("http://juice.lab:3000"), engagement)

    with (
        patch("src.tools.http.gate_private_request", new=AsyncMock(return_value="")),
        patch(
            "src.tools.http.httpx.AsyncClient.stream",
            return_value=make_stream_cm(),
        ) as mock_stream,
    ):
        await tool.run(
            {"url": "http://juice.lab:4000/allowed"}, None, FakePrompter()
        )

    mock_stream.assert_called_once()
    with pytest.raises(OutOfScopeError):
        tool.validate_args({"url": "http://juice.lab:5000/blocked"})


# ---------------------------------------------------------------------------
# private-host target wiring (session-cache fix)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_http_passes_target_to_private_gate():

    target = Target("http://juice.lab:3000")
    tool = scoped_tool(target.base_url(), target)

    with (
        patch(
            "src.tools.http.gate_private_request",
            new=AsyncMock(return_value="loopback IPv4"),
        ) as mock_gate,
        patch(
            "src.tools.http.httpx.AsyncClient.stream",
            return_value=make_stream_cm(),
        ),
    ):
        await tool.run(
            {"url": "http://juice.lab:3000/"},
            None,
            FakePrompter(),
        )

    mock_gate.assert_awaited_once()

    assert mock_gate.await_args is not None
    kwargs = mock_gate.await_args.kwargs

    assert kwargs.get("target") is target

@pytest.mark.asyncio
async def test_http_prepends_private_note_when_reason_present():

    target = Target("http://juice.lab:3000")
    tool = scoped_tool(target.base_url(), target)

    with (
        patch(
            "src.tools.http.gate_private_request",
            new=AsyncMock(return_value="loopback IPv4"),
        ),
        patch(
            "src.tools.http.httpx.AsyncClient.stream",
            return_value=make_stream_cm(),
        ),
    ):
        out = await tool.run(
            {"url": "http://juice.lab:3000/"},
            None,
            FakePrompter(),
        )

    assert out.startswith("note: private/internal host approved")
    assert "loopback IPv4" in out

@pytest.mark.asyncio
async def test_http_no_note_when_host_is_public():

    tool = scoped_tool()

    with (
        patch(
            "src.tools.http.gate_private_request",
            new=AsyncMock(return_value=""),
        ),
        patch(
            "src.tools.http.httpx.AsyncClient.stream",
            return_value=make_stream_cm(),
        ),
    ):
        out = await tool.run(
            {"url": "http://example.test/"},
            None,
            FakePrompter(),
        )

    assert not out.startswith("note:")
