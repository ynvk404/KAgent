import pytest
from unittest.mock import AsyncMock, patch
from src.permission.http_grants import HTTPLimits
from src.permission.permission import Decision, UserControlledRefusal, YoloPrompter
from src.engagement.state import EngagementState, OutOfScopeError
from src.target.target import Target
from src.tools.http import HTTPTool, RESPONSE_BYTE_CAP
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

    async def aclose(self):
        pass

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
    return FakeResponse()


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
        "url", "phase"
    ]


def test_http_tool_requires_engagement_state_at_construction():
    with pytest.raises(TypeError):
        HTTPTool(Target())  # type: ignore[call-arg]

def test_summarize_default_get():

    tool = scoped_tool()

    result = tool.summarize(
        {
            "phase": "recon",
            "url": "http://example.test"
        }
    )

    assert result["summary"] == (
        "http: GET http://example.test"
    )

    assert "GET http://example.test" in result["detail"]
    assert "user-agent: kagent/0.1" in result["detail"]


def test_summarize_ignores_malformed_headers():
    result = scoped_tool().summarize(
        {"phase": "recon", "url": "http://example.test", "headers": "not-an-object"}
    )

    assert "GET http://example.test" in result["detail"]
    assert "user-agent: kagent/0.1" in result["detail"]

@pytest.mark.asyncio
async def test_default_get_runtime():

    tool = scoped_tool()

    response = FakeResponse()

    stream_cm = response

    with (
        patch(
            "src.tools.http.httpx.AsyncClient.send",
            new=AsyncMock(return_value=stream_cm),
        ) as mock_stream,
        patch(
            "src.tools.http.gate_private_request",
            new=AsyncMock(return_value=""),
        ),
    ):

        out = await tool.run(
            {
                "url": "http://example.test"
            },
            None,
            FakePrompter(),
        )

        mock_stream.assert_called_once()

        request = mock_stream.call_args.args[0]

        assert request.method == "GET"

        assert "HTTP/1.1 200 OK" in out
        assert "ok" in out


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [
    RESPONSE_BYTE_CAP - 1, RESPONSE_BYTE_CAP,
    RESPONSE_BYTE_CAP + 1, RESPONSE_BYTE_CAP * 3,
])
@pytest.mark.parametrize("status", [200, 403])
async def test_http_body_cap_reports_only_actual_truncation(size, status):
    response = FakeResponse(
        text="x" * size, status=status,
        status_text="OK" if status == 200 else "Forbidden",
    )
    stream_cm = response

    with (
        patch("src.tools.http.httpx.AsyncClient.send", return_value=stream_cm),
        patch(
            "src.tools.http.gate_private_request",
            new=AsyncMock(return_value=""),
        ),
    ):
        out = await scoped_tool().run(
            {"url": "http://example.test"}, None, FakePrompter(),
        )

    assert out.status == "observation"
    assert out.error_kind is None
    assert out.http_status == status
    assert out.truncated is (size > RESPONSE_BYTE_CAP)
    assert out.split("\n\n", 1)[1].split("\n[response body truncated", 1)[0] == (
        "x" * min(size, RESPONSE_BYTE_CAP)
    )
    assert ("[response body truncated" in out) is (size > RESPONSE_BYTE_CAP)


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

        async def send(self, request, **kwargs):
            return FakeResponse()

    monkeypatch.setattr("src.tools.http.httpx.AsyncClient", FakeClient)
    monkeypatch.setattr(
        "src.tools.http.gate_private_request",
        AsyncMock(return_value=""),
    )

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

    stream_cm = response

    with patch(
        "src.tools.http.httpx.AsyncClient.send",
        new=AsyncMock(return_value=stream_cm),
    ) as mock_stream:

        out = await tool.run(
            {
                "url": "http://127.0.0.1:8080/"
            },
            None,
            prompter,
        )

        assert prompter.ask.call_count == 2
        mock_stream.assert_called_once()

        assert "HTTP/1.1 200 OK" in out

def test_permission_scope():

    tool = scoped_tool()

    assert tool.permission_hints(
        {
            "phase": "recon",
            "url":
            "https://app.example.com/a?x=1"
        }
    ) == {
        "noSessionCache": True,
        "riskTier": "high-impact",
        "yoloAutoApprove": False,
    }

    assert tool.permission_hints(
        {
            "phase": "recon",
            "url":
            "http://169.254.169.254/"
        }
    ) == {
        "noSessionCache": True,
        "riskTier": "high-impact",
        "yoloAutoApprove": False,
    }


@pytest.mark.parametrize(
    ("args", "expected_tier", "expected_auto"),
    [
        ({"phase": "recon", "method": "GET", "url": "https://app.example/"}, "high-impact", False),
        ({"phase": "validation", "method": "POST", "url": "https://app.example/submit", "body": "marker"}, "high-impact", False),
        ({"phase": "impact", "method": "POST", "url": "https://app.example/submit", "body": "effect"}, "high-impact", False),
        ({"phase": "impact", "method": "GET", "url": "https://app.example/resource/1"}, "high-impact", False),
    ],
)
def test_http_permission_hints_never_authorize_from_phase_method_or_body(args, expected_tier, expected_auto):
    hints = scoped_tool().permission_hints(args)
    assert hints.get("noSessionCache", False) is (not expected_auto)
    assert hints.get("riskTier") == expected_tier
    assert hints.get("yoloAutoApprove", False) is expected_auto


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
            "http", {"url": "https://other.example/path", "phase": "recon"}, None, yolo
        )

    assert yolo.calls == 0
    inner.ask.assert_not_called()


def test_permission_cache_key_uses_canonical_origin():
    tool = scoped_tool()

    assert tool.permission_hints({"url": "HTTPS://App.Example:443/path", "phase": "recon"}) == {
        "noSessionCache": True,
        "riskTier": "high-impact",
        "yoloAutoApprove": False,
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
            "src.tools.http.httpx.AsyncClient.send",
            new=AsyncMock(return_value=make_stream_cm()),
        ) as mock_stream,
    ):
        await tool.run(
            {"url": "http://juice.lab:4000/allowed"}, None, FakePrompter()
        )

    mock_stream.assert_called_once()
    with pytest.raises(OutOfScopeError):
        tool.validate_args({"url": "http://juice.lab:5000/blocked", "phase": "recon"})


@pytest.mark.asyncio
async def test_autonomous_grant_approves_in_scope_post_validation():
    target = Target("https://app.example")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    registry = Registry()
    registry.register(HTTPTool(target, engagement))
    engagement.http_permissions.activate(target.base_url(), HTTPLimits())
    inner = FakePrompter(Decision.DENY)

    with (
        patch("src.tools.private_host.private_host_reason", new=AsyncMock(return_value="")),
        patch(
            "src.tools.http.httpx.AsyncClient.send",
            new=AsyncMock(return_value=make_stream_cm()),
        ) as mock_stream,
    ):
        result = await registry.execute(
            "http",
            {"phase": "validation", "method": "POST", "url": "/submit", "body": "marker"},
            None,
            YoloPrompter(inner, True),
        )

    assert "HTTP/1.1 200 OK" in str(result)
    mock_stream.assert_called_once()
    inner.ask.assert_not_called()


@pytest.mark.asyncio
async def test_impact_without_yolo_requires_exact_approval():
    target = Target("https://app.example")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    registry = Registry()
    registry.register(HTTPTool(target, engagement))
    inner = FakePrompter(Decision.DENY)

    with patch("src.tools.http.httpx.AsyncClient.send") as mock_stream:
        with pytest.raises(UserControlledRefusal, match="denied"):
            await registry.execute(
                "http",
                {"phase": "impact", "method": "GET", "url": "/resource/1"},
                None,
                YoloPrompter(inner, False),
            )

    inner.ask.assert_called_once()
    request = inner.ask.call_args.args[0]
    assert request.risk_tier == "high-impact"
    assert request.no_session_cache is True
    assert request.yolo_auto_approve is False
    mock_stream.assert_not_called()


@pytest.mark.asyncio
async def test_private_target_gate_preserves_independent_yolo_policy():
    target = Target("http://juice.lab:3000")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    registry = Registry()
    registry.register(HTTPTool(target, engagement))
    engagement.http_permissions.activate(target.base_url(), HTTPLimits())
    inner = FakePrompter(Decision.DENY)

    with (
        patch(
            "src.tools.private_host.private_host_reason",
            new=AsyncMock(return_value="DNS resolves to loopback IPv4"),
        ),
        patch(
            "src.tools.http.httpx.AsyncClient.send",
            new=AsyncMock(return_value=make_stream_cm()),
        ) as mock_stream,
    ):
        await registry.execute(
            "http",
            {"phase": "recon", "url": "http://juice.lab:3000/"},
            None,
            YoloPrompter(inner, True),
        )

    mock_stream.assert_called_once()
    inner.ask.assert_not_called()


@pytest.mark.asyncio
async def test_yolo_does_not_bypass_private_gate_for_another_scoped_origin():
    target = Target("http://juice.lab:3000")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    engagement.add_origin("http://127.0.0.1:8080")
    registry = Registry()
    registry.register(HTTPTool(target, engagement))
    engagement.http_permissions.activate("http://127.0.0.1:8080", HTTPLimits())
    inner = FakePrompter(Decision.DENY)

    with (
        patch(
            "src.tools.private_host.private_host_reason",
            new=AsyncMock(return_value="loopback IPv4"),
        ),
        patch("src.tools.http.httpx.AsyncClient.send") as mock_stream,
    ):
        with pytest.raises(UserControlledRefusal, match="private/internal URL denied"):
            await registry.execute(
                "http",
                {"phase": "recon", "url": "http://127.0.0.1:8080/"},
                None,
                YoloPrompter(inner, True),
            )

    assert inner.ask.call_count == 1
    private_request = inner.ask.call_args.args[0]
    assert private_request.no_session_cache is True
    assert private_request.yolo_auto_approve is False
    mock_stream.assert_not_called()


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
            "src.tools.http.httpx.AsyncClient.send",
            new=AsyncMock(return_value=make_stream_cm()),
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
            "src.tools.http.httpx.AsyncClient.send",
            new=AsyncMock(return_value=make_stream_cm()),
        ),
    ):
        out = await tool.run(
            {"url": "http://juice.lab:3000/"},
            None,
            FakePrompter(),
        )

    assert out.startswith("note: private/internal host independently approved")
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
            "src.tools.http.httpx.AsyncClient.send",
            new=AsyncMock(return_value=make_stream_cm()),
        ),
    ):
        out = await tool.run(
            {"url": "http://example.test/"},
            None,
            FakePrompter(),
        )

    assert not out.startswith("note:")
