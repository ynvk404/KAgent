import pytest
from unittest.mock import AsyncMock, patch
from src.permission.permission import Decision
from src.target.target import Target
from src.tools.http import HTTPTool


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


def test_schema_not_require_method():

    tool = HTTPTool(Target())

    assert tool.schema()["required"] == [
        "url"
    ]

def test_summarize_default_get():

    tool = HTTPTool(Target())

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
    result = HTTPTool(Target()).summarize(
        {"url": "http://example.test", "headers": "not-an-object"}
    )

    assert result["detail"] == "GET http://example.test"

@pytest.mark.asyncio
async def test_default_get_runtime():

    tool = HTTPTool(Target())

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
async def test_require_url():

    tool = HTTPTool(Target())

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

    tool = HTTPTool(Target())

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

    tool = HTTPTool(Target())

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

    tool = HTTPTool(Target())

    assert tool.permission_hints(
        {
            "url":
            "https://app.example.com/a?x=1"
        }
    ) == {
        "cacheKey":
        "https://app.example.com"
    }

    assert tool.permission_hints(
        {
            "url":
            "http://169.254.169.254/"
        }
    ) == {
        "cacheKey":
        "http://169.254.169.254"
    }


# ---------------------------------------------------------------------------
# private-host target wiring (session-cache fix)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_http_passes_target_to_private_gate():

    target = Target("http://juice.lab:3000")
    tool = HTTPTool(target)

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
    tool = HTTPTool(target)

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

    tool = HTTPTool(Target())

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
