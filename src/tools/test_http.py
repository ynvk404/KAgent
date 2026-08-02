import pytest
from unittest.mock import AsyncMock, patch
from permission.permission import Decision
from target.target import Target
from tools.http import HTTPTool


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


# ======================================================
# schema
# ======================================================

def test_schema_not_require_method():

    tool = HTTPTool(Target())

    assert tool.schema()["required"] == [
        "url"
    ]


# ======================================================
# summarize
# ======================================================

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


# ======================================================
# runtime default GET
# ======================================================

@pytest.mark.asyncio
async def test_default_get_runtime():

    tool = HTTPTool(Target())

    response = FakeResponse()

    stream_cm = AsyncMock()
    stream_cm.__aenter__.return_value = response
    stream_cm.__aexit__.return_value = None

    with patch(
        "tools.http.httpx.AsyncClient.stream",
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

# ======================================================
# require url
# ======================================================

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


# ======================================================
# SSRF deny
# ======================================================

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


# ======================================================
# SSRF allow
# ======================================================

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
        "tools.http.httpx.AsyncClient.stream",
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

# ======================================================
# permission cache key
# ======================================================

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