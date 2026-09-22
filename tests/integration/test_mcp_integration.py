import asyncio
from typing import cast

import pytest

from src.tools.mcp_integration import (
    MCPTool,
    MCPSession,
)


class FakeSession:
    def __init__(self, result):
        self.server_name = "browser"
        self.result = result

    async def call_tool(self, name, args, cancel_event=None):
        return self.result


class DummyPrompter:
    pass


@pytest.mark.asyncio
async def test_formats_text_mcp_errors_without_raw_content_json():

    session = FakeSession(
        {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": "Error: WebSocket response timeout after 30000ms",
                }
            ],
        }
    )

    tool = MCPTool(
        cast(MCPSession, session),
        "mcp_browser_browser_click",
        "browser_click",
        "Click in browser",
        {"type": "object"},
    )

    with pytest.raises(
        RuntimeError,
        match="Browser Click failed: WebSocket response timeout after 30000ms",
    ):
        await tool.run(
            {},
            None,
            DummyPrompter(),
        )

    try:
        await tool.run({}, None, DummyPrompter())
    except RuntimeError as err:
        assert "isError" not in str(err)

@pytest.mark.asyncio
async def test_truncates_large_successful_mcp_results():

    session = FakeSession(
        {
            "isError": False,
            "content": [
                {
                    "type": "text",
                    "text": "a" * 200_000,
                }
            ],
        }
    )

    tool = MCPTool(
        cast(MCPSession, session),
        "mcp_browser_big",
        "big",
        "Big output",
        {"type": "object"},
    )

    out = await tool.run(
        {},
        None,
        DummyPrompter(),
    )

    assert "truncated" in out
    assert len(out) < 140_000


@pytest.mark.asyncio
async def test_bounds_deeply_nested_content():

    deep = {"leaf": "x"}

    for _ in range(100):
        deep = {"nested": deep}

    session = FakeSession(
        {
            "isError": False,
            "content": deep,
        }
    )
    tool = MCPTool(
        cast(MCPSession, session),
        "mcp_browser_deep",
        "deep",
        "Deep output",
        {"type": "object"},
    )
    out = await tool.run(
        {},
        None,
        DummyPrompter(),
    )
    assert "max depth exceeded" in out
