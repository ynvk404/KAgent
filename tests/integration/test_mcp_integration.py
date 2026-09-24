import asyncio
from contextlib import AsyncExitStack
from typing import Any
from unittest.mock import create_autospec

import pytest
from mcp import ClientSession

from src.tools.mcp_integration import (
    MCPTool,
    MCPSession,
    sanitize,
)
from src.tools.registry import Registry


class FakeSession:
    def __init__(self, result: dict[str, Any]) -> None:
        self.server_name = "browser"
        self.result = result

    async def call_tool(
        self, name: str, args: dict[str, Any],
        cancel_event: asyncio.Event | None = None,
    ) -> dict[str, Any]:
        return self.result


class DummyPrompter:
    pass


@pytest.mark.asyncio
async def test_direct_mcp_cancellation_awaits_inner_call_cleanup():
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def blocking_call(name: str, arguments: dict[str, Any]) -> None:
        started.set()
        try:
            await asyncio.Future()
        finally:
            stopped.set()

    client_session = create_autospec(ClientSession, instance=True)
    client_session.call_tool.side_effect = blocking_call
    session = MCPSession("test", client_session, AsyncExitStack())
    task = asyncio.create_task(session.call_tool("wait", {}, asyncio.Event()))
    await asyncio.wait_for(started.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    assert stopped.is_set()


def test_sanitized_mcp_name_collision_is_rejected():
    registry = Registry()
    session = FakeSession({"isError": False, "content": []})
    first = MCPTool(session, f"mcp_{sanitize('a-b')}_scan", "scan", "", {})
    second = MCPTool(session, f"mcp_{sanitize('a_b')}_scan", "scan", "", {})
    registry.register(first)
    with pytest.raises(ValueError, match="duplicate tool registration: mcp_a_b_scan"):
        registry.register(second)
    assert registry.get("mcp_a_b_scan") is first


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
        session,
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
        session,
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
        session,
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
