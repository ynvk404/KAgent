import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import create_autospec

import pytest
from mcp import ClientSession

from src.tools.mcp.integration import (
    MCPTool,
    MCPSession,
    sanitize,
)
from src.config.config import MCPServerConfig
from src.tools.common.registry import Registry
import src.tools.mcp.integration as mcp_integration


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






def test_sanitized_mcp_name_collision_is_rejected():
    registry = Registry()
    session = FakeSession({"isError": False, "content": []})
    first = MCPTool(session, f"mcp_{sanitize('a-b')}_scan", "scan", "", {})
    second = MCPTool(session, f"mcp_{sanitize('a_b')}_scan", "scan", "", {})
    registry.register(first)
    with pytest.raises(ValueError, match="duplicate tool registration: mcp_a_b_scan"):
        registry.register(second)
    assert registry.get("mcp_a_b_scan") is first


def test_mcp_actions_require_fresh_high_impact_approval():
    tool = MCPTool(
        FakeSession({"isError": False, "content": []}),
        "mcp_browser_click",
        "click",
        "Click in browser",
        {"type": "object"},
    )

    assert tool.permission_hints({"button": "submit"}) == {
        "noSessionCache": True,
        "riskTier": "high-impact",
    }
