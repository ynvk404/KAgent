"""
Test session_mcp_servers().

Port từ:
agent/src/mcp/mcpServers.test.ts
"""

from __future__ import annotations

from config.config import MCPServerConfig
from tools.mcp_server import (
    BROWSER_MCP_SERVER,
    session_mcp_servers,
)


other = MCPServerConfig(
    name="other",
    command="foo",
    args=[],
)

stale_browser = MCPServerConfig(
    name="browser",
    command="npx",
    args=["old"],
)


def test_adds_no_browser_server_when_flag_off() -> None:
    assert session_mcp_servers([], False) == []

    assert session_mcp_servers(
        [other],
        False,
    ) == [other]


def test_appends_exactly_one_browser_server_when_flag_on() -> None:
    out = session_mcp_servers([], True)

    assert len(out) == 1
    assert out[0].name == "browser"
    assert out[0].command == "npx"


def test_strips_stale_browser_entry_when_flag_off() -> None:
    out = session_mcp_servers(
        [other, stale_browser],
        False,
    )

    assert out == [other]


def test_replaces_stale_browser_entry_when_flag_on() -> None:
    out = session_mcp_servers(
        [other, stale_browser],
        True,
    )

    browser = [
        s
        for s in out
        if s.name == "browser"
    ]

    assert len(browser) == 1

    assert out[0] == other

    assert out[-1].args == [
        "-y",
        "@browsermcp/mcp@latest",
    ]

    assert out[-1] == BROWSER_MCP_SERVER


def test_does_not_mutate_input() -> None:
    input_servers = [other]

    session_mcp_servers(
        input_servers,
        True,
    )

    assert input_servers == [other]