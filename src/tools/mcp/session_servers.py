from __future__ import annotations

from typing import Final

from src.config.config import MCPServerConfig


# ==========================================================
# Browser MCP
# ==========================================================

#: Các tên được coi là Browser MCP.
BROWSER_MCP_NAMES: Final[frozenset[str]] = frozenset(
    {
        "browser",
        "browser-mcp",
    }
)

#: Browser MCP mặc định được inject khi chạy với --browser.
BROWSER_MCP_SERVER: Final[MCPServerConfig] = MCPServerConfig(
    name="browser",
    command="npx",
    args=[
        "-y",
        "@browsermcp/mcp@latest",
    ],
)


# ==========================================================
# Public API
# ==========================================================

def session_mcp_servers(
    configured: list[MCPServerConfig],
    browser_enabled: bool,
) -> list[MCPServerConfig]:

    base = [
        server
        for server in configured
        if server.name not in BROWSER_MCP_NAMES
    ]

    if browser_enabled:
        return [
            *base,
            BROWSER_MCP_SERVER,
        ]

    return base