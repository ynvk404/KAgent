from __future__ import annotations

from typing import Final

from src.config.config import MCPServerConfig
from src.tools.mcp.browser_deployment import BROWSER_MCP_COMMAND, BROWSER_MCP_ARGS, BROWSER_LOCAL_ARGS


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

#: Reviewed upstream fixture for isolated protocol/resource checks only.
#: CLI --browser always selects BROWSER_LOCAL_SERVER below.
BROWSER_MCP_SERVER: Final[MCPServerConfig] = MCPServerConfig(
    name="browser",
    command=BROWSER_MCP_COMMAND,
    args=list(BROWSER_MCP_ARGS),
)
BROWSER_LOCAL_SERVER: Final[MCPServerConfig] = MCPServerConfig(
    name='browser', command=BROWSER_MCP_COMMAND, args=list(BROWSER_LOCAL_ARGS),
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
            BROWSER_LOCAL_SERVER,
        ]

    return base
