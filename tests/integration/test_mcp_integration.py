"""Non-executing MCP objects retain fresh high-impact permission metadata."""
from src.tools.mcp.integration import MCPTool


def test_mcp_actions_require_fresh_high_impact_approval():
    tool = MCPTool(
        None,
        "mcp_browser_click",
        "click",
        "Click in browser",
        {"type": "object"},
    )

    assert tool.permission_hints({"button": "submit"}) == {
        "noSessionCache": True,
        "riskTier": "high-impact",
    }
