from __future__ import annotations

from src.tools.common.tool_display import (
    display_tool_name,
)

def test_display_browser_navigate():
    assert (
        display_tool_name(
            "mcp_browser_browser_navigate"
        )
        == "Browser"
    )

def test_display_browser_actions():
    assert (
        display_tool_name(
            "mcp_browser_browser_click"
        )
        == "Browser Click"
    )
    assert (
        display_tool_name(
            "mcp_browser_browser_type_text"
        )
        == "Browser Type Text"
    )

def test_display_load_skill():
    assert (
        display_tool_name(
            "load_skill"
        )
        == "Skill"
    )

def test_display_confirm_finding():
    assert (
        display_tool_name(
            "confirm_finding"
        )
        == "Confirmed Finding"
    )

def test_display_ask_user():
    assert (
        display_tool_name(
            "ask_user"
        )
        == "Ask User"
    )

def test_display_web_tools():
    assert (
        display_tool_name(
            "web_fetch"
        )
        == "Web Fetch"
    )
    assert (
        display_tool_name(
            "web_search"
        )
        == "Web Search"
    )

def test_display_unknown():
    assert display_tool_name("shell") == "shell"
    assert display_tool_name("not_real") == "not_real"
