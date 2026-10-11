from __future__ import annotations

import re

TOOL_DISPLAY_NAMES: dict[str, str] = {
    "ask_user": "Ask User",
    "confirm_finding": "Confirmed Finding",
    "load_skill": "Skill",
    "mcp_browser_browser_navigate": "Browser",
    "mcp_browser_browser_click": "Browser Click",
    "web_fetch": "Web Fetch",
    "web_search": "Web Search",
}

def display_tool_name(name: str) -> str:
    if name.startswith("mcp_browser_browser_"):
        return browser_tool_name(name)

    return TOOL_DISPLAY_NAMES.get(name, name)

def browser_tool_name(name: str) -> str:
    if name in TOOL_DISPLAY_NAMES:
        return TOOL_DISPLAY_NAMES[name]

    action = (
        name.removeprefix("mcp_browser_browser_")
        .replace("_", " ")
    )

    return f"Browser {title_case(action)}"

def title_case(text: str) -> str:
    return re.sub(
        r"\b[a-z]",
        lambda m: m.group(0).upper(),
        text,
    )
