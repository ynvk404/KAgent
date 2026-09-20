from __future__ import annotations

from src.tools.tool_display import (
    display_tool_name,
    primary_tool_arg,
    format_tool_result,
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

def test_primary_browser():
    assert (
        primary_tool_arg(
            "mcp_browser_browser_navigate",
            {
                "url": "https://x.test"
            },
        )
        == "https://x.test"
    )

def test_primary_shell():
    assert (
        primary_tool_arg(
            "shell",
            {
                "command": "id"
            },
        )
        == "id"
    )
    assert (
        primary_tool_arg(
            "bash",
            {
                "command": "ls -la"
            },
        )
        == "ls -la"
    )
    assert (
        primary_tool_arg(
            "BashTool",
            {
                "command": "whoami"
            },
        )
        == "whoami"
    )

def test_primary_http():
    assert (
        primary_tool_arg(
            "http",
            {
                "method": "GET",
                "url": "https://gobus.net",
            },
        )
        == "GET https://gobus.net"
    )
    assert (
        primary_tool_arg(
            "http",
            {
                "method": "post",
                "url": "/api/login",
            },
        )
        == "POST /api/login"
    )
    assert (
        primary_tool_arg(
            "http",
            {
                "url": "https://gobus.net",
            },
        )
        == "https://gobus.net"
    )

def test_primary_confirm_finding():
    assert (
        primary_tool_arg(
            "confirm_finding",
            {
                "severity": "high",
                "title": "XSS",
            },
        )
        == "(high) XSS"
    )
    assert (
        primary_tool_arg(
            "confirm_finding",
            {
                "title": "XSS",
            },
        )
        == "XSS"
    )

def test_primary_load_skill():
    assert (
        primary_tool_arg(
            "load_skill",
            {
                "name": "webvuln"
            },
        )
        == "webvuln"
    )

def test_primary_ask_user():
    assert (
        primary_tool_arg(
            "ask_user",
            {
                "questions": [
                    {
                        "header": "Scope",
                        "question": (
                            "Confirming scope — I want to make sure "
                            "I test the right surface. "
                            "Which of these matches the engagement?"
                        ),
                        "options": [
                            {
                                "label": "Passive recon"
                            },
                            {
                                "label": "Full recon"
                            },
                        ],
                    },
                    {
                        "question":
                            "How deep should the testing go?",
                        "options": [
                            {
                                "label": "Passive only"
                            },
                            {
                                "label":
                                    "Active web vuln hunt"
                            },
                        ],
                    },
                ]
            },
        )
        == (
            "Scope · 2 questions total · "
            "Confirming scope — I want to make sure "
            "I test the right surface. "
            "Which of these matches the engagement?"
        )
    )

def test_primary_unknown():
    assert (
        primary_tool_arg(
            "http",
            {},
        )
        is None
    )
    assert (
        primary_tool_arg(
            "shell",
            {},
        )
        is None
    )
    assert (
        primary_tool_arg(
            "mcp_browser_browser_navigate",
            {
                "url": ""
            },
        )
        is None
    )
    assert (
        primary_tool_arg(
            "confirm_finding",
            {},
        )
        is None
    )

def test_browser_capture_status():
    result = format_tool_result(
        "browser_capture_status",
        """
{
    "requests":0,
    "endpoints":0,
    "snapshots":0,
    "lastActivityAt":"never"
}
""",
    )
    assert (
        result
        ==
        "requests: 0 · endpoints: 0 · snapshots: 0 · last activity: never"
    )

def test_load_skill():
    body = "\n".join(
        [
            "# Skill: webvuln",
            "",
            "# Web vuln hunting playbook",
            "",
            "Full model-facing body.",
            "",
            "## 1. Triage the target",
            "## 2. Known-CVE pass",
        ]
    )
    assert (
        format_tool_result(
            "load_skill",
            body,
        )
        ==
        "\n".join(
            [
                "loaded skill: webvuln",
                "playbook: Web vuln hunting playbook",
            ]
        )
    )

def test_ask_user_result():
    result = """
{
    "answers":[
        {
            "question":"Confirming scope — I want to make sure I test the right surface. Which of these matches the engagement?",
            "answer":"Full recon: dsquares.com + all mazaya* apexes + pivots"
        },
        {
            "question":"How deep should the testing go?",
            "answer":"Active web vuln hunt"
        }
    ]
}
"""
    assert (
        format_tool_result(
            "ask_user",
            result,
        )
        ==
        "\n".join(
            [
                "answers:",
                "- Full recon: dsquares.com + all mazaya* apexes + pivots",
                "  Confirming scope — I want to make sure I test the right surface. Which of these matches the engagement?",
                "- Active web vuln hunt",
                "  How deep should the testing go?",
            ]
        )
    )

def test_format_result_fallback():
    assert (
        format_tool_result(
            "shell",
            "{}",
        )
        is None
    )
    assert (
        format_tool_result(
            "browser_capture_status",
            "not json",
        )
        is None
    )
    assert (
        format_tool_result(
            "load_skill",
            "# Missing skill heading",
        )
        is None
    )
    assert (
        format_tool_result(
            "ask_user",
            "not json",
        )
        is None
    )