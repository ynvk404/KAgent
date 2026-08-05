"""
Tool display helpers.

Port từ:
kagent/src/tools/toolDisplay.ts
"""

from __future__ import annotations

import json
import re
from typing import Any


TOOL_DISPLAY_NAMES: dict[str, str] = {
    "ask_user": "Ask User",
    "confirm_finding": "Confirmed Finding",
    "load_skill": "Skill",
    "mcp_browser_browser_navigate": "Browser",
    "mcp_browser_browser_click": "Browser Click",
    "web_fetch": "Web Fetch",
    "web_search": "Web Search",
}


# ==========================================================
# Display name
# ==========================================================

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


# ==========================================================
# Primary tool arg
# ==========================================================

def primary_tool_arg(
    name: str,
    args: dict[str, Any],
) -> str | None:

    if name == "mcp_browser_browser_navigate":
        url = args.get("url")
        if isinstance(url, str) and url:
            return url

    if name in (
        "shell",
        "bash",
        "BashTool",
    ):
        cmd = args.get("command")
        if isinstance(cmd, str) and cmd:
            return cmd

    if name == "http":
        method = args.get("method")
        url = args.get("url")

        method = (
            method.upper()
            if isinstance(method, str) and method
            else ""
        )

        url = (
            url
            if isinstance(url, str)
            else ""
        )

        if method and url:
            return f"{method} {url}"

        if url:
            return url

    if name == "confirm_finding":
        title = args.get("title")
        severity = args.get("severity")

        title = (
            title
            if isinstance(title, str)
            else ""
        )

        severity = (
            severity
            if isinstance(severity, str)
            else ""
        )

        if title:
            if severity:
                return f"({severity}) {title}"
            return title

    if name == "load_skill":
        skill = args.get("name")
        if isinstance(skill, str) and skill:
            return skill

    if name == "ask_user":
        return format_ask_user_call(args)

    return None


# ==========================================================
# Tool result formatter
# ==========================================================

def format_tool_result(
    name: str,
    result: str,
) -> str | None:

    if name == "load_skill":
        return format_load_skill_result(result)

    if name == "browser_capture_status":
        try:
            data = json.loads(result)

            requests = (
                data["requests"]
                if isinstance(data.get("requests"), int)
                else 0
            )

            endpoints = (
                data["endpoints"]
                if isinstance(data.get("endpoints"), int)
                else 0
            )

            snapshots = (
                data["snapshots"]
                if isinstance(data.get("snapshots"), int)
                else 0
            )

            last = (
                data["lastActivityAt"]
                if isinstance(data.get("lastActivityAt"), str)
                else "never"
            )

            return (
                f"requests: {requests}"
                f" · endpoints: {endpoints}"
                f" · snapshots: {snapshots}"
                f" · last activity: {last}"
            )

        except Exception:
            return None

    if name == "ask_user":
        return format_ask_user_result(result)

    return None


# ==========================================================
# load_skill formatter
# ==========================================================

def format_load_skill_result(
    result: str,
) -> str | None:

    match = re.search(
        r"^# Skill:\s*(.+)$",
        result,
        re.MULTILINE,
    )

    if not match:
        return None

    skill = match.group(1).strip()

    title = None

    for line in result.splitlines():

        line = line.strip()

        if (
            line.startswith("# ")
            and
            not line.startswith("# Skill:")
        ):
            title = line[2:].strip()
            break

    lines = [
        f"loaded skill: {skill}"
    ]

    if title:
        lines.append(
            f"playbook: {title}"
        )

    return "\n".join(lines)


# ==========================================================
# ask_user formatter
# ==========================================================

def format_ask_user_call(
    args: dict[str, Any],
) -> str | None:

    questions = args.get("questions")

    if not isinstance(
        questions,
        list,
    ) or not questions:
        return None

    first = questions[0]

    if not isinstance(first, dict):
        return None

    header = (
        first.get("header")
        if isinstance(first.get("header"), str)
        else ""
    )

    question = (
        first.get("question")
        if isinstance(first.get("question"), str)
        else ""
    )

    count = len(questions)

    count_text = (
        f"{count} question"
        if count == 1
        else f"{count} questions"
    )

    if header and question:
        return f"{header} · {count_text} · {question}"

    if header:
        return f"{header} · {count_text}"

    if question:
        return f"{count_text} · {question}"

    return count_text


def format_ask_user_result(
    result: str,
) -> str | None:

    try:
        parsed = json.loads(result)
    except Exception:
        return None

    if (
        not isinstance(parsed, dict)
        or
        not isinstance(
            parsed.get("answers"),
            list,
        )
    ):
        return None

    lines = ["answers:"]

    for item in parsed["answers"]:

        if not isinstance(item, dict):
            continue

        question = (
            item.get("question", "")
            if isinstance(item.get("question"), str)
            else ""
        ).strip()

        answer = (
            item.get("answer", "")
            if isinstance(item.get("answer"), str)
            else ""
        ).strip()

        if not question and not answer:
            continue

        if answer:
            lines.append(f"- {answer}")

        if question:
            lines.append(f"  {question}")

    if len(lines) == 1:
        return None

    return "\n".join(lines)