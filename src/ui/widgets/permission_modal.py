from __future__ import annotations

import re

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.text import Text

from src.tools.tool_display import display_tool_name
from src.ui.bridges.perm_bridge import BridgedPermissionRequest
from src.permission.permission import Decision

COMMAND_TOOLS = {
    "shell",
    "bash",
    "BashTool",
    "http",
    "file_write",
    "FileWriteTool",
    "file_edit",
    "FileEditTool",
}

COMMAND_DETAIL_CAP = 8000
PROSE_DETAIL_CAP = 1200

_COMMAND_TITLES = {
    "shell": "Shell command",
    "bash": "Shell command",
    "BashTool": "Shell command",
    "http": "HTTP request",
    "file_write": "File write",
    "FileWriteTool": "File write",
    "file_edit": "File edit",
    "FileEditTool": "File edit",
}


def is_command_tool(tool: str) -> bool:
    """
    True nếu detail là payload cần hiển thị nguyên bản:
    shell command, HTTP request, file write/edit...
    """
    return tool in COMMAND_TOOLS



def truncate(
    text: str,
    max_len: int,
) -> str:
    if len(text) <= max_len:
        return text

    return (
        text[:max_len]
        + "\n[... truncated ...]"
    )


def _framed_action(req: BridgedPermissionRequest) -> tuple[str, str, str] | None:
    """Return the existing structured action and any explanatory remainder."""
    detail = req.detail

    if req.tool in {"shell", "bash", "BashTool"} and detail:
        return _COMMAND_TITLES[req.tool], detail, ""

    if req.tool == "http":
        private_prefix = "http: private/internal URL "
        if req.summary.startswith(private_prefix):
            return _COMMAND_TITLES[req.tool], req.summary.removeprefix(private_prefix), detail
        if re.match(r"^[A-Z]+\s+\S+", detail):
            return _COMMAND_TITLES[req.tool], detail, ""

    if req.tool in {"file_write", "FileWriteTool", "file_edit", "FileEditTool"}:
        path, separator, remainder = detail.partition("\n")
        if path.startswith("path: "):
            scope_prefix = (
                "writes to "
                if req.tool in {"file_write", "FileWriteTool"}
                else "edits to "
            )
            display_path = (req.session_scope_display or "").removeprefix(scope_prefix)
            return (
                _COMMAND_TITLES[req.tool],
                display_path or path.removeprefix("path: "),
                remainder if separator else "",
            )

    return None



class PermissionModal:

    def __init__(
        self,
        req: BridgedPermissionRequest,
    ):
        self.req = req

    def handle_key(
        self,
        key: str,
    ) -> None:

        key = key.lower()

        if key in ("escape", "esc"):
            self.req.resolve(Decision.DENY)

        elif key == "y":
            self.req.resolve(Decision.ALLOW_ONCE)

        elif key == "a":
            self.req.resolve(Decision.ALLOW_SESSION)

        elif key == "n":
            self.req.resolve(Decision.DENY)

    def render(self) -> RenderableType:

        req = self.req

        parts: list[RenderableType] = [Text(
            f"Permission requested: "
            f"{display_tool_name(req.tool)}"
        )]


        action = _framed_action(req)
        show_detail = bool(req.detail) and req.detail != req.summary

        if action is None:
            parts.extend((Text(""), Text(req.summary)))

        if action is not None:
            parts.append(Text(""))
            title, action_text, explanation = action
            parts.append(
                Panel(
                    Text(truncate(action_text, COMMAND_DETAIL_CAP)),
                    title=title,
                    title_align="left",
                    expand=False,
                    padding=(0, 1),
                )
            )
            if explanation:
                parts.extend((Text(""), Text(truncate(explanation, PROSE_DETAIL_CAP))))

        if action is None and show_detail:
            parts.extend((Text(""), Text(truncate(req.detail, PROSE_DETAIL_CAP))))

        parts.append(Text(""))

        if req.no_session_cache:
            parts.append(Text("Session trust unavailable for this sensitive action"))
        else:
            parts.append(Text(
                "Session trust: "
                + (req.session_scope_display or "this tool for the current runtime")
            ))

        parts.extend((Text(""), Text(
            "y allow once · "
            "a trust for session · "
            "n deny · "
            "Esc cancel"
        )))

        return Group(*parts)
