from __future__ import annotations

import re

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.text import Text

from src.ui.theme import MUTED, WARNING

from src.tools.common.tool_display import display_tool_name
from src.ui.bridges.perm_bridge import BridgedPermissionRequest
from src.permission.permission import Decision
from src.tools.common.approval_display import redact_approval as redact

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
            scope = req.session_scope_display or ""
            for scope_prefix in ("writes to ", "writes under ", "edits to ", "edits under "):
                if scope.startswith(scope_prefix):
                    scope = scope.removeprefix(scope_prefix)
                    break
            display_path = scope
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
        self.show_full_detail = False

    def handle_key(
        self,
        key: str,
    ) -> None:

        key = key.lower()

        if key == "v":
            self.show_full_detail = not self.show_full_detail
            return

        if key in ("escape", "esc"):
            self.req.resolve(Decision.DENY)

        elif key == "y":
            self.req.resolve(Decision.ALLOW_ONCE)

        elif key == "g" and self.req.offer_http_lab:
            self.req.resolve(Decision.GRANT_LAB)

        elif key == "a" and not self.req.no_session_cache:
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
            parts.extend((Text(""), Text(redact(req.summary))))

        if action is not None:
            parts.append(Text(""))
            title, action_text, explanation = action
            parts.append(
                Panel(
                    Text(self._detail(action_text, COMMAND_DETAIL_CAP)),
                    title=title,
                    title_align="left",
                    border_style=MUTED,
                    box=box.ROUNDED,
                    expand=False,
                    padding=(0, 1),
                )
            )
            if explanation:
                parts.extend((Text(""), Text(self._detail(explanation, PROSE_DETAIL_CAP))))

        if action is None and show_detail:
            parts.extend((Text(""), Text(self._detail(req.detail, PROSE_DETAIL_CAP))))

        parts.append(Text(""))

        if req.risk_tier != "routine":
            parts.append(Text(
                f"Risk tier: {req.risk_tier} · explicit action approval required",
                style=WARNING,
            ))

        if req.no_session_cache:
            parts.append(Text(
                "Exact request review; generic session trust unavailable. Use operator HTTP grants."
                if req.tool == "http_lab_grant" or (req.tool == "http" and not req.summary.startswith("http: private/internal URL "))
                else "Session trust unavailable for this sensitive action", style=WARNING))
        else:
            parts.append(Text(
                "Session trust: "
                + (req.session_scope_display or "this tool for the current runtime")
            ))

        permission_keys = (
            "y allow once · n deny · Esc cancel"
            if req.no_session_cache
            else "y allow once · a trust for session · n deny · Esc cancel"
        )
        parts.extend((Text(""), Text(permission_keys, style=MUTED)))
        if req.offer_http_lab:
            parts.append(Text("g review broad lab grant (separate confirmation)", style=WARNING))
        parts.append(Text(
            "v full detail / preview · scroll to review · secrets redacted",
            style=MUTED,
        ))

        return Group(*parts)

    def _detail(self, text: str, cap: int) -> str:
        safe = redact(text)
        return safe if self.show_full_detail else truncate(safe, cap)
