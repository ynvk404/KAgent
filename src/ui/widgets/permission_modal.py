from __future__ import annotations

import asyncio
import re

from rich.console import Group, RenderableType
from rich.text import Text

from src.target.origin import HTTPOrigin

from src.ui.theme import MUTED

from src.tools.common.tool_display import display_tool_name
from src.ui.bridges.perm_bridge import BridgedPermissionRequest
from src.permission.permission import Decision, PermissionReviewCancelled
from src.ui.render.sanitize import sanitize_text as redact

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
            return (
                _COMMAND_TITLES[req.tool],
                path.removeprefix("path: "),
                remainder if separator else "",
            )

    return None



class PermissionModal:

    def __init__(
        self,
        req: BridgedPermissionRequest,
    ):
        self.req = req

    def _supports_reuse(self) -> bool:
        # The bridge remains authoritative at decision time. Do not advertise
        # a reusable decision for a review whose lifecycle has already ended.
        try:
            return self.req.supports_session and (
                self.req.is_current is None or self.req.is_current()
            )
        except Exception:
            return False

    def handle_key(
        self,
        key: str,
    ) -> None:

        key = key.lower()

        if key in ("escape", "esc"):
            self.req.reject(PermissionReviewCancelled())

        elif key == "y":
            self.req.resolve(Decision.ALLOW_ONCE)

        elif key == "a" and self._supports_reuse():
            self.req.resolve(Decision.ALLOW_SESSION)

        elif key == "n":
            self.req.resolve(Decision.DENY)

    def instructions(self) -> Text:
        keys = ("y allow once · a trust for session · n deny · Esc cancel"
                if self._supports_reuse() else "y allow once · n deny · Esc cancel")
        return Text(keys, style=MUTED)

    def render(self, *, include_instructions: bool = True) -> RenderableType:

        req = self.req
        supports_reuse = self._supports_reuse()

        action = _framed_action(req)
        parts: list[RenderableType] = [] if action else [Text(f"Tool: {display_tool_name(req.tool)}")]

        scope = req.session_scope_display if supports_reuse else "unavailable; proposed operation only"
        scope_row = Text("Session authority: " + redact(scope or ""), style=MUTED)

        show_detail = bool(req.detail) and req.detail != req.summary

        if action is None:
            parts.extend((Text(redact(req.summary)), scope_row))

        if action is not None:
            title, action_text, explanation = action
            head, separator, tail = action_text.partition("\n")
            parts.append(Text(title, style=MUTED))
            parts.append(Text(redact(head)))
            if req.tool == "http":
                url = action_text.split()[1] if re.match(r"^[A-Z]+\s+", action_text) else action_text
                try:
                    origin = HTTPOrigin.from_url(url)
                except (ValueError, IndexError):
                    pass
                else:
                    parts.append(Text(f"Effective port: {origin.port}", style=MUTED))
            parts.append(scope_row)
            if separator:
                parts.append(Text(redact(tail)))
            if explanation:
                parts.append(Text(redact(explanation)))

        if action is None and show_detail:
            parts.extend((Text(""), Text(redact(req.detail))))

        if include_instructions:
            parts.extend((Text(""), self.instructions()))
        return Group(*parts)
