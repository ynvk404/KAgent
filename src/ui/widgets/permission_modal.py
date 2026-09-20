from __future__ import annotations

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

    def render(self) -> list[str]:

        req = self.req

        lines: list[str] = []
        lines.append(
            f"Permission requested: "
            f"{display_tool_name(req.tool)}"
        )


        lines.append("")

        lines.append(req.summary)


        show_detail = (
            bool(req.detail)
            and req.detail != req.summary
        )


        if show_detail:

            lines.append("")

            if is_command_tool(req.tool):

                lines.append(
                    "╭─ command ─────────"
                )


                lines.extend(
                    truncate(
                        req.detail,
                        COMMAND_DETAIL_CAP,
                    ).splitlines()
                )


                lines.append(
                    "╰───────────────────"
                )


            else:
                lines.append(
                    truncate(
                        req.detail,
                        PROSE_DETAIL_CAP,
                    )
                )


        lines.append("")

        lines.append(
            "y allow once · "
            "a allow session · "
            "n deny · "
            "Esc cancel"
        )


        return lines
