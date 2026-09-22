from __future__ import annotations

from src.ui.bridges.ask_bridge import (
    AskRequest,
)
from src.ui.commands.menu_window import compute_menu_window

ASK_MODAL_VISIBLE_CAP = 8


class AskModal:
    """
    Ask user modal.

    Keys:
        ↑ / up       previous
        ↓ / down     next
        Shift+Tab    previous
        Tab          next
        Enter        select
        1-9          jump
        Esc          cancel
    """

    def __init__(
        self,
        req: AskRequest,
    ) -> None:
        self.req = req
        self.idx = 0

    def handle_key(
        self,
        key: str,
    ) -> None:
        options = self.req.question.options

        key = key.lower()

        if key in ("escape", "esc"):
            self.req.reject(
                Exception("cancelled")
            )
            return

        if not options:
            return

        if key in ("up", "arrowup", "shift+tab"):
            self.idx = (
                self.idx - 1 + len(options)
            ) % len(options)
            return

        if key in ("down", "arrowdown", "tab"):
            self.idx = (
                self.idx + 1
            ) % len(options)
            return

        if key in ("enter", "return"):
            picked = options[self.idx]

            self.req.resolve(
                picked.label
            )
            return

        if key in "123456789":
            n = int(key) - 1

            if n < len(options):
                self.idx = n

    def render(self) -> list[str]:
        q = self.req.question

        lines: list[str] = []

        if q.header:
            lines.append(
                f"[{q.header}]"
            )

        lines.append(
            q.question
        )

        lines.append("")

        if not q.options:
            lines.append("Esc cancel")
            return lines

        window = compute_menu_window(
            len(q.options),
            self.idx,
            cap=ASK_MODAL_VISIBLE_CAP,
        )

        if window.hidden_above > 0:
            lines.append(f"  ↑ {window.hidden_above} more")

        for i in range(window.start, window.end):
            option = q.options[i]
            selected = i == self.idx

            prefix = (
                "› "
                if selected
                else "  "
            )

            line = (
                prefix
                + option.label
            )

            if option.description:
                line += (
                    " — "
                    + option.description
                )

            lines.append(line)

        if window.hidden_below > 0:
            lines.append(f"  ↓ {window.hidden_below} more")

        lines.append("")
        lines.append(
            "↑↓/Tab select · Enter pick · Esc cancel"
        )

        return lines
