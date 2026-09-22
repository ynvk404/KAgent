from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from src.ui.widgets.input_box import DEFAULT_PROMPT


@dataclass(slots=True)
class TextInputRequest:
    header: str
    question: str
    placeholder: str | None

    resolve: Callable[[str], None]
    reject: Callable[[Exception], None]
    masked: bool = False
    initial_value: str = ""


class TextInputModal:

    def __init__(
        self,
        req: TextInputRequest,
    ):
        self.req = req
        self.value = ""
        self.value = getattr(req, "initial_value", "") or ""
        self.cursor = len(self.value)

    def handle_key(
        self,
        key: str,
        text: str = "",
    ) -> None:
        if key in ("escape", "esc"):
            self.req.reject(
                Exception("cancelled")
            )
            return

        if key in ("enter", "return"):
            self.req.resolve(
                self.value.strip()
            )
            return

        if key in ("left", "arrowleft"):
            self.cursor = max(0, self.cursor - 1)
            return

        if key in ("right", "arrowright"):
            self.cursor = min(len(self.value), self.cursor + 1)
            return

        if key in ("home", "ctrl+a"):
            self.cursor = 0
            return

        if key in ("end", "ctrl+e"):
            self.cursor = len(self.value)
            return

        if key == "backspace":
            if self.cursor > 0:
                self.value = self.value[: self.cursor - 1] + self.value[self.cursor :]
                self.cursor -= 1
            return

        if key == "delete":
            if self.cursor < len(self.value):
                self.value = self.value[: self.cursor] + self.value[self.cursor + 1 :]
            elif self.cursor > 0:
                # Fallback for platforms/terminals mapping backspace to 'delete'
                self.value = self.value[: self.cursor - 1] + self.value[self.cursor :]
                self.cursor -= 1
            return

        printable = text or (
            key
            if len(key) == 1
            else ""
        )

        if printable:
            sanitized = (
                printable
                .replace("\r", "")
                .replace("\n", "")
            )
            if sanitized:
                cur = max(0, min(self.cursor, len(self.value)))
                self.value = self.value[:cur] + sanitized + self.value[cur:]
                self.cursor = cur + len(sanitized)

    def render(self) -> list[str]:
        cur = max(0, min(self.cursor, len(self.value)))
        if self.value:
            content = (
                "•" * len(self.value)
                if self.req.masked
                else self.value
            )
            shown = f"{content[:cur]}▌{content[cur:]}"
        else:
            shown = f"{self.req.placeholder or ''}▌"

        return [
            f"[{self.req.header}]",
            self.req.question,
            "",
            "Answer:",
            f"{DEFAULT_PROMPT}{shown}",
            "",
            "Enter confirm · Esc cancel",
        ]
