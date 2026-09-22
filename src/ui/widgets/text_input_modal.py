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

        if key in (
            "backspace",
            "delete",
        ):
            self.value = self.value[:-1]
            return

        printable = text or (
            key
            if len(key) == 1
            else ""
        )

        if printable:
            self.value += (
                printable
                .replace("\r", "")
                .replace("\n", "")
            )

    def render(self) -> list[str]:
        if self.value:
            shown = (
                "•" * len(self.value)
                if self.req.masked
                else self.value
            )
        else:
            shown = self.req.placeholder or ""

        return [
            f"[{self.req.header}]",
            self.req.question,
            "",
            "Answer:",
            f"{DEFAULT_PROMPT}{shown}▌",
            "",
            "type key · Enter submit · Esc cancel",
        ]
