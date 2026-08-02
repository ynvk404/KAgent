from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


# ==========================================================
# Request
# ==========================================================

@dataclass(slots=True)
class SecretInputRequest:
    header: str
    question: str
    placeholder: str | None

    resolve: Callable[[str], None]
    reject: Callable[[Exception], None]


# ==========================================================
# Helpers
# ==========================================================

def mask_secret(value: str) -> str:
    """
    Mask secret value.

    Examples:
        abc     -> ***
        abcd    -> ****
        password123 -> *******d123
    """

    if not value:
        return ""

    if len(value) <= 4:
        return "*" * len(value)

    return (
        "*" * (len(value) - 4)
        + value[-4:]
    )


# ==========================================================
# Widget
# ==========================================================

class SecretInputModal:
    """
    Secret input modal.

    Keys:
        normal key -> append character
        backspace/delete -> remove last char
        Enter -> submit
        Esc -> cancel
    """


    def __init__(
        self,
        req: SecretInputRequest,
    ):
        self.req = req
        self.value = ""


    # ------------------------------------------------------
    # Input handling
    # ------------------------------------------------------

    def handle_key(
        self,
        key: str,
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


        if key:
            self.value += (
                key
                .replace("\r", "")
                .replace("\n", "")
            )


    # ------------------------------------------------------
    # Render
    # ------------------------------------------------------

    def render(self) -> list[str]:

        shown = (
            mask_secret(self.value)
            if self.value
            else (
                self.req.placeholder
                or ""
            )
        )


        return [
            f"[{self.req.header}]",
            self.req.question,
            "",
            shown,
            "",
            "type key · Enter submit · Esc cancel",
        ]