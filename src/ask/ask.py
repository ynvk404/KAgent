"""
AskPrompter

Port từ:
kagent/src/ask/ask.ts
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


# -------------------------------------------------
# Option
# -------------------------------------------------

@dataclass
class Option:
    label: str
    description: str | None = None


# -------------------------------------------------
# Question
# -------------------------------------------------

@dataclass
class Question:
    header: str | None
    question: str
    options: list[Option]


# -------------------------------------------------
# AskPrompter interface
# -------------------------------------------------

@runtime_checkable
class AskPrompter(Protocol):
    """
    Interface mà TUI implement.

    ask_user tool dùng interface này để hỏi
    người dùng câu hỏi nhiều lựa chọn.
    """

    async def ask(
        self,
        q: Question,
        signal=None,
    ) -> str:
        """
        Trả về label của option được chọn.

        Raise exception nếu:
        - user nhấn Esc
        - signal bị abort
        """
        ...


# -------------------------------------------------
# Test Prompter
# -------------------------------------------------

class FirstOptionPrompter:
    """
    Hermetic prompter dùng cho test.

    Luôn chọn option đầu tiên.
    """
    async def ask(
        self,
        q: Question,
        signal=None,
    ) -> str:

        if not q.options:
            raise Exception("ask: no options")

        return q.options[0].label