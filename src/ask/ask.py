from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


@dataclass
class Option:
    label: str
    description: Optional[str] = None


@dataclass
class Question:
    question: str
    options: list[Option] = field(default_factory=list)
    header: Optional[str] = None


class AskPrompter(Protocol):

    async def ask(self, q: Question, signal: Any = None) -> str:
        ...


class FirstOptionPrompter:

    async def ask(self, q: Question, signal: Any = None) -> str:
        if not q.options:
            raise RuntimeError("ask: no options")
        return q.options[0].label