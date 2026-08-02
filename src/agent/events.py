"""
Định nghĩa các sự kiện (Event) mà Agent phát ra trong quá trình
thực thi run() hoặc compact().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias


# =============================================================================
# Base Event
# =============================================================================


@dataclass(slots=True)
class BaseEvent:
    """
    Base class cho tất cả AgentEvent.
    Hỗ trợ cả event.type và event["type"] giống object bên TypeScript.
    """

    def __getitem__(self, key: str):
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

# =============================================================================
# Event Types
# =============================================================================


@dataclass(slots=True)
class AssistantTextEvent(BaseEvent):
    type: Literal["assistant-text"] = "assistant-text"
    text: str = ""


@dataclass(slots=True)
class AssistantDeltaEvent(BaseEvent):
    type: Literal["assistant-delta"] = "assistant-delta"
    text: str = ""


@dataclass(slots=True)
class ToolCallEvent(BaseEvent):
    type: Literal["tool-call"] = "tool-call"

    id: str = ""
    name: str = ""

    args: dict[str, Any] = field(default_factory=dict)

    # Python naming
    args_json: str = ""

    # TypeScript compatibility
    @property
    def argsJSON(self) -> str:
        return self.args_json


@dataclass(slots=True)
class ToolResultEvent(BaseEvent):
    type: Literal["tool-result"] = "tool-result"

    id: str = ""
    name: str = ""

    result: str = ""
    err: str = ""

    duration_ms: float = 0.0

    @property
    def durationMs(self) -> float:
        return self.duration_ms


@dataclass(slots=True)
class ErrorEvent(BaseEvent):
    type: Literal["error"] = "error"
    err: Exception | None = None


@dataclass(slots=True)
class CompactEvent(BaseEvent):
    type: Literal["compact"] = "compact"

    summary: str = ""

    tokens_before: int | None = None
    tokens_after: int | None = None
    memory_items: int | None = None

    @property
    def tokensBefore(self):
        return self.tokens_before

    @property
    def tokensAfter(self):
        return self.tokens_after

    @property
    def memoryItems(self):
        return self.memory_items


@dataclass(slots=True)
class DecisionEvent(BaseEvent):
    type: Literal["decision"] = "decision"
    summary: str = ""


@dataclass(slots=True)
class SkillActiveEvent(BaseEvent):
    type: Literal["skill-active"] = "skill-active"
    name: str = ""


@dataclass(slots=True)
class MemoryRecallEvent(BaseEvent):
    type: Literal["memory-recall"] = "memory-recall"
    names: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DoneEvent(BaseEvent):
    type: Literal["done"] = "done"


# =============================================================================
# Agent Event Union
# =============================================================================


AgentEvent: TypeAlias = (
    AssistantTextEvent
    | AssistantDeltaEvent
    | ToolCallEvent
    | ToolResultEvent
    | ErrorEvent
    | CompactEvent
    | DecisionEvent
    | SkillActiveEvent
    | MemoryRecallEvent
    | DoneEvent
)


# =============================================================================
# Exceptions
# =============================================================================


class MaxStepsError(RuntimeError):
    """
    Raised when the agent exceeds the maximum reasoning/tool-call steps
    within a single turn.
    """

    def __init__(self, steps: int):
        super().__init__(
            f"hit max steps ({steps}) without finishing"
        )
        self.steps = steps

# =============================================================================
# TypeScript compatibility aliases
# =============================================================================

# =============================================================================
# TypeScript compatibility aliases
# =============================================================================

AssistantText = AssistantTextEvent
AssistantDelta = AssistantDeltaEvent
ToolCall = ToolCallEvent
ToolResult = ToolResultEvent
Compact = CompactEvent
Decision = DecisionEvent
SkillActive = SkillActiveEvent
MemoryRecall = MemoryRecallEvent
Done = DoneEvent


# =============================================================================
# Public exports
# =============================================================================

__all__ = [
    "AgentEvent",

    "AssistantTextEvent",
    "AssistantDeltaEvent",
    "ToolCallEvent",
    "ToolResultEvent",
    "ErrorEvent",
    "CompactEvent",
    "DecisionEvent",
    "SkillActiveEvent",
    "MemoryRecallEvent",
    "DoneEvent",

    "AssistantText",
    "AssistantDelta",
    "ToolCall",
    "ToolResult",
    "Compact",
    "Decision",
    "SkillActive",
    "MemoryRecall",
    "Done",

    "MaxStepsError",
]