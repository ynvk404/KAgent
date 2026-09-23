from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias


@dataclass(slots=True)
class BaseEvent:

    def __getitem__(self, key: str):
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


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
    args_json: str = ""

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
    stop_reason: str | None = None
    agent_loop_llm_calls: int = 0
    compaction_llm_calls: int = 0
    final_synthesis_llm_calls: int = 0
    total_llm_calls: int = 0


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


class MaxStepsError(RuntimeError):

    def __init__(self, steps: int):
        super().__init__(
            f"hit max steps ({steps}) without finishing"
        )
        self.steps = steps


class InvalidResponseError(RuntimeError):
    def __init__(self, reason: str = "assistant response has no visible final text"):
        super().__init__(reason)


AssistantText = AssistantTextEvent
AssistantDelta = AssistantDeltaEvent
ToolCall = ToolCallEvent
ToolResult = ToolResultEvent
Compact = CompactEvent
Decision = DecisionEvent
SkillActive = SkillActiveEvent
MemoryRecall = MemoryRecallEvent
Done = DoneEvent


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
    "InvalidResponseError",
]
