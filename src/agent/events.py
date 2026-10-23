from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias

from src.tools.common.runtime_metadata import RuntimeMetadata


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


@dataclass(frozen=True, slots=True)
class Invocation:
    """One controller dispatch and its immutable original scope."""
    id: str
    scope: str


@dataclass(slots=True)
class ToolCallEvent(BaseEvent):
    type: Literal["tool-call"] = "tool-call"

    id: str = ""
    name: str = ""

    args: dict[str, Any] = field(default_factory=dict)
    args_json: str = ""
    invocation: Invocation | None = None

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
    status: str = "success"
    error_kind: str | None = None
    http_status: int | None = None
    truncated: bool = False
    invocation: Invocation | None = None
    # Controller admission of a real candidate-creation receipt, never tool args.
    accepted_candidate_id: str | None = None
    runtime_metadata: RuntimeMetadata | None = None

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
    recommended_skill: str | None = None
    decision_id: str = ""
    candidate_id: str | None = None
    reason: str | None = None
    target_origin: str | None = None
    target_revision: int | None = None
    objective_id: str | None = None
    context_diagnostics: dict[str, Any] | None = None


@dataclass(slots=True)
class SkillActiveEvent(BaseEvent):
    type: Literal["skill-active"] = "skill-active"
    name: str = ""
    call_id: str = ""
    invocation: Invocation | None = None
    target_origin: str | None = None
    target_revision: int | None = None
    objective_id: str | None = None


@dataclass(slots=True)
class MemoryRecallEvent(BaseEvent):
    type: Literal["memory-recall"] = "memory-recall"
    names: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WorkflowProgressEvent(BaseEvent):
    """Controller counters only; no traffic, paths, reasons or user text."""
    type: Literal["workflow-progress"] = "workflow-progress"
    stage: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DoneEvent(BaseEvent):
    type: Literal["done"] = "done"
    stop_reason: str | None = None
    agent_loop_llm_calls: int = 0
    compaction_llm_calls: int = 0
    final_synthesis_llm_calls: int = 0
    total_llm_calls: int = 0
    workflow_metrics: dict[str, Any] = field(default_factory=dict)


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
    | WorkflowProgressEvent
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
    "WorkflowProgressEvent",

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
