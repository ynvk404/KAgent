from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from .reasoning import ReasoningLevel
from .metrics import TokenUsage

Role = Literal[
    "system",
    "user",
    "assistant",
    "tool",
]

@dataclass(slots=True)
class FunctionCall:
    name: str
    arguments: str

# ============================================================================
# Provider Metadata
# ============================================================================

@dataclass(slots=True)
class GeminiProvider:
    thought_signature: str | None = None

@dataclass(slots=True)
class ToolProvider:
    gemini: GeminiProvider | None = None

# ============================================================================
# Tool Call
# ============================================================================

@dataclass(slots=True)
class ToolCall:
    id: str
    function: FunctionCall
    type: Literal["function"] = "function"
    provider: ToolProvider | None = None

# ============================================================================
# Message
# ============================================================================

@dataclass(slots=True)
class Message:
    role: Role
    content: str
    # Provider state which must stay distinct from the user-visible answer.
    # DeepSeek requires this to be replayed on tool-enabled follow-up calls.
    reasoning_content: str | None = None
    tool_calls: list[ToolCall] | None = None
    tool_call_id: str | None = None
    name: str | None = None
    # Internal tool outcome; providers serialize only the established fields.
    tool_status: str | None = None
    tool_error_kind: str | None = None
    tool_http_status: int | None = None
    tool_truncated: bool = False
    # Internal provenance prevents provider-private state from crossing adapters.
    provider_state_provider: str | None = None
    provider_state_model: str | None = None
    # Gemini REST parts in original order. Signed thought parts are retained
    # only for exact provider replay and must never enter rendered artifacts.
    gemini_parts: list[dict[str, Any]] | None = None

# ============================================================================
# Tool Definition
# ============================================================================

@dataclass(slots=True)
class ToolFunction:
    name: str
    description: str
    parameters: dict[str, Any]

@dataclass(slots=True)
class ToolSpec:
    function: ToolFunction
    type: Literal["function"] = "function"

# ============================================================================
# Chat
# ============================================================================

@dataclass(slots=True)
class ChatRequest:
    model: str
    messages: list[Message]
    tools: list[ToolSpec] | None = None
    stream: bool | None = None
    # None leaves provider defaults intact; otherwise this is the user's
    # explicit thinking-mode preference for providers that support it.
    thinking_enabled: bool | None = None
    # Generic level: callers may request a level, or pass the level selected
    # for an entire Agent turn. Adapters re-check model support before encoding.
    reasoning_level: ReasoningLevel | None = None
    requested_reasoning_level: ReasoningLevel | None = None

    def __post_init__(self) -> None:
        if self.reasoning_level is None or self.thinking_enabled is None:
            return
        if (self.reasoning_level is ReasoningLevel.OFF) != (not self.thinking_enabled):
            raise ValueError("reasoning_level conflicts with thinking_enabled")

FinishReason = Literal[
    "stop",
    "length",
    "tool_calls",
] | str

@dataclass(slots=True)
class ChatResponse:
    message: Message
    finish_reason: FinishReason
    usage: TokenUsage | None = None
    retry_count: int | None = None
    retry_wait_ms: float | None = None

# ============================================================================
# Helpers
# ============================================================================

def parsed_args(call: FunctionCall) -> dict[str, Any]:
    if not call.arguments:
        return {}
    args = json.loads(call.arguments)
    if not isinstance(args, dict):
        raise ValueError("tool call arguments must be a JSON object")
    return args
