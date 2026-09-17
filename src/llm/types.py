from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

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

FinishReason = Literal[
    "stop",
    "length",
    "tool_calls",
] | str

@dataclass(slots=True)
class ChatResponse:
    message: Message
    finish_reason: FinishReason

# ============================================================================
# Helpers
# ============================================================================

def parsed_args(call: FunctionCall) -> dict[str, Any]:
    if not call.arguments:
        return {}
    return json.loads(call.arguments)
