from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

# ============================================================================
# Roles
# ============================================================================

Role = Literal[
    "system",
    "user",
    "assistant",
    "tool",
]


# ============================================================================
# Function Call
# ============================================================================


@dataclass(slots=True)
class FunctionCall:
    """
    Function call emitted by the model.
    """

    name: str

    # JSON-encoded arguments exactly as returned by the model.
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
    """
    Tool call produced by the model.
    """

    id: str
    function: FunctionCall

    type: Literal["function"] = "function"
    provider: ToolProvider | None = None


# ============================================================================
# Message
# ============================================================================


@dataclass(slots=True)
class Message:
    """
    One chat message.
    """

    role: Role
    content: str

    tool_calls: list[ToolCall] | None = None
    tool_call_id: str | None = None
    name: str | None = None


# ============================================================================
# Tool Definition
# ============================================================================


@dataclass(slots=True)
class ToolFunction:
    """
    Function exposed to the model.
    """

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(slots=True)
class ToolSpec:
    """
    Tool specification passed to the model.
    """

    function: ToolFunction
    type: Literal["function"] = "function"


# ============================================================================
# Chat
# ============================================================================


@dataclass(slots=True)
class ChatRequest:
    """
    Chat completion request.
    """

    model: str
    messages: list[Message]

    tools: list[ToolSpec] | None = None
    stream: bool | None = None


FinishReason = Literal[
    "stop",
    "length",
    "tool_calls",
] | str


@dataclass(slots=True)
class ChatResponse:
    """
    Chat completion response.
    """

    message: Message
    finish_reason: FinishReason


# ============================================================================
# Helpers
# ============================================================================


def parsed_args(call: FunctionCall) -> dict[str, Any]:
    """
    Parse a FunctionCall.arguments JSON string.

    Returns:
        Parsed arguments dictionary.

    Raises:
        json.JSONDecodeError:
            If the JSON is malformed.
    """

    if not call.arguments:
        return {}

    return json.loads(call.arguments)