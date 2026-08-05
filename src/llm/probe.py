
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal

from .client import Client
from .types import (
    ChatRequest,
    Message,
    ToolFunction,
    ToolSpec,
)


PROBE_TIMEOUT = 8

PING_TOOL_NAME = "__kagent_probe_ping"


ToolSupport = Literal[
    "yes",
    "no",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class ProbeResult:
    tool_support: ToolSupport
    detail: str | None = None


async def probe_tool_support(
    client: Client,
    parent_signal: asyncio.Event | None = None,
) -> ProbeResult:

    ping_tool = ToolSpec(
        type="function",
        function=ToolFunction(
            name=PING_TOOL_NAME,
            description=(
                "Echo back the value received. "
                "Used only to verify tool calling."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": (
                            "Value to echo back."
                        ),
                    },
                },
                "required": [
                    "value",
                ],
            },
        ),
    )


    request = ChatRequest(
        model=client.model(),
        messages=[
            Message(
                role="system",
                content=(
                    "You are a tool-calling probe. "
                    f"Your only response must be a call to "
                    f"the {PING_TOOL_NAME} tool "
                    'with value="ok". '
                    "Do not produce any text."
                ),
            ),
            Message(
                role="user",
                content="probe",
            ),
        ],
        tools=[
            ping_tool,
        ],
    )


    try:

        response = await client.chat(
            request,
        )

    except Exception as exc:

        return ProbeResult(
            tool_support="unknown",
            detail=str(exc),
        )

    tool_calls = (
        response.message.tool_calls
        or []
    )

    for tool_call in tool_calls:

        if (
            tool_call.function.name
            == PING_TOOL_NAME
        ):

            return ProbeResult(
                tool_support="yes",
            )

    return ProbeResult(
        tool_support="no",
        detail=(
            "Model trả về text thay vì tool_call. "
            "Model có thể không hỗ trợ Function Calling."
        ),
    )