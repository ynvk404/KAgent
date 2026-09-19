
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any, Literal

from .client import Client
from .types import (
    ChatRequest,
    ChatResponse,
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
        response = await _probe_chat(client, request, parent_signal)

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


async def _probe_chat(
    client: Client,
    request: ChatRequest,
    parent_signal: asyncio.Event | None,
) -> ChatResponse:
    """Bound a billable probe and stop it when KAgent is shutting down."""
    chat_task = asyncio.create_task(client.chat(request))
    signal_task: asyncio.Task[bool] | None = None

    if parent_signal is not None:
        signal_task = asyncio.create_task(parent_signal.wait())

    try:
        wait_for: set[asyncio.Future[Any]] = {chat_task}
        if signal_task is not None:
            wait_for.add(signal_task)

        done, _ = await asyncio.wait(
            wait_for,
            timeout=PROBE_TIMEOUT,
            return_when=asyncio.FIRST_COMPLETED,
        )

        if chat_task in done:
            return chat_task.result()

        if signal_task is not None and signal_task in done:
            raise RuntimeError("probe cancelled")

        raise TimeoutError(f"probe timed out after {PROBE_TIMEOUT}s")
    finally:
        for task in (chat_task, signal_task):
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
