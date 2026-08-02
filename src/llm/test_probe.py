"""
tests/llm/test_probe.py

Port of probe.test.ts (Vitest) to Python (pytest + pytest-asyncio).

Only `probe_tool_support` is covered here. The original TS suite also
covered `parseOllamaContextInfo`, but the Ollama context-window probe
(`detect_ollama_context_window` / `parse_ollama_context_info`) was removed
from `llm/probe.py` along with Ollama/LM Studio backend support, so there is
nothing left to port for that half of the suite.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest

from llm.client import Client
from llm.probe import PING_TOOL_NAME, probe_tool_support
from llm.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall


class _StubClient:
    """Client stub that always returns a fixed ChatResponse."""

    def __init__(self, reply: ChatResponse) -> None:
        self._reply = reply

    def name(self) -> str:
        return "stub"

    def model(self) -> str:
        return "stub-model"

    async def chat(
        self,
        req: ChatRequest,
        signal: Optional[Any] = None,
    ) -> ChatResponse:
        return self._reply


class _RejectingClient:
    """Client stub whose chat() always raises."""

    def __init__(self, err: Exception) -> None:
        self._err = err

    def name(self) -> str:
        return "stub"

    def model(self) -> str:
        return "stub-model"

    async def chat(
        self,
        req: ChatRequest,
        signal: Optional[Any] = None,
    ) -> ChatResponse:
        raise self._err


def _stub_client(reply: ChatResponse) -> Client:
    return _StubClient(reply)  # type: ignore[return-value]


def _rejecting_client(err: Exception) -> Client:
    return _RejectingClient(err)  # type: ignore[return-value]


class TestProbeToolSupport:
    @pytest.mark.asyncio
    async def test_returns_yes_when_the_model_calls_the_probe_tool(self) -> None:
        c = _stub_client(
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call-1",
                            function=FunctionCall(
                                name=PING_TOOL_NAME,
                                arguments='{"value":"ok"}',
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            )
        )

        r = await probe_tool_support(c)

        assert r.tool_support == "yes"

    @pytest.mark.asyncio
    async def test_returns_no_when_the_model_returns_plain_text(self) -> None:
        c = _stub_client(
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="sure, here is the ping result: ok",
                ),
                finish_reason="stop",
            )
        )

        r = await probe_tool_support(c)

        assert r.tool_support == "no"
        assert r.detail is not None
        assert "tool_call" in r.detail
        assert "Function Calling" in r.detail

    @pytest.mark.asyncio
    async def test_returns_no_when_the_model_calls_a_different_tool(self) -> None:
        c = _stub_client(
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call-1",
                            function=FunctionCall(name="something_else", arguments="{}"),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            )
        )

        r = await probe_tool_support(c)

        assert r.tool_support == "no"

    @pytest.mark.asyncio
    async def test_returns_unknown_when_the_client_throws(self) -> None:
        c = _rejecting_client(Exception("connection refused"))

        r = await probe_tool_support(c)

        assert r.tool_support == "unknown"