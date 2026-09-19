from __future__ import annotations

import asyncio
from typing import Any, Optional

import pytest

from src.llm.client import Client
from src.llm import probe
from src.llm.probe import PING_TOOL_NAME, probe_tool_support
from src.llm.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall

class _StubClient:
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


class _BlockingClient(Client):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = False

    def name(self) -> str:
        return "stub"

    def model(self) -> str:
        return "stub-model"

    async def chat(
        self,
        request: ChatRequest,
        signal: Optional[Any] = None,
    ) -> ChatResponse:
        self.started.set()
        try:
            await asyncio.Event().wait()
            raise AssertionError("blocking event unexpectedly resolved")
        except asyncio.CancelledError:
            self.cancelled = True
            raise

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

    @pytest.mark.asyncio
    async def test_cancels_an_inflight_probe_when_parent_signal_is_set(self) -> None:
        c = _BlockingClient()
        signal = asyncio.Event()
        task = asyncio.create_task(probe_tool_support(c, signal))

        await c.started.wait()
        signal.set()
        result = await task

        assert result.tool_support == "unknown"
        assert result.detail == "probe cancelled"
        assert c.cancelled is True

    @pytest.mark.asyncio
    async def test_times_out_and_cancels_an_inflight_probe(self, monkeypatch) -> None:
        monkeypatch.setattr(probe, "PROBE_TIMEOUT", 0)
        c = _BlockingClient()

        result = await probe_tool_support(c)

        assert result.tool_support == "unknown"
        assert result.detail == "probe timed out after 0s"
        assert c.cancelled is True
