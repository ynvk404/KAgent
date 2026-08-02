from __future__ import annotations

import json

import pytest

from src.llm.types import (
    ChatRequest,
    ChatResponse,
    FunctionCall,
    Message,
    ToolCall,
    ToolFunction,
    ToolProvider,
    ToolSpec,
    GeminiProvider,
    parsed_args,
)


# ============================================================================
# parsed_args
# ============================================================================


class TestParsedArgs:

    def test_returns_empty_dict_when_arguments_empty(self) -> None:
        call = FunctionCall(
            name="test",
            arguments="",
        )

        assert parsed_args(call) == {}

    def test_parses_valid_json(self) -> None:
        call = FunctionCall(
            name="shell",
            arguments='{"cmd":"ls","timeout":5}',
        )

        assert parsed_args(call) == {
            "cmd": "ls",
            "timeout": 5,
        }

    def test_raises_for_invalid_json(self) -> None:
        call = FunctionCall(
            name="shell",
            arguments="{bad json}",
        )

        with pytest.raises(json.JSONDecodeError):
            parsed_args(call)


# ============================================================================
# FunctionCall
# ============================================================================


class TestFunctionCall:

    def test_construct(self) -> None:
        call = FunctionCall(
            name="grep",
            arguments='{"pattern":"test"}',
        )

        assert call.name == "grep"
        assert call.arguments == '{"pattern":"test"}'


# ============================================================================
# ToolCall
# ============================================================================


class TestToolCall:

    def test_construct(self) -> None:
        call = ToolCall(
            id="call_1",
            function=FunctionCall(
                name="shell",
                arguments="{}",
            ),
        )

        assert call.id == "call_1"
        assert call.type == "function"
        assert call.function.name == "shell"

    def test_provider(self) -> None:
        call = ToolCall(
            id="call",
            function=FunctionCall(
                name="tool",
                arguments="{}",
            ),
            provider=ToolProvider(
                gemini=GeminiProvider(
                    thought_signature="abc123",
                ),
            ),
        )

        assert call.provider is not None
        assert call.provider.gemini is not None
        assert call.provider.gemini.thought_signature == "abc123"


# ============================================================================
# Message
# ============================================================================


class TestMessage:

    def test_basic_message(self) -> None:
        msg = Message(
            role="user",
            content="hello",
        )

        assert msg.role == "user"
        assert msg.content == "hello"
        assert msg.tool_calls is None
        assert msg.tool_call_id is None

    def test_message_with_tool_call(self) -> None:
        tool = ToolCall(
            id="1",
            function=FunctionCall(
                name="shell",
                arguments="{}",
            ),
        )

        msg = Message(
            role="assistant",
            content="",
            tool_calls=[tool],
        )

        assert msg.tool_calls is not None
        assert len(msg.tool_calls) == 1
        assert msg.tool_calls[0].id == "1"


# ============================================================================
# ToolFunction / ToolSpec
# ============================================================================


class TestToolSpec:

    def test_construct(self) -> None:
        spec = ToolSpec(
            function=ToolFunction(
                name="shell",
                description="Execute shell commands",
                parameters={
                    "type": "object",
                },
            ),
        )

        assert spec.type == "function"
        assert spec.function.name == "shell"


# ============================================================================
# ChatRequest
# ============================================================================


class TestChatRequest:

    def test_construct(self) -> None:
        req = ChatRequest(
            model="qwen3:14b",
            messages=[
                Message(
                    role="user",
                    content="hi",
                )
            ],
        )

        assert req.model == "qwen3:14b"
        assert len(req.messages) == 1
        assert req.tools is None
        assert req.stream is None


# ============================================================================
# ChatResponse
# ============================================================================


class TestChatResponse:

    def test_construct(self) -> None:
        res = ChatResponse(
            message=Message(
                role="assistant",
                content="hello",
            ),
            finish_reason="stop",
        )

        assert res.finish_reason == "stop"
        assert res.message.role == "assistant"
        assert res.message.content == "hello"