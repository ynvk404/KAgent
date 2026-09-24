import asyncio
from pathlib import Path

import pytest

from src.agent.agent import Agent, AgentOptions
from src.llm.gemini import GeminiClient
from src.llm.anthropic import AnthropicClient
from src.llm.openai import OpenAIClient
from src.llm.reasoning import ReasoningCapabilities, ReasoningLevel
from src.llm.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.session.store import Store
from src.tools.registry import Registry as ToolRegistry
from tests.helpers.agent_fakes import EchoTool, FakeClient, FakeSignal, collect, seed_compactable_history


class _PreferenceChangingClient(FakeClient):
    agent: Agent | None = None

    async def chat(self, request, signal=None):
        response = await super().chat(request, signal)
        if self.idx == 1 and self.agent is not None:
            await self.agent.set_thinking_enabled(False)
        return response


class _OpenAIRestrictedClient(FakeClient):
    def reasoning_capabilities(self, *, has_tools=False):
        return OpenAIClient(
            "https://api.openai.com/v1", "", "gpt-6-luna", "openai"
        ).reasoning_capabilities(has_tools=has_tools)


class _OffFallsBackToLowClient(FakeClient):
    def reasoning_capabilities(self, *, has_tools=False):
        return ReasoningCapabilities(
            frozenset({ReasoningLevel.LOW}),
            fallbacks={ReasoningLevel.OFF: ReasoningLevel.LOW},
        )


def _agent(client, *, thinking=True, max_steps=1):
    tools = ToolRegistry()
    tools.register(EchoTool())
    return Agent(
        AgentOptions(
            client=client,
            tools=tools,
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
            thinking_enabled=thinking,
            max_steps=max_steps,
        )
    )


@pytest.mark.asyncio
async def test_tool_loop_and_final_synthesis_keep_turn_level_after_preference_change():
    first_call = ToolCall(
        id="call_1",
        function=FunctionCall(name="echo", arguments='{"msg":"hello"}'),
    )
    second_call = ToolCall(
        id="call_2",
        function=FunctionCall(name="echo", arguments='{"msg":"again"}'),
    )
    client = _PreferenceChangingClient([
        ChatResponse(Message(role="assistant", content="", tool_calls=[first_call]), "tool_calls"),
        ChatResponse(Message(role="assistant", content="", tool_calls=[second_call]), "tool_calls"),
        ChatResponse(Message(role="assistant", content="finished"), "stop"),
    ])
    agent = _agent(client, max_steps=2)
    client.agent = agent

    await agent.run("test", FakeSignal(), collect()["sink"])

    assert len(client.requests) == 3
    assert [req.reasoning_level for req in client.requests] == [
        ReasoningLevel.LOW, ReasoningLevel.LOW, ReasoningLevel.LOW
    ]
    assert [req.thinking_enabled for req in client.requests] == [True, True, True]
    assert client.requests[0].tools and client.requests[1].tools
    assert not client.requests[2].tools  # final synthesis follows the tool loop
    assert agent.thinking_is_enabled() is False  # preference applies next turn
    assert [row.purpose for row in agent.request_metrics.records] == [
        "agent_turn", "agent_turn", "final_synthesis"
    ]
    assert all(row.requested_reasoning_level == "low" for row in agent.request_metrics.records)
    assert all(row.effective_reasoning_level is None for row in agent.request_metrics.records)
    deepseek = OpenAIClient("https://api.deepseek.com", "", "deepseek-flash", "deepseek")
    assert all(
        deepseek.encode_request(req, False)["reasoning_effort"] == "low"
        for req in client.requests
    )


@pytest.mark.asyncio
async def test_effective_tool_level_stays_off_during_final_synthesis():
    call = ToolCall(
        id="call_1", function=FunctionCall(name="echo", arguments='{"msg":"hello"}')
    )
    client = _OpenAIRestrictedClient([
        ChatResponse(Message(role="assistant", content="", tool_calls=[call]), "tool_calls"),
        ChatResponse(Message(role="assistant", content="done"), "stop"),
    ])
    agent = _agent(client)

    await agent.run("test", FakeSignal(), collect()["sink"])

    assert [req.reasoning_level for req in client.requests] == [
        ReasoningLevel.OFF, ReasoningLevel.OFF
    ]
    assert [req.thinking_enabled for req in client.requests] == [False, False]
    openai = OpenAIClient("https://api.openai.com/v1", "", "gpt-6-luna", "openai")
    assert [openai.encode_request(req, False)["reasoning_effort"] for req in client.requests] == [
        "none", "none"
    ]
    assert [row.requested_reasoning_level for row in agent.request_metrics.records] == ["low", "low"]
    assert [row.effective_reasoning_level for row in agent.request_metrics.records] == ["off", "off"]


def test_compaction_settings_resolve_fallback_without_changing_user_preference():
    fallback = _agent(_OffFallsBackToLowClient([]), thinking=True)
    assert fallback._compaction_reasoning_settings() == (ReasoningLevel.LOW, True)
    assert fallback.thinking_is_enabled() is True

    unknown = _agent(FakeClient([]), thinking=True)
    assert unknown._compaction_reasoning_settings() == (ReasoningLevel.OFF, False)
    assert unknown.thinking_is_enabled() is True


@pytest.mark.asyncio
@pytest.mark.parametrize("manual", [False, True])
async def test_compaction_records_requested_off_and_verified_low_fallback(manual):
    summary = ChatResponse(
        Message(role="assistant", content="## Current objective\n- Continue authorized testing"),
        "stop",
    )
    client = _OffFallsBackToLowClient([summary])
    agent = _agent(client, thinking=True)
    seed_compactable_history(agent)

    if manual:
        await agent.compact(FakeSignal(), collect()["sink"])
    else:
        assert await agent.compact_in_place(FakeSignal()) is True

    request = client.requests[0]
    metric = agent.request_metrics.records[-1]
    assert request.requested_reasoning_level is ReasoningLevel.OFF
    assert request.reasoning_level is ReasoningLevel.LOW
    assert request.thinking_enabled is True
    assert metric.requested_reasoning_level == "off"
    assert metric.effective_reasoning_level == "low"
    assert agent.thinking_is_enabled() is True


def test_status_distinguishes_requested_and_effective_reasoning():
    deepseek = _agent(OpenAIClient("https://api.deepseek.com", "", "deepseek-flash", "deepseek"))
    assert deepseek.reasoning_status(True) == "thinking on; model uses low"
    assert deepseek.reasoning_status(False) == "thinking off; model uses off"


def test_provider_specific_metrics_and_compaction_keep_unknown_distinct():
    kimi = _agent(OpenAIClient("https://api.moonshot.ai/v1", "", "kimi-k2.6", "kimi"))
    off = ChatRequest("kimi-k2.6", [], reasoning_level=ReasoningLevel.OFF,
                      requested_reasoning_level=ReasoningLevel.OFF)
    low = ChatRequest("kimi-k2.6", [], reasoning_level=ReasoningLevel.LOW,
                      requested_reasoning_level=ReasoningLevel.LOW)
    assert kimi._known_effective_reasoning_level(off) == "off"
    assert kimi._known_effective_reasoning_level(low) is None
    assert kimi._compaction_reasoning_settings() == (ReasoningLevel.OFF, False)

    groq = _agent(OpenAIClient("https://api.groq.com/openai/v1", "",
                             "openai/gpt-oss-120b", "groq"))
    assert groq._known_effective_reasoning_level(off) is None
    assert groq._known_effective_reasoning_level(low) == "low"
    assert groq._compaction_reasoning_settings() == (ReasoningLevel.OFF, False)

    claude = _agent(AnthropicClient("https://api.anthropic.com/v1", "",
                                   "claude-sonnet-4-6"))
    assert claude._known_effective_reasoning_level(off) is None
    assert claude._known_effective_reasoning_level(low) is None


@pytest.mark.asyncio
async def test_hidden_provider_reasoning_stays_out_of_events_snapshot_and_metrics(tmp_path):
    marker = "SECRET_INTERNAL_REASONING_MARKER"
    client = FakeClient([
        ChatResponse(Message(
            role="assistant", content="visible answer", reasoning_content=marker,
            provider_state_provider="deepseek", provider_state_model="deepseek-flash",
        ), "stop")
    ])
    agent = _agent(client)
    agent.store = Store.new_with_id(tmp_path / "sessions", "private")
    emitted = collect()
    await agent.run("question", FakeSignal(), emitted["sink"])
    snapshot = await agent.save_context_snapshot()
    assert marker in agent.store.path.read_text()  # internal replay state
    assert marker not in str(emitted["events"])
    assert marker not in Path(snapshot).read_text(encoding="utf-8")
    assert marker not in str(agent.request_metrics.records)


@pytest.mark.asyncio
async def test_request_metrics_record_error_and_cancellation_without_fabricating_usage():
    agent = _agent(FakeClient([]))
    request = ChatRequest(model="fake-model", messages=[Message(role="user", content="q")])
    with pytest.raises(Exception, match="script exhausted"):
        await agent._chat_for_turn(request, FakeSignal(), lambda _event: None)
    assert agent.request_metrics.records[-1].status == "error"
    assert agent.request_metrics.records[-1].usage is None
    assert agent.request_metrics.records[-1].retry_count is None

    class CancelledClient(FakeClient):
        async def chat(self, request, signal=None):
            raise asyncio.CancelledError()

    agent.client = CancelledClient([])
    with pytest.raises(asyncio.CancelledError):
        await agent._chat_for_turn(request, FakeSignal(), lambda _event: None)
    assert agent.request_metrics.records[-1].status == "cancelled"
    assert agent.request_metrics.records[-1].usage is None

    gemini = _agent(GeminiClient("https://generativelanguage.googleapis.com/v1beta", "", "models/gemini-3.8-flash"))
    assert gemini.reasoning_status(False) == (
        "thinking off requested; model uses low (fallback). "
        "System prompt guidance follows this setting."
    )

    generic = _agent(OpenAIClient("https://gateway.example/v1", "", "deepseek-flash", "openai-compat"))
    assert generic.reasoning_status(False) == (
        "thinking off requested; provider behavior unverified. "
        "System prompt guidance follows this setting."
    )
