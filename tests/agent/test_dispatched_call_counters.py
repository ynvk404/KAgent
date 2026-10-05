"""Counters compared to independent client invocations through actual callers."""
from copy import deepcopy
from typing import Any

import pytest

from src.agent.agent import AgentRunOptions
from src.agent.context_estimate import estimate_request
from src.llm.core.client import StreamingClient
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.tools.common.registry import Registry
from tests.agent.test_agent import whole_target_agent, MALFORMED_TOOL_CALL_TEXT
from tests.agent.test_token_accounting_independent_verify import make_agent
from tests.helpers.agent_fakes import FakeSignal, EchoTool
from tests.integration.test_requested_goal_lifecycle import _direct_goal_agent

FINAL = ChatResponse(Message("assistant", "done"), "stop")
INVALID = ChatResponse(Message("assistant", "", tool_calls=[ToolCall("invalid", FunctionCall("echo", "{}"))]), "tool_calls")


class CountingClient(StreamingClient):
    def __init__(self, responses, *, reject_after=None):
        self.responses = list(responses)
        self.invocations = []
        self.reject_after = reject_after
    def name(self): return "offline-counter"
    def model(self): return "offline-fixture"
    def dispatch(self, request, method):
        self.invocations.append((method, deepcopy(request)))
        if self.reject_after is not None and len(self.invocations) == self.reject_after:
            self.input_token_limit = estimate_request(request).estimated_total + 10
        response = self.responses.pop(0)
        if isinstance(response, Exception): raise response
        return response
    async def chat(self, request, signal=None):
        return self.dispatch(request, "chat")
    async def chat_stream(self, request, on_delta, signal=None):
        response = self.dispatch(request, "stream")
        if response.message.content: on_delta(response.message.content)
        return response


def assert_counts(agent, client, *, loop=0, synthesis=0, compaction=0):
    assert agent._llm_call_counts == {
        "agent_loop_llm_calls": loop, "final_synthesis_llm_calls": synthesis,
        "compaction_llm_calls": compaction,
    }
    assert len(client.invocations) == loop + synthesis + compaction
    assert len(agent.request_metrics.records) == len(client.invocations)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("outcome", ["reject", "accepted", "provider_failure"])
async def test_normal_turn_dispatch_accounting(streaming, outcome):
    client = CountingClient([RuntimeError("offline provider failure") if outcome == "provider_failure" else FINAL])
    if outcome == "reject": client.input_token_limit = 100
    agent = make_agent(client=client)
    agent.streaming_enabled = streaming
    agent.set_auto_compact_threshold(0)
    events = []
    await agent.run("next", FakeSignal(), events.append, AgentRunOptions(tools=False))
    expected = 0 if outcome == "reject" else 1
    assert_counts(agent, client, loop=expected)
    assert events[-1].total_llm_calls == expected
    assert events[-1].stop_reason == {"reject": "context_capacity", "accepted": "final_response", "provider_failure": "client_error"}[outcome]
    if expected:
        assert client.invocations[0][0] == ("stream" if streaming else "chat")
    if outcome == "provider_failure":
        assert agent.request_metrics.records[0].usage is None
        assert agent.request_metrics.records[0].status == "error"


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("reject_retry", [False, True])
async def test_real_malformed_retry_counts_only_admitted_calls(streaming, reject_retry):
    client = CountingClient([ChatResponse(Message("assistant", MALFORMED_TOOL_CALL_TEXT), "stop"), FINAL],
                            reject_after=1 if reject_retry else None)
    agent = make_agent(client=client)
    agent.set_auto_compact_threshold(0)
    agent.streaming_enabled = streaming
    events = []
    await agent.run("next", FakeSignal(), events.append)
    assert any("malformed tool-call text" in str(e.get("err", "")) for e in events)
    assert_counts(agent, client, loop=1 if reject_retry else 2)
    assert events[-1].stop_reason == ("context_capacity" if reject_retry else "final_response")
    if not reject_retry:
        assert any("tool-call" in m.content.lower() for m in client.invocations[1][1].messages)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("outcome", ["reject", "accepted", "provider_failure"])
async def test_generic_synthesis_after_real_tool_execution(streaming, outcome):
    class Receipt(EchoTool):
        def context_reduction_policy(self): return "preserve"
        async def run(self, args, signal, prompter):
            self.calls += 1
            return "recorded observation " * 2000
    tool = Receipt()
    registry = Registry()
    registry.register(tool)
    client = CountingClient([
        ChatResponse(Message("assistant", "", tool_calls=[ToolCall("id", FunctionCall("echo", "{}"))]), "tool_calls"),
        RuntimeError("offline synthesis failure") if outcome == "provider_failure" else FINAL,
    ], reject_after=1 if outcome == "reject" else None)
    agent = make_agent(client=client, tools=registry)
    agent.set_auto_compact_threshold(0)
    agent.streaming_enabled = streaming
    events = []
    await agent.run("Use echo", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    assert tool.calls == 1
    assert_counts(agent, client, loop=1, synthesis=0 if outcome == "reject" else 1)
    assert events[-1].stop_reason == {"reject": "context_capacity", "accepted": "final_response", "provider_failure": "client_error"}[outcome]
    if outcome != "reject": assert client.invocations[-1][1].tools is None


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("objective", ["whole_target", "requested_goal"])
@pytest.mark.parametrize("outcome", ["reject", "accepted", "retry", "reject_retry", "provider_failure"])
async def test_objective_synthesis_and_retry_from_agent_run(tmp_path, monkeypatch, objective, outcome, streaming):
    responses: list[Any] = [FINAL]
    if outcome in {"retry", "reject_retry"}: responses += [INVALID, FINAL]
    else: responses += [RuntimeError("offline synthesis failure") if outcome == "provider_failure" else FINAL]
    client = CountingClient(responses)
    if objective == "whole_target":
        agent, _ = whole_target_agent([], [EchoTool()], max_steps=1)
        agent.set_client(client)
        prompt = "Perform a whole-target assessment"
    else:
        agent, _ = _direct_goal_agent(tmp_path, client=client, max_steps=1)
        prompt = "Test SQL Injection and XSS for GET /search?term=sample"
    agent.set_auto_compact_threshold(0)
    agent.streaming_enabled = streaming
    # Reject only the actual tools-free caller request; the first loop request
    # must complete so production workflow routes select their synthesis.
    original = agent._admit_request
    synthesis_admissions = []
    async def admit(request, emit):
        if request.tools is None:
            synthesis_admissions.append(deepcopy(request))
            if outcome == "reject" or (outcome == "reject_retry" and len(synthesis_admissions) == 2):
                client.input_token_limit = 100
        await original(request, emit)
    monkeypatch.setattr(agent, "_admit_request", admit)
    events = []
    await agent.run(prompt, FakeSignal(), events.append)
    assert agent.workflow.objective is not None
    if objective == "whole_target": assert agent.workflow.objective.mode == "whole_target"
    else: assert agent.workflow.objective.requested_goals
    assert synthesis_admissions
    synth_count = 0 if outcome == "reject" else (2 if outcome == "retry" else 1)
    assert_counts(agent, client, loop=1, synthesis=synth_count)
    assert all(req.tools is None for req in synthesis_admissions)
    if outcome in {"retry", "reject_retry"}:
        assert len(synthesis_admissions) == 2
        assert "plain-text assessment summary" in synthesis_admissions[1].messages[-1].content
    if outcome in {"reject", "reject_retry"}: assert events[-1].stop_reason == "context_capacity"
    if outcome == "provider_failure": assert events[-1].stop_reason == "client_error"


@pytest.mark.parametrize("automatic", [False, True])
@pytest.mark.parametrize("outcome", ["reject", "accepted", "provider_failure"])
async def test_manual_and_automatic_compaction_callers(automatic, outcome):
    summary = ChatResponse(Message("assistant", "## Current objective\n- Continue offline"), "stop")
    client = CountingClient([RuntimeError("offline summary failure") if outcome == "provider_failure" else summary, FINAL])
    if outcome == "reject": client.input_token_limit = 100
    agent = make_agent(client=client)
    agent.history.extend([Message("user", "old" * 12000), Message("assistant", "old" * 12000)])
    events = []
    if automatic:
        agent.set_auto_compact_threshold(1)
        await agent.run("pending", FakeSignal(), events.append, AgentRunOptions(tools=False))
    else:
        await agent.compact(FakeSignal(), events.append)
    count = 0 if outcome == "reject" else 1
    assert_counts(agent, client, compaction=count, loop=(1 if automatic and outcome != "reject" else 0))
    if count:
        assert client.invocations[0][0] == "chat"  # Summary dispatch is non-streaming.
        assert client.invocations[0][1].tools is None
    if outcome == "reject":
        assert not agent.request_metrics.records
        if automatic: assert events[-1].stop_reason == "context_capacity"
