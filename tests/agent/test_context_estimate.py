"""Request accounting/admission boundaries without network or inference."""
from copy import deepcopy
import json
from types import SimpleNamespace
from typing import Any, cast

import pytest

from src.agent.agent import AgentRunOptions, IneffectiveCompactionError
from src.agent.context_estimate import estimate_request, text_tokens
from src.llm.core.reasoning import ReasoningLevel
from src.llm.core.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall
from src.llm.providers.openai import OpenAIClient
from src.llm.runtime.context_budget import ContextCapacityError, resolve_input_budget
from src.llm.runtime.metrics import TokenUsage, anthropic_usage
from src.session.store import SessionMemory
from src.workflow.state import Candidate
from tests.agent.test_token_accounting_independent_verify import make_agent, SnapshotClient
from tests.helpers.agent_fakes import FakeSignal


@pytest.mark.parametrize("provider,model,thinking,eligible", [
    ("deepseek", "deepseek-chat", False, True),  # Encoder replays even with thinking off.
    ("kimi", "kimi-k2.6", True, True),
    ("kimi", "kimi-k2.6", False, False),
    ("kimi", "kimi-k2.7-code", False, True),
    ("kimi", "moonshot-v1-8k", True, False),
    ("openai-compat", "kimi-k2.6", True, False),
])
def test_reasoning_estimator_matches_real_encoder(provider, model, thinking, eligible):
    message = Message("assistant", "visible", reasoning_content="private" * 1000,
                      provider_state_provider=provider, provider_state_model=model)
    req = ChatRequest(model=model, messages=[message], thinking_enabled=thinking)
    client = OpenAIClient("https://fixture.invalid", "", model, provider)
    encoded = client.encode_request(req, stream=False)["messages"][0]
    estimate = estimate_request(req, provider)
    assert ("reasoning_content" in encoded) is eligible
    assert bool(estimate.provider_private_tokens) is eligible
    message.provider_state_model = "other"
    assert estimate_request(req, provider).provider_private_tokens == 0
    message.provider_state_model = model
    message.provider_state_provider = "other"
    assert estimate_request(req, provider).provider_private_tokens == 0


def test_gemini_ordered_parts_replace_generic_content_and_calls():
    parts = [{"thought": True, "text": "discard" * 1000},
             {"text": "actual"},
             {"functionCall": {"name": "http", "args": {"url": "/"}}, "thoughtSignature": "s" * 100}]
    message = Message("assistant", "duplicate" * 1000,
                      tool_calls=[ToolCall("call", FunctionCall("http", json.dumps({"blob": "x" * 10000})))],
                      gemini_parts=parts, provider_state_provider="gemini",
                      provider_state_model="models/gemini-fixture")
    req = ChatRequest(model="gemini-fixture", messages=[message])
    estimate = estimate_request(req, "gemini")
    assert estimate.provider_private_tokens == 100
    assert estimate.history_tokens == text_tokens("actual") + text_tokens(json.dumps(parts[2]["functionCall"]))
    assert estimate.estimated_total < 200
    for provider, model in [("openai-compat", req.model), ("gemini", "other")]:
        mismatch = estimate_request(ChatRequest(model=model, messages=[message]), provider)
        assert mismatch.provider_private_tokens == 0
        assert mismatch.history_tokens > 4000


def test_large_arguments_and_tiny_unicode_components_are_represented():
    req = ChatRequest(model="unknown", messages=[
        Message("user", "a"), Message("user", "雨"), Message("user", "🙂"),
        Message("assistant", "", tool_calls=[ToolCall("id", FunctionCall("f", "x" * 40000))]),
    ])
    estimate = estimate_request(req)
    assert estimate.history_tokens >= 10004
    assert estimate.framing_tokens >= 20
    assert estimate.provider_private_tokens == 0


@pytest.mark.parametrize("component", ["memory", "workflow", "intelligence", "recall", "catalog"])
async def test_each_injected_component_changes_projected_gate_once(monkeypatch, component):
    agent = make_agent()
    agent.history.append(Message("user", "h" * 24000))
    baseline = agent.approx_tokens()
    agent.set_auto_compact_threshold(baseline + 200)
    attempts = []
    calls = []
    async def compact(signal):
        attempts.append(True)
        return False
    monkeypatch.setattr(agent, "compact_in_place", compact)
    if component == "memory":
        agent.memory = SessionMemory(todos=["todo " + "m" * 200 for _ in range(20)])
    elif component == "workflow":
        for i in range(20):
            agent.workflow.add_candidate(Candidate(candidate_class="sqli", endpoint=f"/api/{i}/" + "w" * 120))
    elif component == "catalog":
        agent.memory_store = cast(Any, SimpleNamespace(index=lambda: "catalog " * 500,
                                                       search=lambda *args: []))
    elif component == "intelligence":
        monkeypatch.setattr(agent, "build_intelligence_context", lambda _: (calls.append("intelligence") or "intelligence " * 500))
    else:
        def recall(user, emit):
            calls.append("recall")
            emit({"type": "memory-recall", "names": ["fixture"]})
            return "recall " * 1000
        monkeypatch.setattr(agent, "recall_curated_memory", recall)
    events = []
    await agent.run("next", FakeSignal(), events.append, AgentRunOptions(tools=False))
    assert attempts == [True]
    assert len(calls) <= 1
    assert sum(event["type"] == "memory-recall" for event in events) == (component == "recall")
    request = cast(SnapshotClient, agent.client).requests[0]
    assert estimate_request(request).estimated_total > agent.get_auto_compact_threshold()


async def test_expanded_file_input_counted_once_and_raw_input_persisted(monkeypatch):
    agent = make_agent()
    agent.history.append(Message("user", "h" * 24000))
    agent.set_auto_compact_threshold(agent.approx_tokens() + 200)
    expanded = "expanded-file-marker " * 500
    calls = []
    monkeypatch.setattr("src.agent.agent.expand_file_mentions", lambda *args, **kwargs: (calls.append(True) or expanded))
    projections = []
    async def compact(signal, emit, **kwargs):
        projections.append(kwargs["trigger_tokens"])
    monkeypatch.setattr(agent, "auto_compact", compact)
    await agent.run("@fixture.txt", FakeSignal(), lambda _: None, AgentRunOptions(tools=False))
    request = cast(SnapshotClient, agent.client).requests[0]
    assert calls == [True]
    assert sum(message.content == expanded for message in request.messages) == 1
    assert projections == [estimate_request(request).estimated_total]
    assert agent.history[-2].content == "@fixture.txt"


async def test_material_compaction_reestimated_with_new_memory_before_dispatch(monkeypatch):
    summary = "## Current objective\n- Continue offline review"
    client = SnapshotClient([ChatResponse(Message("assistant", summary), "stop"),
                             ChatResponse(Message("assistant", "done"), "stop")])
    agent = make_agent(client=client)
    agent.history.extend([Message("user", "old" * 12000), Message("assistant", "old" * 12000)])
    agent.set_auto_compact_threshold(1)
    observed = []
    original = agent._admit_request
    async def admission(req, emit):
        observed.append(estimate_request(req).estimated_total)
        await original(req, emit)
    monkeypatch.setattr(agent, "_admit_request", admission)
    await agent.run("pending", FakeSignal(), lambda _: None, AgentRunOptions(tools=False))
    assert len(client.requests) == 2
    assert client.requests[0].tools is None
    assert agent.memory is not None
    assert "Continue offline review" in "\n".join(message.content for message in client.requests[1].messages)
    assert observed[-1] == estimate_request(client.requests[1]).estimated_total


@pytest.mark.parametrize("soft,history,failures", [(0, 0, 0), (16000, 0, 0), (1, 24000, 3)])
async def test_hard_admission_independent_of_soft_gate(soft, history, failures):
    agent = make_agent()
    setattr(agent.client, "input_token_limit", 100)
    agent.set_auto_compact_threshold(soft)
    agent.consecutive_compact_failures = failures
    if history:
        agent.history.append(Message("user", "h" * history))
    events = []
    await agent.run("pending", FakeSignal(), events.append, AgentRunOptions(tools=False))
    assert cast(SnapshotClient, agent.client).requests == []
    assert events[-1].stop_reason == "context_capacity"
    assert any(isinstance(event.get("err"), ContextCapacityError) for event in events)
    assert agent.history[-1].content == "pending"


@pytest.mark.parametrize("route", ["turn", "malformed_retry", "final_synthesis", "compaction", "whole_target_retry"])
async def test_dispatch_routes_reject_known_overflow_after_late_guidance(route):
    agent = make_agent()
    setattr(agent.client, "input_token_limit", 100)
    req = ChatRequest(model=agent.client.model(), messages=[Message("user", "small"), Message("system", "late" * 400)])
    with pytest.raises(ContextCapacityError):
        if route == "compaction":
            await agent._chat_for_compaction(req, FakeSignal(), "manual")
        else:
            await agent._chat_for_turn(req, FakeSignal(), lambda _: None,
                                       purpose="final_synthesis" if "synthesis" in route or "target" in route else "agent_turn",
                                       trace_phase=route)
    assert not cast(SnapshotClient, agent.client).requests


async def test_synthesis_retry_measures_added_instruction_and_zero_schemas():
    invalid = ChatResponse(Message("assistant", "", tool_calls=[ToolCall("id", FunctionCall("f", "{}"))]), "tool_calls")
    agent = make_agent(client=SnapshotClient([invalid]))
    working = [Message("user", "small")]
    # The first synthesis fits; the longer retry guidance exceeds this budget.
    setattr(agent.client, "input_token_limit", 20)
    agent.set_auto_compact_threshold(0)
    with pytest.raises(ContextCapacityError):
        await agent._whole_target_synthesis(working, FakeSignal(), lambda _: None,
            thinking_enabled=False, reasoning_level=ReasoningLevel.OFF,
            requested_reasoning_level=ReasoningLevel.OFF, stop_reason="max_steps",
            instruction="Summarize.", max_steps=1)
    requests = cast(SnapshotClient, agent.client).requests
    assert len(requests) == 1 and requests[0].tools is None


def test_known_kimi_budget_reserves_output_and_unknown_identity_does_not_guess():
    client = OpenAIClient("https://fixture.invalid", "", "moonshot-v1-8k", "kimi", gen_opts={"max_tokens": 2048})
    budget = resolve_input_budget(client)
    assert budget.input_limit == 8192 - 2048 - budget.safety_tokens
    assert budget.reserved_output_tokens == 2048
    for identity in ("openai-compat", "custom Kimi", "groq"):
        other = OpenAIClient("https://fixture.invalid", "", "moonshot-v1-8k", identity)
        assert resolve_input_budget(other).input_limit is None
    explicit = OpenAIClient("https://fixture.invalid", "", "unknown", gen_opts={"input_token_limit": 5000, "max_tokens": 1000})
    assert resolve_input_budget(explicit).input_limit == 5000  # Separate input limit, no output subtraction.


def test_client_switch_budget_follows_active_instance_and_rollback():
    agent = make_agent()
    old = agent.client
    kimi = OpenAIClient("https://fixture.invalid", "", "moonshot-v1-8k", "kimi")
    agent.set_client(kimi)
    assert agent.input_budget().source == "kimi-context"
    kimi.model_id = "moonshot-v1-32k"
    switched_budget = agent.input_budget().input_limit
    assert switched_budget is not None and switched_budget > 20000
    agent.set_client(old)
    assert agent.input_budget().source == "unknown"


@pytest.mark.parametrize("raw,expected", [
    (None, None), ("malformed", None), ({}, None),
    ({"input_tokens": 100, "output_tokens": 20}, 100),
    ({"input_tokens": 100, "cache_read_input_tokens": "bad"}, None),
    ({"input_tokens": True, "output_tokens": -1}, None),
    ({"input_tokens": 100, "cache_creation_input_tokens": None}, None),
])
def test_anthropic_missing_or_malformed_usage_stays_unknown(raw, expected):
    usage = anthropic_usage(raw)
    assert (usage.input_tokens if usage else None) == expected
    if usage is not None:
        assert usage.reasoning_tokens is None


async def test_provider_usage_does_not_change_next_request_estimate():
    huge = TokenUsage(999999, 888888, 777777)
    estimates = []
    for usage in (None, huge):
        client = SnapshotClient([ChatResponse(Message("assistant", "done"), "stop", usage=usage)])
        agent = make_agent(client=client)
        await agent.run("next", FakeSignal(), lambda _: None, AgentRunOptions(tools=False))
        estimates.append(agent.idle_request_estimate())
    assert estimates[0] == estimates[1]


async def test_real_malformed_retry_includes_retry_guidance_in_admission():
    class MalformedClient(SnapshotClient):
        async def chat(self, request, signal=None):
            response = await super().chat(request, signal)
            # First request fits; the real retry instruction cannot fit.
            self.input_token_limit = estimate_request(request).estimated_total + 10
            return response
    malformed = ('<｜｜DSML｜｜ calls><｜｜DSML｜｜ invoke name="http">'
                 '<｜｜DSML｜｜ parameter name="url">/</｜｜DSML｜｜ parameter>'
                 '</｜｜DSML｜｜ invoke></｜｜DSML｜｜ calls>')
    client = MalformedClient([ChatResponse(Message("assistant", malformed), "stop")])
    agent = make_agent(client=client)
    agent.set_auto_compact_threshold(0)
    events = []
    await agent.run("next", FakeSignal(), events.append)
    assert len(client.requests) == 1
    assert events[-1].stop_reason == "context_capacity"
    assert any(isinstance(event.get("err"), ContextCapacityError) for event in events)


async def test_real_generic_final_synthesis_uses_zero_schemas_and_hard_check(monkeypatch):
    from src.agent.agent import ToolExecutionBatch
    class ToolClient(SnapshotClient):
        async def chat(self, request, signal=None):
            response = await super().chat(request, signal)
            self.input_token_limit = estimate_request(request).estimated_total + 10
            return response
    client = ToolClient([ChatResponse(Message("assistant", "", tool_calls=[
        ToolCall("id", FunctionCall("fixture", "{}"))]), "tool_calls")])
    agent = make_agent(client=client)
    agent.set_auto_compact_threshold(0)
    async def execute(calls, signal, emit, working, **kwargs):
        result = Message("tool", "preserved" * 4000, name="fixture", tool_call_id="id")
        working.append(result)
        agent.history.append(result)
        return ToolExecutionBatch(all_refused=False, calls=[])
    monkeypatch.setattr(agent, "execute_tool_calls", execute)
    monkeypatch.setattr(agent.tools, "context_reduction_policy", lambda name: "preserve")
    requests = []
    original = agent._admit_request
    async def admit(req, emit):
        requests.append(deepcopy(req))
        await original(req, emit)
    monkeypatch.setattr(agent, "_admit_request", admit)
    events = []
    await agent.run("next", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    assert len(requests) == 2 and requests[-1].tools is None
    assert len(client.requests) == 1
    assert events[-1].stop_reason == "context_capacity"
    assert agent.history[-1].content == "preserved" * 4000


async def test_failed_auto_compaction_still_checks_hard_budget_without_loop():
    agent = make_agent()
    setattr(agent.client, "input_token_limit", 100)
    agent.set_auto_compact_threshold(1)
    agent.history.append(Message("user", "h" * 24000))
    events = []
    await agent.run("pending", FakeSignal(), events.append, AgentRunOptions(tools=False))
    assert agent.consecutive_compact_failures == 1
    assert not cast(SnapshotClient, agent.client).requests
    assert events[-1].stop_reason == "context_capacity"
    assert agent.history[-2].content == "h" * 24000


async def test_summary_failure_preserves_history_memory_and_prompt():
    agent = make_agent(client=SnapshotClient([ChatResponse(Message("assistant", ""), "stop")]))
    agent.memory = SessionMemory(todos=["still pending"])
    agent.history.append(Message("user", "h" * 24000))
    before = deepcopy(agent.history), deepcopy(agent.memory), agent.sys_prompt
    events = []
    await agent.compact(FakeSignal(), events.append)
    assert (agent.history, agent.memory, agent.sys_prompt) == before
    assert any(event["type"] == "error" for event in events)


def test_anthropic_usage_positional_compatibility_and_jsonl_export(tmp_path):
    from src.llm.runtime.metrics import MetricsCollector, RequestMetrics
    original = TokenUsage(1, 2, 3, 4, 5, True)
    assert original.output_includes_reasoning is True
    assert original.cache_creation_input_tokens is None
    usage = anthropic_usage({"input_tokens": 100, "output_tokens": 20,
                             "cache_read_input_tokens": 40, "cache_creation_input_tokens": 10,
                             "cache_creation": {"ephemeral_5m_input_tokens": 10}})
    collector = MetricsCollector()
    collector.add(RequestMetrics("fixture", "fixture", 1, "anthropic", "fixture", "agent_turn",
                                 "fixture", None, None, "success", usage))
    path = tmp_path / "metrics.jsonl"
    collector.export_jsonl(path)
    exported = json.loads(path.read_text())["usage"]
    assert exported["input_tokens"] == 150
    assert exported["cache_creation_input_tokens"] == 10
    assert exported["total_tokens"] == 170  # Lifetime breakdown is not added again.


def test_projection_snapshot_is_pure_and_reuses_catalog_workflow_refs(monkeypatch):
    agent = make_agent()
    agent.memory = SessionMemory(todos=["old"])
    agent.memory_store = cast(Any, SimpleNamespace(index=lambda: "catalog before"))
    agent.workflow.add_candidate(Candidate(candidate_class="sqli", endpoint="/before"))
    before = deepcopy(agent.workflow), dict(agent.result_retention.scope)
    def unexpected_refresh():
        raise AssertionError("projection must not rotate retention scope")
    monkeypatch.setattr(agent.result_retention, "refresh_scope", unexpected_refresh)
    context = agent._idle_context()
    first = agent._projected_estimate(agent.history, agent.memory, context)
    assert (agent.workflow, agent.result_retention.scope) == before
    agent.memory_store = cast(Any, SimpleNamespace(index=lambda: "changed catalog" * 1000))
    agent.workflow.add_candidate(Candidate(candidate_class="xss", endpoint="/after"))
    assert agent._projected_estimate(agent.history, agent.memory, context) == first
    second = agent._projected_estimate(agent.history, SessionMemory(todos=["new" * 200]), context)
    assert second.injected_tokens > first.injected_tokens
