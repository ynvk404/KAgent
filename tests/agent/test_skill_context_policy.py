"""History-system compaction and capacity-aware soft policy, entirely offline."""
from copy import deepcopy
from typing import cast

import pytest

from src.agent.agent import AgentRunOptions, minimum_compactable_history_tokens
from src.agent.context_estimate import estimate_request, text_tokens
from src.cli.runtime import effective_auto_compact_threshold
from src.config.config import Config
from src.llm.core.types import ChatRequest, ChatResponse, Message
from src.llm.providers.openai import OpenAIClient
from src.llm.runtime.context_budget import resolve_input_budget
from src.session.store import Store
from src.skills.registry import Skill
from tests.agent.test_token_accounting_independent_verify import make_agent, SnapshotClient
from tests.helpers.agent_fakes import FakeSignal, seed_compactable_history


def add_skill(agent, name="validator"):
    # User-only skills cannot rely on a later model load_skill to restore gates.
    agent.skills.add(Skill(
        name=name, description="Synthetic validation contract", tools=["http", "workflow"],
        disable_model_invocation=True, path=f"/synthetic/{name}/SKILL.md",
        body="Require reproducible evidence. Stop after confirmation.\n" + "proof gate\n" * 2000,
        stage="validation",
    ))


def test_history_system_instructions_have_exact_fixed_and_compactable_breakdown():
    prompt = Message("system", "fixed prompt")
    skill = Message("system", "full skill")
    old = Message("user", "old conversation")
    guidance = Message("system", "pending planner guidance")
    incoming = Message("user", "pending input")
    req = ChatRequest(model="fixture", messages=[prompt, skill, old, guidance, incoming])
    estimate = estimate_request(req, history_count=3, incoming_index=4)
    assert estimate.system_tokens == text_tokens(prompt.content) + text_tokens(guidance.content)
    assert estimate.history_tokens == text_tokens(skill.content) + text_tokens(old.content)
    assert estimate.incoming_tokens == text_tokens(incoming.content)
    assert estimate.compactable_history_tokens == sum(
        text_tokens(message.content) + 4 for message in [skill, old]
    )
    assert estimate.fixed_floor_tokens == sum(
        text_tokens(message.content) + 4 for message in [prompt, guidance, incoming]
    )


async def test_inject_skill_adds_compactable_history_without_inflating_fixed_floor():
    agent = make_agent()
    add_skill(agent)
    agent.rebuild_system_prompt()
    before = agent.idle_request_estimate()
    await agent.inject_skill("validator")
    skill = agent.history[-1]
    after = agent.idle_request_estimate()
    assert skill.role == "system"
    assert agent.pending_skills == {"validator"}
    assert after.system_tokens == before.system_tokens
    assert after.history_tokens == before.history_tokens + text_tokens(skill.content)
    assert before.compactable_history_tokens == 0
    assert after.compactable_history_tokens == text_tokens(skill.content) + 4
    assert after.fixed_floor_tokens == before.fixed_floor_tokens


async def test_initial_system_prompt_alone_has_nothing_to_compact():
    agent = make_agent()
    before_history = deepcopy(agent.history)
    assert await agent.compact_in_place(FakeSignal()) is False
    events = []
    await agent.compact(FakeSignal(), events.append)
    assert agent.history == before_history
    assert not cast(SnapshotClient, agent.client).requests
    assert any(event.get("summary") == "nothing to compact" for event in events)


@pytest.mark.parametrize("manual", [False, True])
async def test_skill_only_history_can_be_compacted(manual):
    client = SnapshotClient([ChatResponse(Message("assistant", "## Open todos\n- Continue validation."), "stop")])
    agent = make_agent(client=client)
    add_skill(agent)
    agent.rebuild_system_prompt()
    await agent.inject_skill("validator")
    skill = deepcopy(agent.history[-1])
    if manual:
        events = []
        await agent.compact(FakeSignal(), events.append)
        assert not [event for event in events if event["type"] == "error"]
    else:
        assert await agent.compact_in_place(FakeSignal()) is True
    assert len(client.requests) == 1
    assert "proof gate" in client.requests[0].messages[1].content
    assert skill not in agent.history
    # Existing fallback supplies a continuation turn when no recent user turn exists.
    assert [message.role for message in agent.history] == ["system", "user"]
    assert "Continue from carried session state." in agent.history[-1].content
    assert agent.pending_skills == {"validator"}


@pytest.mark.parametrize("manual", [False, True])
@pytest.mark.parametrize("summary", ["## Open todos\n- Continue validation.", "Short derived summary."])
async def test_compaction_summarizes_skill_and_other_history_system_messages(tmp_path, manual, summary):
    client = SnapshotClient([ChatResponse(Message("assistant", summary), "stop")])
    agent = make_agent(client=client, store=Store.new_with_id(tmp_path / "sessions", "skill-policy"))
    add_skill(agent)
    agent.rebuild_system_prompt()
    seed_compactable_history(agent, size=24000)
    await agent.inject_skill("validator")
    agent.history.append(Message("system", "Extra fixed security instructions."))
    original_instructions = deepcopy(agent.history[-2:])
    agent.history.extend([Message("user", "Recent question"), Message("assistant", "Recent answer")])
    agent.active_skills.add("validator")
    if manual:
        events = []
        await agent.compact(FakeSignal(), events.append)
        assert not [event for event in events if event["type"] == "error"]
    else:
        assert await agent.compact_in_place(FakeSignal()) is True
    assert [message for message in agent.history if message.role == "system"] == [agent.history[0]]
    assert all(instruction not in agent.history for instruction in original_instructions)
    assert agent.pending_skills == agent.active_skills == {"validator"}
    assert agent.history[-2:] == [Message("user", "Recent question"), Message("assistant", "Recent answer")]
    assert len(client.requests) == 1
    summary_input = client.requests[0].messages[1].content
    assert "Recent question" in summary_input
    assert "proof gate" in summary_input
    assert "Extra fixed security instructions" in summary_input
    # Persist the compacted history, without restoring discarded instructions.
    assert agent.store is not None
    loaded = agent.store.load()
    assert [message.role for message in loaded.messages].count("system") == 1
    assert all(instruction not in loaded.messages for instruction in original_instructions)
    assert loaded.messages[-2:] == agent.history[-2:]


def test_no_skill_breakdown_and_eligibility_stay_unchanged():
    messages = [Message("system", "fixed"), Message("user", "question"), Message("assistant", "answer")]
    estimate = estimate_request(ChatRequest(model="fixture", messages=messages))
    assert estimate.system_tokens == text_tokens("fixed")
    assert estimate.history_tokens == text_tokens("question") + text_tokens("answer")
    assert estimate.compactable_history_tokens == estimate.history_tokens + 8
    assert estimate.fixed_floor_tokens == text_tokens("fixed") + 4


@pytest.mark.parametrize("provider,model,expected", [
    ("kimi", "moonshot-v1-8k", 4300),
    ("kimi", "moonshot-v1-32k", 21810),
    ("kimi", "moonshot-v1-128k", 32000),
    ("kimi", "kimi-k2.6", 32000),
    ("kimi", "unknown", 16000),
    ("openai-compat", "kimi-k2.6", 16000),
    ("openai", "unknown", 16000),
    ("gemini", "unknown", 16000),
    ("deepseek", "unknown", 16000),
    ("anthropic", "unknown", 16000),
    ("groq", "kimi-k2.6", 5500),
])
def test_default_threshold_uses_known_input_capacity_only(provider, model, expected):
    cfg = Config(backend=provider, model=model)
    client = OpenAIClient("https://fixture.invalid", "", model, provider)
    assert effective_auto_compact_threshold(cfg, client) == expected
    assert effective_auto_compact_threshold(cfg) == expected
    budget = resolve_input_budget(client)
    if budget.input_limit is not None:
        assert expected < budget.input_limit
        if expected == 32000:
            assert expected + minimum_compactable_history_tokens(expected) <= budget.input_limit


@pytest.mark.parametrize("limit,expected", [(5000, 3750), (32000, 24000), (43000, 32000), (100000, 32000)])
def test_explicit_input_budget_and_custom_display_names(limit, expected):
    cfg = Config(backend="openai-compat", model="unknown")
    client = OpenAIClient("https://fixture.invalid", "", "unknown", "custom Kimi",
                          gen_opts={"input_token_limit": limit})
    assert effective_auto_compact_threshold(cfg, client) == expected
    assert resolve_input_budget(client).source == "explicit-input"


def test_live_output_reservation_overrides_config_and_default_follows_client_switch():
    cfg = Config(backend="kimi", model="moonshot-v1-32k")
    client = OpenAIClient("https://fixture.invalid", "", cfg.model, "kimi", gen_opts={"max_tokens": 16000})
    budget = resolve_input_budget(client)
    assert budget.input_limit is not None
    assert budget.reserved_output_tokens == 16000
    assert effective_auto_compact_threshold(cfg, client) == budget.input_limit * 3 // 4
    assert effective_auto_compact_threshold(cfg, client) < effective_auto_compact_threshold(cfg)
    agent = make_agent(client=client)
    agent.set_client(OpenAIClient("https://fixture.invalid", "", "kimi-k2.6", "kimi"))
    assert effective_auto_compact_threshold(cfg, agent.client) == 32000
    agent.set_client(client)
    assert effective_auto_compact_threshold(cfg, agent.client) == budget.input_limit * 3 // 4


@pytest.mark.parametrize("threshold", [0, 7000, 32000, 100000])
def test_manual_threshold_override_survives_known_small_budget(threshold):
    cfg = Config(backend="kimi", model="moonshot-v1-8k", auto_compact_threshold=threshold)
    client = OpenAIClient("https://fixture.invalid", "", cfg.model, "kimi")
    assert effective_auto_compact_threshold(cfg, client) == threshold
    agent = make_agent(client=client)
    agent.set_auto_compact_threshold(threshold)
    hard = agent.input_budget().input_limit
    assert hard is not None
    assert agent._reduction_threshold() == (min(threshold, hard) if threshold > 0 else hard)


async def test_21k_fixed_floor_has_no_pressure_warning_with_verified_32k_policy(monkeypatch):
    agent = make_agent()
    setattr(agent.client, "input_token_limit", 100000)
    monkeypatch.setattr("src.agent.agent.build_system_prompt", lambda *args, **kwargs: "f" * (21000 * 4))
    agent.rebuild_system_prompt()
    agent.history = [Message("system", agent.sys_prompt)]
    agent.set_auto_compact_threshold(effective_auto_compact_threshold(Config(), agent.client))
    assert agent.idle_request_estimate().fixed_floor_tokens == 21004
    events = []
    await agent.run("next", FakeSignal(), events.append, AgentRunOptions(tools=False))
    assert not any(event["type"] == "compact" or "context pressure" in event.get("summary", "") for event in events)
    assert len(cast(SnapshotClient, agent.client).requests) == 1


@pytest.mark.parametrize("threshold", [32000, 100000])
@pytest.mark.parametrize("history_role", ["user", "system"])
async def test_known_capacity_can_compact_below_economic_history_gate(monkeypatch, threshold, history_role):
    agent = make_agent()
    agent.history.extend([Message(history_role, "older" * 200), Message("assistant", "old answer")])
    context = agent._snapshot_context("pending", ChatRequest(model=agent.client.model(), messages=[]))
    projection = agent._projected_estimate(agent.history, agent.memory, context)
    limit = projection.estimated_total - 10
    setattr(agent.client, "input_token_limit", limit)
    agent.set_auto_compact_threshold(threshold)
    assert 0 < projection.compactable_history_tokens < minimum_compactable_history_tokens(threshold)
    assert projection.fixed_floor_tokens < limit < threshold
    attempts = []
    async def compact(signal):
        attempts.append(True)
        # Local fake contraction; the real compactor's safety/acceptance is
        # covered separately. No model call is involved here.
        agent.history = agent.history[:1]
        return True
    monkeypatch.setattr(agent, "compact_in_place", compact)
    events = []
    await agent.run("pending", FakeSignal(), events.append, AgentRunOptions(tools=False))
    assert attempts == [True]
    request = cast(SnapshotClient, agent.client).requests[0]
    assert estimate_request(request).estimated_total <= limit
    assert events[-1].stop_reason != "context_capacity"
    trigger = next(event["summary"] for event in events if event["type"] == "compact")
    assert f"hard input budget {limit}" in trigger
    assert f">= threshold {threshold}" not in trigger


@pytest.mark.parametrize("history_chars,expected_attempts", [(40000, []), (48000, [True])])
async def test_32k_soft_policy_still_requires_economic_history(monkeypatch, history_chars, expected_attempts):
    agent = make_agent()
    setattr(agent.client, "input_token_limit", 100000)
    monkeypatch.setattr("src.agent.agent.build_system_prompt", lambda *args, **kwargs: "f" * (24000 * 4))
    agent.rebuild_system_prompt()
    agent.history = [Message("system", agent.sys_prompt), Message("user", "h" * history_chars)]
    agent.set_auto_compact_threshold(effective_auto_compact_threshold(Config(), agent.client))
    assert agent.idle_request_estimate().estimated_total > 32000
    attempts = []
    async def compact(signal):
        attempts.append(True)
        return False
    monkeypatch.setattr(agent, "compact_in_place", compact)
    events = []
    await agent.run("next", FakeSignal(), events.append, AgentRunOptions(tools=False))
    assert attempts == expected_attempts


async def test_failed_capacity_compaction_preserves_history_and_still_refuses_overflow(monkeypatch):
    agent = make_agent()
    agent.history.extend([Message("user", "older" * 200), Message("assistant", "old answer")])
    previous = deepcopy(agent.history)
    setattr(agent.client, "input_token_limit", agent.approx_tokens() - 10)
    agent.set_auto_compact_threshold(32000)
    attempts = []
    async def compact(signal):
        attempts.append(True)
        raise RuntimeError("Synthetic summary failure")
    monkeypatch.setattr(agent, "compact_in_place", compact)
    events = []
    await agent.run("pending", FakeSignal(), events.append, AgentRunOptions(tools=False))
    assert attempts == [True]
    assert agent.consecutive_compact_failures == 1
    assert agent.history[:-1] == previous
    assert not cast(SnapshotClient, agent.client).requests
    assert events[-1].stop_reason == "context_capacity"
