import logging
from types import SimpleNamespace

import pytest
import asyncio
import json
import re
import shutil
import tempfile
import shutil
import tempfile
import asyncio
from copy import deepcopy
from pathlib import Path
from typing import Any
from src.tools.types import Tool
from src.memory.store import MemoryStore
from src.agent.agent import (
    Agent,
    AgentOptions,
    AgentRunOptions,
    ParsedToolCall,
    make_safe_emit,
    reconcile_tool_calls,
    elide_persisted_workflow_results,
    WORKFLOW_HISTORY_MARKER,
    COMPACTION_RECENT_MESSAGE_CHAR_LIMIT,
    MIDTURN_ELISION_PREFIX,
    MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR,
    MIDTURN_MIN_SAFETY_TOKENS,
    approximate_message_tokens,
    bound_recent_tool_result,
    IneffectiveCompactionError,
    MaxStepsError,
    minimum_compactable_history_tokens,
)
from src.agent.system_prompt import PromptProfile
from src.coverage.store import CoverageEntry, CoverageStore
from src.findings.store import Store as FindingsStore
from src.intelligence.store import IntelligenceStore
from src.llm.client import Client
from src.llm.types import (
    ChatRequest,
    ChatResponse,
    Message,
    ToolCall,
    FunctionCall,
)
from src.permission.permission import AlwaysAllow, AlwaysDeny, Decision
from src.skills.registry import Registry as SkillRegistry, Skill, SkillTriggers
from src.target.target import Target
from src.tools.registry import Registry as ToolRegistry
from src.tools.http import HTTPTool
from src.tools.coverage import CoverageTool
from src.tools.finding import ConfirmFindingTool
from src.tools.workflow import WorkflowTool
from src.workflow.state import Candidate, ValidationResult, WorkflowState

from src.session.store import Store, new_id


def test_elides_successful_prior_workflow_results_but_preserves_errors():
    messages = [
        Message(
            role="tool",
            name="workflow",
            tool_call_id="ok",
            content=json.dumps({"ok": True, "candidate": {"id": "cand_1"}}),
        ),
        Message(
            role="tool",
            name="workflow",
            tool_call_id="error",
            content="error: unknown candidate",
        ),
        Message(
            role="tool",
            name="http",
            tool_call_id="http",
            content=json.dumps({"ok": True, "body": "keep"}),
        ),
    ]

    elide_persisted_workflow_results(messages)

    assert messages[0].content == WORKFLOW_HISTORY_MARKER
    assert messages[1].content == "error: unknown candidate"
    assert '"body": "keep"' in messages[2].content


@pytest.mark.asyncio
async def test_workflow_state_survives_compaction_and_resume(tmp_path):
    session_id = new_id()
    summary = "## Current objective\n- Continue validation\n## Open TODOs\n- Next candidate"
    first = Agent(
        AgentOptions(
            client=FakeClient(
                [
                    ChatResponse(
                        message=Message(role="assistant", content="first turn"),
                        finish_reason="stop",
                    ),
                    ChatResponse(
                        message=Message(role="assistant", content=summary),
                        finish_reason="stop",
                    ),
                ]
            ),
            tools=ToolRegistry(),
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=Store.new_with_id(tmp_path, session_id),
            target=Target(),
        )
    )
    done, _ = first.workflow.add_candidate(
        Candidate(candidate_class="sqli", endpoint="/done", parameter="id")
    )
    active, _ = first.workflow.add_candidate(
        Candidate(candidate_class="xss", endpoint="/search", parameter="q")
    )
    first.workflow.add_validation_result(
        ValidationResult(done.id, "sql-injection", "not-confirmed")
    )
    seed_compactable_history(first)

    collector = collect()
    await first.run("start", FakeSignal(), collector["sink"])
    await first.compact(FakeSignal(), collector["sink"])

    resumed = Agent(
        AgentOptions(
            client=FakeClient([]),
            tools=ToolRegistry(),
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=Store.new_with_id(tmp_path, session_id),
            target=Target(),
        )
    )
    resumed.resume_saved()

    assert set(resumed.workflow.candidates) == {done.id, active.id}
    assert resumed.workflow.latest_result(done.id) is not None
    assert resumed.workflow.relevant_candidate_classes() == frozenset(
        {"cross-site-scripting"}
    )
    prompt = resumed.get_history()[0].content
    assert active.id in prompt
    assert done.id in prompt
class FakeSignal:

    def __init__(self):
        self.aborted = False


class FakeClient(Client):

    def __init__(
        self,
        scripted: list[ChatResponse],
    ):
        self.scripted = scripted
        self.idx = 0
        self.requests: list[ChatRequest] = []

    def name(self) -> str:
        return "fake"

    def model(self) -> str:
        return "fake-model"

    async def chat(
        self,
        request: ChatRequest,
        signal=None,
    ) -> ChatResponse:

        self.requests.append(request)

        if self.idx >= len(self.scripted):
            raise Exception(
                "FakeClient: script exhausted"
            )

        response = self.scripted[self.idx]

        self.idx += 1

        return response


class EchoTool:

    def __init__(self):
        self.calls = 0

    def name(self) -> str:
        return "echo"

    def description(self) -> str:
        return "echo"

    def schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "msg": {
                    "type": "string"
                }
            }
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        signal,
        prompter,
    ) -> str:

        self.calls += 1

        return (
            f"echoed: "
            f"{str(args.get('msg', ''))}"
        )


class NamedTool:

    def __init__(self, name: str, description: str):
        self._name = name
        self._description = description

    def name(self) -> str:
        return self._name

    def description(self) -> str:
        return self._description

    def schema(self) -> dict:
        return {
            "type": "object",
            "properties": {},
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        signal,
        prompter,
    ) -> str:
        return ""


def make_agent_with_client(
    scripted: list[ChatResponse],
):

    tools = ToolRegistry()

    tool = EchoTool()

    tools.register(tool)

    client = FakeClient(scripted)

    opts = AgentOptions(
        client=client,
        tools=tools,
        skills=SkillRegistry(),
        prompter=AlwaysAllow(),
        store=None,
        target=Target(),
    )

    agent = Agent(opts)

    return {
        "agent": agent,
        "client": client,
        "tool": tool,
    }


def make_agent_with_skills(
    scripted: list[ChatResponse],
    skills: SkillRegistry,
):

    client = FakeClient(scripted)

    opts = AgentOptions(
        client=client,
        tools=ToolRegistry(),
        skills=skills,
        prompter=AlwaysAllow(),
        store=None,
        target=Target(),
    )

    agent = Agent(opts)

    return {
        "agent": agent,
        "client": client,
    }


def make_agent(
    scripted: list[ChatResponse],
):

    return make_agent_with_client(
        scripted
    )["agent"]


def seed_compactable_history(agent: Agent, size: int = 12_000) -> None:
    agent.history.extend(
        [
            Message(role="user", content="older request " + "x" * size),
            Message(role="assistant", content="older answer " + "y" * size),
        ]
    )


def test_approx_tokens_counts_reasoning_content_without_changing_other_accounting():
    agent = make_agent([])
    agent.history = [
        Message(role="system", content="abcd"),
        Message(
            role="assistant",
            content="",
            reasoning_content="abcdefgh",
            tool_calls=[
                ToolCall(
                    id="call_1",
                    function=FunctionCall(name="abcd", arguments="efgh"),
                )
            ],
        ),
    ]

    # System content (1), private provider state (2), and tool metadata (2).
    assert agent.approx_tokens() == 5

    agent.history[1].reasoning_content = None

    # Content and tool-call accounting retain their previous behavior.
    assert agent.approx_tokens() == 3


def test_context_guard_accounts_for_reasoning_without_eliding_assistant_state():
    agent = make_agent([])
    agent.set_auto_compact_threshold(300)
    reasoning = "r" * 1000
    working = [
        Message(role="assistant", content="", reasoning_content=reasoning),
        *[
            Message(role="tool", content="x" * 100, tool_call_id=f"call_{i}")
            for i in range(5)
        ],
    ]
    events = []

    agent.guard_working_context(working, events.append, AgentRunOptions(tools=False))

    assert working[0].reasoning_content == reasoning
    assert working[1].content.startswith("[tool output elided mid-turn to fit context")
    assert any("context guard" in event["summary"] for event in events)


def collect():

    events = []

    def sink(event):

        events.append(event)

    return {
        "events": events,
        "sink": sink,
    }


def test_tools_token_estimate_cache_key_tracks_tool_names_not_only_count():

    tools = ToolRegistry()
    tools.register(
        NamedTool(
            "a",
            "x",
        )
    )

    agent = Agent(
        AgentOptions(
            client=FakeClient([]),
            tools=tools,
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
        )
    )

    first = agent.tools_token_estimate()

    agent.tools.tools.clear()
    agent.tools.register(
        NamedTool(
            "very_long_replacement_tool_name",
            "y" * 1000,
        )
    )

    second = agent.tools_token_estimate()

    assert second != first
    assert second > first


@pytest.mark.asyncio
async def test_run_completes_turn_with_single_assistant_text_response():

    agent = make_agent(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="hello there",
                ),
                finish_reason="stop",
            )
        ]
    )

    collector = collect()

    await agent.run(
        "hi",
        FakeSignal(),
        collector["sink"],
    )

    texts = [
        event
        for event in collector["events"]
        if event["type"] == "assistant-text"
    ]

    assert len(texts) == 1

    assert (
        collector["events"][-1]["type"]
        == "done"
    )


@pytest.mark.asyncio
async def test_does_not_execute_returned_tool_calls_when_tools_are_disabled():

    result = make_agent_with_client(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_1",
                            type="function",
                            function=FunctionCall(
                                name="echo",
                                arguments='{"msg":"blocked"}',
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            )
        ]
    )

    agent = result["agent"]
    tool = result["tool"]

    collector = collect()

    await agent.run(
        "make a plan",
        FakeSignal(),
        collector["sink"],
        {
            "tools": False
        },
    )

    assert tool.calls == 0

    assert any(
        event["type"] == "error"
        and "plan-only mode blocked tool calls"
        in str(event["err"])
        for event in collector["events"]
    )


@pytest.mark.asyncio
async def test_injects_decision_guidance_before_user_message_for_normal_turn():

    skills = SkillRegistry()

    skills.add(
        Skill(
            name="recon",
            description="External recon playbook for subdomain enumeration",
            tools=[],
            disable_model_invocation=False,
            path="/tmp/recon/SKILL.md",
            body="",
            stage="reconnaissance",
            triggers=SkillTriggers(strong=["enumerate subdomains"]),
        )
    )

    result = make_agent_with_skills(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="ok",
                ),
                finish_reason="stop",
            )
        ],
        skills,
    )

    agent = result["agent"]
    client = result["client"]

    collector = collect()

    await agent.run(
        "enumerate subdomains for example.com",
        FakeSignal(),
        collector["sink"],
    )

    decision = next(
        event for event in collector["events"] if event["type"] == "decision"
    )
    assert decision["summary"] == (
        "Planner · recon · risk: normal\n"
        "matched: enumerate subdomains"
    )
    assert "decision planner:" not in decision["summary"]
    assert "selected skill:" not in decision["summary"]

    messages = client.requests[0].messages

    assert messages[-3].role == "system"

    assert (
        "Decision planner guidance"
        in messages[-3].content
    )

    assert messages[-2].role == "user"

    assert (
        messages[-2].content
        == "enumerate subdomains for example.com"
    )

@pytest.mark.asyncio
async def test_injects_local_intelligence_guidance_for_sqli_context():

    tmp = tempfile.mkdtemp(
        prefix="pf-agent-intel-"
    )

    try:

        client = FakeClient(
            [
                ChatResponse(
                    message=Message(
                        role="assistant",
                        content="ok",
                    ),
                    finish_reason="stop",
                )
            ]
        )

        opts = AgentOptions(
            client=client,
            tools=ToolRegistry(),
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
            intelligence=IntelligenceStore(
                cwd=Path(tmp) / "project",
                home=Path(tmp) / "home",
            ),
        )

        agent = Agent(opts)

        collector = collect()

        await agent.run(
            "test the login endpoint for SQL injection using user input parameter",
            FakeSignal(),
            collector["sink"],
            AgentRunOptions(
                tools=False
            ),
        )

        messages = client.requests[0].messages

        assert any(
            "Local KAgent Intelligence"
            in msg.content
            for msg in messages
        )

        assert any(
            "sqlmap verification"
            in msg.content
            for msg in messages
        )

    finally:

        shutil.rmtree(
            tmp,
            ignore_errors=True,
        )

@pytest.mark.asyncio
async def test_learns_continuous_memory_from_substantive_tool_using_turns():

    tmp = tempfile.mkdtemp(
        prefix="pf-agent-learn-"
    )

    try:

        tools = ToolRegistry()

        tool = EchoTool()

        tools.register(tool)

        client = FakeClient(
            [
                ChatResponse(
                    message=Message(
                        role="assistant",
                        content="",
                        tool_calls=[
                            ToolCall(
                                id="call_1",
                                type="function",
                                function=FunctionCall(
                                    name="echo",
                                    arguments='{"msg":"check"}',
                                ),
                            )
                        ],
                    ),
                    finish_reason="tool_calls",
                ),
                ChatResponse(
                    message=Message(
                        role="assistant",
                        content="noted",
                    ),
                    finish_reason="stop",
                ),
            ]
        )

        intelligence = IntelligenceStore(
            cwd=Path(tmp) / "project",
            home=Path(tmp) / "home",
        )

        agent = Agent(
            AgentOptions(
                client=client,
                tools=tools,
                skills=SkillRegistry(),
                prompter=AlwaysAllow(),
                store=None,
                target=Target(),
                intelligence=intelligence,
            )
        )

        collector = collect()

        await agent.run(
            "I prefer short final answers with clear explanations.",
            FakeSignal(),
            collector["sink"],
        )
        category = None

        # End-of-turn learning chạy background nên polling
        for _ in range(100):

            result = intelligence.search(
                "short final answers clear explanations",
                limit=3,
            )

            if result:
                category = result[0]["scenario"].category
                break

            await asyncio.sleep(0.01)

        assert category == "user-preference"

    finally:

        shutil.rmtree(
            tmp,
            ignore_errors=True,
        )

@pytest.mark.asyncio
async def test_does_not_learn_from_turn_with_no_tool_calls():

    tmp = tempfile.mkdtemp(
        prefix="pf-agent-nolearn-"
    )

    try:

        intelligence = IntelligenceStore(
            cwd=Path(tmp) / "project",
            home=Path(tmp) / "home",
        )

        agent = Agent(
            AgentOptions(
                client=FakeClient(
                    [
                        ChatResponse(
                            message=Message(
                                role="assistant",
                                content="noted",
                            ),
                            finish_reason="stop",
                        )
                    ]
                ),
                tools=ToolRegistry(),
                skills=SkillRegistry(),
                prompter=AlwaysAllow(),
                store=None,
                target=Target(),
                intelligence=intelligence,
            )
        )

        collector = collect()

        await agent.run(
            "I prefer short final answers with clear explanations.",
            FakeSignal(),
            collector["sink"],
            AgentRunOptions(
                tools=False
            ),
        )

        # Cho background learning (nếu lỡ bị gọi) có thời gian chạy
        await asyncio.sleep(0.05)

        result = intelligence.search(
            "short final answers clear explanations",
            limit=3,
        )

        assert len(result) == 0

    finally:

        shutil.rmtree(
            tmp,
            ignore_errors=True,
        )

@pytest.mark.asyncio
async def test_skips_decision_guidance_for_plan_only_turns():

    skills = SkillRegistry()

    skills.add(
        Skill(
            name="recon",
            description="External recon playbook for subdomain enumeration",
            tools=[],
            disable_model_invocation=False,
            path="/tmp/recon/SKILL.md",
            body="",
        )
    )

    result = make_agent_with_skills(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="plan",
                ),
                finish_reason="stop",
            )
        ],
        skills,
    )

    agent = result["agent"]
    client = result["client"]

    collector = collect()

    await agent.run(
        "plan recon for example.com",
        FakeSignal(),
        collector["sink"],
        AgentRunOptions(
            tools=False
        ),
    )

    # Không emit decision event
    assert not any(
        event["type"] == "decision"
        for event in collector["events"]
    )

    # Không inject Decision planner guidance vào prompt
    messages = client.requests[0].messages

    assert not any(
        "Decision planner"
        in msg.content
        for msg in messages
    )

@pytest.mark.asyncio
async def test_surfaces_tool_failure_as_tool_result_with_err_set():

    agent = make_agent(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_x",
                            type="function",
                            function=FunctionCall(
                                name="nonexistent",
                                arguments="{}",
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="oh well",
                ),
                finish_reason="stop",
            ),
        ]
    )

    collector = collect()

    await agent.run(
        "go",
        FakeSignal(),
        collector["sink"],
    )

    result = next(
        (
            event
            for event in collector["events"]
            if event["type"] == "tool-result"
        ),
        None,
    )

    assert result is not None

    assert "unknown tool" in str(
        result.get("err", "")
    )

@pytest.mark.asyncio
async def test_auto_compacts_before_next_turn_when_over_threshold():

    compact_summary = ChatResponse(
        message=Message(
            role="assistant",
            content="## Current objective\n- Continue the current test",
        ),
        finish_reason="stop",
    )

    user_turn = ChatResponse(
        message=Message(
            role="assistant",
            content="answer",
        ),
        finish_reason="stop",
    )

    tools = ToolRegistry()
    tools.register(EchoTool())

    agent = Agent(
        AgentOptions(
            client=FakeClient(
                [
                    compact_summary,
                    user_turn,
                ]
            ),
            tools=tools,
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
            auto_compact_threshold=1,   # gần như luôn trigger
        )
    )

    agent.history.append(
        Message(
            role="user",
            content="previous useful turn " + "x" * 12_000,
        )
    )
    agent.history.append(
        Message(
            role="assistant",
            content="previous useful answer " + "y" * 12_000,
        )
    )

    collector = collect()

    await agent.run(
        "hi",
        FakeSignal(),
        collector["sink"],
    )

    compact_events = [
        e
        for e in collector["events"]
        if e["type"] == "compact"
    ]

    # Có ít nhất 2 event:
    # 1. triggered
    # 2. auto-compacted
    assert len(compact_events) >= 2

    triggered_summary = compact_events[0]["summary"]
    history_tokens = compact_events[0]["tokensBefore"]
    input_tokens = len("hi") // 4
    tools_tokens = agent.tools_token_estimate()
    trigger_tokens = history_tokens + input_tokens + tools_tokens

    assert f"~{trigger_tokens} tokens >= threshold 1" in triggered_summary
    assert (
        f"history: {history_tokens} + input: {input_tokens} + "
        f"tools: {tools_tokens}"
    ) in triggered_summary

    assert "auto-compacted" in compact_events[-1]["summary"]


async def run_auto_compact_trigger_probe(
    monkeypatch,
    *,
    threshold: int,
    history_chars: int,
    tool_description_chars: int = 0,
    tools_enabled: bool = True,
    prompt_profile: PromptProfile = "compact",
) -> tuple[int, int, int, int, int]:
    tools = ToolRegistry()
    if tool_description_chars:
        tools.register(NamedTool("large-schema", "s" * tool_description_chars))
    client = FakeClient(
        [
            ChatResponse(
                message=Message(role="assistant", content="answer"),
                finish_reason="stop",
            )
        ]
    )
    agent = Agent(
        AgentOptions(
            client=client,
            tools=tools,
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
            auto_compact_threshold=threshold,
            prompt_profile=prompt_profile,
        )
    )
    agent.history.append(Message(role="user", content="h" * history_chars))
    attempts = 0

    async def compact_probe(signal) -> bool:
        nonlocal attempts
        attempts += 1
        return True

    monkeypatch.setattr(agent, "compact_in_place", compact_probe)
    history_tokens = agent.approx_tokens()
    compactable_history_tokens = sum(
        len(message.content) // 4 for message in agent.history[1:]
    )
    tools_tokens = agent.tools_token_estimate() if tools_enabled else 0
    await agent.run(
        "next",
        FakeSignal(),
        collect()["sink"],
        AgentRunOptions(tools=tools_enabled),
    )
    return (
        attempts,
        history_tokens,
        compactable_history_tokens,
        tools_tokens,
        len("next") // 4,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "threshold",
        "history_chars",
        "tool_description_chars",
        "tools_enabled",
        "prompt_profile",
        "expected_attempts",
    ),
    [
        # Groq-style: schema overhead pushes modest history over 5,500.
        (5_500, 7_000, 19_000, True, "compact", 0),
        # A larger compactable history should trigger at the same threshold.
        (5_500, 14_000, 19_000, True, "compact", 1),
        # Large history triggers even with no tool schemas.
        (5_500, 20_000, 0, True, "compact", 1),
        # At 16,000, fixed full prompt plus schemas cannot trigger modest history.
        (16_000, 16_000, 19_000, True, "full", 0),
        # The default threshold triggers once full-prompt history is genuinely large.
        (16_000, 24_000, 19_000, True, "full", 1),
        # A Kimi 8k-derived threshold still measures conversation, not full prompt.
        (6_144, 7_000, 19_000, True, "full", 0),
        # Disabling tools removes their schema cost from the trigger calculation.
        (5_500, 7_000, 19_000, False, "compact", 0),
    ],
)
async def test_characterizes_auto_compact_trigger_components(
    monkeypatch,
    threshold,
    history_chars,
    tool_description_chars,
    tools_enabled,
    prompt_profile,
    expected_attempts,
):
    (
        attempts,
        history_tokens,
        compactable_history_tokens,
        tools_tokens,
        incoming_tokens,
    ) = (
        await run_auto_compact_trigger_probe(
            monkeypatch,
            threshold=threshold,
            history_chars=history_chars,
            tool_description_chars=tool_description_chars,
            tools_enabled=tools_enabled,
            prompt_profile=prompt_profile,
        )
    )

    assert attempts == expected_attempts
    trigger_tokens = history_tokens + tools_tokens + incoming_tokens
    if expected_attempts:
        assert trigger_tokens >= threshold
        assert compactable_history_tokens >= minimum_compactable_history_tokens(
            threshold
        )
    else:
        assert (
            trigger_tokens < threshold
            or compactable_history_tokens
            < minimum_compactable_history_tokens(threshold)
        )


@pytest.mark.asyncio
async def test_ineffective_auto_compaction_counts_as_a_circuit_breaker_failure():
    agent = make_agent(
        [
            ChatResponse(
                message=Message(role="assistant", content="z" * 20_000),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(role="assistant", content="answer"),
                finish_reason="stop",
            ),
        ]
    )
    agent.set_auto_compact_threshold(1)
    agent.history.append(Message(role="user", content="h" * 12_000))
    collector = collect()

    await agent.run("next", FakeSignal(), collector["sink"])

    assert agent.consecutive_compact_failures == 1
    assert any(
        event["type"] == "error"
        and "would not shrink meaningfully" in str(event["err"])
        for event in collector["events"]
    )


@pytest.mark.asyncio
async def test_auto_compact_skip_does_not_emit_success_when_history_is_empty():

    agent = make_agent([])

    skipped = await agent.compact_in_place(
        FakeSignal()
    )

    assert skipped is False

    collector = collect()

    await agent.auto_compact(
        FakeSignal(),
        collector["sink"],
        trigger_tokens=1,
        history_tokens=agent.approx_tokens(),
        incoming_tokens=0,
        tools_tokens=0,
    )

    compact_events = [
        e
        for e in collector["events"]
        if e["type"] == "compact"
    ]

    assert len(compact_events) == 2
    assert "auto-compact triggered" in compact_events[0]["summary"]
    assert compact_events[1]["summary"] == "auto-compact skipped: nothing to compact"
    assert not any(
        "auto-compacted" in e["summary"]
        for e in compact_events
    )
    assert agent.consecutive_compact_failures == 0


@pytest.mark.asyncio
async def test_compaction_rejects_larger_summary_without_mutating_history():
    agent = make_agent(
        [
            ChatResponse(
                message=Message(role="assistant", content="z" * 20_000),
                finish_reason="stop",
            )
        ]
    )
    agent.history.extend(
        [
            Message(role="user", content="short request"),
            Message(
                role="tool",
                name="workflow",
                tool_call_id="workflow-1",
                content='{"ok": true, "candidate": {"id": "cand_keep"}}',
            ),
            Message(role="assistant", content="short answer"),
        ]
    )
    before = agent.get_history()

    with pytest.raises(IneffectiveCompactionError, match="would not shrink"):
        await agent.compact_in_place(FakeSignal())

    assert agent.get_history() == before
    assert agent.memory is None


@pytest.mark.asyncio
async def test_compaction_preserves_latest_useful_turn_after_reducing_history():
    summary = "## Current objective\n- Continue SQL injection validation"
    agent = make_agent(
        [
            ChatResponse(
                message=Message(role="assistant", content=summary),
                finish_reason="stop",
            )
        ]
    )
    seed_compactable_history(agent)
    agent.history.extend(
        [
            Message(role="user", content="keep this recent request"),
            Message(role="assistant", content="keep this recent answer"),
        ]
    )
    before = agent.approx_tokens()

    assert await agent.compact_in_place(FakeSignal()) is True

    assert agent.approx_tokens() < before
    assert any(message.content == "keep this recent request" for message in agent.history)
    assert any(message.content == "keep this recent answer" for message in agent.history)


@pytest.mark.asyncio
async def test_compaction_bounds_oversized_recent_message_and_preserves_its_edges():
    summary = "## Current objective\n- Continue validation"
    agent = make_agent(
        [
            ChatResponse(
                message=Message(role="assistant", content=summary),
                finish_reason="stop",
            )
        ]
    )
    seed_compactable_history(agent)
    recent = "RECENT-START " + "r" * 8_000 + " RECENT-END"
    agent.history.append(Message(role="user", content=recent))

    assert await agent.compact_in_place(FakeSignal()) is True

    preserved = next(message for message in agent.history if message.role == "user")
    assert len(preserved.content) <= COMPACTION_RECENT_MESSAGE_CHAR_LIMIT
    assert "characters summarized during compaction" in preserved.content
    assert preserved.content.startswith("RECENT-START")
    assert preserved.content.endswith("RECENT-END")


@pytest.mark.asyncio
async def test_compaction_does_not_duplicate_authoritative_workflow_candidate():
    agent = make_agent([])
    candidate, _ = agent.workflow.add_candidate(
        Candidate(
            candidate_class="sqli",
            target="https://target.test",
            endpoint="/product",
            parameter="id",
            status="queued",
        )
    )
    agent.client = FakeClient(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=(
                        "## Current objective\n- Continue validation\n"
                        f"## Open TODOs\n- Candidate {candidate.id} remains queued"
                    ),
                ),
                finish_reason="stop",
            )
        ]
    )
    seed_compactable_history(agent)

    assert await agent.compact_in_place(FakeSignal()) is True

    assert candidate.id not in agent.format_memory()
    assert agent.get_history()[0].content.count(candidate.id) == 1

@pytest.mark.asyncio
async def test_stores_structured_memory_after_manual_compaction():

    summary = "\n".join(
        [
            "## Current objective",
            "- Test horizontal authorization on orders API",
            "## Tested surface",
            "- Replayed GET /api/orders/100 as USER_B and received 403",
            "## Findings and evidence",
            "- Confirmed IDOR on GET /api/invoices/200 with USER_A token",
            "## Files and commands",
            "- `curl https://app.example.com/api/invoices/200`",
            "- findings/invoice-idor.md",
            "## Credentials and placeholders",
            "- USER_A_TOKEN and USER_B_TOKEN placeholders only",
            "## Open TODOs",
            "- Retest invoice download endpoint",
        ]
    )

    result = make_agent_with_client(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="first turn",
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=summary,
                ),
                finish_reason="stop",
            ),
        ]
    )

    agent = result["agent"]
    seed_compactable_history(agent)

    collector = collect()

    await agent.run(
        "start testing authz",
        FakeSignal(),
        collector["sink"],
    )

    await agent.compact(
        FakeSignal(),
        collector["sink"],
    )

    memory = agent.format_memory()

    assert "Test horizontal authorization" in memory
    assert "Confirmed IDOR" in memory
    assert "USER_A_TOKEN" in memory

    stats = agent.get_memory_stats()

    assert stats["items"] > 0

@pytest.mark.asyncio
async def test_parses_plan_and_completed_tasks_headings_into_structured_memory():

    summary = "\n".join(
        [
            "## Current objective",
            "- Test authz on orders API",
            "## Plan",
            "- Map endpoints, then probe IDOR, then privilege escalation",
            "## Completed tasks",
            "- Enumerated the orders and invoices endpoints",
            "## Open TODOs",
            "- Probe the export endpoint next",
        ]
    )

    result = make_agent_with_client(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="first turn",
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=summary,
                ),
                finish_reason="stop",
            ),
        ]
    )

    agent = result["agent"]
    seed_compactable_history(agent)

    collector = collect()

    await agent.run(
        "start",
        FakeSignal(),
        collector["sink"],
    )

    await agent.compact(
        FakeSignal(),
        collector["sink"],
    )

    memory = agent.format_memory()

    assert "Plan" in memory
    assert "Map endpoints, then probe IDOR" in memory

    assert "Completed" in memory
    assert "Enumerated the orders and invoices endpoints" in memory

@pytest.mark.asyncio
async def test_injects_carried_memory_into_system_prompt_after_compaction():

    summary = "\n".join(
        [
            "## Current objective",
            "- Test horizontal authorization on orders API",
            "## Findings and evidence",
            "- Confirmed IDOR on GET /api/invoices/200",
        ]
    )

    result = make_agent_with_client(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="first turn",
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=summary,
                ),
                finish_reason="stop",
            ),
        ]
    )

    agent = result["agent"]
    seed_compactable_history(agent)

    collector = collect()

    await agent.run(
        "start",
        FakeSignal(),
        collector["sink"],
    )

    await agent.compact(
        FakeSignal(),
        collector["sink"],
    )

    # Carried session state phải được inject vào system prompt
    history = agent.get_history()

    system_prompt = history[0].content

    assert "Carried session state" in system_prompt

    assert (
        "Confirmed IDOR on GET /api/invoices/200"
        in system_prompt
    )

@pytest.mark.asyncio
async def test_accumulates_earlier_compactions_in_system_prompt_across_second_compaction():

    first = "\n".join(
        [
            "## Findings and evidence",
            "- Finding from compaction ONE",
        ]
    )

    second = "\n".join(
        [
            "## Findings and evidence",
            "- Finding from compaction TWO",
        ]
    )

    result = make_agent_with_client(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="turn 1",
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=first,
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="turn 2",
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=second,
                ),
                finish_reason="stop",
            ),
        ]
    )

    agent = result["agent"]
    seed_compactable_history(agent)

    collector = collect()

    await agent.run(
        "first",
        FakeSignal(),
        collector["sink"],
    )

    await agent.compact(
        FakeSignal(),
        collector["sink"],
    )

    seed_compactable_history(agent)

    await agent.run(
        "second",
        FakeSignal(),
        collector["sink"],
    )

    await agent.compact(
        FakeSignal(),
        collector["sink"],
    )

    history = agent.get_history()

    system_prompt = history[0].content

    # Sau lần compact thứ hai, system prompt vẫn phải giữ
    # cả memory từ lần compact đầu và lần compact thứ hai.
    assert "Finding from compaction ONE" in system_prompt
    assert "Finding from compaction TWO" in system_prompt

@pytest.mark.asyncio
async def test_restores_carried_memory_into_system_prompt_on_resume():

    tmp = tempfile.mkdtemp(
        prefix="pf-agent-resume-"
    )

    try:

        session_id = new_id()

        summary = "\n".join(
            [
                "## Current objective",
                "- Test horizontal authorization on orders API",
                "## Findings and evidence",
                "- Confirmed IDOR on GET /api/invoices/200",
            ]
        )

        first = Agent(
            AgentOptions(
                client=FakeClient(
                    [
                        ChatResponse(
                            message=Message(
                                role="assistant",
                                content="first turn",
                            ),
                            finish_reason="stop",
                        ),
                        ChatResponse(
                            message=Message(
                                role="assistant",
                                content=summary,
                            ),
                            finish_reason="stop",
                        ),
                    ]
                ),
                tools=ToolRegistry(),
                skills=SkillRegistry(),
                prompter=AlwaysAllow(),
                store=Store.new_with_id(
                    tmp,
                    session_id,
                ),
                target=Target(),
            )
        )
        seed_compactable_history(first)

        collector = collect()

        await first.run(
            "start",
            FakeSignal(),
            collector["sink"],
        )

        await first.compact(
            FakeSignal(),
            collector["sink"],
        )

        # Giả lập process mới

        resumed = Agent(
            AgentOptions(
                client=FakeClient([]),
                tools=ToolRegistry(),
                skills=SkillRegistry(),
                prompter=AlwaysAllow(),
                store=Store.new_with_id(
                    tmp,
                    session_id,
                ),
                target=Target(),
            )
        )

        resumed.resume_saved()

        history = resumed.get_history()

        system_prompt = history[0].content

        assert "Carried session state" in system_prompt

        assert (
            "Confirmed IDOR on GET /api/invoices/200"
            in system_prompt
        )

    finally:

        shutil.rmtree(
            tmp,
            ignore_errors=True,
        )

@pytest.mark.asyncio
async def test_injects_operator_authored_engagement_notes_into_system_prompt():

    agent = Agent(
        AgentOptions(
            client=FakeClient([]),
            tools=ToolRegistry(),
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
            engagement=(
                "Out of scope: *.corp.internal\n"
                "Test account: USER_A_TOKEN"
            ),
        )
    )

    system_prompt = agent.get_history()[0].content

    assert (
        "Engagement notes (operator-authored"
        in system_prompt
    )

    assert (
        "Out of scope: *.corp.internal"
        in system_prompt
    )

@pytest.mark.asyncio
async def test_renders_staleness_caveat_above_carried_memory_block():

    summary = (
        "## Findings and evidence\n"
        "- Confirmed IDOR on /api/invoices/200"
    )

    result = make_agent_with_client(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="turn",
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=summary,
                ),
                finish_reason="stop",
            ),
        ]
    )

    agent = result["agent"]
    seed_compactable_history(agent)

    collector = collect()

    await agent.run(
        "start",
        FakeSignal(),
        collector["sink"],
    )

    await agent.compact(
        FakeSignal(),
        collector["sink"],
    )

    system_prompt = agent.get_history()[0].content

    assert "verify it still holds" in system_prompt

@pytest.mark.asyncio
async def test_clear_memory_wipes_carried_state_from_system_prompt():

    summary = (
        "## Findings and evidence\n"
        "- Confirmed IDOR on /api/invoices/200"
    )

    result = make_agent_with_client(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="turn",
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=summary,
                ),
                finish_reason="stop",
            ),
        ]
    )

    agent = result["agent"]
    seed_compactable_history(agent)

    collector = collect()

    await agent.run(
        "start",
        FakeSignal(),
        collector["sink"],
    )

    await agent.compact(
        FakeSignal(),
        collector["sink"],
    )

    system_prompt = agent.get_history()[0].content

    assert "Confirmed IDOR" in system_prompt

    await agent.clear_memory()

    system_prompt = agent.get_history()[0].content

    assert "Carried session state" not in system_prompt

    stats = agent.get_memory_stats()

    assert stats.items == 0


@pytest.mark.asyncio
async def test_reset_rebuilds_system_prompt_without_carried_memory():

    summary = (
        "## Findings and evidence\n"
        "- Confirmed IDOR on /api/invoices/200"
    )

    result = make_agent_with_client(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="turn",
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=summary,
                ),
                finish_reason="stop",
            ),
        ]
    )

    agent = result["agent"]
    seed_compactable_history(agent)
    collector = collect()

    await agent.run("start", FakeSignal(), collector["sink"])
    await agent.compact(FakeSignal(), collector["sink"])

    assert "Confirmed IDOR" in agent.get_history()[0].content

    await agent.reset()

    assert len(agent.get_history()) == 1
    assert "Carried session state" not in agent.get_history()[0].content
    assert "Confirmed IDOR" not in agent.get_history()[0].content
    assert agent.memory is None

@pytest.mark.asyncio
async def test_forget_memory_drops_only_matching_items():

    summary = "\n".join(
        [
            "## Findings and evidence",
            "- Confirmed IDOR on /api/invoices/200",
            "- XSS in the search box",
        ]
    )

    result = make_agent_with_client(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="turn",
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=summary,
                ),
                finish_reason="stop",
            ),
        ]
    )

    agent = result["agent"]
    seed_compactable_history(agent)

    collector = collect()

    await agent.run(
        "start",
        FakeSignal(),
        collector["sink"],
    )

    await agent.compact(
        FakeSignal(),
        collector["sink"],
    )

    removed = await agent.forget_memory("IDOR")

    assert len(removed) == 1

    system_prompt = agent.get_history()[0].content

    assert "Confirmed IDOR" not in system_prompt

    assert "XSS in the search box" in system_prompt

@pytest.mark.asyncio
async def test_caps_the_findings_list_so_memory_cannot_grow_unbounded():

    scripted: list[ChatResponse] = []

    total = 250

    for i in range(total):

        scripted.append(
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=f"turn {i}",
                ),
                finish_reason="stop",
            )
        )

        scripted.append(
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=(
                        "## Findings and evidence\n"
                        f"- finding number {i}"
                    ),
                ),
                finish_reason="stop",
            )
        )

    result = make_agent_with_client(scripted)

    agent = result["agent"]

    for i in range(total):

        collector = collect()
        seed_compactable_history(agent, size=5_000)

        await agent.run(
            f"turn {i}",
            FakeSignal(),
            collector["sink"],
        )

        await agent.compact(
            FakeSignal(),
            collector["sink"],
        )

    stats = agent.get_memory_stats()

    assert stats.items <= 200

    memory = agent.format_memory()

    assert f"finding number {total - 1}" in memory

@pytest.mark.asyncio
async def test_bounds_oversized_compaction_input():

    huge = "older context " + ("x" * 100_000)

    result = make_agent_with_client(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content=huge,
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="## Current objective\n- keep going",
                ),
                finish_reason="stop",
            ),
        ]
    )

    agent = result["agent"]
    client = result["client"]

    collector = collect()

    await agent.run(
        "start",
        FakeSignal(),
        collector["sink"],
    )

    await agent.compact(
        FakeSignal(),
        collector["sink"],
    )

    compact_req = client.requests[1]

    compact_text = compact_req.messages[1].content

    assert len(compact_text) < 23_000

    assert "Older conversation text was omitted" in compact_text

@pytest.mark.asyncio
async def test_circuit_breaker_stops_retrying_auto_compact_after_three_failures():

    class FlakyClient(Client):

        def __init__(self):
            self.calls = 0

        def name(self) -> str:
            return "flaky"

        def model(self) -> str:
            return "m"

        async def chat(
            self,
            request: ChatRequest,
            signal=None,
        ) -> ChatResponse:

            self.calls += 1

            raise RuntimeError("compact-fail")

    flaky = FlakyClient()

    agent = Agent(
        AgentOptions(
            client=flaky,
            tools=ToolRegistry(),
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
            auto_compact_threshold=1,
        )
    )
    agent.history.append(Message(role="user", content="h" * 12_000))

    for i in range(5):

        collector = collect()

        await agent.run(
            f"turn {i}",
            FakeSignal(),
            collector["sink"],
        )

    assert flaky.calls == 8

@pytest.mark.asyncio
async def test_emits_error_event_when_exception_escapes():

    class CrashClient(Client):

        def name(self) -> str:
            return "crash"

        def model(self) -> str:
            return "m"

        async def chat(
            self,
            request: ChatRequest,
            signal=None,
        ) -> ChatResponse:

            raise RuntimeError("boom")

    agent = Agent(
        AgentOptions(
            client=CrashClient(),
            tools=ToolRegistry(),
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
        )
    )

    collector = collect()

    await agent.run(
        "x",
        FakeSignal(),
        collector["sink"],
    )

    events = collector["events"]

    assert any(
        e.type == "error"
        for e in events
    )

    assert events[-1].type == "done"

@pytest.mark.asyncio
async def test_renders_user_cancellation_without_leaking_backend_abort_text():

    class AbortClient(Client):

        def name(self) -> str:
            return "ollama"

        def model(self) -> str:
            return "m"

        async def chat(
            self,
            request: ChatRequest,
            signal: Any = None,
        ) -> ChatResponse:

            if signal is not None:
                signal.throw_if_aborted()

            raise RuntimeError(
                "ollama: The operation was aborted."
            )

    agent = Agent(
        AgentOptions(
            client=AbortClient(),
            tools=ToolRegistry(),
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
        )
    )

    signal = FakeSignal()

    signal.aborted = True

    collector = collect()

    await agent.run(
        "x",
        signal,
        collector["sink"],
    )

    events = collector["events"]

    error_event = next(
        (
            e
            for e in events
            if e.type == "error"
        ),
        None,
    )

    assert error_event is not None

    assert error_event.err.message == "turn cancelled"

    assert events[-1].type == "done"

# ==========================================================
# Allowed-tools enforcement helpers
# ==========================================================


class RestrictedShellTool(Tool):

    def name(self) -> str:
        return "shell"

    def description(self) -> str:
        return "shell"

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                },
            },
        }

    def requires_permission(self) -> bool:
        return True

    async def run(
        self,
        args: dict[str, Any],
        signal,
        prompter,
    ) -> str:
        return f"ran: {args.get('command', '')}"


class PermissionTool(Tool):
    def __init__(self, name: str):
        self._name = name

    def name(self) -> str:
        return self._name

    def description(self) -> str:
        return self._name

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {}}

    def requires_permission(self) -> bool:
        return True

    async def run(self, args, signal, prompter) -> str:
        return f"ran:{self._name}"


class FailingTool(PermissionTool):
    def requires_permission(self) -> bool:
        return False

    async def run(self, args, signal, prompter) -> str:
        raise RuntimeError("recoverable failure")


class EscPrompter:
    """The permission modal maps Esc to DENY."""

    def __init__(self):
        self.calls = 0

    async def ask(self, request, signal=None) -> Decision:
        self.calls += 1
        return Decision.DENY


class SequencePrompter:
    def __init__(self, *decisions: Decision):
        self.decisions = list(decisions)

    async def ask(self, request, signal=None) -> Decision:
        return self.decisions.pop(0)


def refusal_agent(
    scripted: list[ChatResponse],
    tools: list[Tool],
    prompter,
    *,
    store=None,
    max_steps: int = 20,
) -> tuple[Agent, FakeClient]:
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    client = FakeClient(scripted)
    return (
        Agent(
            AgentOptions(
                client=client,
                tools=registry,
                skills=SkillRegistry(),
                prompter=prompter,
                store=store,
                target=Target(),
                max_steps=max_steps,
            )
        ),
        client,
    )


def tool_batch(*calls: ToolCall) -> ChatResponse:
    return ChatResponse(
        message=Message(role="assistant", content="", tool_calls=list(calls)),
        finish_reason="tool_calls",
    )


@pytest.mark.asyncio
async def test_generic_permission_denial_ends_turn_without_synthesis():
    agent, client = refusal_agent(
        [tool_batch(tool_call("deny", "denied", {}))],
        [PermissionTool("denied")],
        AlwaysDeny(),
    )
    collector = collect()

    await agent.run("go", FakeSignal(), collector["sink"])

    assert len(client.requests) == 1
    results = [event for event in collector["events"] if event.type == "tool-result"]
    assert len(results) == 1
    assert results[0].err == "permission denied by user for denied"
    assert collector["events"][-1].type == "done"
    assert agent.get_history()[-1].role == "tool"
    assert agent.get_history()[-1].content == "ERROR: permission denied by user for denied"


@pytest.mark.asyncio
async def test_permission_escape_denial_ends_turn_without_synthesis():
    prompter = EscPrompter()
    agent, client = refusal_agent(
        [tool_batch(tool_call("esc", "denied", {}))],
        [PermissionTool("denied")],
        prompter,
    )

    await agent.run("go", FakeSignal(), collect()["sink"])

    assert prompter.calls == 1
    assert len(client.requests) == 1


@pytest.mark.asyncio
async def test_private_host_denial_ends_turn_without_synthesis():
    target = Target()
    tool = HTTPTool(target)
    client = FakeClient(
        [tool_batch(tool_call("private", "http", {"url": "http://127.0.0.1/status"}))]
    )
    agent = Agent(
        AgentOptions(
            client=client,
            tools=ToolRegistry(),
            skills=SkillRegistry(),
            prompter=SequencePrompter(Decision.ALLOW_ONCE, Decision.DENY),
            store=None,
            target=target,
        )
    )
    agent.tools.register(tool)
    collector = collect()

    await agent.run("go", FakeSignal(), collector["sink"])

    assert len(client.requests) == 1
    result = next(event for event in collector["events"] if event.type == "tool-result")
    assert "private/internal URL denied" in result.err
    assert collector["events"][-1].type == "done"


@pytest.mark.asyncio
async def test_all_refused_tool_batch_ends_turn_without_synthesis():
    agent, client = refusal_agent(
        [
            tool_batch(
                tool_call("one", "one", {}),
                tool_call("two", "two", {}),
            )
        ],
        [PermissionTool("one"), PermissionTool("two")],
        AlwaysDeny(),
    )
    collector = collect()

    await agent.run("go", FakeSignal(), collector["sink"])

    assert len(client.requests) == 1
    assert [event.name for event in collector["events"] if event.type == "tool-result"] == ["one", "two"]
    assert collector["events"][-1].type == "done"


@pytest.mark.asyncio
async def test_mixed_denial_and_success_still_synthesizes():
    agent, client = refusal_agent(
        [
            tool_batch(tool_call("deny", "denied", {}), tool_call("ok", "ok", {})),
            ChatResponse(message=Message(role="assistant", content="synthesized"), finish_reason="stop"),
        ],
        [PermissionTool("denied"), PermissionTool("ok")],
        SequencePrompter(Decision.DENY, Decision.ALLOW_ONCE),
    )

    await agent.run("go", FakeSignal(), collect()["sink"])

    assert len(client.requests) == 2
    assert agent.get_history()[-1].content == "synthesized"


@pytest.mark.asyncio
async def test_mixed_denial_and_recoverable_error_still_synthesizes():
    agent, client = refusal_agent(
        [
            tool_batch(tool_call("deny", "denied", {}), tool_call("fail", "fail", {})),
            ChatResponse(message=Message(role="assistant", content="recovered"), finish_reason="stop"),
        ],
        [PermissionTool("denied"), FailingTool("fail")],
        AlwaysDeny(),
    )

    await agent.run("go", FakeSignal(), collect()["sink"])

    assert len(client.requests) == 2
    assert agent.get_history()[-1].content == "recovered"


@pytest.mark.asyncio
async def test_next_turn_after_refusal_keeps_valid_history_and_runs_normally():
    agent, client = refusal_agent(
        [
            tool_batch(tool_call("deny", "denied", {})),
            ChatResponse(message=Message(role="assistant", content="next answer"), finish_reason="stop"),
        ],
        [PermissionTool("denied")],
        AlwaysDeny(),
    )

    await agent.run("first", FakeSignal(), collect()["sink"])
    await agent.run("second", FakeSignal(), collect()["sink"])

    assert len(client.requests) == 2
    history = agent.get_history()
    call_index = next(index for index, message in enumerate(history) if message.tool_calls)
    assert history[call_index + 1].role == "tool"
    assert history[-1].content == "next answer"


@pytest.mark.asyncio
async def test_save_resume_after_refusal_preserves_tool_pair(tmp_path):
    store = Store.new_with_id(tmp_path, "refusal-session")
    agent, client = refusal_agent(
        [tool_batch(tool_call("deny", "denied", {}))],
        [PermissionTool("denied")],
        AlwaysDeny(),
        store=store,
    )

    await agent.run("go", FakeSignal(), collect()["sink"])

    resumed, _ = refusal_agent([], [PermissionTool("denied")], AlwaysDeny(), store=store)
    resumed.resume_saved()
    history = resumed.get_history()
    call_index = next(index for index, message in enumerate(history) if message.tool_calls)

    assert len(client.requests) == 1
    assert history[call_index + 1].role == "tool"
    assert history[call_index + 1].content.startswith("ERROR: permission denied")
    assert not any(message.role == "assistant" and message.content == "synthesized" for message in history)


@pytest.mark.asyncio
async def test_successful_final_step_tool_call_keeps_existing_max_step_behavior():
    agent, client = refusal_agent(
        [tool_batch(tool_call("ok", "ok", {}))],
        [PermissionTool("ok")],
        AlwaysAllow(),
        max_steps=1,
    )
    collector = collect()

    await agent.run("go", FakeSignal(), collector["sink"])

    assert len(client.requests) == 1
    assert any(event.type == "error" and isinstance(event.err, MaxStepsError) for event in collector["events"])


class FakeLoadSkillTool(Tool):

    def __init__(self, registry: SkillRegistry):
        self.registry = registry

    def name(self) -> str:
        return "load_skill"

    def description(self) -> str:
        return "load_skill"

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                },
            },
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        signal,
        prompter,
    ) -> str:

        name = args.get("name", "")

        if not isinstance(name, str):
            name = ""

        skill = self.registry.get(name)

        if skill is None:
            raise RuntimeError(f"unknown {name}")

        return skill.body


def make_agent_with_skill(
    scripted: list[ChatResponse],
    skill_tools: list[str],
):

    tools = ToolRegistry()

    tools.register(EchoTool())
    tools.register(RestrictedShellTool())

    skills = SkillRegistry()

    skills.add(
        Skill(
            name="narrow",
            description="narrow skill",
            tools=skill_tools,
            disable_model_invocation=False,
            path="/virtual/narrow/SKILL.md",
            body="# narrow body",
        )
    )

    tools.register(FakeLoadSkillTool(skills))

    agent = Agent(
        AgentOptions(
            client=FakeClient(scripted),
            tools=tools,
            skills=skills,
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
        )
    )

    collector = collect()

    return {
        "agent": agent,
        "events": collector["events"],
        "sink": collector["sink"],
    }


@pytest.mark.asyncio
async def test_blocks_action_aware_coverage_clear_not_listed_in_active_skill(
    tmp_path,
):
    coverage_store = CoverageStore(str(tmp_path / "coverage.json"))
    await coverage_store.mark(
        endpoint="GET /orders/1",
        param="id",
        vulnClass="idor",
        status="tried",
    )

    tools = ToolRegistry()
    tools.register(CoverageTool(coverage_store))

    skills = SkillRegistry()
    skills.add(
        Skill(
            name="narrow",
            description="narrow skill",
            tools=["echo"],
            disable_model_invocation=False,
            path="/virtual/narrow/SKILL.md",
            body="# narrow body",
        )
    )

    agent = Agent(
        AgentOptions(
            client=FakeClient([]),
            tools=tools,
            skills=skills,
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
        )
    )
    agent.active_skills.add("narrow")

    clear_result = await agent.run_parsed_tool_call(
        ToolCall(
            id="clear",
            type="function",
            function=FunctionCall(
                name="coverage",
                arguments='{"action":"clear"}',
            ),
        ),
        ParsedToolCall({"action": "clear"}, '{"action":"clear"}'),
        FakeSignal(),
    )

    assert "not in any active skill" in clear_result.err_str
    assert coverage_store.entries

    summary_result = await agent.run_parsed_tool_call(
        ToolCall(
            id="summary",
            type="function",
            function=FunctionCall(
                name="coverage",
                arguments='{"action":"summary"}',
            ),
        ),
        ParsedToolCall({"action": "summary"}, '{"action":"summary"}'),
        FakeSignal(),
    )

    assert summary_result.err_str == ""
    assert json.loads(summary_result.result)["total"] == 1


@pytest.mark.asyncio
async def test_blocks_capability_tool_not_listed_in_active_skill():

    helper = make_agent_with_skill(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_1",
                            type="function",
                            function=FunctionCall(
                                name="load_skill",
                                arguments=json.dumps(
                                    {
                                        "name": "narrow",
                                    }
                                ),
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_2",
                            type="function",
                            function=FunctionCall(
                                name="shell",
                                arguments=json.dumps(
                                    {
                                        "command": "id",
                                    }
                                ),
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="understood",
                ),
                finish_reason="stop",
            ),
        ],
        ["echo"],
    )

    await helper["agent"].run(
        "go",
        FakeSignal(),
        helper["sink"],
    )

    shell_result = next(
        (
            e
            for e in helper["events"]
            if e.type == "tool-result"
            and getattr(e, "name", "") == "shell"
        ),
        None,
    )

    assert shell_result is not None
    assert re.search(
        r"not in any active skill",
        shell_result.err,
    )

@pytest.mark.asyncio
async def test_allows_capability_tool_listed_in_active_skill():

    helper = make_agent_with_skill(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_1",
                            type="function",
                            function=FunctionCall(
                                name="load_skill",
                                arguments=json.dumps(
                                    {
                                        "name": "narrow",
                                    }
                                ),
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_2",
                            type="function",
                            function=FunctionCall(
                                name="shell",
                                arguments=json.dumps(
                                    {
                                        "command": "id",
                                    }
                                ),
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="ok",
                ),
                finish_reason="stop",
            ),
        ],
        [
            "shell",
            "echo",
        ],
    )

    await helper["agent"].run(
        "go",
        FakeSignal(),
        helper["sink"],
    )

    shell_result = next(
        (
            e
            for e in helper["events"]
            if e.type == "tool-result"
            and getattr(e, "name", "") == "shell"
        ),
        None,
    )

    assert shell_result is not None
    assert shell_result.err == ""
    assert "ran:" in shell_result.result


@pytest.mark.asyncio
async def test_allowed_tools_never_bypasses_independent_permission_denial():
    tools = ToolRegistry()
    tools.register(RestrictedShellTool())
    skills = SkillRegistry()
    skills.add(
        Skill(
            name="shell-skill",
            description="uses shell",
            tools=["shell"],
            disable_model_invocation=False,
            path="/virtual/shell-skill/SKILL.md",
            body="",
        )
    )
    agent = Agent(
        AgentOptions(
            client=FakeClient([]),
            tools=tools,
            skills=skills,
            prompter=AlwaysDeny(),
            store=None,
            target=Target(),
        )
    )
    agent.active_skills.add("shell-skill")

    tool_call = ToolCall(
        id="denied",
        type="function",
        function=FunctionCall(name="shell", arguments='{"command":"id"}'),
    )
    parsed = ParsedToolCall({"command": "id"}, '{"command":"id"}')
    result = await agent.run_parsed_tool_call(
        tool_call,
        parsed,
        FakeSignal(),
    )

    assert "permission denied" in result.err_str
    assert result.result == f"ERROR: {result.err_str}"

    events = []
    working = []
    agent.record_tool_result(tool_call, parsed, result, events.append, working)

    assert events[-1]["err"] == result.err_str
    assert events[-1]["result"] == result.result
    assert working[-1].role == "tool"
    assert working[-1].content == result.result
    assert agent.get_history()[-1].content == result.result


def test_multiple_active_skills_use_union_for_permission_tool_capability():
    tools = ToolRegistry()
    tools.register(RestrictedShellTool())
    skills = SkillRegistry()
    for name, allowed in (("one", ["http"]), ("two", ["shell"])):
        skills.add(
            Skill(
                name=name,
                description=name,
                tools=allowed,
                disable_model_invocation=False,
                path=f"/virtual/{name}/SKILL.md",
                body="",
            )
        )
    agent = Agent(
        AgentOptions(
            client=FakeClient([]),
            tools=tools,
            skills=skills,
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
        )
    )
    agent.active_skills.update({"one", "two"})

    assert agent.is_tool_allowed("shell", {"command": "id"}).ok is True

@pytest.mark.asyncio
async def test_active_skill_with_empty_allowed_tools_means_unrestricted():

    helper = make_agent_with_skill(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_1",
                            type="function",
                            function=FunctionCall(
                                name="load_skill",
                                arguments=json.dumps(
                                    {
                                        "name": "narrow",
                                    }
                                ),
                            ),
                        ),
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_2",
                            type="function",
                            function=FunctionCall(
                                name="shell",
                                arguments=json.dumps(
                                    {
                                        "command": "id",
                                    }
                                ),
                            ),
                        ),
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="ok",
                ),
                finish_reason="stop",
            ),
        ],
        [],      # allowed-tools rỗng -> unrestricted
    )

    await helper["agent"].run(
        "go",
        FakeSignal(),
        helper["sink"],
    )

    shell_result = next(
        (
            e
            for e in helper["events"]
            if e.type == "tool-result"
            and getattr(e, "name", "") == "shell"
        ),
        None,
    )

    assert shell_result is not None
    assert shell_result.err == ""

@pytest.mark.asyncio
async def test_no_skill_loaded_places_no_restriction():

    helper = make_agent_with_skill(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_x",
                            type="function",
                            function=FunctionCall(
                                name="shell",
                                arguments=json.dumps(
                                    {
                                        "command": "whoami",
                                    }
                                ),
                            ),
                        ),
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="done",
                ),
                finish_reason="stop",
            ),
        ],
        ["echo"],
    )

    await helper["agent"].run(
        "go",
        FakeSignal(),
        helper["sink"],
    )

    shell_result = next(
        (
            e
            for e in helper["events"]
            if e.type == "tool-result"
            and getattr(e, "name", "") == "shell"
        ),
        None,
    )

    assert shell_result is not None
    assert shell_result.err == ""

@pytest.mark.asyncio
async def test_allows_bash_tool_when_skill_declares_shell_alias():

    tools = ToolRegistry()

    class ShellTool(Tool):

        def name(self) -> str:
            return "shell"

        def description(self) -> str:
            return "shell"

        def schema(self) -> dict[str, Any]:
            return {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                    },
                },
            }

        def requires_permission(self) -> bool:
            return True

        async def run(
            self,
            args,
            signal,
            prompter,
        ) -> str:
            return "unused"

    class BashToolAlias(Tool):

        def name(self) -> str:
            return "BashTool"

        def description(self) -> str:
            return "bash"

        def schema(self) -> dict[str, Any]:
            return {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                    },
                },
            }

        def requires_permission(self) -> bool:
            return True

        async def run(
            self,
            args,
            signal,
            prompter,
        ) -> str:
            return f"bashed: {args.get('command', '')}"

    tools.register(ShellTool())
    tools.register(BashToolAlias())

    skills = SkillRegistry()

    skills.add(
        Skill(
            name="unix-skill",
            description="declares the Unix name",
            tools=["shell"],
            disable_model_invocation=False,
            path="/virtual/unix/SKILL.md",
            body="",
        )
    )

    tools.register(FakeLoadSkillTool(skills))

    agent = Agent(
        AgentOptions(
            client=FakeClient(
                [
                    ChatResponse(
                        message=Message(
                            role="assistant",
                            content="",
                            tool_calls=[
                                ToolCall(
                                    id="c1",
                                    type="function",
                                    function=FunctionCall(
                                        name="load_skill",
                                        arguments=json.dumps(
                                            {
                                                "name": "unix-skill",
                                            }
                                        ),
                                    ),
                                )
                            ],
                        ),
                        finish_reason="tool_calls",
                    ),
                    ChatResponse(
                        message=Message(
                            role="assistant",
                            content="",
                            tool_calls=[
                                ToolCall(
                                    id="c2",
                                    type="function",
                                    function=FunctionCall(
                                        name="BashTool",
                                        arguments=json.dumps(
                                            {
                                                "command": "id",
                                            }
                                        ),
                                    ),
                                )
                            ],
                        ),
                        finish_reason="tool_calls",
                    ),
                    ChatResponse(
                        message=Message(
                            role="assistant",
                            content="ok",
                        ),
                        finish_reason="stop",
                    ),
                ]
            ),
            tools=tools,
            skills=skills,
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
        )
    )

    collector = collect()

    await agent.run(
        "go",
        FakeSignal(),
        collector["sink"],
    )

    bash_result = next(
        (
            e
            for e in collector["events"]
            if e.type == "tool-result"
            and getattr(e, "name", "") == "BashTool"
        ),
        None,
    )

    assert bash_result is not None
    assert bash_result.err == ""
    assert "bashed: id" in bash_result.result

@pytest.mark.asyncio
async def test_active_skill_tool_restrictions_do_not_carry_into_next_turn():
    """
    Active skill tool restrictions only apply to the current agent turn.

    After a turn finishes, the next run should not inherit the previous
    skill's allowed-tools restriction.
    """

    helper = make_agent_with_skill(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_1",
                            type="function",
                            function=FunctionCall(
                                name="load_skill",
                                arguments=json.dumps(
                                    {
                                        "name": "narrow",
                                    }
                                ),
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="first done",
                ),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_2",
                            type="function",
                            function=FunctionCall(
                                name="shell",
                                arguments=json.dumps(
                                    {
                                        "command": "id",
                                    }
                                ),
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="second done",
                ),
                finish_reason="stop",
            ),
        ],
        ["echo"],
    )

    # First turn:
    # Load "narrow" skill which only allows "echo".
    await helper["agent"].run(
        "first",
        FakeSignal(),
        helper["sink"],
    )

    # Second turn:
    # The previous skill restriction must not affect this turn.
    # shell should be executed successfully.
    await helper["agent"].run(
        "second",
        FakeSignal(),
        helper["sink"],
    )

    shell_result = next(
        (
            event
            for event in helper["events"]
            if event.type == "tool-result"
            and getattr(event, "name", "") == "shell"
        ),
        None,
    )

    assert shell_result is not None
    assert shell_result.err == ""
    assert "ran:" in shell_result.result

def asst(*ids: str):
    return Message(
        role="assistant",
        content="",
        tool_calls=[
            ToolCall(
                id=id_,
                type="function",
                function=FunctionCall(
                    name=f"tool_{id_}",
                    arguments="{}",
                ),
            )
            for id_ in ids
        ],
    )


def tool_msg(id_: str):
    return Message(
        role="tool",
        content="ok",
        tool_call_id=id_,
        name=f"tool_{id_}",
    )


def test_reconcile_tool_calls_synthesizes_result_for_unanswered_tool_call():
    out = reconcile_tool_calls(
        [
            Message(
                role="system",
                content="s",
            ),
            Message(
                role="user",
                content="u",
            ),
            asst("a", "b"),
            tool_msg("a"),
        ]
    )

    assert [
        m.role for m in out
    ] == [
        "system",
        "user",
        "assistant",
        "tool",
        "tool",
    ]

    synth = out[4]

    assert synth.role == "tool"
    assert synth.tool_call_id == "b"
    assert synth.name == "tool_b"
    assert "did not complete" in synth.content.lower()


def test_reconcile_tool_calls_is_noop_when_every_tool_call_is_answered():
    input_messages = [
        Message(
            role="system",
            content="s",
        ),
        asst("a", "b"),
        tool_msg("a"),
        tool_msg("b"),
    ]

    out = reconcile_tool_calls(input_messages)

    assert len(out) == len(input_messages)

    assert [
        getattr(m, "tool_call_id", None)
        for m in out
    ] == [
        None,
        None,
        "a",
        "b",
    ]


def test_reconcile_tool_calls_repairs_dangling_call_mid_history():
    out = reconcile_tool_calls(
        [
            asst("a"),
            Message(
                role="user",
                content="next turn",
            ),
            asst("b"),
            tool_msg("b"),
        ]
    )

    assert [
        f"{m.role}:{getattr(m, 'tool_call_id', '') or ''}"
        for m in out
    ] == [
        "assistant:",
        "tool:a",
        "user:",
        "assistant:",
        "tool:b",
    ]

def test_reconcile_tool_calls_leaves_plain_conversation_untouched():
    input_messages = [
        Message(
            role="system",
            content="s",
        ),
        Message(
            role="user",
            content="hi",
        ),
        Message(
            role="assistant",
            content="hello",
        ),
    ]

    output = reconcile_tool_calls(input_messages)

    assert output == input_messages

class BarrierTool(Tool):

    def __init__(self, need: int):
        self.need = need
        self.count = 0
        self.waiters: list[asyncio.Future[bool]] = []

    def name(self) -> str:
        return "barrier"

    def description(self) -> str:
        return "barrier"

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                },
            },
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        signal=None,
        prompter=None,
    ) -> str:

        self.count += 1

        if self.count >= self.need:
            for waiter in self.waiters:
                if not waiter.done():
                    waiter.set_result(True)

            self.waiters.clear()

            return f"parallel-ok:{args.get('id', '')}"


        loop = asyncio.get_running_loop()

        future = loop.create_future()
        self.waiters.append(future)

        try:
            ok = await asyncio.wait_for(
                future,
                timeout=0.3,
            )
        except asyncio.TimeoutError:
            ok = False

        return (
            f"{'parallel-ok' if ok else 'serial'}:"
            f"{args.get('id', '')}"
        )

class DelayTool(Tool):

    def name(self) -> str:
        return "delay"

    def description(self) -> str:
        return "delay"

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                },
                "delay_ms": {
                    "type": "number",
                },
            },
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        signal=None,
        prompter=None,
    ) -> str:

        delay_ms = float(
            args.get("delay_ms", 0)
        )

        await asyncio.sleep(
            delay_ms / 1000
        )

        return f"done:{args.get('id', '')}"

def tool_call(
    id: str,
    name: str,
    args: dict,
) -> ToolCall:
    return ToolCall(
        id=id,
        type="function",
        function=FunctionCall(
            name=name,
            arguments=json.dumps(args),
        ),
    )


def agent_with_tools(
    scripted: list[ChatResponse],
    tools: list[Tool],
) -> Agent:

    registry = ToolRegistry()

    for tool in tools:
        registry.register(tool)

    return Agent(
        AgentOptions(
            client=FakeClient(scripted),
            tools=registry,
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
        )
    )


@pytest.mark.asyncio
async def test_runs_independent_tool_calls_in_same_step_concurrently():

    agent = agent_with_tools(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        tool_call(
                            "c1",
                            "barrier",
                            {
                                "id": "a",
                            },
                        ),
                        tool_call(
                            "c2",
                            "barrier",
                            {
                                "id": "b",
                            },
                        ),
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="done",
                ),
                finish_reason="stop",
            ),
        ],
        [
            BarrierTool(2),
        ],
    )

    collector = collect()

    await agent.run(
        "go",
        FakeSignal(),
        collector["sink"],
    )

    results = [
        event.result
        for event in collector["events"]
        if event.type == "tool-result"
    ]

    assert results == [
        "parallel-ok:a",
        "parallel-ok:b",
    ]

@pytest.mark.asyncio
async def test_emits_tool_results_in_call_order_even_when_later_calls_finish_first():

    agent = agent_with_tools(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        tool_call(
                            "c1",
                            "delay",
                            {
                                "id": "first",
                                "delay_ms": 60,
                            },
                        ),
                        tool_call(
                            "c2",
                            "delay",
                            {
                                "id": "second",
                                "delay_ms": 0,
                            },
                        ),
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="done",
                ),
                finish_reason="stop",
            ),
        ],
        [
            DelayTool(),
        ],
    )

    collector = collect()

    await agent.run(
        "go",
        FakeSignal(),
        collector["sink"],
    )

    order = [
        event.result
        for event in collector["events"]
        if event.type == "tool-result"
    ]

    # second finishes first, but output order follows tool call order
    assert order == [
        "done:first",
        "done:second",
    ]


    tool_messages = [
        message
        for message in agent.get_history()
        if message.role == "tool"
    ]

    assert [
        message.tool_call_id
        for message in tool_messages
    ] == [
        "c1",
        "c2",
    ]

class BigOutputTool(Tool):

    def __init__(self, size: int):
        self.size = size

    def name(self) -> str:
        return "big"

    def description(self) -> str:
        return "big"

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {},
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        signal=None,
        prompter=None,
    ) -> str:
        return "x" * self.size


class BigErrorTool(BigOutputTool):
    def name(self) -> str:
        return "big_error"

    async def run(self, args, signal=None, prompter=None) -> str:
        raise RuntimeError("e" * self.size)


class PreservedBigOutputTool(BigOutputTool):
    def context_reduction_policy(self) -> str:
        return "preserve"


def tool_content(request: ChatRequest, call_id: str) -> str:
    return next(
        message.content
        for message in request.messages
        if message.role == "tool" and message.tool_call_id == call_id
    )


def make_big_output_agent(
    size: int,
    *,
    store=None,
    tool: Tool | None = None,
) -> tuple[Agent, FakeClient]:
    selected_tool = tool or BigOutputTool(size)
    client = FakeClient(
        [
            tool_batch(tool_call("large", selected_tool.name(), {})),
            ChatResponse(
                message=Message(role="assistant", content="synthesized"),
                finish_reason="stop",
            ),
        ]
    )
    registry = ToolRegistry()
    registry.register(selected_tool)
    agent = Agent(
        AgentOptions(
            client=client,
            tools=registry,
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=store,
            target=Target(),
            prompt_profile="compact",
        )
    )
    return agent, client


@pytest.mark.asyncio
async def test_small_immediate_tool_result_reaches_synthesis_unchanged():
    agent, client = make_big_output_agent(200)
    agent.set_auto_compact_threshold(agent.approx_tokens() + 5_000)

    await agent.run("go", FakeSignal(), collect()["sink"])

    assert len(client.requests) == 2
    assert tool_content(client.requests[1], "large") == "x" * 200
    assert next(m.content for m in agent.get_history() if m.role == "tool") == "x" * 200


@pytest.mark.asyncio
async def test_large_immediate_result_is_bounded_only_for_synthesis():
    raw = "x" * 12_000
    agent, client = make_big_output_agent(len(raw))
    agent.set_auto_compact_threshold(agent.approx_tokens() + 1_000)

    await agent.run("go", FakeSignal(), collect()["sink"])

    bounded = tool_content(client.requests[1], "large")
    persisted = next(m.content for m in agent.get_history() if m.role == "tool")
    assert len(client.requests) == 2
    assert persisted == raw
    assert bounded != raw
    assert MIDTURN_ELISION_PREFIX in bounded
    assert len(bounded) > MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR
    assert len(raw) - len(bounded) < 10_000


@pytest.mark.asyncio
async def test_preserved_semantic_result_reaches_synthesis_and_history_raw():
    tool = PreservedBigOutputTool(12_000)
    agent, client = make_big_output_agent(12_000, tool=tool)
    collector = collect()
    agent.set_auto_compact_threshold(agent.approx_tokens() + 1_000)

    await agent.run("go", FakeSignal(), collector["sink"])

    assert len(client.requests) == 2
    assert tool_content(client.requests[1], "large") == "x" * 12_000
    assert next(m.content for m in agent.get_history() if m.role == "tool") == "x" * 12_000
    assert not any(
        event.type == "decision" and "context guard" in event.summary
        for event in collector["events"]
    )


def test_context_guard_bounds_only_oversized_results_and_preserves_pairing():
    agent = make_agent([])
    agent.set_auto_compact_threshold(1)
    raw = "H" * 12_000
    working = [
        Message(role="tool", name="small", tool_call_id="a", content="small"),
        Message(role="tool", name="huge", tool_call_id="b", content=raw),
    ]

    agent.guard_working_context(working, lambda _: None, AgentRunOptions(tools=False))

    assert [(m.name, m.tool_call_id) for m in working] == [("small", "a"), ("huge", "b")]
    assert working[0].content == "small"
    assert MIDTURN_ELISION_PREFIX in working[1].content
    assert raw.startswith(working[1].content.split("\n", 1)[0])


def test_context_guard_bounds_each_oversized_recent_result_idempotently():
    agent = make_agent([])
    agent.set_auto_compact_threshold(1)
    working = [
        Message(role="tool", name="one", tool_call_id="a", content="A" * 12_000),
        Message(role="tool", name="two", tool_call_id="b", content="B" * 15_000),
    ]

    agent.guard_working_context(working, lambda _: None, AgentRunOptions(tools=False))
    first = [message.content for message in working]
    agent.guard_working_context(working, lambda _: None, AgentRunOptions(tools=False))

    assert [message.content for message in working] == first
    assert all(len(content) == MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR for content in first)
    assert all(content.count(MIDTURN_ELISION_PREFIX) >= 1 for content in first)


def test_context_guard_slight_pressure_removes_only_required_budget_plus_safety():
    agent = make_agent([])
    events = []
    raw = "x" * 12_000
    working = [Message(role="tool", name="large", tool_call_id="a", content=raw)]
    threshold = 2_628
    safety = max(MIDTURN_MIN_SAFETY_TOKENS, round(threshold * 0.02))
    target = threshold - safety
    original_tokens = approximate_message_tokens(working)
    agent.set_auto_compact_threshold(threshold)

    agent.guard_working_context(working, events.append, AgentRunOptions(tools=False))

    required_reduction = (original_tokens - target) * 4
    assert original_tokens == 3_000
    assert safety == 128
    assert target == 2_500
    assert required_reduction == 2_000
    assert len(working[0].content) == 10_000
    assert approximate_message_tokens(working) == target
    assert len(working[0].content) > MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR
    assert len(events) == 1
    assert "reduced 2000 characters" in events[0]["summary"]
    assert "unresolved pressure" not in events[0]["summary"]


def test_context_guard_pressure_without_tool_output_emits_no_event():
    agent = make_agent([])
    agent.set_auto_compact_threshold(1)
    working = [Message(role="user", content="hi")]
    original = list(working)
    events = []

    agent.guard_working_context(working, events.append)

    assert working == original
    assert events == []


def test_context_guard_no_reducible_candidate_never_reports_zero_reduction():
    agent = make_agent([])
    agent.set_auto_compact_threshold(1)
    working = [Message(role="system", content="fixed request overhead" * 100)]
    events = []

    agent.guard_working_context(working, events.append, AgentRunOptions(tools=False))

    assert events == []
    assert not any("reduced 0 characters" in event["summary"] for event in events)


def test_context_guard_severe_pressure_reaches_floor_and_reports_residual():
    agent = make_agent([])
    events = []
    working = [
        Message(role="user", content="u" * 512),
        Message(role="tool", name="large", tool_call_id="a", content="x" * 12_000),
    ]
    agent.set_auto_compact_threshold(500)

    agent.guard_working_context(working, events.append, AgentRunOptions(tools=False))

    assert len(working[1].content) == MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR
    assert approximate_message_tokens(working) == 628
    assert len(events) == 1
    assert "reduced 10000 characters" in events[0]["summary"]
    assert "unresolved pressure: 256 tokens" in events[-1]["summary"]
    assert "reduced 0 characters" not in events[0]["summary"]


def test_context_guard_preserves_recent_semantic_result_under_severe_pressure():
    agent = make_agent([])
    agent.tools.register(PreservedBigOutputTool(12_000))
    raw = "S" * 12_000
    working = [Message(role="tool", name="big", tool_call_id="s", content=raw)]
    events = []
    agent.set_auto_compact_threshold(1)

    agent.guard_working_context(working, events.append, AgentRunOptions(tools=False))

    assert working[0].content == raw
    assert events == []


def test_context_guard_does_not_old_elide_protected_semantic_result():
    agent = make_agent([])
    agent.tools.register(PreservedBigOutputTool(12_000))
    protected = "S" * 12_000
    working = [
        Message(role="tool", name="big", tool_call_id="protected", content=protected),
        *[
            Message(role="tool", name=f"small-{i}", tool_call_id=str(i), content="x" * 100)
            for i in range(4)
        ],
    ]
    events = []
    agent.set_auto_compact_threshold(1)

    agent.guard_working_context(working, events.append, AgentRunOptions(tools=False))

    assert working[0].content == protected
    assert [message.content for message in working[1:]] == ["x" * 100] * 4
    assert events == []


def test_context_guard_mixed_policy_reduces_only_adaptive_capacity():
    agent = make_agent([])
    agent.tools.register(PreservedBigOutputTool(12_000))
    protected = "S" * 12_000
    working = [
        Message(role="tool", name="big", tool_call_id="s", content=protected),
        Message(role="tool", name="adaptive-one", tool_call_id="a", content="A" * 6_000),
        Message(role="tool", name="adaptive-two", tool_call_id="b", content="B" * 10_000),
    ]
    agent.set_auto_compact_threshold(6_633)

    agent.guard_working_context(working, lambda _: None, AgentRunOptions(tools=False))

    assert working[0].content == protected
    assert [6_000 - len(working[1].content), 10_000 - len(working[2].content)] == [
        667,
        1_333,
    ]
    assert approximate_message_tokens(working) == 6_499


def test_context_guard_preserves_production_workflow_and_finding_results(tmp_path):
    agent = make_agent([])
    agent.tools.register(WorkflowTool(WorkflowState()))
    agent.tools.register(ConfirmFindingTool(FindingsStore(str(tmp_path / "findings"))))
    workflow_result = "W" * 12_000
    finding_result = "F" * 12_000
    history = [
        Message(
            role="tool",
            name="workflow",
            tool_call_id="workflow",
            content=workflow_result,
        ),
        Message(
            role="tool",
            name="confirm_finding",
            tool_call_id="finding",
            content=finding_result,
        ),
        Message(
            role="tool",
            name="adaptive-old",
            tool_call_id="old",
            content="O" * 12_000,
        ),
        *[
            Message(
                role="tool",
                name=f"adaptive-{index}",
                tool_call_id=f"adaptive-{index}",
                content="A" * 12_000,
            )
            for index in range(4)
        ],
    ]
    working = deepcopy(history)
    agent.set_auto_compact_threshold(1)

    agent.guard_working_context(working, lambda _: None, AgentRunOptions(tools=False))

    assert working[0].content == workflow_result
    assert working[1].content == finding_result
    assert MIDTURN_ELISION_PREFIX in working[2].content
    assert all(MIDTURN_ELISION_PREFIX in message.content for message in working[3:])
    assert [message.content for message in history] == [
        workflow_result,
        finding_result,
        "O" * 12_000,
        *("A" * 12_000 for _ in range(4)),
    ]


def test_context_guard_preserves_confirm_finding_error_semantics(tmp_path):
    agent = make_agent([])
    agent.tools.register(ConfirmFindingTool(FindingsStore(str(tmp_path / "findings"))))
    error = "ERROR: severity must be one of: critical, high, medium, low, info"
    working = [
        Message(
            role="tool",
            name="confirm_finding",
            tool_call_id="finding-error",
            content=error,
        ),
        *[
            Message(
                role="tool",
                name=f"later-{index}",
                tool_call_id=f"later-{index}",
                content="x" * 100,
            )
            for index in range(4)
        ],
    ]
    agent.set_auto_compact_threshold(1)

    agent.guard_working_context(working, lambda _: None, AgentRunOptions(tools=False))

    assert working[0].content == error


@pytest.mark.asyncio
async def test_complete_workflow_result_reaches_immediate_next_request():
    workflow = WorkflowState()
    tool = WorkflowTool(workflow)
    client = FakeClient(
        [
            tool_batch(
                tool_call(
                    "workflow-call",
                    "workflow",
                    {
                        "action": "record_candidate",
                        "candidate_class": "xss",
                        "target": "https://target.test",
                        "endpoint": "/search",
                        "parameter": "q",
                    },
                )
            ),
            ChatResponse(
                message=Message(role="assistant", content="candidate recorded"),
                finish_reason="stop",
            ),
        ]
    )
    registry = ToolRegistry()
    registry.register(tool)
    agent = Agent(
        AgentOptions(
            client=client,
            tools=registry,
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
            auto_compact_threshold=1,
            prompt_profile="compact",
        )
    )

    await agent.run("record it", FakeSignal(), collect()["sink"])

    raw = next(
        message.content
        for message in agent.get_history()
        if message.tool_call_id == "workflow-call"
    )
    assert tool_content(client.requests[1], "workflow-call") == raw
    payload = json.loads(raw)
    assert payload["created"] is True
    assert payload["candidate"]["id"]


@pytest.mark.asyncio
async def test_incomplete_coverage_page_stays_explicit_under_context_pressure(tmp_path):
    coverage_store = CoverageStore(str(tmp_path / "coverage.json"))
    coverage_store.loaded = True
    for index in range(40):
        coverage_store.entries[str(index)] = CoverageEntry(
            endpoint=f"GET /coverage/{index:03d}/" + "e" * 180,
            param=f"p{index:03d}",
            vulnClass="cross-site-scripting",
            status="tried",
            count=1,
            firstSeen=index,
            lastSeen=index,
            notes="n" * 300,
        )
    tool = CoverageTool(coverage_store)
    client = FakeClient(
        [
            tool_batch(
                tool_call(
                    "coverage-page",
                    "coverage",
                    {"action": "list", "limit": 25},
                )
            ),
            ChatResponse(
                message=Message(role="assistant", content="continue later"),
                finish_reason="stop",
            ),
        ]
    )
    registry = ToolRegistry()
    registry.register(tool)
    agent = Agent(
        AgentOptions(
            client=client,
            tools=registry,
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
            auto_compact_threshold=1_000,
            prompt_profile="compact",
        )
    )

    await agent.run("show coverage", FakeSignal(), collect()["sink"])

    raw = next(
        message.content
        for message in agent.get_history()
        if message.tool_call_id == "coverage-page"
    )
    llm_facing = tool_content(client.requests[1], "coverage-page")
    payload = json.loads(raw)
    assert payload["complete"] is False
    assert payload["next_cursor"] is not None
    assert payload["returned_count"] < payload["total_count"]
    assert MIDTURN_ELISION_PREFIX in llm_facing
    assert '"complete": false' in llm_facing
    assert '"next_cursor":' in llm_facing
    assert raw != llm_facing


@pytest.mark.asyncio
async def test_coverage_context_keeps_next_flow_compatible_with_paginated_results(tmp_path):
    coverage_store = CoverageStore(str(tmp_path / "coverage.json"))
    coverage_store.loaded = True
    for index in range(11):
        coverage_store.entries[str(index)] = CoverageEntry(
            endpoint=f"GET /next/{index:02d}",
            param="id",
            vulnClass="access-control",
            status="tried",
            count=1,
            firstSeen=index,
            lastSeen=index,
        )
    agent = make_agent([])
    agent.tools.register(CoverageTool(coverage_store))

    context = await agent.coverage_context(FakeSignal())

    assert "Coverage summary:" in context
    assert "Coverage entries:" in context
    assert '"total_count": 11' in context
    assert '"returned_count": 10' in context
    assert '"complete": false' in context
    assert '"next_cursor": "10"' in context


def _source_with_canaries(size: int = 12_000) -> tuple[str, list[str]]:
    chars = ["."] * size
    canaries = ["HEAD-CANARY", "Q1-CANARY", "MID-CANARY", "Q3-CANARY", "TAIL-CANARY"]
    positions = [0, size // 4, size // 2, size * 3 // 4, size - len(canaries[-1])]
    for position, canary in zip(positions, canaries):
        chars[position : position + len(canary)] = canary
    return "".join(chars), canaries


def test_distributed_windows_preserve_canaries_and_characterize_gaps():
    raw, canaries = _source_with_canaries()

    bounded = bound_recent_tool_result(raw, 4_000)

    assert len(bounded) == 4_000
    assert all(canary in bounded for canary in canaries)
    assert bounded.count(MIDTURN_ELISION_PREFIX) == 4
    assert re.search(r"characters \d+-\d+ omitted; original length 12000", bounded)


def test_distributed_windows_have_no_slight_pressure_size_cliff():
    raw, canaries = _source_with_canaries()

    bounded = bound_recent_tool_result(raw, 11_999)

    assert len(bounded) == 11_999
    assert all(canary in bounded for canary in canaries)


@pytest.mark.parametrize(
    ("evidence", "position"),
    [
        ('<script>alert("reflected-xss")</script>', 6_000),
        ("SQL syntax error near unexpected token", 3_000),
        ('"critical_field":"keep-this-value"', 6_000),
        ("PORT 8443/tcp open critical-service", 9_000),
    ],
)
def test_distributed_windows_preserve_middle_security_evidence(evidence, position):
    chars = ["."] * 12_000
    chars[position : position + len(evidence)] = evidence
    raw = "".join(chars)
    old_head_tail = raw[:1_500] + raw[-500:]

    bounded = bound_recent_tool_result(raw, 4_000)

    assert evidence not in old_head_tail
    assert evidence in bounded


def test_context_guard_allocates_multi_result_reduction_proportionally():
    agent = make_agent([])
    working = [
        Message(role="tool", name="small", tool_call_id="s", content="ok"),
        Message(role="tool", name="one", tool_call_id="a", content="A" * 6_000),
        Message(role="tool", name="two", tool_call_id="b", content="B" * 10_000),
    ]
    agent.set_auto_compact_threshold(3_628)

    agent.guard_working_context(working, lambda _: None, AgentRunOptions(tools=False))

    reductions = [6_000 - len(working[1].content), 10_000 - len(working[2].content)]
    assert working[0].content == "ok"
    assert [(m.name, m.tool_call_id) for m in working] == [
        ("small", "s"), ("one", "a"), ("two", "b")
    ]
    assert reductions == [667, 1_333]
    assert all(len(message.content) > 2_000 for message in working[1:])
    assert approximate_message_tokens(working) <= 3_500


def test_context_guard_stops_after_actual_rendered_reduction_reaches_target():
    agent = make_agent([])
    first_raw = "A" * 12_001
    later_raw = "B" * 2_020
    working = [
        Message(role="tool", name="first", tool_call_id="a", content=first_raw),
        Message(role="tool", name="later", tool_call_id="b", content=later_raw),
    ]
    # Current estimate is 3,505 tokens. With the 128-token safety margin,
    # target is 3,377 and the proportional character plan is [511, 1].
    # Because 12,001 -> 11,490 crosses a token-accounting boundary, the first
    # rendered replacement alone recovers all 128 required tokens.
    agent.set_auto_compact_threshold(3_505)

    agent.guard_working_context(working, lambda _: None, AgentRunOptions(tools=False))

    assert len(first_raw) - len(working[0].content) == 511
    assert approximate_message_tokens(working) == 3_377
    assert working[1].content == later_raw


def test_context_guard_stops_after_older_elision_recovers_budget():
    agent = make_agent([])
    working = [
        Message(role="tool", name=str(i), tool_call_id=str(i), content=chr(65 + i) * 12_000)
        for i in range(5)
    ]
    recent_raw = [message.content for message in working[-4:]]
    agent.set_auto_compact_threshold(12_800)

    agent.guard_working_context(working, lambda _: None, AgentRunOptions(tools=False))

    assert working[0].content.startswith(MIDTURN_ELISION_PREFIX)
    assert [message.content for message in working[-4:]] == recent_raw


@pytest.mark.asyncio
async def test_large_recoverable_error_still_synthesizes_with_bounded_copy():
    tool = BigErrorTool(12_000)
    agent, client = make_big_output_agent(12_000, tool=tool)
    agent.set_auto_compact_threshold(agent.approx_tokens() + 1_000)

    await agent.run("go", FakeSignal(), collect()["sink"])

    assert len(client.requests) == 2
    assert MIDTURN_ELISION_PREFIX in tool_content(client.requests[1], "large")
    raw = next(m.content for m in agent.get_history() if m.role == "tool")
    assert raw.startswith("ERROR: ")
    assert len(raw) > 12_000


@pytest.mark.asyncio
async def test_mixed_refusal_and_large_success_bounds_result_and_synthesizes():
    client = FakeClient(
        [
            tool_batch(
                tool_call("denied", "denied", {}),
                tool_call("large", "big", {}),
            ),
            ChatResponse(
                message=Message(role="assistant", content="synthesized"),
                finish_reason="stop",
            ),
        ]
    )
    registry = ToolRegistry()
    registry.register(PermissionTool("denied"))
    registry.register(BigOutputTool(12_000))
    agent = Agent(
        AgentOptions(
            client=client,
            tools=registry,
            skills=SkillRegistry(),
            prompter=AlwaysDeny(),
            store=None,
            target=Target(),
            prompt_profile="compact",
        )
    )
    agent.set_auto_compact_threshold(agent.approx_tokens() + 1_000)

    await agent.run("go", FakeSignal(), collect()["sink"])

    assert len(client.requests) == 2
    assert tool_content(client.requests[1], "denied").startswith("ERROR: permission denied")
    assert MIDTURN_ELISION_PREFIX in tool_content(client.requests[1], "large")
    assert next(m.content for m in agent.get_history() if m.tool_call_id == "large") == "x" * 12_000


@pytest.mark.asyncio
async def test_large_result_save_resume_preserves_raw_history(tmp_path):
    store = Store.new_with_id(tmp_path, "large-result")
    agent, client = make_big_output_agent(12_000, store=store)
    agent.set_auto_compact_threshold(agent.approx_tokens() + 1_000)

    await agent.run("go", FakeSignal(), collect()["sink"])

    resumed, _ = make_big_output_agent(1, store=store)
    resumed.resume_saved()
    raw = next(m.content for m in resumed.get_history() if m.role == "tool")
    assert len(client.requests) == 2
    assert raw == "x" * 12_000


@pytest.mark.asyncio
async def test_preserved_semantic_result_save_resume_is_unchanged(tmp_path):
    store = Store.new_with_id(tmp_path, "preserved-result")
    tool = PreservedBigOutputTool(12_000)
    agent, client = make_big_output_agent(12_000, store=store, tool=tool)
    agent.set_auto_compact_threshold(agent.approx_tokens() + 1_000)

    await agent.run("go", FakeSignal(), collect()["sink"])

    resumed, _ = make_big_output_agent(1, store=store)
    resumed.resume_saved()
    raw = next(m.content for m in resumed.get_history() if m.role == "tool")
    assert len(client.requests) == 2
    assert raw == "x" * 12_000

@pytest.mark.asyncio
async def test_mid_turn_context_guard_elides_old_tool_results_without_touching_history():

    tool_step = ChatResponse(
        message=Message(
            role="assistant",
            content="",
            tool_calls=[
                ToolCall(
                    id="c",
                    type="function",
                    function=FunctionCall(
                        name="big",
                        arguments="{}",
                    ),
                )
            ],
        ),
        finish_reason="tool_calls",
    )


    scripted = [
        tool_step,
        tool_step,
        tool_step,
        tool_step,
        tool_step,
        tool_step,
        ChatResponse(
            message=Message(
                role="assistant",
                content="done",
            ),
            finish_reason="stop",
        ),
    ]


    tools = ToolRegistry()
    tools.register(
        BigOutputTool(6000)
    )


    agent = Agent(
        AgentOptions(
            client=FakeClient(scripted),
            tools=tools,
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
        )
    )


    # Không để compact giữa turn kích hoạt,
    # chỉ để mid-turn guard hoạt động
    agent.set_auto_compact_threshold(
        agent.approx_tokens() + 5000
    )


    collector = collect()

    await agent.run(
        "go",
        FakeSignal(),
        collector["sink"],
    )


    guard_event = next(
        (
            e
            for e in collector["events"]
            if e.type == "decision"
            and "context guard" in e.summary
        ),
        None,
    )


    assert guard_event is not None


    tool_messages = [
        m
        for m in agent.get_history()
        if m.role == "tool"
    ]


    assert len(tool_messages) == 6

    assert all(
        len(m.content) == 6000
        for m in tool_messages
    )

def make_memory_agent(
    scripted: list[ChatResponse],
):
    cwd = tempfile.mkdtemp(
        prefix="pf-agent-mem-cwd-"
    )

    home = tempfile.mkdtemp(
        prefix="pf-agent-mem-home-"
    )

    memory_store = MemoryStore(
        cwd=cwd,
        home=home,
    )

    tools = ToolRegistry()
    tools.register(EchoTool())

    agent = Agent(
        AgentOptions(
            client=FakeClient(scripted),
            tools=tools,
            skills=SkillRegistry(),
            prompter=AlwaysAllow(),
            store=None,
            target=Target(),
            memory_store=memory_store,
        )
    )

    return {
        "agent": agent,
        "memory_store": memory_store,
        "cleanup": lambda: (
            shutil.rmtree(
                cwd,
                ignore_errors=True,
            ),
            shutil.rmtree(
                home,
                ignore_errors=True,
            ),
        ),
    }


@pytest.mark.asyncio
async def test_pins_saved_fact_into_system_prompt_immediately():

    helper = make_memory_agent([])

    try:
        fact = await helper["agent"].add_memory(
            {
                "text": "orders API IDOR on /api/orders/{id}"
            }
        )

        assert fact is not None

        sys = (
            helper["agent"]
            .get_history()[0]
            .content
            or ""
        )

        assert "Saved memory" in sys
        assert fact.name in sys

    finally:
        helper["cleanup"]()


@pytest.mark.asyncio
async def test_recalls_relevant_fact_and_emits_memory_recall_event():

    helper = make_memory_agent(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="ok",
                ),
                finish_reason="stop",
            )
        ]
    )

    try:
        await helper["agent"].add_memory(
            {
                "text": (
                    "orders API IDOR via sequential id "
                    "on /api/orders/{id}"
                )
            }
        )
        print("STORE:", helper["agent"].memory_store)
        print(
            "SEARCH:",
            helper["agent"].memory_store.search(
                "test the orders endpoint for idor",
                5,
            )
        )

        collector = collect()

        await helper["agent"].run(
            "test the orders endpoint for idor",
            FakeSignal(),
            collector["sink"],
        )

        recall = next(
            (
                e
                for e in collector["events"]
                if e.type == "memory-recall"
            ),
            None,
        )

        assert recall is not None
        assert len(recall.names) > 0

    finally:
        helper["cleanup"]()

@pytest.mark.asyncio
async def test_keeps_saved_memory_catalog_in_prompt_after_compaction():

    helper = make_memory_agent(
        [
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="COMPACTED SUMMARY",
                ),
                finish_reason="stop",
            )
        ]
    )

    try:
        fact = await helper["agent"].add_memory(
            {
                "text": "login OAuth redirect_uri bypass works"
            }
        )

        # seed/access history (same as TS no-op accessor)
        helper["agent"].get_history()

        await helper["agent"].compact(
            FakeSignal(),
            lambda e: None,
        )

        sys = (
            helper["agent"]
            .get_history()[0]
            .content
            or ""
        )

        assert "Saved memory" in sys
        assert fact.name in sys

    finally:
        helper["cleanup"]()


@pytest.mark.asyncio
async def test_forget_memory_removes_curated_fact_and_prompt():

    helper = make_memory_agent([])

    try:
        fact = await helper["agent"].add_memory(
            {
                "text": "orders API IDOR on /api/orders/{id}"
            }
        )

        name = fact.name if fact else "NOPE"

        assert len(
            helper["agent"].list_curated_memory()
        ) == 1


        removed = await helper["agent"].forget_memory(
            "orders"
        )


        assert name in removed

        assert len(
            helper["agent"].list_curated_memory()
        ) == 0


        system = (
            helper["agent"]
            .get_history()[0]
            .content
            or ""
        )

        assert name not in system


    finally:
        helper["cleanup"]()


class TestErrorReporting:
    def test_safe_emit_reports_listener_failures_instead_of_dropping_them(
        self, caplog
    ):
        signal = SimpleNamespace(aborted=False)

        def broken_listener(event):
            raise RuntimeError("listener blew up")

        emit = make_safe_emit(signal, broken_listener)

        with caplog.at_level(logging.ERROR, logger="kagent"):
            emit({"type": "assistant-text", "text": "hi"})

        assert any("listener blew up" in str(r.err) for r in caplog.records)

    @pytest.mark.asyncio
    async def test_background_task_failure_is_logged(self, caplog):
        agent = make_agent([])

        async def boom():
            raise RuntimeError("background boom")

        with caplog.at_level(logging.ERROR, logger="kagent"):
            task = agent._spawn_background(boom(), "unit-test")
            await asyncio.gather(task, return_exceptions=True)
            await asyncio.sleep(0)

        assert agent._background_tasks == set()
        assert any("background boom" in str(r.err) for r in caplog.records)
