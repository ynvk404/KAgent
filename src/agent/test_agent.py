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
from pathlib import Path
from typing import Any
from src.tools.types import Tool
from src.memory.store import MemoryStore
from src.agent.agent import (
    Agent,
    AgentOptions,
    AgentRunOptions,
    make_safe_emit,
    reconcile_tool_calls,
)
from src.intelligence.store import IntelligenceStore
from src.llm.client import Client
from src.llm.types import (
    ChatRequest,
    ChatResponse,
    Message,
    ToolCall,
    FunctionCall,
)
from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as SkillRegistry, Skill
from src.target.target import Target
from src.tools.registry import Registry as ToolRegistry

from src.session.store import Store, new_id
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
        req: ChatRequest,
        signal=None,
    ) -> ChatResponse:

        self.requests.append(req)

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

    assert any(
        event["type"] == "decision"
        and "selected skill: recon"
        in event["summary"]
        for event in collector["events"]
    )

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
            content="Compacted summary of prior turn.",
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
            content="previous useful turn",
        )
    )
    agent.history.append(
        Message(
            role="assistant",
            content="previous useful answer",
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
            req: ChatRequest,
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
            req: ChatRequest,
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
            req: ChatRequest,
            signal=None,
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
