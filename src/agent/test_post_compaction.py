from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from src.agent.agent import Agent, AgentOptions
from src.agent.test_agent import EchoTool, FakeClient, FakeSignal, collect
from src.llm.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import AlwaysAllow
from src.session.store import Store
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.registry import Registry as ToolRegistry
from src.workflow.state import Candidate, WorkflowState


SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills"
FINAL_RESPONSE = "Post-compaction continuation succeeded."
TOOL_RESULT = "echoed: deterministic tool result"


def _topic_turn(topic: str, detail: str) -> list[Message]:
    context = f"{topic} {detail} " * 220
    return [
        Message(
            role="user",
            content=f"Investigate {topic} in the authorized target. {context}",
        ),
        Message(
            role="assistant",
            content=f"Recorded deterministic {topic} observations. {context}",
        ),
    ]


@pytest.mark.asyncio
async def test_complete_post_compaction_planner_and_tool_continuation(tmp_path) -> None:
    summary = "\n".join(
        [
            "## Current objective",
            "- Continue SQL injection validation on parameter id",
            "## Tested surface",
            "- SQL injection testing covered parameter id",
            "- XSS testing covered the search query",
            "- CSRF testing covered the profile update action",
            "- SSRF testing covered the webhook URL",
            "## Open TODOs",
            "- Validate the SQL injection candidate with a deterministic probe",
        ]
    )
    scripted = [
        ChatResponse(
            message=Message(role="assistant", content=summary),
            finish_reason="stop",
        ),
        ChatResponse(
            message=Message(
                role="assistant",
                content="",
                tool_calls=[
                    ToolCall(
                        id="post_compaction_echo",
                        type="function",
                        function=FunctionCall(
                            name="echo",
                            arguments='{"msg":"deterministic tool result"}',
                        ),
                    )
                ],
            ),
            finish_reason="tool_calls",
        ),
        ChatResponse(
            message=Message(role="assistant", content=FINAL_RESPONSE),
            finish_reason="stop",
        ),
    ]
    client = FakeClient(scripted)
    echo = EchoTool()
    tools = ToolRegistry()
    tools.register(echo)
    skills = SkillRegistry()
    skills.load_dir(SKILLS_ROOT)
    target = Target(base_url="https://target.test", name="authorized-target")
    workflow = WorkflowState(current_phase="validation")
    workflow.completed_skills.add("web-input-analysis")
    candidate, _ = workflow.add_candidate(
        Candidate(
            candidate_class="sql-injection",
            target="https://target.test",
            endpoint="/items",
            method="GET",
            parameter="id",
            status="queued",
        )
    )
    store = Store.new_with_id(tmp_path, "post-compaction")
    agent = Agent(
        AgentOptions(
            client=client,
            tools=tools,
            skills=skills,
            prompter=AlwaysAllow(),
            store=store,
            target=target,
            workflow=workflow,
            prompt_profile="compact",
        )
    )
    for topic, detail in (
        ("SQL injection", "parameter id returned database syntax differences"),
        ("XSS", "search query reflected encoded markers"),
        ("CSRF", "profile update required an anti-CSRF token"),
        ("SSRF", "webhook URL rejected private network destinations"),
    ):
        agent.history.extend(_topic_turn(topic, detail))

    before_history = agent.get_history()
    before_tokens = agent.approx_tokens()
    before_text = "\n".join(message.content for message in before_history).lower()
    for topic in ("sql injection", "xss", "csrf", "ssrf"):
        assert topic in before_text
    compact_events = collect()

    await agent.compact(FakeSignal(), compact_events["sink"])

    after_history = agent.get_history()
    assert len(after_history) < len(before_history)
    assert 1 < len(after_history)
    assert agent.approx_tokens() < before_tokens
    assert after_history[0].role == "system"
    assert all(message.role in {"system", "user", "assistant"} for message in after_history)
    assert any(event["type"] == "compact" for event in compact_events["events"])
    assert not any(event["type"] == "error" for event in compact_events["events"])
    compaction_input = client.requests[0].messages[1].content.lower()
    assert "older conversation text was omitted" in compaction_input
    assert "ssrf" in compaction_input

    stats = agent.get_memory_stats()
    memory_text = agent.format_memory().lower()
    assert stats.compactions == 1
    assert stats.items >= 5
    for topic in ("sql injection", "xss", "csrf", "ssrf"):
        assert topic in memory_text
    assert "carried session state" in after_history[0].content.lower()
    assert target.base_url() == "https://target.test"
    assert workflow.current_phase == "validation"
    assert workflow.completed_skills == {"web-input-analysis"}
    assert workflow.candidates[candidate.id].parameter == "id"

    post_compaction_events = collect()
    await agent.run(
        "test parameter id for sql injection",
        FakeSignal(),
        post_compaction_events["sink"],
    )
    if agent._background_tasks:
        await asyncio.gather(*agent._background_tasks, return_exceptions=True)

    assert len(client.requests) == 3
    first_post_compaction_request = client.requests[1]
    second_post_compaction_request = client.requests[2]
    first_context = "\n".join(
        message.content for message in first_post_compaction_request.messages
    ).lower()
    assert "carried session state" in first_context
    for topic in ("sql injection", "xss", "csrf", "ssrf"):
        assert topic in first_context
    assert any(
        event["type"] == "decision"
        and "selected skill: sql-injection" in event["summary"]
        for event in post_compaction_events["events"]
    )

    assert echo.calls == 1
    assert any(
        event["type"] == "tool-call" and event["name"] == "echo"
        for event in post_compaction_events["events"]
    )
    assert any(
        event["type"] == "tool-result" and event["result"] == TOOL_RESULT
        for event in post_compaction_events["events"]
    )
    assert any(
        message.role == "tool"
        and message.tool_call_id == "post_compaction_echo"
        and message.content == TOOL_RESULT
        for message in second_post_compaction_request.messages
    )
    assert any(
        message.role == "tool"
        and message.tool_call_id == "post_compaction_echo"
        and message.content == TOOL_RESULT
        for message in agent.get_history()
    )
    assert agent.get_history()[-1].content == FINAL_RESPONSE
    assert any(
        event["type"] == "assistant-text" and event["text"] == FINAL_RESPONSE
        for event in post_compaction_events["events"]
    )
    assert not any(
        event["type"] == "compact" for event in post_compaction_events["events"]
    )
    assert agent.get_memory_stats().compactions == 1
    assert target.base_url() == "https://target.test"
    assert workflow.candidates[candidate.id].status == "queued"

    persisted = store.load()
    assert persisted.target is not None
    assert persisted.target.base_url() == "https://target.test"
    assert candidate.id in persisted.workflow.candidates
    assert any(
        message.role == "tool" and message.content == TOOL_RESULT
        for message in persisted.messages
    )
