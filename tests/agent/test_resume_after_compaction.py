from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable

import pytest

from src.agent.agent import Agent, AgentOptions
from tests.helpers.agent_fakes import EchoTool, FakeSignal, collect, seed_compactable_history
from src.llm.client import Client
from src.llm.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import AlwaysAllow
from src.session.store import Store
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.registry import Registry as ToolRegistry
from src.workflow.state import Candidate, ValidationResult, WorkflowState


SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills"
MARKER = "KAGENT-RESUME-MARKER-7421-ZEBRA"
TARGET_ALIAS = "ORANGE-VAULT-931"
CANDIDATE_NOTE = "PARAM-Q-ONLY-551"
TOOL_RESULT = "echoed: RESUME-TOOL-RESULT-8842"
CONTINUATION = "resume-after-compaction continuation succeeded"


class GatedFakeClient(Client):
    """A scripted client which refuses recall answers without persisted context."""

    def __init__(
        self,
        scripted: list[ChatResponse],
        checks: dict[int, Callable[[ChatRequest], None]] | None = None,
    ) -> None:
        self.scripted = scripted
        self.checks = checks or {}
        self.requests: list[ChatRequest] = []

    def name(self) -> str:
        return "resume-test-fake"

    def model(self) -> str:
        return "resume-test-model"

    async def chat(self, request: ChatRequest, signal=None) -> ChatResponse:
        index = len(self.requests)
        self.requests.append(request)
        check = self.checks.get(index)
        if check is not None:
            check(request)
        if index >= len(self.scripted):
            raise AssertionError("script exhausted")
        return self.scripted[index]


def _all_request_text(request: ChatRequest) -> str:
    return "\n".join(message.content for message in request.messages)


def _require_resumed_marker(request: ChatRequest) -> None:
    context = _all_request_text(request)
    assert MARKER in context
    assert TARGET_ALIAS in context
    assert CANDIDATE_NOTE in context


def _require_absent_marker(request: ChatRequest) -> None:
    assert MARKER not in _all_request_text(request)


def _skills() -> SkillRegistry:
    skills = SkillRegistry()
    skills.load_dir(SKILLS_ROOT)
    return skills


def _agent(
    *,
    client: Client,
    store: Store,
    target: Target | None = None,
    workflow: WorkflowState | None = None,
    tools: ToolRegistry | None = None,
) -> Agent:
    return Agent(
        AgentOptions(
            client=client,
            tools=tools or ToolRegistry(),
            skills=_skills(),
            prompter=AlwaysAllow(),
            store=store,
            target=target or Target(),
            workflow=workflow,
            # Keep the real pressure calculation enabled while ensuring the
            # small post-resume turns do not manufacture compaction pressure.
            auto_compact_threshold=16_000,
            prompt_profile="compact",
            streaming_enabled=False,
        )
    )


def _compaction_summary() -> str:
    return "\n".join(
        [
            "## Current objective",
            f"- Resume marker: {MARKER}; target alias: {TARGET_ALIAS}.",
            "## Plan",
            "- Continue SQL injection validation for the active q parameter.",
            "## Completed tasks",
            "- Recorded SQL injection, XSS, CSRF, and SSRF investigation turns.",
            "## Target and scope",
            "- http://juice.lab:3000 is the authorized target.",
            "## Decisions and assumptions",
            f"- Candidate note: {CANDIDATE_NOTE}.",
            "## Tested surface",
            "- SQL injection, XSS, CSRF, and SSRF were covered.",
            "## Findings and evidence",
            f"- Preserve {MARKER}, {TARGET_ALIAS}, and {CANDIDATE_NOTE} exactly.",
            "## Files and commands",
            "- No files or commands retained.",
            "## Credentials and placeholders",
            "- None.",
            "## Open TODOs",
            "- Test parameter q for SQL injection.",
            "## Next best actions",
            "- Continue from the persisted workflow candidate.",
        ]
    )


@pytest.mark.asyncio
async def test_resume_after_real_compaction_persists_context_planner_and_tool_continuation(
    tmp_path,
) -> None:
    """Exercise compact -> save -> fresh resume -> continue -> save -> fresh resume."""
    session_id = "resume-after-compaction"
    store = Store.new_with_id(tmp_path, session_id)
    target = Target(base_url="http://juice.lab:3000", name=TARGET_ALIAS)
    workflow = WorkflowState(current_phase="validation")
    workflow.completed_skills.add("web-input-analysis")
    active, _ = workflow.add_candidate(
        Candidate(
            candidate_class="sql-injection",
            target="http://juice.lab:3000",
            endpoint="/rest/products/search",
            method="GET",
            parameter="q",
            signals=[CANDIDATE_NOTE],
            status="queued",
        )
    )
    completed, _ = workflow.add_candidate(
        Candidate(
            candidate_class="cross-site-scripting",
            target="http://juice.lab:3000",
            endpoint="/rest/products/search",
            method="GET",
            parameter="q",
            status="queued",
        )
    )
    workflow.add_validation_result(
        ValidationResult(
            candidate_id=completed.id,
            skill_name="cross-site-scripting",
            outcome="not-confirmed",
            notes="completed deterministic XSS validation",
        )
    )

    original_client = GatedFakeClient(
        [
            ChatResponse(
                message=Message(role="assistant", content=_compaction_summary()),
                finish_reason="stop",
            )
        ]
    )
    original = _agent(
        client=original_client,
        store=store,
        target=target,
        workflow=workflow,
    )
    # These are actual session turns; the large tail supplies real compaction pressure.
    original.history.extend(
        [
            Message(
                role="user",
                content=(
                    f"Investigate SQL injection, XSS, CSRF and SSRF. {MARKER} "
                    f"Resume target alias: {TARGET_ALIAS}. Candidate note: {CANDIDATE_NOTE}."
                ),
            ),
            Message(
                role="assistant",
                content="Recorded the four deterministic investigation categories.",
            ),
        ]
    )
    seed_compactable_history(original)
    pre_compaction_history = original.get_history()
    compact_events = collect()
    await original.compact(FakeSignal(), compact_events["sink"])

    assert any(event["type"] == "compact" for event in compact_events["events"])
    assert not any(event["type"] == "error" for event in compact_events["events"])
    assert len(original.get_history()) < len(pre_compaction_history)
    assert original.memory is not None
    assert original.memory.compactions == 1
    assert MARKER in original.format_memory()
    assert TARGET_ALIAS in original.format_memory()
    assert CANDIDATE_NOTE in original.format_memory()
    assert store.path.exists()

    persisted = store.load()
    assert persisted.id == session_id
    assert persisted.memory is not None and persisted.memory.compactions == 1
    assert MARKER in (persisted.memory.last_summary or "")
    assert persisted.target is not None
    assert persisted.target.base_url() == "http://juice.lab:3000"
    assert persisted.workflow.current_phase == "validation"
    assert active.id in persisted.workflow.candidates
    assert persisted.workflow.latest_result(completed.id) is not None
    assert all(message.role in {"system", "user", "assistant", "tool"} for message in persisted.messages)

    original_target = target
    original_workflow = workflow
    original_memory = original.memory
    del original
    del target
    del workflow
    del original_memory

    resumed_client = GatedFakeClient(
        [
            ChatResponse(
                message=Message(role="assistant", content=MARKER), finish_reason="stop"
            ),
            ChatResponse(
                message=Message(role="assistant", content="planner guidance accepted"),
                finish_reason="stop",
            ),
            ChatResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="resume_echo",
                            type="function",
                            function=FunctionCall(
                                name="echo",
                                arguments='{"msg":"RESUME-TOOL-RESULT-8842"}',
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            ),
            ChatResponse(
                message=Message(role="assistant", content=CONTINUATION), finish_reason="stop"
            ),
        ],
        checks={0: _require_resumed_marker},
    )
    echo = EchoTool()
    resumed_tools = ToolRegistry()
    resumed_tools.register(echo)
    resumed = _agent(
        client=resumed_client,
        store=Store.new_with_id(tmp_path, session_id),
        target=Target(),
        workflow=WorkflowState(),
        tools=resumed_tools,
    )
    resumed.resume_saved()

    assert resumed.target is not original_target
    assert resumed.workflow is not original_workflow
    assert resumed.memory is not None
    assert resumed.target.base_url() == "http://juice.lab:3000"
    assert resumed.target.name() == TARGET_ALIAS
    assert resumed.workflow.current_phase == "validation"
    assert resumed.workflow.candidates[active.id].parameter == "q"
    assert resumed.workflow.candidates[active.id].signals == [CANDIDATE_NOTE]
    assert resumed.workflow.latest_result(completed.id) is not None
    assert resumed.workflow.completed_skills == {"web-input-analysis"}
    assert MARKER in resumed.format_memory()
    assert TARGET_ALIAS in resumed.format_memory()
    assert CANDIDATE_NOTE in resumed.format_memory()
    assert resumed.get_history()[0].role == "system"

    recall_events = collect()
    await resumed.run(
        "what exact unique session marker did I give you earlier?",
        FakeSignal(),
        recall_events["sink"],
    )
    assert resumed.get_history()[-1].content == MARKER
    assert not any(event["type"] == "compact" for event in recall_events["events"])

    negative_client = GatedFakeClient(
        [
            ChatResponse(
                message=Message(role="assistant", content="no prior marker"),
                finish_reason="stop",
            )
        ],
        checks={0: _require_absent_marker},
    )
    negative = _agent(
        client=negative_client,
        store=Store.new_with_id(tmp_path, "plain-new-session"),
    )
    negative_events = collect()
    await negative.run(
        "what exact unique session marker did I give you earlier?",
        FakeSignal(),
        negative_events["sink"],
    )
    assert negative.get_history()[-1].content == "no prior marker"

    planner_events = collect()
    await resumed.run(
        "test parameter id for sql injection",
        FakeSignal(),
        planner_events["sink"],
    )
    assert any(
        event["type"] == "decision"
        and "Planner · sql-injection · risk: normal" in event["summary"]
        for event in planner_events["events"]
    )
    assert resumed.workflow.candidates[active.id].status == "queued"

    tool_events = collect()
    await resumed.run("continue the resumed validation", FakeSignal(), tool_events["sink"])
    if resumed._background_tasks:
        await asyncio.gather(*resumed._background_tasks, return_exceptions=True)
    assert echo.calls == 1
    assert any(event["type"] == "tool-call" and event["name"] == "echo" for event in tool_events["events"])
    assert any(event["type"] == "tool-result" and event["result"] == TOOL_RESULT for event in tool_events["events"])
    assert TOOL_RESULT in _all_request_text(resumed_client.requests[3])
    assert resumed.get_history()[-1].content == CONTINUATION
    assert any(message.role == "tool" and message.content == TOOL_RESULT for message in resumed.get_history())
    assert resumed.target.base_url() == "http://juice.lab:3000"
    assert resumed.workflow.candidates[active.id].status == "queued"

    await resumed.save()
    resumed_memory = resumed.memory
    resumed_target = resumed.target
    resumed_workflow = resumed.workflow
    del resumed

    third = _agent(
        client=GatedFakeClient([]),
        store=Store.new_with_id(tmp_path, session_id),
        target=Target(),
        workflow=WorkflowState(),
    )
    third.resume_saved()
    assert third.memory is not resumed_memory
    assert third.target is not resumed_target
    assert third.workflow is not resumed_workflow
    assert MARKER in third.format_memory()
    assert third.target.base_url() == "http://juice.lab:3000"
    assert third.workflow.candidates[active.id].parameter == "q"
    assert third.workflow.latest_result(completed.id) is not None
    assert any(message.role == "tool" and message.content == TOOL_RESULT for message in third.get_history())
    assert third.get_history()[-1].content == CONTINUATION
