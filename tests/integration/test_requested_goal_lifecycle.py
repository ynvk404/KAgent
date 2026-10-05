from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from pathlib import Path

import pytest

from src.agent.agent import Agent, AgentOptions
from src.agent.decision_planner import build_decision_plan
from src.llm.core.client import Client
from src.llm.core.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.registry import Registry as ToolRegistry
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.goals import RequestedGoal
from src.workflow.evidence import EvidenceArtifact
from src.workflow.state import (
    AttackSurfaceInput, Candidate, ValidationResult,
    WorkflowObjective, WorkflowState,
)
from tests.helpers.agent_fakes import FakeSignal, collect
from tests.helpers.workflow import record_completed_phase


class GoalLifecycleClient(Client):
    def __init__(self) -> None:
        self.agent: Agent | None = None
        self.requests: list[ChatRequest] = []
        self.sent_early_final: set[str] = set()
        self.plans: list[str | None] = []

    def name(self) -> str:
        return "goal-lifecycle-test"

    def model(self) -> str:
        return "goal-lifecycle-test-model"

    async def chat(self, request: ChatRequest, signal=None) -> ChatResponse:
        self.requests.append(deepcopy(request))
        assert self.agent is not None and self.agent.workflow.objective is not None
        self.agent._reconcile_requested_goals()
        objective = self.agent.workflow.objective
        goals = objective.requested_goals
        plan = build_decision_plan(
            "Test SQL Injection, XSS and IDOR for GET /search?term=sample",
            self.agent.skills.list_enabled(), self.agent.target,
            self.agent._planner_context(),
        )
        self.plans.append(plan.guidance if plan else None)
        complete = all(
            goal.status in {"tested_confirmed", "tested_not_confirmed"}
            for goal in goals
        )
        if not complete:
            just_completed = next((
                goal for goal in goals
                if goal.status in {"tested_confirmed", "tested_not_confirmed"}
                and goal.id not in self.sent_early_final
            ), None)
            if just_completed is not None:
                self.sent_early_final.add(just_completed.id)
                return self._final(f"I have finished {just_completed.candidate_class}.")
        if complete:
            return self._final("All requested classes were validated.")

        first_open = next(
            goal for goal in goals
            if goal.status not in {"tested_confirmed", "tested_not_confirmed"}
        )
        candidates = self.agent.workflow.objective_goal_candidates(first_open)
        if not candidates:
            return self._tool("record-candidate", {
                "action": "record_candidate",
                "candidate_class": first_open.candidate_class,
                "endpoint": "GET /search",
                "parameter": "term",
            })
        candidate = candidates[0]
        if candidate.status in {"new", "queued"}:
            return self._tool("start-validation", {
                "action": "start_validation", "candidate_id": candidate.id,
            })
        if candidate.status == "validating":
            references = [
                item.id for item in self.agent.workflow.evidence.values()
                if item.candidate_id == candidate.id
            ]
            if not references:
                return self._tool("record-evidence", {
                    "action": "record_evidence", "candidate_id": candidate.id,
                    "evidence_path": "goal-evidence.md",
                })
            skill = {
                "sql-injection": "sql-injection",
                "cross-site-scripting": "cross-site-scripting",
                "access-control": "access-control",
            }[candidate.candidate_class]
            return self._tool("record-result", {
                "action": "record_result", "candidate_id": candidate.id,
                "skill_name": skill, "outcome": "not-confirmed",
                "evidence_refs": references,
            })
        raise AssertionError(f"planner did not advance from {first_open.candidate_class}")

    @staticmethod
    def _tool(call_id: str, args: dict) -> ChatResponse:
        return ChatResponse(message=Message(
            role="assistant", content="",
            tool_calls=[ToolCall(
                id=call_id,
                function=FunctionCall(name="workflow", arguments=json.dumps(args)),
            )],
        ), finish_reason="tool_calls")

    @staticmethod
    def _final(content: str) -> ChatResponse:
        return ChatResponse(message=Message(role="assistant", content=content), finish_reason="stop")


def _direct_goal_agent(
    tmp_path: Path,
    *,
    client: Client | None = None,
    max_steps: int = 30,
    extra_tools: tuple = (),
):
    (tmp_path / "goal-evidence.md").write_text(
        "Deterministic comparison fixture for a not-confirmed test.", encoding="utf-8",
    )
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    target = Target("https://target.test")
    workflow = WorkflowState()
    client = client or GoalLifecycleClient()
    tools = ToolRegistry()
    tools.register(WorkflowTool(
        workflow, target, skills=skills, evidence_root=tmp_path,
    ))
    for tool in extra_tools:
        tools.register(tool)
    agent = Agent(AgentOptions(
        client=client, tools=tools, skills=skills, prompter=AlwaysAllow(),
        store=None, target=target, max_steps=max_steps, streaming_enabled=False,
        workflow=workflow,
    ))
    setattr(client, "agent", agent)
    return agent, client


class IncompleteFinalClient(Client):
    def __init__(self) -> None:
        self.requests: list[ChatRequest] = []

    def name(self) -> str:
        return "incomplete-final-test"

    def model(self) -> str:
        return "incomplete-final-test-model"

    async def chat(self, request: ChatRequest, signal=None) -> ChatResponse:
        self.requests.append(deepcopy(request))
        if request.tools is None:
            return ChatResponse(
                message=Message(role="assistant", content="Partial: endpoint context is needed."),
                finish_reason="stop",
            )
        return ChatResponse(
            message=Message(role="assistant", content="All requested classes are complete."),
            finish_reason="stop",
        )


class CancelSummaryClient(Client):
    def __init__(self) -> None:
        self.requests: list[ChatRequest] = []

    def name(self) -> str:
        return "cancel-summary-test"

    def model(self) -> str:
        return "cancel-summary-test-model"

    async def chat(self, request: ChatRequest, signal=None) -> ChatResponse:
        self.requests.append(deepcopy(request))
        assert request.tools is None
        summary = "\n".join(
            message.content for message in request.messages if message.role == "system"
        )
        assert "status=cancelled" in summary
        assert "incomplete/partial" in summary
        return ChatResponse(
            message=Message(role="assistant", content="Unresolved requested testing was cancelled."),
            finish_reason="stop",
        )


class AbortedTurnClient(Client):
    def name(self) -> str:
        return "aborted-turn-test"

    def model(self) -> str:
        return "aborted-turn-test-model"

    async def chat(self, request: ChatRequest, signal=None) -> ChatResponse:
        raise asyncio.CancelledError()


class NoProgressToolClient(IncompleteFinalClient):
    async def chat(self, request: ChatRequest, signal=None) -> ChatResponse:
        self.requests.append(deepcopy(request))
        if request.tools is None:
            return ChatResponse(
                message=Message(role="assistant", content="Partial: requested validation is incomplete."),
                finish_reason="stop",
            )
        return self._tool(f"no-progress-{len(self.requests)}", {"msg": "no structured goal progress"})

    @staticmethod
    def _tool(call_id: str, args: dict) -> ChatResponse:
        return ChatResponse(message=Message(
            role="assistant", content="",
            tool_calls=[ToolCall(
                id=call_id,
                function=FunctionCall(name="echo", arguments=json.dumps(args)),
            )],
        ), finish_reason="tool_calls")


def test_candidate_validation_request_links_one_current_candidate_goal_and_rejects_stale_result(tmp_path):
    agent, _ = _direct_goal_agent(tmp_path)
    candidate, _ = agent.workflow.add_candidate(Candidate(
        candidate_class="xss", target="https://target.test", endpoint="/search",
    ))
    agent.workflow.add_validation_result(ValidationResult(
        candidate.id, "cross-site-scripting", "not-confirmed", objective_id="older-objective",
    ))

    agent._initialize_request_objective(f"Retest candidate {candidate.id}", True)
    objective = agent.workflow.objective
    assert objective is not None and objective.mode == "candidate_validation"
    assert len(objective.requested_goals) == 1
    goal = objective.requested_goals[0]
    assert goal.candidate_class == "cross-site-scripting"
    assert goal.candidate_ids == [candidate.id]
    agent._reconcile_requested_goals()
    assert goal.status == "in_progress"
    assert "another objective" in (goal.reason or "")


@pytest.mark.asyncio
async def test_direct_goal_does_not_link_legacy_candidate_by_class_alone(tmp_path):
    agent, _ = _direct_goal_agent(tmp_path)
    legacy, _ = agent.workflow.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test", endpoint="/old",
    ))
    agent._initialize_request_objective("Test SQLi", True)
    objective = agent.workflow.objective
    assert objective is not None
    goal = objective.requested_goals[0]
    assert goal.candidate_ids == []

    workflow_tool = agent.tools.get("workflow")
    assert isinstance(workflow_tool, WorkflowTool)
    response = json.loads(await workflow_tool.run({
        "action": "record_candidate", "candidate_class": "sql-injection",
        "target": "https://target.test", "endpoint": "/current",
    }, None, agent.prompter))
    current = agent.workflow.candidates[response["candidate"]["id"]]
    assert current.id != legacy.id
    assert current.objective_id == objective.id
    assert goal.candidate_ids == [current.id]


def test_objective_continuation_keeps_goals_and_replacement_drops_old_goal_set(tmp_path):
    agent, _ = _direct_goal_agent(tmp_path)
    agent._initialize_request_objective("Test SQL injection and XSS at GET /search", True)
    first = agent.workflow.objective
    assert first is not None
    first_ids = [goal.id for goal in first.requested_goals]

    agent._initialize_request_objective("continue", True)
    assert agent.workflow.objective is first
    assert [goal.id for goal in first.requested_goals] == first_ids

    agent._initialize_request_objective("Start a new task: Test CORS at GET /settings", True)
    replacement = agent.workflow.objective
    assert replacement is not None and replacement.id != first.id
    assert [goal.candidate_class for goal in replacement.requested_goals] == [
        "cors-misconfiguration",
    ]


@pytest.mark.asyncio
async def test_generic_goal_is_tracked_without_bypassing_generic_admission(tmp_path):
    agent, _ = _direct_goal_agent(tmp_path)
    agent._initialize_request_objective("candidate_class=unlisted-check", True)
    objective = agent.workflow.objective
    assert objective is not None
    goal = objective.requested_goals[0]
    context = agent._planner_context()
    from src.agent.decision_planner import build_decision_plan
    plan = build_decision_plan(
        "candidate_class=unlisted-check", agent.skills.list_enabled(), agent.target,
        context,
    )
    assert context.goal_validation_routes[goal.candidate_class].kind == "generic"
    assert goal.status == "pending"
    assert plan is not None and plan.candidate_id is None
    assert "No matching candidate is linked" in plan.guidance

    workflow_tool = agent.tools.get("workflow")
    assert isinstance(workflow_tool, WorkflowTool)
    response = json.loads(await workflow_tool.run({
        "action": "record_candidate", "candidate_class": goal.candidate_class,
        "target": "https://target.test", "endpoint": "/specific",
    }, None, agent.prompter))
    agent._reconcile_requested_goals()
    assert response["supported"] is False
    assert goal.status == "deferred"
    assert agent.workflow.validation_results == []


def test_invalid_or_missing_result_evidence_does_not_keep_goal_tested(tmp_path):
    agent, _ = _direct_goal_agent(tmp_path)
    objective = WorkflowObjective(
        id="objective-proof", mode="direct", target_origin="https://target.test",
        requested_goals=[RequestedGoal("cross-site-scripting")],
    )
    agent.workflow.objective = objective
    candidate, _ = agent.workflow.add_candidate(Candidate(
        candidate_class="xss", target="https://target.test", endpoint="/search",
        objective_id=objective.id,
    ))
    agent.workflow.link_requested_goal_candidate(
        objective.requested_goals[0].id, candidate.id,
    )
    agent.workflow.add_validation_result(ValidationResult(
        candidate.id, "cross-site-scripting", "not-confirmed",
        evidence_refs=["ev_missing"], objective_id=objective.id,
    ))

    agent._reconcile_requested_goals()
    assert objective.requested_goals[0].status == "in_progress"
    assert "evidence" in (objective.requested_goals[0].reason or "")


def test_discovered_extra_whole_target_candidate_remains_an_obligation_not_a_requested_goal(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    objective = WorkflowObjective(
        id="objective-extra", mode="whole_target", target_origin="https://target.test",
        requested_goals=[RequestedGoal("sql-injection")],
    )
    state = WorkflowState(objective=objective)
    for phase in ("recon", "enumeration", "input_analysis"):
        record_completed_phase(
            state, phase, objective_id=objective.id,
            target_origin="https://target.test", artifact_ref=f"artifacts/{phase}.md",
            no_inputs_discovered=phase == "input_analysis",
        )
    extra, _ = state.add_candidate(Candidate(
        candidate_class="ssrf", target="https://target.test", endpoint="/fetch",
        objective_id=objective.id,
    ))
    agent = Agent(AgentOptions(
        client=GoalLifecycleClient(), tools=ToolRegistry(), skills=skills,
        prompter=AlwaysAllow(), store=None, target=Target("https://target.test"),
        workflow=state,
    ))

    status, actionable, _ = agent._whole_target_state()
    assert status == "actionable"
    assert f"candidate:{extra.id}" in actionable
    assert [goal.candidate_class for goal in objective.requested_goals] == ["sql-injection"]


@pytest.mark.asyncio
async def test_direct_three_goal_lifecycle_rejects_early_finals_and_advances_in_user_order(tmp_path):
    agent, client = _direct_goal_agent(tmp_path)
    collector = collect()
    await agent.run(
        "Test SQL Injection, XSS and IDOR for GET /search?term=sample",
        FakeSignal(), collector["sink"],
    )

    objective = agent.workflow.objective
    assert objective is not None
    assert isinstance(client, GoalLifecycleClient)
    assert [goal.candidate_class for goal in objective.requested_goals] == [
        "sql-injection", "cross-site-scripting", "access-control",
    ]
    assert [goal.status for goal in objective.requested_goals] == [
        "tested_not_confirmed", "tested_not_confirmed", "tested_not_confirmed",
    ]
    assert len(client.sent_early_final) == 2
    request_guidance = [
        [message.content for message in request.messages if message.role == "system"]
        for request in client.requests
    ]
    assert any("Next requested goal: cross-site-scripting" in " ".join(messages)
               for messages in request_guidance[4:]), client.plans
    assert any("Next requested goal: access-control" in " ".join(messages)
               for messages in request_guidance[8:]), client.plans
    displayed = [event["text"] for event in collector["events"] if event["type"] == "assistant-text"]
    assert displayed == ["All requested classes were validated."]
    assert collector["events"][-1]["stop_reason"] == "final_response"
    assert all(result.objective_id == objective.id for result in agent.workflow.validation_results)


@pytest.mark.asyncio
async def test_direct_without_candidate_context_stops_as_deferred_partial(tmp_path):
    client = IncompleteFinalClient()
    agent, _ = _direct_goal_agent(tmp_path, client=client)
    collector = collect()
    await agent.run("Test SQL injection and XSS", FakeSignal(), collector["sink"])

    objective = agent.workflow.objective
    assert objective is not None
    assert [goal.status for goal in objective.requested_goals] == ["deferred", "deferred"]
    assert all("does not broaden into discovery" in (goal.reason or "") for goal in objective.requested_goals)
    assert collector["events"][-1]["stop_reason"] == "workflow_blocked"
    synthesis = client.requests[-1]
    assert synthesis.tools is None
    assert any(
        "incomplete/partial" in message.content and "status=deferred" in message.content
        for message in synthesis.messages if message.role == "system"
    )


@pytest.mark.asyncio
async def test_direct_max_steps_reports_unresolved_goal_without_cancelling_or_completing(tmp_path):
    from tests.helpers.agent_fakes import EchoTool

    client = NoProgressToolClient()
    agent, _ = _direct_goal_agent(
        tmp_path, client=client, max_steps=2, extra_tools=(EchoTool(),),
    )
    collector = collect()
    await agent.run(
        "Test XSS at GET /search", FakeSignal(), collector["sink"],
    )

    objective = agent.workflow.objective
    assert objective is not None
    assert objective.requested_goals[0].status == "pending"
    assert collector["events"][-1]["stop_reason"] == "max_steps"
    assert any(
        "incomplete/partial" in message.content and "status=pending" in message.content
        for message in client.requests[-1].messages if message.role == "system"
    )


@pytest.mark.asyncio
async def test_explicit_operator_stop_cancels_unresolved_goals_and_synthesizes_partial(tmp_path):
    client = CancelSummaryClient()
    agent, _ = _direct_goal_agent(tmp_path, client=client)
    objective = WorkflowObjective(
        id="explicit-cancel", mode="direct", target_origin="https://target.test",
        requested_goals=[
            RequestedGoal("sql-injection", status="pending"),
            RequestedGoal("cross-site-scripting", status="deferred", reason="missing context"),
        ],
    )
    agent.workflow.objective = objective
    collector = collect()

    await agent.run("Stop testing this assessment", FakeSignal(), collector["sink"])

    assert [goal.status for goal in objective.requested_goals] == ["cancelled", "cancelled"]
    assert all("Operator explicitly cancelled" in (goal.reason or "") for goal in objective.requested_goals)
    assert len(client.requests) == 1
    assert collector["events"][-1]["stop_reason"] == "workflow_blocked"


@pytest.mark.asyncio
async def test_runtime_abort_keeps_requested_goal_resumable(tmp_path):
    agent, _ = _direct_goal_agent(tmp_path, client=AbortedTurnClient())
    objective = WorkflowObjective(
        id="runtime-abort", mode="direct", target_origin="https://target.test",
        requested_goals=[RequestedGoal("sql-injection")],
    )
    agent.workflow.objective = objective

    with pytest.raises(asyncio.CancelledError):
        await agent.run("continue", FakeSignal(), collect()["sink"])

    assert objective.requested_goals[0].status == "pending"


@pytest.mark.asyncio
async def test_whole_target_requested_goals_keep_phase_order_and_gate_completion(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    objective = WorkflowObjective(
        id="whole-goals", mode="whole_target", target_origin="https://target.test",
        requested_goals=[
            RequestedGoal("sql-injection"),
            RequestedGoal("cross-site-scripting"),
            RequestedGoal("idor"),
        ],
    )
    state = WorkflowState(objective=objective)
    phase_agent = Agent(AgentOptions(
        client=GoalLifecycleClient(), tools=ToolRegistry(), skills=skills,
        prompter=AlwaysAllow(), store=None, target=Target("https://target.test"),
        workflow=state,
    ))
    phase_plan = phase_agent._planner_context()
    from src.agent.decision_planner import build_decision_plan
    first = build_decision_plan(
        "Perform whole-target assessment", skills.list_enabled(), phase_agent.target,
        phase_plan,
    )
    assert first is not None and first.recommended_skill == "recon"

    for phase in ("recon", "enumeration", "input_analysis"):
        record_completed_phase(
            state, phase, objective_id=objective.id,
            target_origin="https://target.test", artifact_ref=f"artifacts/{phase}.md",
            no_inputs_discovered=phase == "input_analysis",
        )
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test",
        endpoint="/search", objective_id=objective.id,
    ))
    proof = tmp_path / "goal-proof.md"
    proof.write_text("deterministic SQL comparison showed no class-specific signal", encoding="utf-8")
    artifact = EvidenceArtifact.capture(candidate.id, "goal-proof.md", tmp_path)
    state.add_evidence(artifact)
    state.add_validation_result(ValidationResult(
        candidate.id, "sql-injection", "not-confirmed",
        evidence_refs=[artifact.id], objective_id=objective.id,
    ))
    phase_agent._reconcile_requested_goals()
    status, actionable, blockers = phase_agent._whole_target_state()
    assert status == "blocked"
    assert not actionable
    assert any("cross-site-scripting" in blocker for blocker in blockers)
    assert any("access-control" in blocker for blocker in blockers)
    assert [goal.status for goal in objective.requested_goals] == [
        "tested_not_confirmed", "pending", "pending",
    ]


@pytest.mark.asyncio
async def test_whole_target_no_candidate_disposition_remains_incomplete(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    objective = WorkflowObjective(
        id="whole-no-candidate", mode="whole_target",
        target_origin="https://target.test",
        requested_goals=[RequestedGoal("cors-misconfiguration")],
    )
    state = WorkflowState(objective=objective)
    for phase in ("recon", "enumeration", "input_analysis"):
        ref = f"artifacts/{phase}.md"
        artifact = tmp_path / ref
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("complete inventory", encoding="utf-8")
        record_completed_phase(
            state, phase, objective_id=objective.id,
            target_origin="https://target.test", artifact_ref=ref,
            no_inputs_discovered=phase == "input_analysis",
        )
    target = Target("https://target.test")
    workflow_tool = WorkflowTool(state, target, skills=skills, evidence_root=tmp_path)
    registry = ToolRegistry()
    registry.register(workflow_tool)
    agent = Agent(AgentOptions(
        client=GoalLifecycleClient(), tools=registry, skills=skills,
        prompter=AlwaysAllow(), store=None, target=target, workflow=state,
    ))

    response = json.loads(await workflow_tool.run({
        "action": "review_no_candidate",
        "goal_id": objective.requested_goals[0].id,
        "artifact_ref": "artifacts/input_analysis.md",
    }, None, agent.prompter))
    status, actionable, blockers = agent._whole_target_state()
    assert response["goal"]["status"] == "no_candidate"
    assert status == "blocked"
    assert not actionable
    assert any("class-specific validation was not performed" in blocker for blocker in blockers)


def test_whole_target_dropped_input_with_weak_reason_cannot_allow_goal_completion():
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    objective = WorkflowObjective(
        id="whole-dropped-review", mode="whole_target",
        target_origin="https://target.test",
        requested_goals=[RequestedGoal("cross-site-scripting")],
    )
    state = WorkflowState(objective=objective)
    state.add_attack_surface_input(AttackSurfaceInput(
        objective.id, "https://target.test", endpoint="/search", parameter="q",
        disposition="dropped", disposition_reason="ignored",
    ))
    for phase in ("recon", "enumeration", "input_analysis"):
        record_completed_phase(
            state, phase, objective_id=objective.id,
            target_origin="https://target.test", artifact_ref=f"artifacts/{phase}.md",
        )
    agent = Agent(AgentOptions(
        client=GoalLifecycleClient(), tools=ToolRegistry(), skills=skills,
        prompter=AlwaysAllow(), store=None, target=Target("https://target.test"),
        workflow=state,
    ))

    status, actionable, blockers = agent._whole_target_state()
    assert status == "blocked"
    assert not actionable
    assert any("dropped without a reviewable reason" in blocker for blocker in blockers)
