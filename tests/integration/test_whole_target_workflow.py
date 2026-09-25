from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.agent.agent import Agent, AgentOptions
from src.agent.decision_planner import build_decision_plan
from src.coverage.store import CoverageStore
from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.registry import Registry as ToolRegistry
from src.tools.workflow import WorkflowTool
from src.workflow.state import (
    AttackSurfaceInput,
    Candidate,
    WorkflowObjective,
    WorkflowState,
)
from tests.helpers.agent_fakes import FakeClient


SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills"


def _artifact(root: Path, relative: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("bounded workflow artifact", encoding="utf-8")


@pytest.mark.asyncio
async def test_whole_target_pipeline_reaches_completion_through_runtime_state(tmp_path):
    target = Target("https://target.test")
    state = WorkflowState(objective=WorkflowObjective(
        id="assessment-1", mode="whole_target", target_origin="https://target.test",
    ))
    old_candidate, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test",
        endpoint="/legacy", objective_id="assessment-previous",
    ))
    skills = SkillRegistry()
    skills.load_dir(SKILLS_ROOT)
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    workflow_tool = WorkflowTool(
        state, target, coverage=coverage, skills=skills, evidence_root=tmp_path,
    )
    tools = ToolRegistry()
    tools.register(workflow_tool)
    agent = Agent(AgentOptions(
        client=FakeClient([]), tools=tools, skills=skills, prompter=AlwaysAllow(),
        store=None, target=target, workflow=state,
    ))

    plan = build_decision_plan("continue", skills.list_enabled(), target, agent._planner_context())
    assert plan is not None and plan.recommended_skill == "recon"
    assert old_candidate.id not in {item.id for item in agent._planner_context().candidates}

    recon_ref = "artifacts/recon/target-test/summary.md"
    _artifact(tmp_path, recon_ref)
    await workflow_tool.run({"action": "complete_skill", "skill_name": "recon"}, None, AlwaysAllow())
    enumeration_plan = build_decision_plan(
        "continue", skills.list_enabled(), target, agent._planner_context()
    )
    assert enumeration_plan is not None
    assert enumeration_plan.recommended_skill == "web-enumeration"

    enumeration_ref = "artifacts/web-enumeration/target-test/inventory.md"
    _artifact(tmp_path, enumeration_ref)
    await workflow_tool.run(
        {"action": "complete_skill", "skill_name": "web-enumeration"}, None, AlwaysAllow()
    )
    input_result = json.loads(await workflow_tool.run({
        "action": "record_input", "method": "GET", "endpoint": "/search",
        "parameter": "q", "location": "query", "input_type": "text",
    }, None, AlwaysAllow()))
    analysis_plan = build_decision_plan(
        "continue", skills.list_enabled(), target, agent._planner_context()
    )
    assert analysis_plan is not None
    assert analysis_plan.recommended_skill == "web-input-analysis"

    candidate_result = json.loads(await workflow_tool.run({
        "action": "record_candidate", "candidate_class": "sql-injection",
        "source_skill": "web-input-analysis", "method": "GET", "endpoint": "/search",
        "parameter": "q", "input_id": input_result["input"]["id"],
    }, None, AlwaysAllow()))
    candidate_id = candidate_result["candidate"]["id"]
    await workflow_tool.run({
        "action": "set_input_disposition", "input_id": input_result["input"]["id"],
        "disposition": "analyzed",
    }, None, AlwaysAllow())
    analysis_ref = "artifacts/web-input-analysis/target-test/candidates.md"
    _artifact(tmp_path, analysis_ref)
    await workflow_tool.run(
        {"action": "complete_skill", "skill_name": "web-input-analysis"}, None, AlwaysAllow()
    )
    validator_plan = build_decision_plan(
        "continue", skills.list_enabled(), target, agent._planner_context()
    )
    assert validator_plan is not None
    assert validator_plan.recommended_skill == "sql-injection"
    assert validator_plan.candidate_id == candidate_id

    await workflow_tool.run({
        "action": "start_validation", "candidate_id": candidate_id,
    }, None, AlwaysAllow())
    result = json.loads(await workflow_tool.run({
        "action": "record_result", "candidate_id": candidate_id,
        "skill_name": "sql-injection", "outcome": "not-confirmed",
    }, None, AlwaysAllow()))
    assert result["coverage_sync"] == "synced"
    assert await coverage.list()
    status, actionable, blockers = agent._whole_target_state()
    assert status == "completed"
    assert actionable == () and blockers == ()
    assert build_decision_plan(
        "continue", skills.list_enabled(), target, agent._planner_context()
    ) is None


def test_whole_target_status_is_blocked_when_only_blocked_input_remains():
    state = WorkflowState(objective=WorkflowObjective(
        id="assessment-blocked", mode="whole_target", target_origin="https://target.test",
    ))
    for phase in ("recon", "enumeration"):
        state.record_phase_completion(
            phase, objective_id="assessment-blocked", target_origin="https://target.test",
            artifact_ref=f"artifacts/{phase}.md",
        )
    item, _ = state.add_attack_surface_input(AttackSurfaceInput(
        "assessment-blocked", "https://target.test", endpoint="/search", parameter="q",
        disposition="blocked", disposition_reason="input is inaccessible",
    ))
    status, actionable, blockers = state.whole_target_status(
        target_origin="https://target.test",
        available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset(),
        coverage_sync_available=True,
    )
    assert item.disposition == "blocked"
    assert status == "blocked" and actionable == () and blockers


def test_whole_target_progress_signature_stays_stable_without_semantic_changes():
    state = WorkflowState(objective=WorkflowObjective(
        id="assessment-stalled", mode="whole_target", target_origin="https://target.test",
    ))
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test",
        endpoint="/search", objective_id="assessment-stalled",
    ))
    before = state.progress_facts()
    candidate.status = "validating"
    candidate.status = "queued"
    assert state.progress_facts() == before
