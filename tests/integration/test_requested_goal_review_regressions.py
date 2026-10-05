"""Regressions for the independent requested-goal lifecycle review."""
import json

import pytest

from src.session.store import SessionLoadError, Store
from src.workflow.goals import RequestedGoal
from src.workflow.state import Candidate, WorkflowObjective, WorkflowState
from tests.integration.test_requested_goal_lifecycle import _direct_goal_agent


@pytest.mark.parametrize("raw_goals", [
    [RequestedGoal("xss").to_dict(), {"candidate_class": "sqli", "status": "unknown"}],
    [{"candidate_class": "sqli", "status": "unknown"}],
    [{"candidate_class": "xss", "id": RequestedGoal("sqli").id}],
    [{"candidate_class": "xss", "id": 42}],
    None,
    "corrupt",
    [RequestedGoal("xss").to_dict(), RequestedGoal("xss").to_dict()],
])
def test_f01_corrupt_goals_reject_runtime_resume(tmp_path, raw_goals):
    agent, _ = _direct_goal_agent(tmp_path)
    store = Store.new_with_id(tmp_path, "corrupt-goals")
    objective = WorkflowObjective("resume", "direct", "https://target.test").to_dict()
    objective["requested_goals"] = raw_goals
    store.path.write_text(json.dumps({"workflow": {"version": 7, "objective": objective}}))
    agent.store = store
    with pytest.raises(SessionLoadError, match="requested goals"):
        agent.resume_saved()


@pytest.mark.parametrize("status", ["tested_confirmed", "tested_not_confirmed"])
def test_f01_unlinked_terminal_goal_is_not_trusted_on_resume(tmp_path, status):
    agent, _ = _direct_goal_agent(tmp_path)
    store = Store.new_with_id(tmp_path, "unlinked-goal")
    state = WorkflowState(objective=WorkflowObjective(
        "resume", "direct", "https://target.test",
        requested_goals=[RequestedGoal("xss", status=status)],
    ))
    store.path.write_text(json.dumps({"workflow": state.to_dict()}))
    agent.store = store
    agent.resume_saved()
    assert agent.workflow.objective is not None
    assert agent.workflow.objective.requested_goals[0].status == "pending"
    assert agent._has_actionable_requested_goal()


def test_f01_legacy_v6_without_goals_resumes(tmp_path):
    agent, _ = _direct_goal_agent(tmp_path)
    store = Store.new_with_id(tmp_path, "legacy-goals")
    store.path.write_text(json.dumps({"workflow": {"version": 6, "objective": {
        "id": "legacy", "mode": "direct", "target_origin": "https://target.test",
    }}}))
    agent.store = store
    agent.resume_saved()
    assert agent.workflow.objective is not None
    assert agent.workflow.objective.requested_goals == []


@pytest.mark.parametrize("text,cancel", [
    ("stop", True), ("stop testing", True), ("cancel assessment", True),
    ("cancel remaining goals", True), ("don't stop", False), ("do not stop", False),
    ("how do I stop?", False), ("if it fails, stop", False), ("stop after SQLi", False),
    ("stop testing XSS but continue SQLi", False),
    ("stop explaining and continue testing", False),
])
def test_f03_narrow_cancellation_preserves_current_objective(tmp_path, text, cancel):
    agent, _ = _direct_goal_agent(tmp_path)
    agent._initialize_request_objective("Test SQLi and XSS at GET /search", True)
    objective = agent.workflow.objective
    assert objective is not None
    assert agent._cancel_requested_goals(text, True) is cancel
    if not cancel:
        agent._initialize_request_objective(text, True)
    assert agent.workflow.objective is objective
    assert [g.status for g in objective.requested_goals] == [
        "cancelled" if cancel else "pending",
    ] * 2


def test_f04_cancelled_linked_goal_stays_cancelled_through_continue_and_planning(tmp_path):
    agent, _ = _direct_goal_agent(tmp_path)
    agent._initialize_request_objective("Test XSS at GET /search", True)
    objective = agent.workflow.objective
    assert objective is not None
    candidate, _ = agent.workflow.add_candidate(Candidate(
        "xss", target="https://target.test", endpoint="/search", objective_id=objective.id,
    ))
    goal = objective.requested_goals[0]
    agent.workflow.link_requested_goal_candidate(goal.id, candidate.id)
    assert agent._cancel_requested_goals("cancel assessment", True)
    agent._reconcile_requested_goals()
    assert goal.status == "cancelled"
    assert agent._planner_context().requested_goals[0].status == "cancelled"
    agent._initialize_request_objective("continue", True)
    agent._reconcile_requested_goals()
    assert agent.workflow.objective is objective
    assert goal.status == "cancelled"


@pytest.mark.asyncio
async def test_f07_workflow_retest_records_current_objective_without_force(tmp_path):
    agent, _ = _direct_goal_agent(tmp_path)
    candidate, _ = agent.workflow.add_candidate(Candidate(
        "xss", target="https://target.test", endpoint="/search",
    ))
    agent._initialize_request_objective(f"Validate candidate {candidate.id}", True)
    assert agent.workflow.objective is not None
    first = agent.workflow.objective.id
    registry = agent.tools
    record = json.loads(await registry.execute("workflow", {
        "action": "record_evidence", "candidate_id": candidate.id,
        "evidence_path": "goal-evidence.md",
    }, None, agent.prompter))
    args = {"action": "record_result", "candidate_id": candidate.id,
            "skill_name": "cross-site-scripting", "outcome": "not-confirmed",
            "evidence_refs": [record["evidence"]["id"]]}
    assert json.loads(await registry.execute("workflow", args, None, agent.prompter))["created"]
    assert not json.loads(await registry.execute("workflow", args, None, agent.prompter))["created"]
    agent._initialize_request_objective(f"Retest candidate {candidate.id}", True)
    assert agent.workflow.objective is not None
    second = agent.workflow.objective.id
    assert second != first
    agent._reconcile_requested_goals()
    assert agent.workflow.objective.requested_goals[0].status == "in_progress"
    assert json.loads(await registry.execute("workflow", args, None, agent.prompter))["created"]
    assert len(agent.workflow.validation_results) == 2
    assert [r.objective_id for r in agent.workflow.validation_results] == [first, second]
    agent._reconcile_requested_goals()
    assert agent.workflow.objective.requested_goals[0].status == "tested_not_confirmed"


@pytest.mark.parametrize("prose", [
    "SQLi is context for documentation.",
    "Test XSS; SQLi is context for documentation.",
    "test XSS with SQLi context for documentation.",
])
def test_f09_candidate_validation_keeps_one_selected_class_on_continuation(tmp_path, prose):
    agent, _ = _direct_goal_agent(tmp_path)
    candidate, _ = agent.workflow.add_candidate(Candidate(
        "xss", target="https://target.test", endpoint="/search",
    ))
    agent._initialize_request_objective(
        f"Validate candidate {candidate.id}. {prose}", True,
    )
    objective = agent.workflow.objective
    assert objective is not None
    assert objective.mode == "candidate_validation"
    assert [g.candidate_class for g in objective.requested_goals] == ["cross-site-scripting"]
    agent._initialize_request_objective("continue; SQLi is context, test SQLi", True)
    assert agent.workflow.objective is objective
    assert [g.candidate_class for g in objective.requested_goals] == ["cross-site-scripting"]


@pytest.mark.asyncio
async def test_f05_blocked_sibling_does_not_mask_actionable_candidate(tmp_path):
    from src.agent.decision_planner import build_decision_plan
    agent, _ = _direct_goal_agent(tmp_path)
    agent._initialize_request_objective("Test XSS at GET /search", True)
    objective = agent.workflow.objective
    assert objective is not None
    blocked, _ = agent.workflow.add_candidate(Candidate(
        "xss", target="https://target.test", endpoint="/blocked", objective_id=objective.id,
    ))
    actionable, _ = agent.workflow.add_candidate(Candidate(
        "xss", target="https://target.test", endpoint="/actionable", objective_id=objective.id,
    ))
    payload = json.loads(await agent.tools.execute("workflow", {
        "action": "record_result", "candidate_id": blocked.id,
        "skill_name": "cross-site-scripting", "outcome": "blocked",
        "deferred_reason": "Operator action required; do not retry this candidate.",
    }, None, agent.prompter))
    assert payload["ok"]
    context = agent._planner_context()
    assert objective.requested_goals[0].status == "in_progress"
    plan = build_decision_plan("continue", agent.skills.list_enabled(), agent.target, context)
    assert plan is not None
    assert plan.candidate_id == actionable.id
    assert blocked.status == "deferred"
    result = agent.workflow.latest_result(blocked.id)
    assert result is not None
    assert result.deferred_reason == payload["result"]["deferred_reason"]


def test_f06_disabled_validator_recovers_without_reopening_cancelled_goal(tmp_path):
    agent, _ = _direct_goal_agent(tmp_path)
    agent._initialize_request_objective("Test XSS at GET /search", True)
    assert agent.workflow.objective is not None
    goal = agent.workflow.objective.requested_goals[0]
    agent.skills.set_disabled("cross-site-scripting", True)
    agent._reconcile_requested_goals()
    assert goal.status == "unsupported"
    agent.skills.set_disabled("cross-site-scripting", False)
    context = agent._planner_context()
    assert goal.status == "pending"
    assert context.requested_goals[0].status == "pending"
    agent._cancel_requested_goals("stop testing", True)
    agent.skills.set_disabled("cross-site-scripting", True)
    agent._reconcile_requested_goals()
    agent.skills.set_disabled("cross-site-scripting", False)
    agent._reconcile_requested_goals()
    assert goal.status == "cancelled"


@pytest.mark.asyncio
async def test_f10_no_candidate_review_binds_artifact_content_and_inventory(tmp_path):
    from tests.helpers.workflow import record_completed_phase
    agent, _ = _direct_goal_agent(tmp_path)
    objective = WorkflowObjective("review", "whole_target", "https://target.test",
                                  requested_goals=[RequestedGoal("xss")])
    agent.workflow.objective = objective
    path = tmp_path / "artifacts/input-review.md"
    path.parent.mkdir(exist_ok=True)
    path.write_text("Completed input inventory: no candidate.")
    for phase in ("recon", "enumeration", "input_analysis"):
        record_completed_phase(agent.workflow, phase, objective_id=objective.id,
                               target_origin="https://target.test",
                               artifact_ref="artifacts/input-review.md", no_inputs_discovered=phase == "input_analysis")
    goal = objective.requested_goals[0]
    args = {"action": "review_no_candidate", "goal_id": goal.id}
    recorded = json.loads(await agent.tools.execute("workflow", args, None, agent.prompter))
    assert recorded["ok"]
    agent._reconcile_requested_goals()
    assert goal.status == "no_candidate"
    resumed = WorkflowState.from_dict(agent.workflow.to_dict())
    agent.workflow.replace_from(resumed)
    assert agent.workflow.objective is not None
    goal = agent.workflow.objective.requested_goals[0]
    agent._reconcile_requested_goals()
    assert goal.status == "no_candidate"
    path.write_text("Changed input inventory: new endpoints need review.")
    assert not agent._no_candidate_review_valid(goal)
    agent._reconcile_requested_goals()
    assert goal.status == "pending"
    assert not agent._whole_target_state()[0] == "completed"
    assert agent.workflow.validation_results == []


@pytest.mark.parametrize("text,expected", [
    ("Do not test SQLi and XSS", []),
    ("XSS is mentioned for context, test SQLi", ["sql-injection"]),
    ("Explain how to test SQLi", []),
    ("candidate_class=xss; test SQLi", ["cross-site-scripting", "sql-injection"]),
])
def test_f08_extractor_operational_context_negation_and_source_order(tmp_path, text, expected):
    from src.workflow.goals import extract_requested_classes
    assert extract_requested_classes(text) == expected
    agent, _ = _direct_goal_agent(tmp_path)
    agent._initialize_request_objective(text, True)
    assert agent.workflow.objective is not None
    assert [g.candidate_class for g in agent.workflow.objective.requested_goals] == expected
