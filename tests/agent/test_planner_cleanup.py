"""Offline Planner cleanup must preserve results without hiding recovery work."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from src.agent.decision_planner import (
    PlannerCandidate, PlannerContext, PlannerGoal, build_whole_target_plan,
)
from src.skills.registry import Registry
from src.workflow.validation.route import ValidationRoute


@pytest.fixture
def preserved_goal():
    registry = Registry()
    registry.load_dir(Path(__file__).resolve().parents[2] / "skills")
    candidate = PlannerCandidate(
        "cand_preserved", "sql-injection", "validated", latest_outcome="confirmed",
        validation_action="preserve_result",
    )
    context = PlannerContext(
        objective_mode="whole_target", workflow_status="blocked",
        completed_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        candidates=(candidate,),
        requested_goals=(PlannerGoal(
            "goal_sqli", "sql-injection", "in_progress", (candidate.id,),
            reason="mutation cleanup unresolved:requires-user-action",
        ),),
        validation_routes={candidate.id: ValidationRoute("expert", "sql-injection")},
    )
    return registry.list_enabled(), context


@pytest.mark.parametrize("status", ["blocked", "actionable"])
def test_preserved_result_is_not_validation_work_for_an_open_goal(preserved_goal, status):
    skills, context = preserved_goal
    context = replace(context, workflow_status=status)
    before = deepcopy(context)
    plan = build_whole_target_plan(skills, context)
    assert context == before
    assert plan is None or (plan.recommended_skill is None and plan.candidate_id is None)


@pytest.mark.parametrize("separate_goal,goal_status", [
    (False, "in_progress"), (True, "in_progress"), (True, "deferred"),
])
def test_blocked_cleanup_keeps_independent_recovery(preserved_goal, separate_goal, goal_status):
    skills, context = preserved_goal
    candidate_class = "cross-site-scripting" if separate_goal else "sql-injection"
    recovery = PlannerCandidate(
        "cand_recovery", candidate_class, "deferred", latest_outcome="insufficient-evidence",
        validation_action="start_validation",
    )
    goals = (
        (*context.requested_goals, PlannerGoal("goal_recovery", candidate_class, goal_status, (recovery.id,)))
        if separate_goal else
        (replace(context.requested_goals[0], candidate_ids=(context.candidates[0].id, recovery.id)),)
    )
    context = replace(context, candidates=(*context.candidates, recovery), requested_goals=goals,
        validation_routes={**context.validation_routes, recovery.id: ValidationRoute("expert", candidate_class)})
    plan = build_whole_target_plan(skills, context)
    assert plan is not None and plan.candidate_id == recovery.id
    assert plan.recommended_skill == candidate_class


@pytest.mark.parametrize("field,expected", [
    ("coverage_sync_candidate_ids", "sync_coverage"),
    ("pending_finding_candidate_ids", "confirm_finding"),
    ("pending_cleanup_candidate_ids", "cleanup"),
    ("revalidation_candidate_ids", "Revalidate candidate"),
])
def test_preserved_result_keeps_explicit_completion_and_evidence_repair(preserved_goal, field, expected):
    skills, context = preserved_goal
    candidate = context.candidates[0]
    context = replace(context, **{field: (candidate.id,)})
    plan = build_whole_target_plan(skills, context)
    assert plan is not None and plan.candidate_id == candidate.id
    assert expected in plan.guidance
    assert plan.recommended_skill == ("sql-injection" if field == "revalidation_candidate_ids" else None)


@pytest.mark.parametrize("action", ["resume_owned", "finalize_owned"])
def test_blocked_cleanup_keeps_owned_attempt_recovery(preserved_goal, action):
    skills, context = preserved_goal
    active = PlannerCandidate("cand_owned", "sql-injection", "validating", validation_action=action)
    context = replace(context, candidates=(*context.candidates, active),
        validation_routes={**context.validation_routes, active.id: ValidationRoute("expert", "sql-injection")})
    plan = build_whole_target_plan(skills, context)
    assert plan is not None and plan.candidate_id == active.id
    assert plan.reason == "current attempt recovery precedes discovery"


def test_goal_context_without_runtime_action_keeps_existing_fallback(preserved_goal):
    skills, context = preserved_goal
    context = replace(context, candidates=(replace(context.candidates[0], validation_action=None),))
    plan = build_whole_target_plan(skills, context)
    assert plan is not None and plan.candidate_id == context.candidates[0].id
    assert plan.recommended_skill == "sql-injection"
