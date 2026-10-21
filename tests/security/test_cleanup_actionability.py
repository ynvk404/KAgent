"""Accepted results retain cleanup obligations without futile automatic work."""
import json

import pytest

from src.workflow.assessment import accepted_result
from src.workflow.planning.goals import RequestedGoal
from src.workflow.state import WorkflowState
from tests.security.test_execution_policy import runtime  # noqa: F401
from tests.security.test_http_observation_reader import reader_runtime


@pytest.mark.parametrize("cleanup,detail,actionable", [
    ("pending", "Cleanup pending; Agent cleanup can continue", True),
    ("requires-user-action", "Operator cleanup required", False),
    ("failed", "Agent cleanup failed; operator intervention required", False),
])
async def test_accepted_cleanup_states_keep_obligations_and_actionability(runtime, tmp_path, cleanup, detail, actionable):
    agent, state, candidate, args, _ = await reader_runtime(runtime, tmp_path)
    registry, prompter, policy, *_ = runtime
    assert state.objective is not None
    state.objective.mode = "direct"
    goal = RequestedGoal(candidate.candidate_class, candidate_ids=[candidate.id])
    state.objective.requested_goals = [goal]
    result = json.loads(await registry.execute("workflow", {**args, "outcome": "not-confirmed",
        "mutation_performed": True, "cleanup_state": cleanup, "cleanup_status": detail}, None, prompter))
    assert result["ok"]
    latest = state.latest_result(candidate.id)
    assert latest is not None and accepted_result(state, candidate, latest, policy)
    agent._reconcile_requested_goals()
    assert goal.status == "in_progress" and "cleanup unresolved" in (goal.reason or "")
    assert agent._has_actionable_requested_goal() is actionable
    assert latest.cleanup_state == cleanup and state.latest_result(candidate.id) is latest


async def test_operator_cleanup_keeps_confirmed_finding_persistence_actionable(runtime, tmp_path):
    agent, state, candidate, args, _ = await reader_runtime(runtime, tmp_path)
    registry, prompter, *_ = runtime
    assert state.objective is not None
    state.objective.mode = "direct"
    state.objective.requested_goals = [RequestedGoal(candidate.candidate_class, candidate_ids=[candidate.id])]
    result = json.loads(await registry.execute("workflow", {**args,
        "mutation_performed": True, "cleanup_state": "requires-user-action",
        "cleanup_status": "Operator cleanup required"}, None, prompter))
    assert result["ok"]
    agent._reconcile_requested_goals()
    assert agent._has_actionable_requested_goal()
    assert not state.finding_is_persisted(candidate.id)


@pytest.mark.parametrize("notes", ["x" * 999 + " trailing text", "é" * 999 + "\u2003 trailing text",
                                  "password=fixture-private-secret " + "summary " * 200])
async def test_bounded_notes_keep_accepted_assessment_binding_after_resume(runtime, tmp_path, notes):
    _, state, candidate, args, _ = await reader_runtime(runtime, tmp_path)
    registry, prompter, policy, *_ = runtime
    recorded = json.loads(await registry.execute("workflow", {**args, "notes": notes}, None, prompter))
    assert recorded["ok"]
    latest = state.latest_result(candidate.id)
    assert latest is not None and accepted_result(state, candidate, latest, policy)
    serialized = json.loads(json.dumps(state.to_dict()))
    restored = WorkflowState.from_dict(serialized)
    hydrated = restored.latest_result(candidate.id)
    assert hydrated is not None and hydrated.to_dict() == latest.to_dict()
    assert hydrated.assessment_binding == latest.assessment_binding
    assert accepted_result(restored, restored.candidates[candidate.id], hydrated, policy)
    assert "fixture-private-secret" not in json.dumps(serialized)
