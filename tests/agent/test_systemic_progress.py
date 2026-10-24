"""Canonical lifecycle regressions; native workflow gates, offline fixtures only."""
from copy import deepcopy
import json

from src.tools.common.outcome import ToolOutput
from src.workflow.state import Candidate, ValidationResult, WorkflowObjective, WorkflowState
from tests.benchmarks.test_scenario1 import isolated_project_environment, op, settings, mock_http
from tests.benchmarks.test_scenario1_closure import active_case


async def test_owned_effect_declaration_rejects_invalid_then_commits_without_http(
        tmp_path, op, settings, mock_http):
    agent, policy, cid, aid = await active_case(op, settings, tmp_path, whole=True)
    state = agent.workflow
    before = deepcopy(state.to_dict())
    invalid_args = {"action": "record_attempt_state", "candidate_id": cid, "attempt_id": aid,
                    "mutation_state": "unknown", "effect_basis": "x" * 2001, "cleanup_state": "unknown"}
    rejected = await agent.tools.execute("workflow", invalid_args, None, agent.prompter)
    assert isinstance(rejected, ToolOutput) and rejected.status == "error"
    assert state.to_dict() == before
    used = policy.used
    output = await agent.tools.execute("workflow", {
        "action": "record_attempt_state", "candidate_id": cid, "attempt_id": aid,
        "mutation_state": "unknown", "effect_basis": "No target action has been dispatched.",
        "cleanup_state": "unknown",
    }, None, agent.prompter)
    assert json.loads(output)["ok"]
    assert policy.used == used + 1 and not mock_http
    declaration = state.attempts[aid]["effects"]["declaration"]
    assert declaration["mutation_state"] == declaration["cleanup_state"] == "unknown"
    output = await agent.tools.execute("workflow", {
        "action": "record_attempt_state", "candidate_id": cid, "attempt_id": aid,
        "mutation_state": "unknown", "effect_basis": "The same fact, explained differently.",
        "cleanup_state": "unknown",
    }, None, agent.prompter)
    assert json.loads(output)["ok"]
    assert state.attempts[aid]["effects"]["declaration"]["mutation_state"] == "unknown"
    assert not state.validation_results and not state.persisted_findings
    assert WorkflowState.from_dict(state.to_dict()).attempts[aid]["effects"] == state.attempts[aid]["effects"]


async def test_direct_reworded_effect_basis_preserves_owned_effect_state(
        tmp_path, op, settings, mock_http):
    # Start through real Whole-target admission, then inspect the same owned
    # records in Direct mode. Objective identity/binding/rights stay fixed.
    agent, _, cid, aid = await active_case(op, settings, tmp_path, whole=True)
    objective = agent.workflow.objective
    assert objective is not None
    objective.mode = "direct"
    goal = objective.add_requested_goal("cross-site-scripting")
    agent.workflow.link_requested_goal_candidate(goal.id, cid)
    args = {"action": "record_attempt_state", "candidate_id": cid, "attempt_id": aid,
            "mutation_state": "unknown", "cleanup_state": "unknown"}
    output = await agent.tools.execute("workflow", {**args, "effect_basis": "No dispatched action."},
                                       None, agent.prompter)
    assert json.loads(output)["ok"]
    for basis in ("Same declaration.", "Still no action.", "Another explanation."):
        output = await agent.tools.execute("workflow", {**args, "effect_basis": basis},
                                           None, agent.prompter)
        assert json.loads(output)["ok"]
        attempt = agent.workflow.attempts[aid]
        declaration = attempt["effects"]["declaration"]
        assert attempt["status"] == "active" and attempt["candidate_id"] == cid
        assert declaration["mutation_state"] == declaration["cleanup_state"] == "unknown"
        assert not declaration["observation_ids"] and not attempt["effects"]["dispatches"]
    assert not mock_http and not agent.workflow.validation_results


def scoped_state():
    state = WorkflowState(objective=WorkflowObjective("objective", "whole_target", "https://fixture.test"))
    candidate, _ = state.add_candidate(Candidate(candidate_class="xss", target="https://fixture.test",
        endpoint="/fixture", method="GET", parameter="q", location="query", objective_id="objective"))
    return state, candidate


def test_cleanup_and_prose_preserve_assessment_identity_without_granting_acceptance():
    from src.workflow.state import validation_result_fingerprint
    state, candidate = scoped_state()
    result = ValidationResult(candidate.id, "cross-site-scripting", "confirmed",
        mutation_performed=True, cleanup_state="pending", objective_id="objective")
    state.validation_results.append(result)
    identity = validation_result_fingerprint(result)
    result.cleanup_status = "A changed explanation with the same pending cleanup."
    assert result.cleanup_state == "pending" and validation_result_fingerprint(result) == identity
    result.cleanup_state = "succeeded"
    assert validation_result_fingerprint(result) == identity
    # Projection is not acceptance: a synthetic unsealed result grants no finding.
    assert not state.finding_is_persisted(candidate.id)


async def test_attempt_start_has_canonical_owner_and_round_trips_without_authority(
        tmp_path, op, settings, mock_http):
    agent, _, cid, aid = await active_case(op, settings, tmp_path, whole=True)
    state = agent.workflow
    started = state.attempts[aid]
    assert state.objective is not None
    assert started["candidate_id"] == cid and started["objective_id"] == state.objective.id
    assert started["status"] == "active" and not started.get("probing_stopped")
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.attempts[aid]["candidate_binding"] == started["candidate_binding"]
    assert restored.attempts[aid]["status"] == "interrupted"
    assert not restored.validation_results and not restored.persisted_findings
    assert not mock_http
