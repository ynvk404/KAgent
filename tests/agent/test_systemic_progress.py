"""Semantic progress regressions; native workflow gates, offline fixtures only."""
from copy import deepcopy
import json

import pytest

from src.agent.agent import WholeTargetStallTracker, ExecutedToolCall, ToolCallResult
from src.tools.common.outcome import ToolOutput
from src.workflow.state import Candidate, ValidationResult, WorkflowObjective, WorkflowState
from tests.benchmarks.test_scenario1 import isolated_project_environment, op, settings, mock_http
from tests.benchmarks.test_scenario1_closure import active_case


async def test_owned_effect_declaration_at_stall_boundary_is_structured_progress(
        tmp_path, op, settings, mock_http):
    agent, policy, cid, aid = await active_case(op, settings, tmp_path, whole=True)
    state = agent.workflow
    tracker = WholeTargetStallTracker(exploration_cap=0)
    tracker.record_iteration(new_facts=state.progress_facts(), activity_fingerprints=[])
    for _ in range(2):
        assert tracker.record_iteration(new_facts=frozenset(), activity_fingerprints=[]) == "no_progress"
    invalid_args = {"action": "record_attempt_state", "candidate_id": cid, "attempt_id": aid,
                    "mutation_state": "unknown", "effect_basis": "x" * 2001, "cleanup_state": "unknown"}
    rejected = await agent.tools.execute("workflow", invalid_args, None, agent.prompter)
    assert isinstance(rejected, ToolOutput) and rejected.status == "error"
    assert tracker.record_validation_batch([ExecutedToolCall("workflow", invalid_args, True,
        ToolCallResult(rejected, str(rejected), 0, status=rejected.status, error_kind=rejected.error_kind))],
        new_facts=frozenset(), target_base_url=None) == "no_progress"
    assert tracker.consecutive_no_progress == 3
    before = state.progress_facts()
    used = policy.used
    output = await agent.tools.execute("workflow", {
        "action": "record_attempt_state", "candidate_id": cid, "attempt_id": aid,
        "mutation_state": "unknown", "effect_basis": "No target action has been dispatched.",
        "cleanup_state": "unknown",
    }, None, agent.prompter)
    assert json.loads(output)["ok"]
    assert policy.used == used + 1 and not mock_http
    assert tracker.record_validation_batch([], new_facts=state.progress_facts() - before,
        target_base_url=None) == "structured_progress"
    assert tracker.consecutive_no_progress == 0
    # Identical or reworded declarations are bookkeeping, not new progress.
    before = state.progress_facts()
    output = await agent.tools.execute("workflow", {
        "action": "record_attempt_state", "candidate_id": cid, "attempt_id": aid,
        "mutation_state": "unknown", "effect_basis": "The same fact, explained differently.",
        "cleanup_state": "unknown",
    }, None, agent.prompter)
    assert json.loads(output)["ok"]
    assert tracker.record_validation_batch([], new_facts=state.progress_facts() - before,
        target_base_url=None) == "no_progress"


async def test_direct_reworded_effect_basis_does_not_change_progress_signature(
        tmp_path, op, settings, mock_http):
    # Start through real Whole-target admission, then inspect the same owned
    # records in Direct projection. Objective identity/binding/rights stay fixed.
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
    signature = agent._requested_goal_progress_signature()
    for basis in ("Same declaration.", "Still no action.", "Another explanation."):
        output = await agent.tools.execute("workflow", {**args, "effect_basis": basis},
                                           None, agent.prompter)
        assert json.loads(output)["ok"]
        assert agent._requested_goal_progress_signature() == signature
    assert not mock_http


def scoped_state():
    state = WorkflowState(objective=WorkflowObjective("objective", "whole_target", "https://fixture.test"))
    candidate, _ = state.add_candidate(Candidate(candidate_class="xss", target="https://fixture.test",
        endpoint="/fixture", method="GET", parameter="q", location="query", objective_id="objective"))
    return state, candidate


def test_cleanup_state_is_progress_but_cleanup_prose_is_not():
    state, candidate = scoped_state()
    result = ValidationResult(candidate.id, "cross-site-scripting", "confirmed",
        mutation_performed=True, cleanup_state="pending", objective_id="objective")
    state.validation_results.append(result)
    tracker = WholeTargetStallTracker(exploration_cap=0)
    tracker.record_iteration(new_facts=state.progress_facts(), activity_fingerprints=[])
    before = state.progress_facts()
    result.cleanup_status = "A changed explanation with the same pending cleanup."
    assert state.progress_facts() == before
    result.cleanup_state = "succeeded"
    assert tracker.record_iteration(new_facts=state.progress_facts() - before,
                                     activity_fingerprints=[]) == "structured_progress"
    # Projection is not acceptance: a synthetic unsealed result grants no finding.
    assert not state.finding_is_persisted(candidate.id)


async def test_attempt_start_counts_once_but_fresh_handles_and_foreign_attempts_do_not(
        tmp_path, op, settings, mock_http):
    agent, _, cid, aid = await active_case(op, settings, tmp_path, whole=True)
    state = agent.workflow
    started = state.attempts.pop(aid)
    before = state.progress_facts()
    state.attempts[aid] = started
    first = state.progress_facts() - before
    assert first, "The committed start must be visible to Whole-target progress."
    tracker = WholeTargetStallTracker(exploration_cap=0)
    assert tracker.record_iteration(new_facts=first, activity_fingerprints=[]) == "structured_progress"
    same = deepcopy(started)
    same["id"] = "attempt_" + "f" * 32
    before = state.progress_facts()
    state.attempts[same["id"]] = same
    assert before == state.progress_facts()
    # An ID change alone has no semantic credit.
    del state.attempts[aid]
    assert state.progress_facts() == before
    same["candidate_binding"] = "stale-binding"
    assert not (state.progress_facts() - (before - first))
    same["candidate_binding"] = started["candidate_binding"]
    same["objective_id"] = "foreign-objective"
    assert not (state.progress_facts() - (before - first))
    assert not mock_http
