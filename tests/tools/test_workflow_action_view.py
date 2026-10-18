"""Objective advertising stays distinct from production dispatch authority."""
from copy import deepcopy
import json
from typing import Any, cast

import pytest

from src.permission.permission import AlwaysAllow
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.workflow.action_view import ActionView, WHOLE_TARGET_ACTIONS
from src.tools.workflow.workflow_tool import ACTIONS, ACTION_INPUTS, ACTION_REQUIRED, WorkflowTool
from src.workflow.state import AttackSurfaceInput, Candidate, WorkflowObjective, WorkflowState, candidate_fingerprint
from src.workflow.assessment import candidate_binding

ORIGIN = "https://fixture.test"


@pytest.mark.parametrize("mode", [None, "unknown", "generic", "whole_target", "direct", "candidate_validation"])
def test_complete_matrix_and_copy_projection(mode):
    view = ActionView.for_objective(mode)
    excluded = WHOLE_TARGET_ACTIONS if mode in {"direct", "candidate_validation"} else set()
    tool = WorkflowTool(WorkflowState())
    registry = Registry()
    registry.register(tool)
    specs = registry.as_llm_tools()
    original = deepcopy(specs)
    projected = view.project_tools(specs)
    assert specs == original and tool.schema() == cast(Any, original)[0]["function"]["parameters"]
    assert projected is not None
    schema = projected[0]["function"]["parameters"]
    action_field = schema["properties"]["action"]
    assert {'select_source', 'get_source', 'get_endpoint', 'set_source_disposition'} <= set(ACTIONS)
    assert ACTION_REQUIRED['triage_scanner_results'] == ('job_id', 'scanner_disposition', 'scanner_reason')
    assert "record_attempt_state" in view.available
    assert ACTION_REQUIRED["record_attempt_state"] == ("candidate_id", "mutation_state", "effect_basis")
    assert set(view.excluded) == excluded
    assert action_field["enum"] == [a for a in ACTIONS if a not in excluded]
    rows = action_field["description"].splitlines()[1:]
    assert [row.partition("(")[0] for row in rows] == action_field["enum"]
    for action, row in zip(view.available, rows):
        fields = row.partition("(")[2][:-1].split(",")
        assert {f.rstrip("*") for f in fields if f} == set(ACTION_INPUTS[action]) & schema["properties"].keys()
        assert {f.rstrip("*") for f in fields if f.endswith("*")} == set(ACTION_REQUIRED.get(action, ()))
    assert len(json.dumps(projected)) <= len(json.dumps(original))
    assert "get_input" in view.available and view.project_tools(None) is None


@pytest.mark.parametrize("mode", ["direct", "candidate_validation"])
@pytest.mark.parametrize("args", [
    {"action": "record_input", "endpoint": "/search"},
    {"action": "set_input_disposition", "input_id": "input-fixture", "disposition": "analyzed"},
    {"action": "link_input_candidate", "input_id": "input-fixture", "candidate_id": "candidate-fixture"},
    {"action": "record_phase_coverage", "phase": "recon", "coverage_dimension": "passive_observation", "coverage_status": "skipped", "coverage_reason": "bounded fixture"},
    {"action": "review_no_candidate", "goal_id": "goal-fixture"},
])
async def test_excluded_calls_still_reach_existing_runtime_rejection(mode, args):
    candidate = Candidate(candidate_class="sqli", objective_id="objective-fixture", target=ORIGIN, endpoint="/search")
    state = WorkflowState(objective=WorkflowObjective("objective-fixture", mode, ORIGIN, candidate_id=candidate.id if mode == "candidate_validation" else None))
    item = AttackSurfaceInput(objective_id="objective-fixture", target_origin=ORIGIN, endpoint="/search",
                              method="GET", parameter="q", location="query")
    state.attack_surface_inputs[item.id] = item
    state.candidates[candidate.id] = candidate
    args = {**args}
    if "input_id" in args:
        args["input_id"] = item.id
    if "candidate_id" in args:
        args["candidate_id"] = candidate.id
    registry = Registry()
    registry.register(WorkflowTool(state, Target(ORIGIN)))
    before = state.to_dict()
    output = await registry.execute("workflow", args, None, AlwaysAllow())
    assert output.startswith("error:")
    assert state.to_dict() == before
    assert args["action"] in ActionView.for_objective(mode).excluded


@pytest.mark.parametrize("mode", ["direct", "candidate_validation"])
async def test_valid_calls_including_owned_get_input_remain_available(mode):
    candidate = Candidate(candidate_class="sqli", objective_id="objective-fixture", target=ORIGIN, endpoint="/search")
    state = WorkflowState(objective=WorkflowObjective("objective-fixture", mode, ORIGIN, candidate_id=candidate.id if mode == "candidate_validation" else None))
    item = AttackSurfaceInput(objective_id="objective-fixture", target_origin=ORIGIN, endpoint="/search",
                              method="GET", parameter="q", location="query")
    state.attack_surface_inputs[item.id] = item
    state.candidates[candidate.id] = candidate
    registry = Registry()
    registry.register(WorkflowTool(state, Target(ORIGIN)))
    for args in ({"action": "get_input", "input_id": item.id},
                 {"action": "record_candidate", "candidate_class": "sqli", "endpoint": "/search"},
                 {"action": "list"}):
        output = json.loads(await registry.execute("workflow", args, None, AlwaysAllow()))
        assert output["ok"] is True
        assert args["action"] in ActionView.for_objective(mode).available


def assigned_fixture(origin_mode, legacy=False):
    original = WorkflowObjective("original-objective", origin_mode, ORIGIN)
    state = WorkflowState(objective=original)
    assigned, _ = state.add_candidate(Candidate("sqli", target=ORIGIN, endpoint="/search", method="POST",
        parameter="q", location="json", objective_id=original.id, baseline_request_ref="baseline-fixture",
        auth_context_ref="auth-fixture", content_type="application/json",
        request_template='{"q":"{INJECTION_POINT}","keep":1}', source_ref="capture-fixture"))
    if legacy:
        row = assigned.to_dict()
        row["id"] = candidate_fingerprint(candidate_class=assigned.candidate_class, target=assigned.target,
            endpoint=assigned.endpoint, method=assigned.method, parameter=assigned.parameter,
            location=assigned.location, objective_id=assigned.objective_id)
        row["identity_media_type"] = ""
        hydrated = Candidate.from_dict(row)
        assert hydrated is not None
        state.candidates = {hydrated.id: hydrated}
        assigned = hydrated
    state.objective = WorkflowObjective("assigned-objective", "candidate_validation", ORIGIN, candidate_id=assigned.id)
    registry = Registry()
    registry.register(WorkflowTool(state, Target(ORIGIN)))
    return registry, state, assigned


@pytest.mark.parametrize("origin_mode", ["direct", "whole_target"])
@pytest.mark.parametrize("legacy", [False, True])
async def test_cv_rerecord_preserves_assigned_identity_context_and_legacy_links(origin_mode, legacy):
    registry, state, assigned = assigned_fixture(origin_mode, legacy)
    binding = candidate_binding(assigned)
    # Omitted request context remains attached to the assigned input. The
    # model can enrich annotations without rekeying its old objective/links.
    output = json.loads(await registry.execute("workflow", {"action": "record_candidate",
        "candidate_class": "sql-injection", "signals": ["Bounded repeat annotation"]}, None, AlwaysAllow()))
    assert output["ok"] and not output["created"] and output["candidate"]["id"] == assigned.id
    assert state.candidates == {assigned.id: assigned}
    assert candidate_binding(assigned) == binding and assigned.objective_id == "original-objective"
    assert assigned.baseline_request_ref == "baseline-fixture" and assigned.auth_context_ref == "auth-fixture"
    assert assigned.source_ref == "capture-fixture" and "{INJECTION_POINT}" in (assigned.request_template or "")
    assert not state.attempts and not state.validation_results


@pytest.mark.parametrize("origin_mode", ["direct", "whole_target"])
@pytest.mark.parametrize("change", [
    {"endpoint": "/other"}, {"method": "GET"}, {"parameter": "other"}, {"location": "query"},
    {"candidate_class": "xss"}, {"test_case": "different-test"},
    {"baseline_request_ref": "different-baseline"}, {"auth_context_ref": "different-auth"},
    {"source_ref": "different-capture"}, {"request_template": '{"q":"{INJECTION_POINT}","keep":2}'},
    {"content_type": "text/plain"}, {"target": "https://outside.invalid"},
])
async def test_cv_rejects_different_assigned_input_or_context_without_shadow(origin_mode, change):
    registry, state, assigned = assigned_fixture(origin_mode)
    before = deepcopy(state.to_dict())
    result = await registry.execute("workflow", {"action": "record_candidate",
        "candidate_class": "sqli", **change}, None, AlwaysAllow())
    assert result.startswith("error:") and state.to_dict() == before
    assert state.candidates == {assigned.id: assigned}


async def test_cv_rerecord_refuses_changed_scope_without_mutating_assigned_candidate():
    registry, state, _ = assigned_fixture("direct")
    assert state.objective is not None
    state.objective.target_origin = "https://outside.invalid:443"
    before = deepcopy(state.to_dict())
    result = await registry.execute("workflow", {"action": "record_candidate", "candidate_class": "sqli"}, None, AlwaysAllow())
    assert result.startswith("error:") and state.to_dict() == before
