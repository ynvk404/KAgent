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
from src.workflow.state import AttackSurfaceInput, Candidate, WorkflowObjective, WorkflowState

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
    assert len(ACTIONS) == 13
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
    item = AttackSurfaceInput(objective_id="objective-fixture", target_origin=ORIGIN, endpoint="/search")
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
    item = AttackSurfaceInput(objective_id="objective-fixture", target_origin=ORIGIN, endpoint="/search")
    state.attack_surface_inputs[item.id] = item
    registry = Registry()
    registry.register(WorkflowTool(state, Target(ORIGIN)))
    for args in ({"action": "get_input", "input_id": item.id},
                 {"action": "record_candidate", "candidate_class": "sqli", "endpoint": "/search"},
                 {"action": "list"}):
        output = json.loads(await registry.execute("workflow", args, None, AlwaysAllow()))
        assert output["ok"] is True
        assert args["action"] in ActionView.for_objective(mode).available
