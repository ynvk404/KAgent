import json
from copy import deepcopy

import pytest

from src.agent.system_prompt import render_workflow
from src.target.target import Target
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.input_view import INPUT_PAGE_BYTES
from src.workflow.state import AttackSurfaceInput, WorkflowObjective, WorkflowState, Candidate

ORIGIN = "https://target.test"


def inventory(count, *, wide=False):
    state = WorkflowState(objective=WorkflowObjective("paging", "whole_target", ORIGIN))
    for i in range(count):
        row = AttackSurfaceInput("paging", ORIGIN, method="GET", endpoint=f"/search/{i}",
            parameter=("字" * 180 if wide else "q"), location="query", input_type="字" * 80 if wide else "text",
            content_type="字" * 200 if wide else None, sample_payload="full-safe-sample-" * 120,
            disposition_reason="字" * 300 if wide else None)
        state.attack_surface_inputs[row.id] = row
    return state, WorkflowTool(state, Target(ORIGIN))


@pytest.mark.parametrize("count", [300, 1000])
def test_complete_bounded_traversal_and_independent_candidate_limit(count):
    state, tool = inventory(count)
    state.add_candidate(Candidate(candidate_class="xss", target=ORIGIN, objective_id="paging"))
    before = deepcopy(state.to_dict())
    response = json.loads(tool._list({"limit": 1}))
    assert response["returned"] == 1
    assert response["inputs_returned"] == 20
    assert response["input_counts"] == dict(total=count, pending=count, blocked=0, analyzed=0, dropped=0)
    cursor = None
    ids = []
    while True:
        args = {"view": "inputs", "input_limit": 25}
        if cursor: args["input_cursor"] = cursor
        raw = tool._list(args)
        assert len(raw.encode()) <= INPUT_PAGE_BYTES
        page = json.loads(raw)
        assert page["inputs_returned"] == len(page["attack_surface_inputs"]) <= 25
        assert "full-safe-sample" not in raw and "sample_payload" not in raw
        ids.extend(row["id"] for row in page["attack_surface_inputs"])
        cursor = page["next_input_cursor"]
        assert page["inputs_complete"] == (cursor is None)
        if not cursor: break
    assert len(ids) == len(set(ids)) == count
    assert set(ids) == set(state.attack_surface_inputs)
    assert state.to_dict() == before
    detail = json.loads(tool._get_input({"input_id": ids[0]}))["input"]
    assert detail["sample_payload"] == state.attack_surface_inputs[ids[0]].sample_payload


def test_unicode_escaping_byte_budget_shrinks_count_without_cutting_json_or_ids():
    state, tool = inventory(100, wide=True)
    raw = tool._list({"view": "inputs", "input_limit": 25})
    page = json.loads(raw)
    assert len(raw.encode()) <= INPUT_PAGE_BYTES
    assert 0 < page["inputs_returned"] < 25
    assert all(row["id"] in state.attack_surface_inputs for row in page["attack_surface_inputs"])


def test_cursor_stable_unrelated_commits_do_not_stale_and_inventory_changes_do():
    state, tool = inventory(40)
    args = {"view": "inputs", "input_limit": 1, "input_disposition": "pending"}
    first = json.loads(tool._list(args))
    cursor = first["next_input_cursor"]
    state.mark_committed()
    state.current_phase = "enumeration"
    assert json.loads(tool._list(args))["next_input_cursor"] == cursor
    second_args = {**args, "input_cursor": cursor}
    assert json.loads(tool._list(second_args))["ok"]
    before = deepcopy(state.to_dict())
    mismatch = tool._list({**second_args, "input_disposition": "blocked"})
    assert "cursor or filter mismatch" in mismatch
    assert state.to_dict() == before
    state.set_input_disposition(first["attack_surface_inputs"][0]["id"], "blocked", reason="needs auth")
    before = deepcopy(state.to_dict())
    assert "stale/invalid input cursor" in tool._list(second_args)
    assert state.to_dict() == before


@pytest.mark.parametrize("mutation", ["add", "remove", "objective", "restore", "reset", "target"])
def test_cursor_cannot_cross_membership_or_owner(mutation):
    state, tool = inventory(40)
    cursor = json.loads(tool._list({"view": "inputs", "input_limit": 1}))["next_input_cursor"]
    if mutation == "add":
        state.add_attack_surface_input(AttackSurfaceInput("paging", ORIGIN, method="GET", endpoint="/late", parameter="q", location="query"))
    elif mutation == "remove": state.attack_surface_inputs.pop(next(iter(state.attack_surface_inputs)))
    elif mutation == "objective": state.objective = WorkflowObjective("other", "whole_target", ORIGIN)
    elif mutation == "restore": tool.state = WorkflowState.from_dict(state.to_dict())
    elif mutation == "reset": state.clear()
    else:
        assert tool.target is not None
        tool.target.set_base_url("https://other.test")
    before = deepcopy(tool.state.to_dict())
    response = tool._list({"view": "inputs", "input_cursor": cursor})
    assert response.startswith("error:")
    assert tool.state.to_dict() == before
    assert not tool.state.attempts and not tool.state.evidence and not tool.state.persisted_findings


def test_pending_rows_visible_before_completed_rows_in_prompt_and_listing():
    state, tool = inventory(50)
    ordered = sorted(state.attack_surface_inputs.values(), key=lambda row: row.id)
    for row in ordered[:-1]: state.set_input_disposition(row.id, "dropped", reason="reviewed irrelevant")
    pending = ordered[-1]
    raw = tool._list({"view": "inputs", "input_limit": 1})
    assert json.loads(raw)["attack_surface_inputs"][0]["id"] == pending.id
    prompt = render_workflow(state)
    assert "pending=1" in prompt and "dropped=49" in prompt and pending.id in prompt
    assert "full-safe-sample" not in prompt


@pytest.mark.parametrize("args", [{"input_limit": 0}, {"input_limit": 26}, {"input_limit": True},
    {"input_cursor": "garbage"}, {"input_disposition": "foreign"}, {"view": "foreign"}])
def test_invalid_paging_arguments_are_read_only(args):
    state, tool = inventory(2)
    before = deepcopy(state.to_dict())
    assert tool._list({"view": "inputs", **args}).startswith("error:")
    assert state.to_dict() == before
