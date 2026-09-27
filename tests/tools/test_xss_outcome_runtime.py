import json

import pytest

from src.permission.permission import AlwaysAllow
from src.target.target import Target
from src.tools.outcome import ToolOutput
from src.tools.workflow import WorkflowTool
from src.workflow.state import Candidate, WorkflowState


def make_xss_workflow():
    state = WorkflowState()
    candidate, _created = state.add_candidate(Candidate(
        candidate_class="cross-site-scripting",
        target="https://target.test",
        endpoint="/search",
        method="GET",
        parameter="q",
        location="query",
    ))
    tool = WorkflowTool(state, Target("https://target.test"))
    return state, candidate, tool


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "expected_status"),
    [("browser-required", "deferred"), ("not-confirmed", "validated")],
)
async def test_record_result_accepts_canonical_xss_outcomes(outcome, expected_status):
    state, candidate, tool = make_xss_workflow()

    output = await tool.run({
        "action": "record_result",
        "candidate_id": candidate.id,
        "skill_name": "cross-site-scripting",
        "outcome": outcome,
    }, None, AlwaysAllow())

    response = json.loads(output)
    stored = state.latest_result(candidate.id)
    assert response["ok"] is True
    assert response["result"]["outcome"] == outcome
    assert stored is not None
    assert stored.outcome == outcome
    assert candidate.status == expected_status


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome", ["requires-browser-confirmation", "not confirmed"],
)
async def test_record_result_rejects_legacy_noncanonical_xss_outcomes(outcome):
    state, candidate, tool = make_xss_workflow()

    output = await tool.run({
        "action": "record_result",
        "candidate_id": candidate.id,
        "skill_name": "cross-site-scripting",
        "outcome": outcome,
    }, None, AlwaysAllow())

    assert isinstance(output, ToolOutput)
    assert output.status == "error"
    assert output.startswith(f"error: unknown validation outcome: {outcome}")
    assert state.latest_result(candidate.id) is None
