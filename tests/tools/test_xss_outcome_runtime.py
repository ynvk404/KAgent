import json

import pytest
from tests.helpers.workflow import run_workflow_fixture

from src.permission.permission import AlwaysAllow
from src.target.target import Target
from src.tools.common.outcome import ToolOutput
from src.tools.workflow.workflow_tool import WorkflowTool
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
async def test_record_result_accepts_canonical_xss_outcomes(outcome, expected_status, tmp_path):
    state, candidate, tool = make_xss_workflow()
    tool.evidence_root = tmp_path
    (tmp_path / "bounded-proof.md").write_text("Bounded offline response interpretation")
    ref = json.loads(await tool.run({"action": "record_evidence", "candidate_id": candidate.id,
        "evidence_path": "bounded-proof.md"}, None, AlwaysAllow()))["evidence"]["id"]

    output = await run_workflow_fixture(tool, {
        "action": "record_result",
        "candidate_id": candidate.id,
        "skill_name": "cross-site-scripting",
        "outcome": outcome,
        "evidence_refs": [ref],
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

    output = await run_workflow_fixture(tool, {
        "action": "record_result",
        "candidate_id": candidate.id,
        "skill_name": "cross-site-scripting",
        "outcome": outcome,
    }, None, AlwaysAllow())

    assert isinstance(output, ToolOutput)
    assert output.status == "error"
    assert output.startswith(f"error: unknown validation outcome: {outcome}")
    assert state.latest_result(candidate.id) is None
