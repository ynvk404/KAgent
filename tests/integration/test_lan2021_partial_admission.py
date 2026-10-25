"""Per-input handoff regressions; no target/provider or historical-state mutation."""
import json

import pytest

from tests.agent.test_workflow_request_preparation import setup
from tests.integration.test_trial1_phase_admission import (
    action,
    linked,
    phases,
    runtime,
)


@pytest.mark.parametrize("late", [False, True])
async def test_independent_blocker_does_not_gate_analyzed_candidate(tmp_path, late):
    tool = runtime(tmp_path)
    await phases(tool)
    item, candidate = await linked(tool)
    path = tmp_path / tool.phase_completion_readiness("web-input-analysis")["artifact_ref"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Analyzed public candidate; private operation remains untested, awaiting credentials.")
    if late:
        assert json.loads(await action(tool, "complete_skill", skill_name="web-input-analysis"))["ok"]
    blocked = json.loads(await action(tool, "record_input", method="POST", endpoint="/private/orders",
        parameter="lines", location="json", input_type="array", content_type="application/json"))["input"]
    await action(tool, "set_input_disposition", input_id=blocked["id"], disposition="blocked",
                 disposition_reason="Required operation credential is unavailable; remains untested.")
    before = tool.state.to_dict()
    assert tool.validation_admission_error(candidate["id"]) is None
    assert tool.state.to_dict() == before
    agent = setup(tmp_path, state=tool.state)
    assert tool.target is not None
    agent.target = tool.target
    agent.tools.tools["workflow"] = tool
    context = agent._planner_context()
    assert context.candidates[0].validation_ready is True
    from src.agent.action_guidance import render_action_guidance
    from src.tools.workflow.action_view import ActionView
    advice = render_action_guidance(ActionView.for_objective("whole_target"), context)
    assert "start_validation" in advice and "independent work" in advice
    assert "Do not ask for exclusion" in advice
    plan = agent._workflow_request_view("continue", agent.tools.as_llm_tools()).decision
    assert plan and plan.candidate_id == candidate["id"]
    assert "start_validation" in plan.guidance
    assert f"candidate:{candidate['id']}" in agent._whole_target_state()[1]
    assert json.loads(await action(tool, "start_validation", candidate_id=candidate["id"]))["ok"]
    assert tool.state.attack_surface_inputs[item["id"]].disposition == "analyzed"
    assert tool.state.attack_surface_inputs[blocked["id"]].disposition == "blocked"
    assert not tool.state.validation_results and not tool.state.evidence and not tool.state.persisted_findings
    assert agent._whole_target_state()[0] != "completed"


async def test_candidate_without_handoff_is_not_advertised_as_actionable(tmp_path):
    tool = runtime(tmp_path)
    await phases(tool)
    _, candidate = await linked(tool)
    blocked = json.loads(await action(tool, "record_input", method="POST", endpoint="/private/orders",
        parameter="lines", location="json"))["input"]
    await action(tool, "set_input_disposition", input_id=blocked["id"], disposition="blocked",
                 disposition_reason="Credential unavailable.")
    agent = setup(tmp_path, state=tool.state)
    assert tool.target is not None
    agent.target = tool.target
    agent.tools.tools["workflow"] = tool
    assert tool.validation_admission_error(candidate["id"]) is not None
    assert f"candidate:{candidate['id']}" not in agent._whole_target_state()[1]
    assert not tool.state.attempts
