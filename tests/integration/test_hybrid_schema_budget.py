"""Check objective-specific tool projection and action guidance."""

from src.agent.action_guidance import render_action_guidance
from src.agent.context_estimate import text_tokens
from src.agent.decision_planner import PlannerCandidate, PlannerContext
from src.tools.workflow.action_view import ActionView
from tests.integration.test_tool_schema_budget import _default_tool_registry


def test_projected_default_inventory_and_guidance_budgets(tmp_path):
    full = []
    for spec in _default_tool_registry(tmp_path).as_llm_tools():
        assert isinstance(spec, dict)
        full.append(spec)
    for mode in (None, "whole_target", "direct", "candidate_validation"):
        view = ActionView.for_objective(mode)
        projected = view.project_tools(full)
        assert projected is not None
        workflows = [spec for spec in projected if spec["function"]["name"] == "workflow"]
        assert len(workflows) == 1
        action_schema = workflows[0]["function"]["parameters"]["properties"]["action"]
        assert action_schema["enum"] == list(view.available)
        assert [spec for spec in projected if spec["function"]["name"] != "workflow"] == [
            spec for spec in full if spec["function"]["name"] != "workflow"
        ]
        fixtures = [PlannerContext(objective_mode=mode),
            PlannerContext(objective_mode=mode, candidates=(PlannerCandidate("fixture", "sqli", "validating", coverage_synced=False),)),
            PlannerContext(objective_mode=mode, candidates=(PlannerCandidate("fixture", "open-redirect", "deferred", coverage_synced=False),))]
        guidance = [render_action_guidance(view, context) for context in fixtures]
        assert max(map(len, guidance)) <= 1000
        assert max(map(text_tokens, guidance)) + 4 <= 300
