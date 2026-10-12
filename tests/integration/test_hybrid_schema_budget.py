"""Measure the established default inventory; never relax its budget caps."""
import json

from src.agent.action_guidance import render_action_guidance
from src.agent.context_estimate import schema_tokens, text_tokens
from src.agent.decision_planner import PlannerCandidate, PlannerContext
from src.tools.common.registry import Registry
from src.tools.workflow.action_view import ActionView
from tests.integration.test_tool_schema_budget import test_default_tool_schema_budget_is_measured_and_bounded as measure_default


def test_projected_default_inventory_and_guidance_budgets(tmp_path, monkeypatch):
    captured = []
    original = Registry.schema_metrics

    def metrics(registry):
        captured.append(registry.as_llm_tools())
        return original(registry)

    monkeypatch.setattr(Registry, "schema_metrics", metrics)
    measure_default(tmp_path)
    full = captured[0]
    measurements = {}
    for mode in (None, "whole_target", "direct", "candidate_validation"):
        projected = ActionView.for_objective(mode).project_tools(full)
        assert projected is not None
        body = json.dumps(projected, ensure_ascii=False, separators=(",", ":"))
        # Match Registry.schema_metrics(), including list commas/brackets.
        characters = len(body)
        assert characters < 28000 and characters // 4 < 7000
        assert len(body) <= len(json.dumps(full, ensure_ascii=False, separators=(",", ":")))
        assert sum(spec["function"]["name"] == "workflow" for spec in projected) == 1
        fixtures = [PlannerContext(objective_mode=mode),
            PlannerContext(objective_mode=mode, candidates=(PlannerCandidate("fixture", "sqli", "validating", coverage_synced=False),)),
            PlannerContext(objective_mode=mode, candidates=(PlannerCandidate("fixture", "open-redirect", "deferred", coverage_synced=False),))]
        guidance = [render_action_guidance(ActionView.for_objective(mode), context) for context in fixtures]
        assert max(map(len, guidance)) <= 1000
        assert max(map(text_tokens, guidance)) + 4 <= 300
        measurements[str(mode)] = {"schema_characters": characters, "approx_schema_tokens": characters // 4,
            "request_schema_estimate": schema_tokens(projected), "guidance_max_characters": max(map(len, guidance)),
            "guidance_max_incremental_tokens": max(map(text_tokens, guidance)) + 4}
    print(json.dumps(measurements, sort_keys=True))
