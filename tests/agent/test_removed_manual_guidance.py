"""Retiring manual commands preserves the evidence guidance given to the agent."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.agent.decision_planner import PlannerCandidate, PlannerContext, build_decision_plan
from src.agent.system_prompt import BuildOptions, build_system_prompt
from src.engagement.state import EngagementState
from src.permission.runtime.execution import default_execution_policy
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry
from src.target.target import Target
from src.workflow.validation_route import GENERIC_VALIDATOR, ValidationRoute


RETIRED_COMMANDS = ("/review-result", "/enrich-cwe")


@pytest.mark.parametrize("profile", ["base", "compact"])
def test_system_prompt_keeps_finding_contract_without_manual_commands(profile):
    prompt = build_system_prompt(BuildOptions(
        skills=Registry(), thinking_enabled=False, target=Target("https://target.test"),
        prompt_profile=profile,
    ))
    assert "confirm_finding" in prompt and "evidence" in prompt
    assert all(command not in prompt for command in RETIRED_COMMANDS)


@pytest.mark.parametrize("startable", [False, True])
def test_generic_planner_keeps_insufficient_evidence_unresolved(startable):
    candidate = PlannerCandidate(
        "cand_fixture", "future-class", "new" if startable else "deferred",
        latest_outcome=None if startable else "insufficient-evidence", generic_startable=startable,
    )
    context = PlannerContext(candidates=(candidate,),
        validation_routes={candidate.id: ValidationRoute("generic", GENERIC_VALIDATOR)})
    plan = build_decision_plan("continue", [], Target("https://target.test"), context)
    assert plan is not None and plan.candidate_id == candidate.id
    if startable:
        assert "record insufficient-evidence" in plan.guidance
        assert "identify what is missing" in plan.guidance
    else:
        assert "keep the unresolved outcome" in plan.guidance
        assert "Do not report the objective completed" in plan.guidance
    assert all(command not in plan.guidance for command in RETIRED_COMMANDS)


async def test_load_skill_keeps_playbook_and_insufficient_evidence_guidance(tmp_path):
    skills = Registry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    policy = default_execution_policy(EngagementState(), tmp_path)
    body = await LoadSkillTool(skills).run(
        {"name": "sql-injection"}, prompter=SimpleNamespace(execution_policy=policy),
    )
    assert "SQL injection playbook" in body
    assert "If evidence is insufficient, submit insufficient-evidence" in body
    assert "A proof file alone cannot establish target traffic" in body
    assert all(command not in body for command in RETIRED_COMMANDS)
