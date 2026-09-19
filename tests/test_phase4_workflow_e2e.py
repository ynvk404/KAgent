import json
from pathlib import Path

import pytest

from src.agent.decision_planner import build_decision_plan
from src.llm.types import Message
from src.permission.permission import AlwaysAllow
from src.session.store import Store
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry
from src.target.target import Target
from src.tools.workflow import WorkflowTool
from src.workflow.state import WorkflowState


SKILLS_ROOT = Path(__file__).resolve().parents[1] / "skills"


def shipped_skills() -> Registry:
    registry = Registry()
    registry.load_dir(SKILLS_ROOT)
    return registry


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("user_text", "skill_name", "candidate_class", "endpoint", "parameter"),
    [
        ("Test POST /product parameter id for SQL injection", "sql-injection", "sqli", "/product", "id"),
        ("Check GET /search parameter q for XSS", "cross-site-scripting", "xss", "/search", "q"),
    ],
)
async def test_offline_request_to_confirmed_workflow_handoff(
    user_text,
    skill_name,
    candidate_class,
    endpoint,
    parameter,
):
    skills = shipped_skills()
    plan = build_decision_plan(user_text, skills.list_enabled(), Target())
    assert plan is not None and plan.recommended_skill == skill_name

    body = await LoadSkillTool(skills).run({"name": skill_name})
    assert f"# Skill: {skill_name}" in body

    state = WorkflowState()
    workflow = WorkflowTool(state, Target("https://target.test"))
    candidate_args = {
        "action": "record_candidate",
        "candidate_class": candidate_class,
        "method": user_text.split()[1],
        "endpoint": endpoint,
        "parameter": parameter,
        "source_skill": "web-input-analysis",
        "signals": ["offline deterministic signal"],
    }
    recorded = json.loads(
        await workflow.run(
            candidate_args,
            None,
            AlwaysAllow(),
        )
    )
    candidate_id = recorded["candidate"]["id"]
    duplicate_candidate = json.loads(
        await workflow.run(candidate_args, None, AlwaysAllow())
    )
    assert duplicate_candidate["created"] is False
    assert duplicate_candidate["candidate"]["id"] == candidate_id
    await workflow.run(
        {"action": "start_validation", "candidate_id": candidate_id},
        None,
        AlwaysAllow(),
    )
    result = json.loads(
        await workflow.run(
            {
                "action": "record_result",
                "candidate_id": candidate_id,
                "skill_name": skill_name,
                "outcome": "confirmed",
                "evidence_refs": [f"captures/{skill_name}-1.json"],
                "repeatable": True,
            },
            None,
            AlwaysAllow(),
        )
    )

    assert result["eligible_for_confirm_finding"] is True
    assert state.eligible_for_finding(candidate_id) is True

    duplicate = json.loads(
        await workflow.run(
            {
                "action": "record_result",
                "candidate_id": candidate_id,
                "skill_name": skill_name,
                "outcome": "confirmed",
                "evidence_refs": [f"captures/{skill_name}-1.json"],
                "repeatable": True,
                "notes": "same result, different prose",
            },
            None,
            AlwaysAllow(),
        )
    )
    retest = json.loads(
        await workflow.run(
            {
                "action": "record_result",
                "candidate_id": candidate_id,
                "skill_name": skill_name,
                "outcome": "confirmed",
                "evidence_refs": [f"captures/{skill_name}-1.json"],
                "repeatable": True,
                "force": True,
            },
            None,
            AlwaysAllow(),
        )
    )
    assert duplicate["created"] is False
    assert retest["created"] is True


def test_offline_direct_validation_and_informational_control():
    skills = shipped_skills().list_enabled()
    direct = build_decision_plan(
        "POST /login parameter username test SQL injection",
        skills,
        Target(),
    )
    informational = build_decision_plan("What is SQL injection?", skills, Target())

    assert direct is not None and direct.recommended_skill == "sql-injection"
    assert informational is None or informational.recommended_skill is None


@pytest.mark.asyncio
async def test_offline_resume_preserves_existing_candidate_and_result(tmp_path):
    state = WorkflowState()
    workflow = WorkflowTool(state, Target("https://target.test"))
    recorded = json.loads(
        await workflow.run(
            {"action": "record_candidate", "candidate_class": "idor", "endpoint": "/orders/1"},
            None,
            AlwaysAllow(),
        )
    )
    candidate_id = recorded["candidate"]["id"]
    await workflow.run(
        {
            "action": "record_result",
            "candidate_id": candidate_id,
            "skill_name": "access-control",
            "outcome": "not-confirmed",
        },
        None,
        AlwaysAllow(),
    )

    store = Store.new_with_id(tmp_path, "offline-resume")
    await store.save([Message(role="user", content="continue")], workflow=state)
    loaded = store.load().workflow

    assert candidate_id in loaded.candidates
    assert loaded.latest_result(candidate_id) is not None
    assert loaded.eligible_for_finding(candidate_id) is False
