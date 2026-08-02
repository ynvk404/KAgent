import pytest

from src.agent.decision_planner import build_decision_plan
from target.target import Target
from skills.registry import Skill


def skill(name: str, description: str) -> Skill:
    return Skill(
        name=name,
        description=description,
        tools=[],
        disable_model_invocation=False,
        path=f"/tmp/{name}/SKILL.md",
        body="",
    )


def test_stays_quiet_for_low_signal_greetings():
    plan = build_decision_plan(
        "hello",
        [
            skill("recon", "External recon playbook for subdomain enumeration"),
            skill("webvuln", "Web vulnerability hunting playbook"),
        ],
        Target(),
    )

    assert plan is None


def test_recommends_recon():
    plan = build_decision_plan(
        "enumerate subdomains and fingerprint live hosts for example.com",
        [
            skill("recon", "External recon playbook for subdomain enumeration"),
            skill("webvuln", "Web vulnerability hunting playbook"),
        ],
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "recon"
    assert "load the recon skill" in plan.guidance


def test_recommends_webvuln():
    plan = build_decision_plan(
        "hunt IDOR and auth bugs on the orders API",
        [
            skill("recon", "External recon playbook for subdomain enumeration"),
            skill("webvuln", "Web vulnerability hunting playbook for IDOR and auth flaws"),
        ],
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "webvuln"


def test_marks_high_risk():
    plan = build_decision_plan(
        "run nuclei and ffuf against https://example.com",
        [
            skill("webvuln", "Web vulnerability hunting playbook"),
        ],
        Target(),
    )

    assert plan is not None
    assert plan.risk == "high"
    assert (
        "ask before scanner-like, destructive, or high-volume actions"
        in plan.checklist
    )


def test_requires_target():
    plan = build_decision_plan(
        "test the orders API for IDOR",
        [
            skill("webvuln", "Web vulnerability hunting playbook"),
        ],
        Target(),
    )

    assert plan is not None
    assert "clarify the exact in-scope target" in plan.checklist[0]


def test_pinned_target():
    target = Target()
    target.set_base_url("https://example.com")

    plan = build_decision_plan(
        "test the orders API for IDOR",
        [
            skill("webvuln", "Web vulnerability hunting playbook"),
        ],
        target,
    )

    assert plan is not None
    assert (
        "clarify the exact in-scope target"
        not in "\n".join(plan.checklist)
    )