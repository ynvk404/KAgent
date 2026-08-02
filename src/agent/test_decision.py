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


def planner_skills() -> list[Skill]:
    return [
        skill("graphql", "GraphQL testing playbook mentioning target safely"),
        skill("recon", "External recon playbook for subdomain enumeration"),
        skill("ssrf", "SSRF testing playbook"),
        skill("webvuln", "Web vulnerability testing playbook"),
        skill("jwt", "JWT authentication testing playbook"),
    ]


def test_scan_target_does_not_recommend_specialized_skill():
    plan = build_decision_plan(
        "scan target",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill is None
    assert (
        plan.reason
        == "no specialized intent detected with sufficient confidence"
    )


def test_recommends_graphql_for_introspection():
    plan = build_decision_plan(
        "test GraphQL introspection endpoint",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "graphql"


def test_recommends_webvuln_for_sql_injection():
    plan = build_decision_plan(
        "test SQL injection login parameter",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "webvuln"


def test_recommends_ssrf_for_webhook_ssrf():
    plan = build_decision_plan(
        "test webhook SSRF",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "ssrf"


def test_nuclei_scan_is_high_risk_without_specialized_intent():
    plan = build_decision_plan(
        "run nuclei scan",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.risk == "high"


def test_weak_common_terms_do_not_accumulate_to_skill():
    plan = build_decision_plan(
        "check the API endpoint query",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill is None


def test_single_strong_keyword_recommends_graphql():
    plan = build_decision_plan(
        "graphql",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "graphql"


def test_known_target_scan_target_does_not_route_to_graphql():
    target = Target()
    target.set_base_url("http://juice.lab:3000")

    plan = build_decision_plan(
        "scan target http://juice.lab:3000",
        planner_skills(),
        target,
    )

    assert plan is not None
    assert plan.recommended_skill != "graphql"
    assert plan.recommended_skill is None


def test_tie_break_uses_alphabetical_skill_name_not_registry_order():
    plan = build_decision_plan(
        "ssrf graphql",
        [
            skill("ssrf", "SSRF testing playbook"),
            skill("graphql", "GraphQL testing playbook"),
        ],
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "graphql"
