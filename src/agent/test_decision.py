import pytest

from src.agent.decision_planner import build_decision_plan
from src.target.target import Target
from src.skills.registry import Skill


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
            skill("recon", "Initial reconnaissance of a target"),
            skill("web-enumeration", "Enumerate the attack surface of a web application"),
        ],
        Target(),
    )

    assert plan is None


def test_recommends_recon():
    plan = build_decision_plan(
        "enumerate subdomains and fingerprint live hosts for example.com",
        [
            skill("recon", "Initial reconnaissance of a target"),
            skill("web-enumeration", "Enumerate the attack surface of a web application"),
        ],
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "recon"
    assert "load the recon skill" in plan.guidance


def test_recommends_web_enumeration():
    plan = build_decision_plan(
        "enumerate the endpoints and routes and api entry points for this app",
        [
            skill("recon", "Initial reconnaissance of a target"),
            skill("web-enumeration", "Enumerate the attack surface of a web application"),
        ],
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "web-enumeration"


def test_marks_high_risk():
    plan = build_decision_plan(
        "run nuclei and ffuf against https://example.com",
        [
            skill("web-enumeration", "Enumerate the attack surface of a web application"),
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
            skill("web-enumeration", "Enumerate the attack surface of a web application"),
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
            skill("web-enumeration", "Enumerate the attack surface of a web application"),
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
        skill("recon", "Initial reconnaissance of a target"),
        skill("web-enumeration", "Enumerate the attack surface of a web application"),
        skill("web-input-analysis", "Analyze a web-enumeration inventory for testing candidates"),
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


def test_recommends_web_enumeration_for_endpoints_and_routes():
    plan = build_decision_plan(
        "map the target's endpoints and routes",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "web-enumeration"


def test_recommends_web_input_analysis_for_candidate_triage():
    plan = build_decision_plan(
        "triage the input analysis candidates for suspected vulnerability class",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "web-input-analysis"


def test_recommends_recon_for_subdomain_enumeration():
    plan = build_decision_plan(
        "enumerate subdomains and check crt for this apex domain",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "recon"


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
        "check the api parameter and form values",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill is None


def test_single_strong_keyword_recommends_web_enumeration():
    plan = build_decision_plan(
        "endpoints",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "web-enumeration"


def test_known_target_scan_target_does_not_route_to_web_enumeration():
    target = Target()
    target.set_base_url("http://juice.lab:3000")

    plan = build_decision_plan(
        "scan target http://juice.lab:3000",
        planner_skills(),
        target,
    )

    assert plan is not None
    assert plan.recommended_skill != "web-enumeration"
    assert plan.recommended_skill is None


def test_tie_break_uses_alphabetical_skill_name_not_registry_order():
    plan = build_decision_plan(
        "recon endpoints",
        [
            skill("web-enumeration", "Enumerate the attack surface of a web application"),
            skill("recon", "Initial reconnaissance of a target"),
        ],
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "recon"