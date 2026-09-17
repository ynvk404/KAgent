import pytest

from src.agent.decision_planner import (
    INTENT_KEYWORDS,
    build_decision_plan,
    has_host_like_text,
    matching_keywords,
    normalize,
)
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


@pytest.mark.parametrize(
    "text",
    [
        "test SQL injection in server.js",
        "test SQL injection in config.json",
        "test SQL injection with Python 3.12.6",
    ],
)
def test_file_names_and_version_numbers_do_not_count_as_targets(text):
    plan = build_decision_plan(
        text,
        [skill("sql-injection", "Validate SQL injection")],
        Target(),
    )

    assert plan is not None
    assert has_host_like_text(text) is False
    assert "clarify the exact in-scope target" in plan.checklist[0]


@pytest.mark.parametrize(
    "text",
    [
        "test SQL injection on api.example.com",
        "test SQL injection on 127.0.0.1",
        "test SQL injection on https://api.example.com/orders",
    ],
)
def test_hostname_ipv4_and_url_text_count_as_targets(text):
    plan = build_decision_plan(
        text,
        [skill("sql-injection", "Validate SQL injection")],
        Target(),
    )

    assert plan is not None
    assert has_host_like_text(text) is True
    assert "clarify the exact in-scope target" not in "\n".join(plan.checklist)


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


def test_requires_target_for_access_control():
    plan = build_decision_plan(
        "test the orders API for IDOR",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "access-control"
    assert "clarify the exact in-scope target" in plan.checklist[0]


def test_pinned_target_for_access_control():
    target = Target()
    target.set_base_url("https://example.com")

    plan = build_decision_plan(
        "test the orders API for IDOR",
        planner_skills(),
        target,
    )

    assert plan is not None
    assert plan.recommended_skill == "access-control"
    assert (
        "clarify the exact in-scope target"
        not in "\n".join(plan.checklist)
    )


def planner_skills() -> list[Skill]:
    return [
        skill("recon", "Initial reconnaissance of a target"),
        skill(
            "web-enumeration",
            "Enumerate the attack surface of a web application",
        ),
        skill(
            "web-input-analysis",
            "Analyze a web-enumeration inventory for testing candidates",
        ),
        skill(
            "access-control",
            "Validate authorization, IDOR/BOLA, and privilege escalation candidates",
        ),
        skill(
            "authentication",
            "Validate session, login/logout, MFA, and password-reset flows",
        ),
        skill(
            "ssrf",
            "Validate suspected server-side URL fetching and characterize impact",
        ),
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


def test_recommends_access_control_for_idor():
    plan = build_decision_plan(
        "test the orders API for IDOR",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "access-control"


def test_recommends_access_control_for_bola():
    plan = build_decision_plan(
        "check the orders API for BOLA",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "access-control"


def test_recommends_access_control_for_horizontal_privilege_escalation():
    # Deliberately avoids the word "endpoint", which is a strong
    # web-enumeration keyword and would tie 5-5 with access-control's
    # "horizontal privilege escalation" hit, only resolved by alphabetical
    # tie-break in confidence_check(). This test should isolate the
    # access-control signal on its own.
    plan = build_decision_plan(
        "test horizontal privilege escalation on the orders resource",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "access-control"


def test_horizontal_privilege_escalation_and_endpoint_is_alphabetical_tie_break():
    # Documents a real tie: "horizontal privilege escalation" (strong,
    # access-control) and "endpoint" (strong, web-enumeration) both score
    # 5 with strong_count 1. access-control wins only because
    # "access-control" < "web-enumeration" alphabetically in
    # confidence_check()'s tie-break, not because of keyword specificity.
    plan = build_decision_plan(
        "test horizontal privilege escalation on the orders endpoint",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "access-control"


def test_recommends_access_control_for_vertical_privilege_escalation():
    plan = build_decision_plan(
        "verify vertical privilege escalation on the admin endpoint",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "access-control"


def test_access_control_keyword_is_not_double_counted():
    hits = matching_keywords(
        normalize("test access-control on this endpoint"),
        INTENT_KEYWORDS["access_control"]["strong"],
    )

    assert hits == ["access control"]


def test_access_control_keyword_normalization_is_consistent():
    assert normalize("access-control") == "access control"
    assert normalize("access_control") == "access control"
    assert normalize("Access   Control") == "access control"


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


def test_recommends_authentication_for_session_fixation():
    plan = build_decision_plan(
        "test for session fixation and session invalidation after login",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "authentication"


def test_recommends_authentication_for_mfa_bypass():
    plan = build_decision_plan(
        "check for mfa bypass and otp bypass in the login flow",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "authentication"


def test_recommends_authentication_for_password_reset():
    plan = build_decision_plan(
        "verify the password reset flow for a reset token bypass",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "authentication"


def test_recommends_authentication_for_user_enumeration():
    plan = build_decision_plan(
        "check for user enumeration and account enumeration on login",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "authentication"


def test_credential_stuffing_does_not_recommend_authentication():
    plan = build_decision_plan(
        "test credential stuffing against the login form",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill != "authentication"


def test_idor_still_recommends_access_control():
    plan = build_decision_plan(
        "test IDOR on the orders API",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "access-control"


def test_authorization_bypass_still_recommends_access_control():
    plan = build_decision_plan(
        "check for authorization bypass on the admin resource",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "access-control"


def test_recommends_ssrf_for_ssrf_keyword():
    plan = build_decision_plan(
        "test this parameter for ssrf",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "ssrf"


def test_recommends_ssrf_for_server_side_request_forgery_spelled_out():
    plan = build_decision_plan(
        "check for server-side request forgery on the webhook field",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "ssrf"


def test_recommends_ssrf_for_server_side_request_forgery_no_hyphen():
    # Confirms both the hyphenated and spaced-out strong keyword variants
    # are registered, not just one spelling.
    plan = build_decision_plan(
        "investigate a server side request forgery report",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "ssrf"


def test_ssrf_weak_keywords_alone_do_not_route_to_ssrf():
    # "image url" and "callback url" are weak-only signals. Weak hits
    # without any strong hit must never clear confidence_check()'s
    # strong_count > 0 requirement — url-shaped input alone should not
    # force routing into ssrf ahead of web-input-analysis triage.
    plan = build_decision_plan(
        "the image url parameter looks like a callback url candidate",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill != "ssrf"


def test_endpoint_with_url_does_not_route_to_ssrf_over_web_enumeration():
    # A bare "endpoint ... url" mention should still favor
    # web-enumeration's strong "endpoint" keyword, not get pulled into
    # ssrf via the weak "url fetch"-adjacent wording.
    plan = build_decision_plan(
        "endpoint takes a url",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill == "web-enumeration"


def test_ssrf_does_not_bleed_into_webhook_alone():
    # "webhook" alone is a weak ssrf keyword. Without a strong hit it
    # must not be enough to recommend ssrf by itself. Note: the original
    # version of this test used a message with no WORKFLOW_TERMS hit and
    # no known target, which correctly returns None entirely (same as
    # test_stays_quiet_for_low_signal_greetings) rather than a plan with
    # no recommendation — "check" is added here so a plan is actually
    # produced for the assertion below to be meaningful.
    plan = build_decision_plan(
        "check the webhook field on this form",
        planner_skills(),
        Target(),
    )

    assert plan is not None
    assert plan.recommended_skill != "ssrf"
