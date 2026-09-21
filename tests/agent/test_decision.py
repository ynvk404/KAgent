from __future__ import annotations

from pathlib import Path

import pytest

from src.agent.decision_planner import (
    PlannerContext,
    build_decision_plan,
    contains_keyword,
    has_host_like_text,
    is_purely_informational,
    normalize,
)
from src.skills.registry import Registry, Skill, SkillTriggers
from src.target.target import Target
from src.workflow.state import Candidate, WorkflowState


SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills"


def shipped_skills() -> list[Skill]:
    registry = Registry()
    registry.load_dir(SKILLS_ROOT)
    return registry.list_enabled()


def metadata_skill(
    name: str,
    *,
    strong: list[str] | None = None,
    weak: list[str] | None = None,
    candidate_classes: list[str] | None = None,
    requires: list[str] | None = None,
    disable_model_invocation: bool = False,
) -> Skill:
    return Skill(
        name=name,
        description=f"Test skill {name}",
        tools=[],
        disable_model_invocation=disable_model_invocation,
        path=f"/tmp/{name}/SKILL.md",
        body="",
        stage="validation",
        triggers=SkillTriggers(strong=strong or [], weak=weak or []),
        candidate_classes=candidate_classes or [],
        requires=requires or [],
    )


def planned_skill(text: str, skills: list[Skill] | None = None) -> str | None:
    plan = build_decision_plan(
        text,
        shipped_skills() if skills is None else skills,
        Target(),
    )
    return None if plan is None else plan.recommended_skill


def test_stays_quiet_for_low_signal_greeting():
    assert build_decision_plan("hello", shipped_skills(), Target()) is None


def test_explicit_skill_name_has_strong_preference():
    assert planned_skill(
        "Use web-input-analysis for these parameters",
    ) == "web-input-analysis"


@pytest.mark.parametrize(
    "text",
    [
        "What is SQL injection?",
        "Explain XSS",
        "Define SSRF",
        "What is CSRF?",
        "What is the difference between IDOR and BOLA?",
        "How does server-side template injection work?",
    ],
)
def test_informational_security_questions_do_not_recommend_validation_skills(text):
    assert planned_skill(text) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Test parameter id for SQL injection", "sql-injection"),
        ("Check this endpoint for XSS", "cross-site-scripting"),
        ("How do I test this request for SQL injection?", "sql-injection"),
        ("Explain SQL injection and test parameter id", "sql-injection"),
    ],
)
def test_operational_action_overrides_informational_wording(text, expected):
    assert planned_skill(text) == expected


def test_informational_classifier_is_generic_not_vulnerability_specific():
    assert is_purely_informational("explain a made up future vulnerability")
    assert not is_purely_informational("explain it then validate this request")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("test this id parameter for SQL injection", "sql-injection"),
        ("check whether q has reflected XSS", "cross-site-scripting"),
        ("validate the webhook parameter for SSRF", "ssrf"),
        ("check this template expression for SSTI", "ssti"),
        ("investigate session fixation after login", "authentication"),
        ("test the order id for horizontal privilege escalation", "access-control"),
        ("check this state changing request for CSRF", "csrf"),
        ("enumerate subdomains and fingerprint live hosts", "recon"),
        ("enumerate endpoints and routes for the app", "web-enumeration"),
        ("triage input candidates by suspected vulnerability class", "web-input-analysis"),
    ],
)
def test_shipped_metadata_routes_current_workflows(text, expected):
    assert planned_skill(text) == expected


@pytest.mark.parametrize(
    ("alias", "expected"),
    [
        ("sqli", "sql-injection"),
        ("xss", "cross-site-scripting"),
        ("idor", "access-control"),
        ("bola", "access-control"),
    ],
)
def test_candidate_class_aliases_are_normalized(alias, expected):
    assert planned_skill(f"validate candidate class {alias}") == expected


@pytest.mark.parametrize(
    "text",
    [
        "Test this endpoint for SQL injection and XSS",
        "Test this endpoint for sqli and cross-site-scripting",
    ],
)
def test_canonical_and_alias_explicit_references_are_semantically_tied(text):
    assert planned_skill(text) is None


def test_aliases_are_explicit_candidate_references_not_skill_specific_routes():
    access = metadata_skill("object-validator", candidate_classes=["access-control"])
    sql = metadata_skill("database-validator", candidate_classes=["sql-injection"])

    assert planned_skill("validate idor", [access, sql]) == "object-validator"
    assert planned_skill("validate bola", [access, sql]) == "object-validator"
    assert planned_skill("validate sqli", [access, sql]) == "database-validator"


def test_known_candidate_context_outweighs_unrelated_vocabulary():
    context = PlannerContext(candidate_classes=frozenset({"idor"}))
    plan = build_decision_plan(
        "continue validation",
        shipped_skills(),
        Target(),
        context,
    )

    assert plan is not None
    assert plan.recommended_skill == "access-control"


@pytest.mark.parametrize(
    ("candidate_class", "expected"),
    [
        ("sqli", "sql-injection"),
        ("xss", "cross-site-scripting"),
    ],
)
def test_structured_analysis_handoff_selects_matching_validator(
    candidate_class,
    expected,
):
    workflow = WorkflowState()
    workflow.add_candidate(
        Candidate(
            candidate_class=candidate_class,
            endpoint="/input",
            parameter="value",
            source_skill="web-input-analysis",
        )
    )
    plan = build_decision_plan(
        "continue validation",
        shipped_skills(),
        Target(),
        PlannerContext(candidate_classes=workflow.relevant_candidate_classes()),
    )
    assert plan is not None
    assert plan.recommended_skill == expected


def test_multiple_structured_candidate_classes_remain_ambiguous():
    workflow = WorkflowState()
    workflow.add_candidate(Candidate(candidate_class="sqli", endpoint="/a"))
    workflow.add_candidate(Candidate(candidate_class="xss", endpoint="/b"))

    plan = build_decision_plan(
        "continue test validation",
        shipped_skills(),
        Target(),
        PlannerContext(candidate_classes=workflow.relevant_candidate_classes()),
    )

    assert plan is not None
    assert plan.recommended_skill is None


@pytest.mark.parametrize(
    ("user_text", "expected"),
    [
        ("POST /product parameter=id test SQL injection", "sql-injection"),
        ("GET /search parameter=q test XSS", "cross-site-scripting"),
    ],
)
def test_direct_validation_does_not_require_structured_candidate(user_text, expected):
    assert planned_skill(user_text) == expected


@pytest.mark.parametrize("text", ["candidate", "endpoint", "test", "scan target"])
def test_generic_vocabulary_does_not_select_a_skill(text):
    plan = build_decision_plan(text, shipped_skills(), Target())

    if plan is not None:
        assert plan.recommended_skill is None


def test_meaningful_tie_returns_no_recommendation_regardless_of_order():
    alpha = metadata_skill("alpha", strong=["shared signal"])
    beta = metadata_skill("beta", strong=["shared signal"])

    assert planned_skill("check shared signal", [alpha, beta]) is None
    assert planned_skill("check shared signal", [beta, alpha]) is None


def test_unavailable_skill_is_not_recommended():
    assert planned_skill(
        "test for sql injection",
        [metadata_skill("unrelated", strong=["other workflow"])],
    ) is None


def test_disabled_skill_is_absent_from_planner_input():
    registry = Registry()
    registry.add(metadata_skill("xxe", strong=["xml external entity"]))
    registry.set_disabled("xxe", True)

    assert planned_skill(
        "test xml external entity",
        registry.list_enabled(),
    ) is None


def test_model_invocation_restricted_skill_is_not_auto_selected():
    skill = metadata_skill(
        "manual-only",
        strong=["manual workflow"],
        disable_model_invocation=True,
    )

    assert planned_skill("run manual workflow", [skill]) is None


def test_explicit_input_bypasses_unsatisfied_soft_prerequisite():
    skill = metadata_skill(
        "xxe",
        strong=["xml external entity"],
        candidate_classes=["xxe"],
        requires=["web-input-analysis"],
    )

    assert planned_skill(
        "Test POST /upload XML body for XXE",
        [skill],
    ) == "xxe"


def test_new_skill_is_discovered_validated_and_selected_from_metadata(tmp_path):
    skill_dir = tmp_path / "skills" / "xxe"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        """---
name: xxe
description: Validate XML external entity candidates.
stage: validation
triggers:
  strong:
    - xxe
    - xml external entity
  weak:
    - xml parser
candidate-classes:
  - xxe
requires:
  - web-input-analysis
allowed-tools:
  - http
---
# XXE playbook
""",
        encoding="utf-8",
    )

    registry = Registry()
    registry.add(metadata_skill("web-input-analysis"))
    registry.load_dir(tmp_path / "skills")

    loaded = registry.get("xxe")
    assert loaded is not None
    assert registry.validation_errors(known_tools={"http"}) == {}
    assert planned_skill(
        "Test POST /upload XML body for an XML external entity issue",
        registry.list_enabled(),
    ) == "xxe"


def test_satisfied_prerequisite_increases_ranking_without_becoming_a_lock():
    alpha = metadata_skill("alpha", strong=["inspect xml"])
    beta = metadata_skill(
        "beta",
        strong=["inspect xml"],
        requires=["recon"],
    )

    without_context = build_decision_plan(
        "test inspect xml",
        [alpha, beta],
        Target(),
    )
    with_context = build_decision_plan(
        "test inspect xml",
        [alpha, beta],
        Target(),
        PlannerContext(active_skills=frozenset({"recon"})),
    )

    assert without_context is not None
    assert without_context.recommended_skill is None
    assert with_context is not None
    assert with_context.recommended_skill == "beta"


def test_generic_strong_trigger_is_downgraded_to_weak_signal():
    skill = metadata_skill("too-generic", strong=["endpoint"])

    assert planned_skill("endpoint", [skill]) is None


def test_word_boundary_matching_is_deterministic():
    assert contains_keyword(normalize("check xss here"), "xss") is True
    assert contains_keyword(normalize("check exssuffix here"), "xss") is False


def test_marks_high_risk_without_forcing_a_skill():
    plan = build_decision_plan("run nuclei scan", shipped_skills(), Target())

    assert plan is not None
    assert plan.risk == "high"


@pytest.mark.parametrize(
    "text",
    [
        "test SQL injection in server.js",
        "test SQL injection in config.json",
        "test SQL injection with Python 3.12.6",
    ],
)
def test_file_names_and_versions_do_not_count_as_targets(text):
    assert has_host_like_text(text) is False


@pytest.mark.parametrize(
    "text",
    [
        "test SQL injection on api.example.com",
        "test SQL injection on 127.0.0.1",
        "test SQL injection on https://api.example.com/orders",
    ],
)
def test_hosts_and_urls_count_as_targets(text):
    assert has_host_like_text(text) is True
