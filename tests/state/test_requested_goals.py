from __future__ import annotations

from src.skills.registry import Registry, Skill, SkillTriggers
from src.workflow.goals import RequestedGoal, extract_requested_classes
from src.workflow.state import Candidate, WorkflowObjective, WorkflowState


def test_extracts_four_canonical_classes_and_deduplicates_aliases():
    assert extract_requested_classes(
        "Test SQL Injection, XSS, IDOR and CORS"
    ) == [
        "sql-injection", "cross-site-scripting", "access-control",
        "cors-misconfiguration",
    ]
    assert extract_requested_classes("Test SQL injection and SQLi") == ["sql-injection"]


def test_extraction_respects_operational_clauses_and_negation():
    assert extract_requested_classes("Test SQLi. Do not test XSS.") == ["sql-injection"]
    assert extract_requested_classes("Test SQLi, not XSS") == ["sql-injection"]
    assert extract_requested_classes(
        "Explain the difference between SQL injection and XSS."
    ) == []
    assert extract_requested_classes("Do not test XSS but test SQLi") == ["sql-injection"]


def test_registered_validation_class_is_recognized_when_disabled_or_manual_only():
    skill = Skill(
        name="private-validator", description="manual class", tools=[],
        disable_model_invocation=True, path="fixture", body="fixture",
        stage="validation", triggers=SkillTriggers(),
        candidate_classes=["novel-risk"],
    )
    registry = Registry()
    registry.add(skill)
    registry.set_disabled(skill.name, True)
    all_registered_classes = tuple(
        label for registered in registry.list()
        if registered.stage == "validation"
        for label in registered.candidate_classes
    )
    assert extract_requested_classes(
        "Test novel risk", registered_classes=all_registered_classes,
    ) == ["novel-risk"]
    assert extract_requested_classes("candidate_class=unmapped-risk") == ["unmapped-risk"]


def test_objective_owns_deduplicated_goals_and_old_payloads_load_empty():
    objective = WorkflowObjective(
        id="objective-goals", mode="direct", target_origin="https://target.test",
        requested_goals=[RequestedGoal("sqli"), RequestedGoal("sql-injection")],
    )
    assert [goal.candidate_class for goal in objective.requested_goals] == ["sql-injection"]
    restored = WorkflowState.from_dict(WorkflowState(objective=objective).to_dict())
    assert restored.objective is not None
    assert restored.objective.requested_goals == objective.requested_goals

    old = WorkflowState.from_dict({
        "version": 6,
        "objective": {
            "id": "legacy", "mode": "direct", "target_origin": None,
        },
    })
    assert old.objective is not None and old.objective.requested_goals == []
    assert old.version == 8


def test_direct_objective_provenance_changes_new_candidate_id_without_rewriting_old_ids():
    old = Candidate(
        candidate_class="xss", target="https://target.test", endpoint="/search",
        parameter="q",
    )
    legacy_payload = old.to_dict()
    new = Candidate(
        candidate_class="xss", target="https://target.test", endpoint="/search",
        parameter="q", objective_id="objective-current",
    )

    assert new.id != old.id
    restored_old = Candidate.from_dict(legacy_payload)
    assert restored_old is not None and restored_old.id == old.id
    assert Candidate.from_dict(new.to_dict()) == new


def test_stale_goal_links_round_trip_for_runtime_reconciliation():
    objective = WorkflowObjective(
        id="objective-stale", mode="direct", target_origin="https://target.test",
        requested_goals=[RequestedGoal("access-control", candidate_ids=["cand_missing"])],
    )
    restored = WorkflowState.from_dict(WorkflowState(objective=objective).to_dict())
    assert restored.objective is not None
    assert restored.objective.requested_goals[0].candidate_ids == ["cand_missing"]
