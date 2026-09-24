from __future__ import annotations

import pytest

from src.workflow.state import (
    VALIDATION_OUTCOMES,
    Candidate,
    ValidationResult,
    WorkflowState,
    candidate_fingerprint,
)
from src.workflow.evidence import EvidenceArtifact


def make_candidate(**changes) -> Candidate:
    values = {
        "candidate_class": "sqli",
        "target": "https://Example.test/",
        "method": "post",
        "endpoint": "/product",
        "parameter": "id",
        "location": "query",
        "signals": ["syntax-sensitive response"],
        "baseline_request_ref": "captures/request-1.json",
        "source_skill": "web_input_analysis",
    }
    values.update(changes)
    return Candidate(**values)


def test_candidate_normalizes_and_has_stable_semantic_identity():
    candidate = make_candidate()
    same = make_candidate(
        candidate_class="sql-injection",
        method="POST",
        signals=["different non-identity signal"],
    )

    assert candidate.candidate_class == "sql-injection"
    assert candidate.target == "https://example.test"
    assert candidate.method == "POST"
    assert candidate.source_skill == "web-input-analysis"
    assert candidate.id == same.id
    assert candidate.id == candidate_fingerprint(
        target="https://Example.test/",
        method="post",
        endpoint="/product",
        parameter="id",
        location="query",
        candidate_class="sqli",
    )


def test_candidate_round_trip_optional_fields_and_malformed_input():
    candidate = Candidate(candidate_class="xss", endpoint="/search")
    restored = Candidate.from_dict(candidate.to_dict())

    assert restored == candidate
    assert restored is not None and restored.parameter is None
    assert Candidate.from_dict({"candidate_class": "sqli", "signals": "raw body"}) is None
    assert Candidate.from_dict({"candidate_class": "", "status": "wat"}) is None


def test_candidate_id_rejects_non_semantic_persisted_identity():
    payload = make_candidate().to_dict()
    payload["id"] = "cand_wrong"
    assert Candidate.from_dict(payload) is None


def test_candidate_dedup_merges_compact_signals():
    state = WorkflowState()
    first, created = state.add_candidate(make_candidate())
    second, duplicate_created = state.add_candidate(make_candidate(signals=["reflected error"]))

    assert created is True
    assert duplicate_created is False
    assert first is second
    assert len(state.candidates) == 1
    assert second.signals == ["syntax-sensitive response", "reflected error"]


def test_candidate_subcases_preserve_old_ids_and_remain_distinct():
    baseline = make_candidate()
    horizontal = make_candidate(test_case="horizontal owner boundary")
    vertical = make_candidate(test_case="vertical admin boundary")
    assert baseline.id == candidate_fingerprint(
        target=baseline.target, method=baseline.method, endpoint=baseline.endpoint,
        parameter=baseline.parameter, location=baseline.location,
        candidate_class=baseline.candidate_class,
    )
    assert len({baseline.id, horizontal.id, vertical.id}) == 3
    state = WorkflowState()
    for item in (baseline, horizontal, vertical):
        state.add_candidate(item)
    restored = WorkflowState.from_dict(state.to_dict())
    assert set(restored.candidates) == {baseline.id, horizontal.id, vertical.id}
    old_payload = baseline.to_dict()
    old_payload.pop("test_case")
    restored_legacy = Candidate.from_dict(old_payload)
    assert restored_legacy is not None and restored_legacy.id == baseline.id


def test_registered_evidence_survives_workflow_serialization(tmp_path):
    state = WorkflowState()
    candidate, _ = state.add_candidate(make_candidate())
    (tmp_path / "proof.txt").write_text("Safe proof", encoding="utf-8")
    artifact = EvidenceArtifact.capture(candidate.id, "proof.txt", tmp_path)
    state.add_evidence(artifact)
    state.add_validation_result(ValidationResult(
        candidate.id, "sql-injection", "confirmed", evidence_refs=[artifact.id],
    ))
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.eligible_for_finding(candidate.id)
    assert restored.evidence[artifact.id].is_resolvable(tmp_path)
    old_payload = state.to_dict()
    old_payload["version"] = 1
    old_payload.pop("evidence")
    migrated = WorkflowState.from_dict(old_payload)
    assert migrated.version == 2
    assert not migrated.eligible_for_finding(candidate.id)


def test_workflow_records_redact_secret_bearing_observation_text():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature"
    state = WorkflowState()
    candidate, _ = state.add_candidate(
        make_candidate(signals=[f"authorization: Bearer {token}"])
    )
    result = ValidationResult(
        candidate.id,
        "sql-injection",
        "confirmed",
        evidence_refs=[f"captures/login?token={token}"],
        notes="password=correct-horse-battery-staple",
    )
    state.add_validation_result(result)

    persisted = state.to_dict()
    assert token not in str(persisted)
    assert "correct-horse-battery-staple" not in str(persisted)
    assert "[REDACTED" in str(persisted)


@pytest.mark.parametrize("outcome", sorted(VALIDATION_OUTCOMES))
def test_validation_result_outcomes_round_trip_and_link(outcome, tmp_path):
    state = WorkflowState()
    candidate, _ = state.add_candidate(make_candidate())
    (tmp_path / "proof.txt").write_text("Observed request and response", encoding="utf-8")
    artifact = EvidenceArtifact.capture(candidate.id, "proof.txt", tmp_path)
    state.add_evidence(artifact)
    result = ValidationResult(
        candidate_id=candidate.id,
        skill_name="sql_injection",
        outcome=outcome,
        evidence_refs=[artifact.id],
        techniques=["boolean differential"],
        repeatable=True,
    )

    assert ValidationResult.from_dict(result.to_dict()) == result
    assert state.add_validation_result(result) is True
    assert state.latest_result(candidate.id) == result
    assert state.eligible_for_finding(candidate.id) is (outcome == "confirmed")


def test_result_duplicate_suppression_and_explicit_retest():
    state = WorkflowState()
    candidate, _ = state.add_candidate(make_candidate())
    result = ValidationResult(
        candidate.id,
        "sql-injection",
        "not-confirmed",
        evidence_refs=["evidence/one"],
        notes="first wording",
    )
    prose_only_change = ValidationResult(
        candidate.id,
        "sql-injection",
        "not-confirmed",
        evidence_refs=["evidence/one"],
        cleanup_status="not applicable",
        deferred_reason="different description",
        notes="second wording",
    )
    different_evidence = ValidationResult(
        candidate.id,
        "sql-injection",
        "not-confirmed",
        evidence_refs=["evidence/two"],
    )

    assert state.add_validation_result(result) is True
    assert state.add_validation_result(prose_only_change) is False
    assert state.validation_results[0].notes == "second wording"
    assert state.validation_results[0].cleanup_status == "not applicable"
    assert state.add_validation_result(different_evidence) is True
    # A later attempt can return to an earlier outcome after an intervening result.
    assert state.add_validation_result(result) is True
    assert state.latest_result(candidate.id) is result
    assert state.add_validation_result(result, force=True) is True
    assert len(state.validation_results) == 4
    assert len(WorkflowState.from_dict(state.to_dict()).validation_results) == 4


@pytest.mark.parametrize("version", [1, 2])
def test_requeued_candidate_status_survives_result_replay(version):
    state = WorkflowState()
    candidate, _ = state.add_candidate(make_candidate())
    state.add_validation_result(ValidationResult(
        candidate.id, "sql-injection", "deferred",
        deferred_reason="browser unavailable",
    ))
    assert candidate.status == "deferred"
    state.set_candidate_status(candidate.id, "queued")
    saved = state.to_dict()
    saved["version"] = version

    restored = WorkflowState.from_dict(saved)

    assert restored.candidates[candidate.id].status == "queued"
    assert candidate.id in restored.active_candidate_ids
    latest = restored.latest_result(candidate.id)
    assert latest is not None
    assert latest.outcome == "deferred"
    assert len(restored.validation_results) == 1


def test_validation_result_does_not_implicitly_complete_whole_skill():
    state = WorkflowState()
    first, _ = state.add_candidate(make_candidate(parameter="first"))
    state.add_candidate(make_candidate(parameter="second"))

    state.add_validation_result(
        ValidationResult(first.id, "sql-injection", "not-confirmed")
    )

    assert state.completed_skills == set()
    assert state.relevant_candidate_classes() == frozenset({"sql-injection"})


def test_result_requires_known_candidate_and_valid_values():
    state = WorkflowState()
    with pytest.raises(ValueError, match="unknown candidate"):
        state.add_validation_result(
            ValidationResult("cand_missing", "sql-injection", "blocked")
        )

    assert ValidationResult.from_dict(
        {"candidate_id": "x", "skill_name": "sqli", "outcome": "maybe"}
    ) is None


def test_workflow_round_trip_and_safe_malformed_degradation():
    state = WorkflowState(current_phase="validation")
    candidate, _ = state.add_candidate(make_candidate(status="validating"))
    state.add_validation_result(
        ValidationResult(
            candidate.id,
            "sql-injection",
            "confirmed",
            evidence_refs=["captures/42"],
        )
    )

    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.to_dict() == state.to_dict()
    assert restored.relevant_candidate_classes() == frozenset()
    assert WorkflowState.from_dict("bad").to_dict() == WorkflowState().to_dict()
    malformed = WorkflowState.from_dict(
        {
            "candidates": [{"candidate_class": 4}],
            "validation_results": [{"outcome": "confirmed"}],
            "active_candidate_ids": "all",
        }
    )
    assert malformed.candidates == {}
    assert malformed.validation_results == []


def test_only_actionable_candidates_feed_planner_context():
    state = WorkflowState()
    sql, _ = state.add_candidate(make_candidate())
    state.add_candidate(make_candidate(candidate_class="xss", parameter="q"))
    state.add_validation_result(
        ValidationResult(sql.id, "sql-injection", "not-confirmed")
    )

    assert state.relevant_candidate_classes() == frozenset(
        {"cross-site-scripting"}
    )
