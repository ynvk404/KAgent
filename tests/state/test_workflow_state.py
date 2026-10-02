from __future__ import annotations

import pytest

from src.workflow.state import (
    VALIDATION_OUTCOMES,
    AttackSurfaceInput,
    Candidate,
    PHASE_COVERAGE_DIMENSIONS,
    ValidationResult,
    WorkflowPhaseCompletion,
    WorkflowObjective,
    WorkflowState,
    candidate_fingerprint,
)
from tests.helpers.workflow import record_completed_phase
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


def test_request_context_round_trips_without_changing_semantic_ids():
    baseline = make_candidate()
    enriched = make_candidate(
        content_type="application/json",
        request_template=(
            '{"email":"{INJECTION_POINT}","password":"example-secret"}'
        ),
        auth_context_ref="captures/auth-context.md",
    )
    assert enriched.id == baseline.id
    assert enriched.request_template is not None
    assert "example-secret" not in enriched.request_template
    restored_candidate = Candidate.from_dict(enriched.to_dict())
    assert restored_candidate == enriched

    legacy_candidate = enriched.to_dict()
    legacy_candidate.pop("content_type")
    legacy_candidate.pop("request_template")
    old_candidate = Candidate.from_dict(legacy_candidate)
    assert old_candidate is not None and old_candidate.id == baseline.id
    assert old_candidate.content_type is None and old_candidate.request_template is None

    old_input = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="email",
        location="body",
        input_type="string",
    )
    rich_input = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="email",
        location="body",
        input_type="string",
        content_type="application/json",
        sample_payload='{"email":"user@example.test","password":"example-secret"}',
    )
    assert rich_input.id == old_input.id
    assert rich_input.sample_payload is not None
    assert "example-secret" not in rich_input.sample_payload
    restored_input = AttackSurfaceInput.from_dict(rich_input.to_dict())
    assert restored_input == rich_input

    legacy_input = rich_input.to_dict()
    legacy_input.pop("content_type")
    legacy_input.pop("sample_payload")
    old_input = AttackSurfaceInput.from_dict(legacy_input)
    assert old_input is not None and old_input.id == rich_input.id
    assert old_input.content_type is None and old_input.sample_payload is None


@pytest.mark.parametrize(
    ("content_type", "payload", "secrets"),
    [
        (
            "application/json",
            '{"nested":{"csrf_token":"{INJECTION_POINT}",'
            '"session_cookie":"json-session-secret","username":"alice"}}',
            ("json-session-secret",),
        ),
        (
            "application/x-www-form-urlencoded",
            "username=alice&password=demo-pass&csrf_token={INJECTION_POINT}",
            ("demo-pass",),
        ),
        (
            "multipart/form-data; boundary=fixture",
            "--fixture\r\n"
            'Content-Disposition: form-data; name="username"\r\n\r\n'
            "alice\r\n"
            "--fixture\r\n"
            'Content-Disposition: form-data; name="session_cookie"\r\n\r\n'
            "multipart-session-secret\r\n"
            "--fixture\r\n"
            'Content-Disposition: form-data; name="csrf_token"\r\n\r\n'
            "{INJECTION_POINT}\r\n"
            "--fixture--\r\n",
            ("multipart-session-secret",),
        ),
    ],
)
def test_request_context_redacts_common_body_formats(
    content_type: str, payload: str, secrets: tuple[str, ...]
):
    candidate = make_candidate(
        content_type=content_type, request_template=payload
    )
    item = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="username",
        location="body",
        input_type="string",
        content_type=content_type,
        sample_payload=payload,
    )

    assert candidate.id == make_candidate().id
    assert item.id == AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="username",
        location="body",
        input_type="string",
    ).id
    for context in (candidate.request_template, item.sample_payload):
        assert context is not None
        assert "alice" in context
        assert "{INJECTION_POINT}" in context
        assert all(secret not in context for secret in secrets)


def test_context_merge_keeps_conflicting_request_context_together():
    state = whole_target_state()
    first_input = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="username",
        location="body",
        input_type="string",
        content_type="application/json",
        sample_payload='{"admin":"{INJECTION_POINT}"}',
    )
    conflicting_input = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="username",
        location="body",
        input_type="string",
        content_type="application/x-www-form-urlencoded",
        sample_payload="username={INJECTION_POINT}",
    )
    stored_input, _ = state.add_attack_surface_input(first_input)
    duplicate_input, created = state.add_attack_surface_input(conflicting_input)
    assert not created and duplicate_input is stored_input
    assert stored_input.content_type == "application/json"
    assert stored_input.sample_payload == '{"admin":"{INJECTION_POINT}"}'

    first_candidate, _ = state.add_candidate(make_candidate(
        target="https://target.test",
        objective_id="objective-current",
        content_type="application/json",
        request_template=None,
        baseline_request_ref="captures/admin-baseline.json",
        auth_context_ref="captures/admin-session.md",
    ))
    conflicting_candidate, created = state.add_candidate(make_candidate(
        target="https://target.test",
        objective_id="objective-current",
        content_type="application/x-www-form-urlencoded",
        request_template="username={INJECTION_POINT}",
        baseline_request_ref="captures/user-baseline.json",
        auth_context_ref="captures/user-session.md",
    ))
    assert not created and conflicting_candidate is first_candidate
    assert first_candidate.content_type == "application/json"
    assert first_candidate.request_template is None
    assert first_candidate.baseline_request_ref == "captures/admin-baseline.json"
    assert first_candidate.auth_context_ref == "captures/admin-session.md"


def test_request_context_dedup_fills_only_missing_context_fields():
    state = whole_target_state()
    first_input = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="email",
        location="body",
        input_type="string",
    )
    enriched_input = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="email",
        location="body",
        input_type="string",
        content_type="application/json",
        sample_payload='{"email":"{INJECTION_POINT}"}',
    )
    first, created = state.add_attack_surface_input(first_input)
    duplicate, duplicate_created = state.add_attack_surface_input(enriched_input)
    assert created is True and duplicate_created is False and duplicate is first
    assert first.content_type == "application/json"
    assert first.sample_payload == '{"email":"{INJECTION_POINT}"}'

    first_candidate, _ = state.add_candidate(make_candidate(
        target="https://target.test",
        objective_id="objective-current",
        baseline_request_ref=None,
        auth_context_ref=None,
    ))
    duplicate_candidate, created = state.add_candidate(make_candidate(
        target="https://target.test",
        objective_id="objective-current",
        content_type="application/json",
        request_template='{"email":"{INJECTION_POINT}"}',
        baseline_request_ref="captures/baseline.json",
        auth_context_ref="captures/auth-context.md",
    ))
    assert created is False and duplicate_candidate is first_candidate
    assert first_candidate.content_type == "application/json"
    assert first_candidate.request_template == '{"email":"{INJECTION_POINT}"}'
    assert first_candidate.baseline_request_ref == "captures/baseline.json"
    assert first_candidate.auth_context_ref == "captures/auth-context.md"

    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.attack_surface_inputs[first.id].sample_payload == first.sample_payload
    restored_candidate = restored.candidates[first_candidate.id]
    assert restored_candidate.request_template == first_candidate.request_template
    assert restored_candidate.baseline_request_ref == "captures/baseline.json"
    assert restored_candidate.auth_context_ref == "captures/auth-context.md"


def test_duplicate_context_enrichment_requires_a_shared_request_anchor():
    state = whole_target_state()
    sample = '{"username":"{INJECTION_POINT}"}'
    first_input = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="username",
        location="body",
        input_type="string",
        sample_payload=sample,
    )
    second_input = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="username",
        location="body",
        input_type="string",
        content_type="application/json",
        sample_payload=sample,
    )
    stored_input, _ = state.add_attack_surface_input(first_input)
    assert state.add_attack_surface_input(second_input) == (stored_input, False)
    assert stored_input.content_type == "application/json"
    assert stored_input.sample_payload == sample

    first_candidate = make_candidate(
        target="https://target.test",
        objective_id="objective-current",
        content_type="application/json",
        request_template=None,
        baseline_request_ref="captures/admin-baseline.json",
        auth_context_ref=None,
    )
    second_candidate = make_candidate(
        target="https://target.test",
        objective_id="objective-current",
        content_type="application/json",
        request_template='{"username":"{INJECTION_POINT}"}',
        baseline_request_ref="captures/admin-baseline.json",
        auth_context_ref="captures/admin-session.md",
    )
    stored_candidate, _ = state.add_candidate(first_candidate)
    duplicate_candidate, created = state.add_candidate(second_candidate)
    assert not created and duplicate_candidate is stored_candidate
    assert stored_candidate.content_type == "application/json"
    assert stored_candidate.request_template == '{"username":"{INJECTION_POINT}"}'
    assert stored_candidate.auth_context_ref == "captures/admin-session.md"


def test_content_type_alone_does_not_anchor_duplicate_request_context():
    state = whole_target_state()
    first_input = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="q",
        location="body",
        input_type="string",
        content_type="application/json",
    )
    duplicate_input = AttackSurfaceInput(
        objective_id="objective-current",
        target_origin="https://target.test",
        method="POST",
        endpoint="/api/login",
        parameter="q",
        location="body",
        input_type="string",
        content_type="application/json",
        sample_payload="q={INJECTION_POINT}&role=user",
    )
    stored_input, _ = state.add_attack_surface_input(first_input)
    duplicate, created = state.add_attack_surface_input(duplicate_input)
    assert not created and duplicate is stored_input
    assert stored_input.content_type == "application/json"
    assert stored_input.sample_payload is None

    base = dict(
        target="https://target.test",
        objective_id="objective-current",
        content_type="application/json",
    )
    first_candidate, _ = state.add_candidate(make_candidate(
        **base,
        baseline_request_ref="captures/json-admin.json",
    ))
    duplicate_candidate, created = state.add_candidate(make_candidate(
        **base,
        auth_context_ref="captures/user-session.md",
        request_template='{"q":"{INJECTION_POINT}","role":"user"}',
    ))
    assert not created and duplicate_candidate is first_candidate
    assert first_candidate.baseline_request_ref == "captures/json-admin.json"
    assert first_candidate.auth_context_ref is None
    assert first_candidate.request_template is None


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
    assert migrated.version == 6
    assert not migrated.eligible_for_finding(candidate.id)


def test_legacy_phase_completion_migrates_only_for_pre_v4_session():
    legacy_marker = {
        "objective_id": "legacy-objective",
        "phase": "recon",
        "target_origin": "https://target.test",
        "artifact_ref": "artifacts/recon/summary.md",
    }
    migrated = WorkflowState.from_dict({
        "version": 3,
        "phase_completions": [legacy_marker],
    })
    marker = migrated.phase_completions.get("legacy-objective:recon")
    assert marker is not None
    assert set(marker.coverage) == set(PHASE_COVERAGE_DIMENSIONS["recon"])
    assert all(item.status == "skipped" for item in marker.coverage.values())
    assert all("legacy" in (item.reason or "") for item in marker.coverage.values())

    current = WorkflowState.from_dict({
        "version": 4,
        "phase_completions": [legacy_marker],
    })
    assert "legacy-objective:recon" not in current.phase_completions

    for malformed_coverage in (None, [], {"unknown-dimension": {"status": "performed"}}):
        malformed = WorkflowState.from_dict({
            "version": 4,
            "phase_completions": [{
                "objective_id": "current-objective",
                "phase": "input_analysis",
                "target_origin": "https://target.test",
                "artifact_ref": "artifacts/input-analysis.md",
                "no_inputs_discovered": True,
                "coverage": malformed_coverage,
            }],
        })
        assert "current-objective:input_analysis" not in malformed.phase_completions


def test_current_phase_completion_with_incomplete_coverage_fails_closed_and_round_trips():
    state = whole_target_state("current-coverage")
    objective = state.objective
    assert objective is not None
    state.record_phase_coverage(
        "recon", "reachability", "performed",
        objective_id=objective.id,
        target_origin=objective.target_origin or "",
    )
    serialized = state.to_dict()
    serialized["phase_completions"] = [{
        "objective_id": objective.id,
        "phase": "recon",
        "target_origin": objective.target_origin,
        "artifact_ref": "artifacts/recon.md",
        "coverage": {"reachability": {"status": "performed"}},
    }]
    restored = WorkflowState.from_dict(serialized)
    assert f"{objective.id}:recon" not in restored.phase_completions
    assert restored.needs_phase_coverage("recon", "service_discovery")
    assert WorkflowState.from_dict(restored.to_dict()).to_dict() == restored.to_dict()


def test_pending_phase_coverage_is_workflow_progress_and_retry_changes_the_fact():
    state = whole_target_state("coverage-progress")
    objective = state.objective
    assert objective is not None

    state.record_phase_coverage(
        "recon", "reachability", "failed",
        objective_id=objective.id,
        target_origin=objective.target_origin or "",
        reason="temporary DNS failure",
    )
    failed_facts = state.progress_facts()
    assert any("reachability:failed" in fact for fact in failed_facts)

    state.record_phase_coverage(
        "recon", "reachability", "performed",
        objective_id=objective.id,
        target_origin=objective.target_origin or "",
    )
    performed_facts = state.progress_facts()
    assert performed_facts - failed_facts
    assert any("reachability:performed" in fact for fact in performed_facts)


def test_phase_completion_moves_pending_coverage_into_the_compact_marker():
    state = whole_target_state("coverage-snapshot")
    objective = state.objective
    assert objective is not None
    record_completed_phase(
        state,
        "recon",
        objective_id=objective.id,
        target_origin=objective.target_origin or "",
        artifact_ref="artifacts/recon.md",
    )

    key = f"{objective.id}:recon"
    assert key not in state.phase_coverage
    assert set(state.phase_completions[key].coverage) == set(PHASE_COVERAGE_DIMENSIONS["recon"])
    assert not any(f"phase-coverage-pending:{key}:" in fact for fact in state.progress_facts())
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.to_dict() == state.to_dict()


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


def test_cleanup_lifecycle_updates_latest_result_without_creating_a_retest():
    state = WorkflowState()
    candidate, _ = state.add_candidate(make_candidate())
    pending = ValidationResult(
        candidate.id,
        "sql-injection",
        "confirmed",
        evidence_refs=["ev_proof"],
        mutation_performed=True,
        cleanup_status="cleanup permission not yet requested",
    )
    assert pending.cleanup_state == "pending"
    assert state.add_validation_result(pending) is True

    failed_cleanup = ValidationResult(
        candidate.id,
        "sql-injection",
        "confirmed",
        evidence_refs=["ev_proof"],
        mutation_performed=True,
        cleanup_status="failed: DELETE returned 401",
    )
    assert failed_cleanup.cleanup_state == "requires-user-action"
    assert state.add_validation_result(failed_cleanup) is False
    assert len(state.validation_results) == 1
    assert state.latest_result(candidate.id) is pending
    assert pending.cleanup_state == "requires-user-action"
    assert WorkflowState.from_dict(state.to_dict()).latest_result(candidate.id) == pending


def test_cleanup_state_is_separate_from_confirmation_and_blocks_clean_completion():
    state = whole_target_state()
    complete_required_phases(state)
    candidate, _ = state.add_candidate(make_candidate(
        objective_id="objective-current", target="https://target.test",
    ))
    artifact = EvidenceArtifact(
        "ev_proof", candidate.id, "artifacts/proof.md", "a" * 64, 1,
    )
    state.add_evidence(artifact)
    state.add_validation_result(ValidationResult(
        candidate.id, "sql-injection", "confirmed",
        evidence_refs=[artifact.id], coverage_synced=True,
        mutation_performed=True, cleanup_status="failed: DELETE returned 401",
    ))
    args = {
        "target_origin": "https://target.test",
        "available_phases": frozenset({"recon", "enumeration", "input_analysis"}),
        "validator_classes": frozenset({"sql-injection"}),
        "coverage_sync_available": True,
    }

    status, actionable, blockers = state.whole_target_status(**args)
    assert status == "actionable"
    assert actionable == (f"finding:{candidate.id}",)
    assert any("cleanup requires operator action" in item for item in blockers)

    state.mark_finding_persisted(candidate.id)
    status, actionable, blockers = state.whole_target_status(**args)
    assert status == "blocked" and actionable == ()
    assert any("requires-user-action" in item for item in blockers)

    cleaned = ValidationResult(
        candidate.id, "sql-injection", "confirmed",
        evidence_refs=[artifact.id], coverage_synced=True,
        mutation_performed=True, cleanup_status="deleted and verified",
    )
    assert cleaned.cleanup_state == "succeeded"
    assert state.add_validation_result(cleaned) is False
    assert state.whole_target_status(**args) == ("completed", (), ())


def test_terminal_candidate_is_revalidated_only_when_evidence_is_invalidated():
    state = whole_target_state()
    complete_required_phases(state)
    candidate, _ = state.add_candidate(make_candidate(
        objective_id="objective-current", target="https://target.test",
    ))
    artifact = EvidenceArtifact(
        "ev_proof", candidate.id, "artifacts/proof.md", "a" * 64, 1,
    )
    state.add_evidence(artifact)
    state.add_validation_result(ValidationResult(
        candidate.id, "sql-injection", "confirmed",
        evidence_refs=[artifact.id], coverage_synced=True,
    ))
    args = {
        "target_origin": "https://target.test",
        "available_phases": frozenset({"recon", "enumeration", "input_analysis"}),
        "validator_classes": frozenset({"sql-injection"}),
        "coverage_sync_available": True,
    }

    status, actionable, _ = state.whole_target_status(**args)
    assert status == "actionable" and actionable == (f"finding:{candidate.id}",)

    state.set_candidate_status(candidate.id, "queued")
    status, actionable, _ = state.whole_target_status(**args)
    assert status == "actionable" and actionable == (f"candidate:{candidate.id}",)
    state.set_candidate_status(candidate.id, "validated")

    invalidated = {
        **args,
        "invalid_evidence_candidate_ids": frozenset({candidate.id}),
    }
    status, actionable, blockers = state.whole_target_status(**invalidated)
    assert status == "actionable"
    assert actionable == (f"revalidate:{candidate.id}",)
    assert not any(item.startswith(f"finding:{candidate.id}") for item in actionable)
    assert blockers == ()

    no_validator = {**invalidated, "validator_classes": frozenset()}
    status, actionable, blockers = state.whole_target_status(**no_validator)
    assert status == "blocked" and actionable == ()
    assert any("evidence unavailable" in item for item in blockers)


def test_missing_terminal_record_or_dismissal_does_not_trigger_automatic_retest():
    state = whole_target_state()
    complete_required_phases(state)
    dismissed, _ = state.add_candidate(make_candidate(
        objective_id="objective-current", target="https://target.test",
        endpoint="/dismissed", status="dismissed",
    ))
    inconsistent, _ = state.add_candidate(make_candidate(
        objective_id="objective-current", target="https://target.test",
        endpoint="/missing-result", status="validated",
    ))

    status, actionable, blockers = state.whole_target_status(
        target_origin="https://target.test",
        available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset({"sql-injection"}),
        coverage_sync_available=True,
    )

    assert status == "blocked" and actionable == ()
    assert any(f"dismissed without terminal result:{dismissed.id}" in item for item in blockers)
    assert any(f"lacks terminal result:{inconsistent.id}" in item for item in blockers)
    assert not any(item.startswith("revalidate:") for item in actionable)


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


def whole_target_state(objective_id: str = "objective-current") -> WorkflowState:
    state = WorkflowState()
    state.objective = WorkflowObjective(
        id=objective_id,
        mode="whole_target",
        target_origin="https://target.test",
    )
    return state


def complete_required_phases(state: WorkflowState) -> None:
    objective = state.objective
    assert objective is not None
    for phase in ("recon", "enumeration", "input_analysis"):
        record_completed_phase(
            state,
            phase,  # type: ignore[arg-type]
            objective_id=objective.id,
            target_origin=objective.target_origin or "",
            artifact_ref=f"artifacts/{phase}.md",
            no_inputs_discovered=phase == "input_analysis",
        )


def test_workflow_objective_round_trip_and_legacy_state_without_objective():
    state = whole_target_state()
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.objective == state.objective
    assert WorkflowState.from_dict({"version": 2}).objective is None


def test_candidate_objective_scoping_preserves_legacy_fingerprint():
    legacy = make_candidate()
    first = make_candidate(objective_id="objective-a")
    second = make_candidate(objective_id="objective-b")
    assert legacy.id == candidate_fingerprint(
        target=legacy.target,
        method=legacy.method,
        endpoint=legacy.endpoint,
        parameter=legacy.parameter,
        location=legacy.location,
        candidate_class=legacy.candidate_class,
    )
    assert first.id != second.id
    assert Candidate.from_dict(legacy.to_dict()) == legacy


def test_attack_surface_identity_deduplicates_and_dispositions_are_structured():
    state = whole_target_state()
    objective = state.objective
    assert objective is not None
    item = AttackSurfaceInput(
        objective.id,
        "https://TARGET.test:443/path",
        method="get",
        endpoint="/search",
        parameter="q",
        location="QUERY",
        input_type="text",
    )
    duplicate = AttackSurfaceInput(
        objective.id,
        "https://target.test",
        method="GET",
        endpoint="/search",
        parameter="q",
        location="query",
        input_type="TEXT",
    )
    stored, created = state.add_attack_surface_input(item)
    same, duplicate_created = state.add_attack_surface_input(duplicate)
    assert created is True and duplicate_created is False and same is stored
    assert len(state.attack_surface_inputs) == 1
    state.set_input_disposition(stored.id, "blocked", reason="authorization required")
    state.set_input_disposition(stored.id, "pending")
    state.set_input_disposition(stored.id, "analyzed")
    assert stored.disposition == "analyzed"
    assert "blocked>pending" in stored.disposition_transitions
    with pytest.raises(ValueError, match="terminal"):
        state.set_input_disposition(stored.id, "pending")


def test_input_candidate_link_requires_same_objective():
    state = whole_target_state()
    objective = state.objective
    assert objective is not None
    item, _ = state.add_attack_surface_input(AttackSurfaceInput(
        objective.id, objective.target_origin or "", endpoint="/search", parameter="q",
    ))
    current, _ = state.add_candidate(make_candidate(
        objective_id=objective.id,
        target=objective.target_origin,
        endpoint="/search",
        parameter="q",
    ))
    old, _ = state.add_candidate(make_candidate(
        objective_id="objective-old",
        target=objective.target_origin,
        endpoint="/search",
        parameter="q",
    ))
    state.link_input_candidate(item.id, current.id)
    with pytest.raises(ValueError, match="active objective"):
        state.link_input_candidate(item.id, old.id)
    assert item.candidate_ids == [current.id]


def test_old_objective_candidate_does_not_affect_current_whole_target_completion():
    state = whole_target_state()
    old, _ = state.add_candidate(make_candidate(
        objective_id="objective-old", target="https://target.test", endpoint="/old",
    ))
    complete_required_phases(state)
    status, actionable, blockers = state.whole_target_status(
        target_origin="https://target.test",
        available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset({"sql-injection"}),
        coverage_sync_available=True,
    )
    assert old.id in state.candidates
    assert status == "completed"
    assert actionable == () and blockers == ()


def test_completed_input_analysis_without_inventory_attestation_stays_blocked():
    state = whole_target_state()
    objective = state.objective
    assert objective is not None
    for phase in ("recon", "enumeration", "input_analysis"):
        record_completed_phase(
            state,
            phase,  # type: ignore[arg-type]
            objective_id=objective.id,
            target_origin=objective.target_origin or "",
            artifact_ref=f"artifacts/{phase}.md",
        )

    status, actionable, blockers = state.whole_target_status(
        target_origin="https://target.test",
        available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset(),
        coverage_sync_available=True,
    )

    assert status == "blocked"
    assert actionable == ()
    assert any("no recorded inputs" in blocker for blocker in blockers)


def test_no_input_attestation_survives_workflow_state_round_trip():
    state = whole_target_state()
    complete_required_phases(state)

    restored = WorkflowState.from_dict(state.to_dict())
    marker = restored.phase_completions["objective-current:input_analysis"]

    assert marker.no_inputs_discovered is True
    status, actionable, blockers = restored.whole_target_status(
        target_origin="https://target.test",
        available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset(),
        coverage_sync_available=True,
    )
    assert status == "completed"
    assert actionable == () and blockers == ()


def test_completion_and_blocker_contract_and_append_only_result_history():
    state = whole_target_state()
    complete_required_phases(state)
    item, _ = state.add_attack_surface_input(AttackSurfaceInput(
        "objective-current", "https://target.test", endpoint="/search", parameter="q",
    ))
    state.set_input_disposition(item.id, "blocked", reason="authorization required")
    available = frozenset({"recon", "enumeration", "input_analysis"})
    status, actionable, blockers = state.whole_target_status(
        target_origin="https://target.test", available_phases=available,
        validator_classes=frozenset({"sql-injection"}), coverage_sync_available=True,
    )
    assert status == "blocked" and actionable == () and blockers
    state.set_input_disposition(item.id, "pending")
    state.set_input_disposition(item.id, "analyzed")
    candidate, _ = state.add_candidate(make_candidate(
        objective_id="objective-current", target="https://target.test",
    ))
    first = ValidationResult(candidate.id, "sql-injection", "authorization-required")
    second = ValidationResult(candidate.id, "sql-injection", "not-confirmed")
    state.add_validation_result(first)
    state.set_candidate_status(candidate.id, "validating")
    state.add_validation_result(second)
    assert state.validation_results == [first, second]
    status, actionable, blockers = state.whole_target_status(
        target_origin="https://target.test", available_phases=available,
        validator_classes=frozenset({"sql-injection"}), coverage_sync_available=True,
    )
    assert status == "completed" and actionable == () and blockers == ()


def test_confirmed_candidate_without_registered_evidence_is_actionable_for_revalidation():
    state = whole_target_state()
    complete_required_phases(state)
    candidate, _ = state.add_candidate(make_candidate(
        objective_id="objective-current", target="https://target.test",
    ))
    state.add_validation_result(ValidationResult(
        candidate.id, "sql-injection", "confirmed", evidence_refs=["ev_missing"],
    ))
    status, actionable, blockers = state.whole_target_status(
        target_origin="https://target.test",
        available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset({"sql-injection"}),
        coverage_sync_available=True,
    )
    assert status == "actionable"
    assert actionable == (f"revalidate:{candidate.id}",)
    assert blockers == ()


def test_confirmed_candidate_requires_current_finding_persistence_to_complete():
    state = whole_target_state()
    complete_required_phases(state)
    candidate, _ = state.add_candidate(make_candidate(
        objective_id="objective-current", target="https://target.test",
    ))
    artifact = EvidenceArtifact(
        "ev_proof", candidate.id, "artifacts/proof.md", "a" * 64, 1,
    )
    state.add_evidence(artifact)
    state.add_validation_result(ValidationResult(
        candidate.id, "sql-injection", "confirmed",
        evidence_refs=[artifact.id], coverage_synced=True,
    ))

    args = {
        "target_origin": "https://target.test",
        "available_phases": frozenset({"recon", "enumeration", "input_analysis"}),
        "validator_classes": frozenset({"sql-injection"}),
        "coverage_sync_available": True,
    }
    status, actionable, blockers = state.whole_target_status(**args)
    assert status == "actionable"
    assert actionable == (f"finding:{candidate.id}",)
    assert blockers == ()

    state.mark_finding_persisted(candidate.id)
    assert state.finding_is_persisted(candidate.id)
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.finding_is_persisted(candidate.id)
    assert restored.whole_target_status(**args) == ("completed", (), ())

    restored.set_candidate_status(candidate.id, "validating")
    restored.add_validation_result(ValidationResult(
        candidate.id, "sql-injection", "confirmed",
        evidence_refs=[artifact.id], techniques=["fresh confirmation"],
        coverage_synced=True,
    ))
    assert not restored.finding_is_persisted(candidate.id)
    assert restored.whole_target_status(**args)[1] == (f"finding:{candidate.id}",)


def test_blocker_does_not_stop_objective_while_another_candidate_is_actionable():
    state = whole_target_state()
    complete_required_phases(state)
    item, _ = state.add_attack_surface_input(AttackSurfaceInput(
        "objective-current", "https://target.test", endpoint="/blocked", parameter="id",
        disposition="blocked", disposition_reason="browser required",
    ))
    candidate, _ = state.add_candidate(make_candidate(
        objective_id="objective-current", target="https://target.test", endpoint="/ready",
    ))
    status, actionable, blockers = state.whole_target_status(
        target_origin="https://target.test",
        available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset({"sql-injection"}),
        coverage_sync_available=True,
    )
    assert item.disposition == "blocked"
    assert status == "actionable"
    assert f"candidate:{candidate.id}" in actionable
    assert blockers


def test_dismissed_candidate_with_terminal_result_is_a_valid_disposition():
    state = whole_target_state()
    complete_required_phases(state)
    candidate, _ = state.add_candidate(make_candidate(
        objective_id="objective-current", target="https://target.test",
    ))
    state.add_validation_result(ValidationResult(
        candidate.id, "sql-injection", "not-confirmed",
    ))
    state.set_candidate_status(candidate.id, "dismissed")
    status, actionable, blockers = state.whole_target_status(
        target_origin="https://target.test",
        available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset({"sql-injection"}),
        coverage_sync_available=True,
    )
    assert status == "completed" and actionable == () and blockers == ()


def test_progress_facts_ignore_prose_timestamps_and_candidate_status_oscillation():
    state = whole_target_state()
    objective = state.objective
    assert objective is not None
    candidate, _ = state.add_candidate(make_candidate(
        objective_id=objective.id, target=objective.target_origin,
    ))
    result = ValidationResult(
        candidate.id, "sql-injection", "not-confirmed", notes="first", recorded_at="t1",
    )
    state.add_validation_result(result)
    facts = state.progress_facts()
    state.set_candidate_status(candidate.id, "queued")
    state.set_candidate_status(candidate.id, "validating")
    result.notes = "edited prose"
    result.recorded_at = "t2"
    assert state.progress_facts() == facts
    retest = ValidationResult(
        candidate.id, "sql-injection", "confirmed", evidence_refs=["ev-new"],
    )
    state.add_validation_result(retest, force=True)
    after_result = state.progress_facts()
    assert after_result - facts
    retest.notes = "different prose"
    retest.recorded_at = "t3"
    assert state.progress_facts() == after_result
    retest.coverage_synced = False
    pending_sync = state.progress_facts()
    retest.coverage_synced = True
    synced = state.progress_facts()
    assert synced - pending_sync


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
