"""Canonical lifecycle regressions; native workflow gates, offline fixtures only."""
from src.workflow.state import Candidate, ValidationResult, WorkflowObjective, WorkflowState


def scoped_state():
    state = WorkflowState(objective=WorkflowObjective("objective", "whole_target", "https://fixture.test"))
    candidate, _ = state.add_candidate(Candidate(candidate_class="xss", target="https://fixture.test",
        endpoint="/fixture", method="GET", parameter="q", location="query", objective_id="objective"))
    return state, candidate


def test_cleanup_and_prose_preserve_assessment_identity_without_granting_acceptance():
    from src.workflow.state import validation_result_fingerprint
    state, candidate = scoped_state()
    result = ValidationResult(candidate.id, "cross-site-scripting", "confirmed",
        mutation_performed=True, cleanup_state="pending", objective_id="objective")
    state.validation_results.append(result)
    identity = validation_result_fingerprint(result)
    result.cleanup_status = "A changed explanation with the same pending cleanup."
    assert result.cleanup_state == "pending" and validation_result_fingerprint(result) == identity
    result.cleanup_state = "succeeded"
    assert validation_result_fingerprint(result) == identity
    # Projection is not acceptance: a synthetic unsealed result grants no finding.
    assert not state.finding_is_persisted(candidate.id)
