"""Frozen read-only production projection. No new session, policy or verifier."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from typing import Any

from benchmarks.common.contracts import CanonicalResultExport, PROTOCOL, decode
from src.workflow.assessment import accepted_result, candidate_binding, seal
from src.workflow.evidence import EvidenceArtifact
from src.workflow.state import Candidate, ValidationResult, WorkflowObjective, WorkflowState


def freeze(run_id, case_id, execution_id, session_id, candidate_id, state, policy, target):
    candidate = state.candidates[candidate_id]
    result = state.latest_result(candidate_id)
    positions = [i for i, r in enumerate(state.validation_results) if r.candidate_id == candidate_id]
    return asdict(CanonicalResultExport(
        run_id, case_id, execution_id, session_id, candidate_id,
        state.objective.id if state.objective else None,
        {'base_url': target.base_url(), 'origin': target.origin().as_url(), 'revision': target.revision},
        policy.engagement.http_permissions.epoch, deepcopy(state.to_dict()),
        result.result_id if result else None, positions[-1] if positions else None,
        bool(result and accepted_result(state, candidate, result, policy)), candidate_binding(candidate)))


def projection(raw: dict) -> WorkflowState:
    """Strict hydration for inspection only; do not use resume's lossy migration."""
    expected_keys = set(WorkflowState().to_dict())
    if not isinstance(raw, dict) or set(raw) != expected_keys or raw['version'] != 8:
        raise ValueError('unsupported frozen workflow schema')
    state = WorkflowState()
    state.objective = WorkflowObjective.from_dict(raw['objective'])
    if raw['objective'] is not None and (state.objective is None or state.objective.to_dict() != raw['objective']):
        raise ValueError('malformed frozen objective')
    for value in raw['candidates']:
        candidate = Candidate.from_dict(value)
        if candidate is None or candidate.to_dict() != value or candidate.id in state.candidates:
            raise ValueError('malformed/duplicate frozen Candidate')
        state.candidates[candidate.id] = candidate
    for value in raw['validation_results']:
        result = ValidationResult.from_dict(value)
        if result is None or result.to_dict() != value:
            raise ValueError('malformed frozen result')
        state.validation_results.append(result)
    for value in raw['evidence']:
        artifact = EvidenceArtifact.from_dict(value)
        if artifact is None or artifact.to_dict() != value or artifact.id in state.evidence:
            raise ValueError('malformed/duplicate frozen evidence')
        state.evidence[artifact.id] = artifact
    state.attempts = deepcopy(raw['attempts'])
    state.evidence_sources = deepcopy(raw['evidence_sources'])
    state.selected_sources = deepcopy(raw['selected_sources'])
    return state


def inspect_export(raw: dict, *, run_id: str, case_id: str, execution_id: str,
                   candidate_args: dict, target: str) -> tuple[str | None, str | None]:
    """Return outcome/error. Reuse production acceptance against frozen bindings."""
    try:
        exported = decode(CanonicalResultExport, raw)
        if exported.protocol_version != PROTOCOL:
            raise ValueError('unsupported result protocol')
        if (exported.run_id, exported.case_id, exported.execution_id) != (run_id, case_id, execution_id):
            raise ValueError('execution identity mismatch')
        state = projection(exported.workflow)
        candidate = state.candidates[exported.candidate_id]
        expected = Candidate(**candidate_args)
        for key in ('target', 'endpoint', 'method', 'parameter', 'location', 'content_type', 'request_template', 'source_ref', 'candidate_class'):
            if getattr(candidate, key) != getattr(expected, key):
                raise ValueError('Candidate operational binding mismatch')
        if exported.target['base_url'] != target or exported.target['origin'] != expected.target:
            raise ValueError('target identity mismatch')
        objective = state.objective
        if (objective is None or objective.mode != 'candidate_validation' or objective.candidate_id != candidate.id
                or objective.id != exported.objective_id or objective.target_origin != candidate.target):
            raise ValueError('objective identity mismatch')
        if exported.candidate_binding != candidate_binding(candidate):
            raise ValueError('Candidate binding mismatch')
        result = state.latest_result(candidate.id)
        positions = [i for i, r in enumerate(state.validation_results) if r.candidate_id == candidate.id]
        if result is None:
            if exported.result_id is not None or exported.latest_position is not None or exported.accepted_at_freeze:
                raise ValueError('missing result identity conflict')
            return None, None
        ids = [r.result_id for r in state.validation_results]
        if len(ids) != len(set(ids)) or not all(ids):
            raise ValueError('duplicate/missing production result identity')
        if result.result_id != exported.result_id or positions[-1] != exported.latest_position:
            raise ValueError('stale/latest result mismatch')
        if (result.session_id != exported.session_id or result.objective_id != exported.objective_id
                or result.candidate_binding != exported.candidate_binding or result.assessment_source != 'agent'
                or result.assessment_contract_version != 2 or result.assessment_binding != seal(result)):
            raise ValueError('unaccepted assessment identity/provenance')
        attempt = state.attempts.get(result.attempt_id) if result.attempt_id else None
        if attempt:
            if attempt.get('epoch') != exported.epoch or attempt.get('target_revision') != exported.target['revision']:
                raise ValueError('stale frozen attempt epoch/target revision')
            if result.assessment.get('attempt') != {k: v for k, v in attempt.items() if k != 'status'}:
                raise ValueError('attempt projection mismatch')
        if any(e['source'].get('epoch') != exported.epoch for e in result.evidence_manifest):
            raise ValueError('source epoch mismatch')
        terminal = result.outcome in {'confirmed', 'not-confirmed'}
        accepted = accepted_result(state, candidate, result)
        if terminal and (not accepted or exported.accepted_at_freeze is not True):
            raise ValueError('unaccepted terminal assessment')
        if not terminal and exported.accepted_at_freeze:
            raise ValueError('unresolved acceptance projection conflict')
        return result.outcome, None
    except (ValueError, TypeError, KeyError, AttributeError, IndexError) as err:
        return None, str(err)
