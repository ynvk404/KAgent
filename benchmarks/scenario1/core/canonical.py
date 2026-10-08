"""Frozen read-only production projection. No new session, policy or verifier."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import hashlib
from typing import Any
from urllib.parse import urlsplit

from benchmarks.common.contracts import CanonicalResultExport, OperationalCaseInput, PROTOCOL, decode
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
        if terminal and any(not isinstance(entry, dict) or not isinstance(entry.get('source'), dict)
                or entry['source'].get('candidate_id') != candidate.id
                or entry['source'].get('candidate_binding') != exported.candidate_binding
                for entry in result.evidence_manifest):
            raise ValueError('evidence candidate ownership mismatch')
        if terminal and (not accepted or exported.accepted_at_freeze is not True):
            raise ValueError('unaccepted terminal assessment')
        if not terminal and exported.accepted_at_freeze:
            raise ValueError('unresolved acceptance projection conflict')
        return result.outcome, None
    except (ValueError, TypeError, KeyError, AttributeError, IndexError) as err:
        return None, str(err)


def inspect_case_evidence(raw: dict, *, op: OperationalCaseInput, candidate_args: dict) -> str | None:
    """Require sealed HTTP evidence to identify this case's exact input slot."""
    try:
        exported = decode(CanonicalResultExport, raw)
        state = projection(exported.workflow)
        candidate = state.candidates[exported.candidate_id]
        result = state.latest_result(candidate.id)
        if result is None or result.outcome not in {'confirmed', 'not-confirmed'}:
            return None

        expected_method = candidate_args['method']
        expected_route = urlsplit(candidate_args['endpoint']).path
        expected_location = op.input_location
        expected_component = op.input_component
        if expected_component not in {'name', 'value'}:
            return 'evidence-case-binding:unsupported-input-component'

        requests = []
        for entry in result.evidence_manifest:
            source = entry.get('source') if isinstance(entry, dict) else None
            if not isinstance(source, dict):
                return 'evidence-case-binding:malformed-source'
            if source.get('source_kind') == 'tool-output':
                continue
            if source.get('source_kind') != 'native-http':
                return 'evidence-case-binding:unsupported-evidence-source'
            requests.append(source)
        if not requests:
            return 'evidence-case-binding:missing-native-http-evidence'

        saw_expected_mutation = False
        baseline_sources: dict[str, list[dict]] = {}
        name_mutations = []
        for source in requests:
            if (source.get('candidate_id') != candidate.id
                    or source.get('candidate_binding') != exported.candidate_binding):
                return 'evidence-case-binding:candidate-ownership-mismatch'
            details = source.get('source_details')
            binding = details.get('scenario1_case_binding') if isinstance(details, dict) else None
            if not isinstance(binding, dict) or binding.get('version') != 1:
                return 'evidence-case-binding:missing-semantic-request-binding'
            if (binding.get('case_id') != op.case_id or binding.get('candidate_id') != candidate.id
                    or binding.get('candidate_binding') != exported.candidate_binding):
                return 'evidence-case-binding:candidate-ownership-mismatch'
            if binding.get('input_name_sha256') != hashlib.sha256(op.input_name.encode()).hexdigest():
                return 'evidence-case-binding:wrong-input-name'
            if binding.get('input_location') != expected_location:
                return 'evidence-case-binding:wrong-input-location'
            if binding.get('input_component') != expected_component:
                return 'evidence-case-binding:wrong-input-component'
            if binding.get('request_hash') != source.get('request_hash'):
                return 'evidence-case-binding:request-identity-mismatch'
            try:
                route = urlsplit(source['url']).path
            except (KeyError, TypeError, ValueError):
                return 'evidence-case-binding:invalid-evidence-url'
            if source.get('method') != expected_method or binding.get('method') != expected_method:
                return 'evidence-case-binding:wrong-http-method'
            if route != expected_route or binding.get('route') != expected_route:
                return 'evidence-case-binding:wrong-route'

            components = binding.get('input_components')
            if not isinstance(components, list):
                return 'evidence-case-binding:missing-input-slot'
            valid_rows = [row for row in components if isinstance(row, dict)
                          and row.get('location') in {'query', 'body', 'header', 'cookie'}
                          and row.get('component') in {'name', 'value', 'baseline'}
                          and type(row.get('count')) is int and row['count'] > 0]
            if len(valid_rows) != len(components):
                return 'evidence-case-binding:malformed-input-slot'
            expected_rows = [row for row in valid_rows if row['location'] == expected_location]
            other_locations = [row for row in valid_rows if row['location'] != expected_location]
            if other_locations:
                return 'evidence-case-binding:wrong-input-location'
            if not expected_rows:
                return 'evidence-case-binding:wrong-input-name'
            if any(row['component'] not in {'baseline', expected_component} for row in expected_rows):
                return 'evidence-case-binding:wrong-input-component'
            if sum(row['count'] for row in expected_rows) != 1:
                return 'evidence-case-binding:ambiguous-input-slot'
            if expected_component == 'name' and expected_rows[0]['component'] == 'baseline':
                if len(components) == 1:
                    baseline_sources.setdefault(source.get('request_hash'), []).append(source)
            elif expected_component == 'name' and expected_rows[0]['component'] == 'name':
                mutation = binding.get('name_mutation')
                field_hash = expected_rows[0].get('field_name_sha256')
                if (not isinstance(mutation, dict) or set(mutation) != {
                        'version', 'from_request_hash', 'input_name_sha256',
                        'field_name_sha256', 'input_location'}
                        or mutation.get('version') != 1
                        or mutation.get('input_name_sha256') != hashlib.sha256(op.input_name.encode()).hexdigest()
                        or mutation.get('input_location') != expected_location
                        or mutation.get('field_name_sha256') != field_hash
                        or not isinstance(field_hash, str) or len(field_hash) != 64
                        or any(char not in '0123456789abcdef' for char in field_hash)
                        or field_hash == hashlib.sha256(op.input_name.encode()).hexdigest()):
                    return 'evidence-case-binding:missing-name-mutation-semantics'
                name_mutations.append((source, mutation))
            else:
                saw_expected_mutation |= any(row['component'] == expected_component for row in expected_rows)

        if expected_component == 'name':
            for source, mutation in name_mutations:
                baseline_hash = mutation.get('from_request_hash')
                if (not isinstance(baseline_hash, str) or len(baseline_hash) != 64
                        or any(char not in '0123456789abcdef' for char in baseline_hash)
                        or baseline_hash == source.get('request_hash')):
                    return 'evidence-case-binding:invalid-name-mutation-baseline'
                matching_baselines = baseline_sources.get(baseline_hash, [])
                if not any(
                        baseline.get('candidate_id') == source.get('candidate_id')
                        and baseline.get('candidate_binding') == source.get('candidate_binding')
                        and baseline.get('method') == source.get('method')
                        and baseline.get('source_details', {}).get('scenario1_case_binding', {}).get('input_name_sha256')
                        == hashlib.sha256(op.input_name.encode()).hexdigest()
                        for baseline in matching_baselines):
                    return 'evidence-case-binding:unproven-name-mutation'
                saw_expected_mutation = True

        if not saw_expected_mutation:
            return 'evidence-case-binding:designated-input-not-mutated'
        return None
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        return 'evidence-case-binding:malformed-canonical-evidence'
