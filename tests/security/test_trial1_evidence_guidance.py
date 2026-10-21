"""Repair feedback preserves the production evidence/ownership gates."""
from dataclasses import replace
import json

from src.workflow.assessment import digest, source_row
from src.workflow.evidence.recovery import current_budget
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime  # noqa: F401


def error(value):
    assert value.startswith('error:')
    return json.loads(value.split('\n', 1)[1])['error']


async def test_write_register_id_submit_flow_and_wrong_path(runtime, tmp_path):
    state, candidate, _, args, oid = await setup(runtime, tmp_path)
    registry, p, _, _, sent, *_ = runtime
    # setup wrote proof.md before its registration, using a real owned mock capture.
    registered = json.loads(await registry.execute('workflow', {
        'action': 'record_evidence', 'candidate_id': candidate.id,
        'evidence_path': 'proof.md', 'observation_ids': [oid]}, None, p))
    eid = registered['evidence']['id']
    assert eid.startswith('ev_') and state.evidence_sources[eid] == [oid]
    rejected = await registry.execute('workflow', {**args, 'evidence_refs': ['proof.md']}, None, p)
    feedback = error(rejected)
    assert feedback['code'] == 'EVIDENCE_REFERENCE_MISMATCH'
    assert 'evidence.id' in feedback['repair_hint'] and 'never evidence_path' in feedback['repair_hint']
    assert not state.validation_results
    accepted = json.loads(await registry.execute('workflow', {**args, 'evidence_refs': [eid]}, None, p))
    latest = state.latest_result(candidate.id)
    assert accepted['ok'] and latest is not None and latest.outcome == 'confirmed'
    assert len(sent) == 1


async def test_missing_file_and_argument_guide_write_first_without_new_budget(runtime, tmp_path):
    state, candidate, _, _, oid = await setup(runtime, tmp_path)
    registry, p, *_ = runtime
    before = state.to_dict()
    for fields, code in [({}, 'MISSING_EVIDENCE_PATH'),
                         ({'evidence_path': 'missing-parent/proof.md'}, 'MISSING_EVIDENCE_FILE')]:
        result = await registry.execute('workflow', {
            'action': 'record_evidence', 'candidate_id': candidate.id,
            'observation_ids': [oid], **fields}, None, p)
        feedback = error(result)
        assert feedback['code'] == code
        assert 'file_write' in feedback['next_action'] and 'artifacts/findings' in feedback['next_action']
        assert state.to_dict() == before
        assert not (tmp_path / 'missing-parent').exists()
    assert current_budget(state, candidate.id) is None


async def test_truncated_primary_is_not_salvaged_and_feedback_identifies_next_step(runtime, tmp_path):
    state, candidate, _, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, _, sent, *_ = runtime
    # A new mock response, not mutation of the already registered parent snapshot.
    await registry.execute('http', {'url': '/fixture?q=bounded', 'phase': 'validation'}, None, p)
    bad_id = next(reversed(policy.observations._items))
    bad = replace(policy.observations._items[bad_id], truncated=True, complete=False)
    policy.observations._items[bad_id] = replace(bad, retained_hash=digest(source_row(bad)))
    result = await registry.execute('workflow', {**args, 'observation_ids': [oid, bad_id]}, None, p)
    feedback = error(result)
    assert feedback['code'] == 'UNUSABLE_PRIMARY_SOURCE'
    hint = feedback['repair_hint']
    assert 'complete, compact, non-sensitive' in hint and 'no credentials or bulk data' in hint
    assert 'insufficient-evidence' in hint and 'inconclusive' in hint
    assert 'pagination cannot recover' in hint and 'Do not increase caps' in hint
    assert not state.validation_results and not state.eligible_for_finding(candidate.id)
    unresolved = await registry.execute('workflow', {**args, 'outcome': 'insufficient-evidence',
        'evidence_refs': [], 'observation_ids': [], 'notes': 'Incomplete primary response.'}, None, p)
    assert json.loads(unresolved)['ok'] and len(sent) == 2
    assert not state.eligible_for_finding(candidate.id)


import pytest
from src.workflow.state import WorkflowObjective


@pytest.mark.parametrize('change', ['objective', 'target', 'artifact'])
async def test_new_attempt_rechecks_scope_and_phase_after_evidence_await(runtime, tmp_path, monkeypatch, change):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, p, _, _, _, _, target = runtime
    assert json.loads(await registry.execute('workflow', {**args, 'outcome': 'not-confirmed'}, None, p))['ok']
    previous_attempts = set(state.attempts)
    async def changed(*a, **kw):
        if change == 'objective':
            state.objective = WorkflowObjective('replacement', 'whole_target', target.base_url())
        elif change == 'target':
            target.set_base_url('https://other.test')
        else:
            path = tmp_path / tool.phase_completion_readiness('recon')['artifact_ref']
            path.unlink()
        return False  # Existing proof repair would otherwise allow a new Attempt.
    monkeypatch.setattr('src.tools.workflow.workflow_tool.verify_evidence_reads', changed)
    result = await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': candidate.id}, None, p)
    assert result.startswith('error:') and set(state.attempts) == previous_attempts
    if change == 'artifact': assert 'WHOLE_TARGET_VALIDATION_PREREQUISITE' in result
    else: assert 'state changed during evidence read' in result
