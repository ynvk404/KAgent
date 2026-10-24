"""Offline proof-parent diagnostics; fixture captures are never SQLi evidence."""
from dataclasses import replace
import hashlib
import json

import pytest

from src.skills.load_skill import LoadSkillTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.assessment import digest, source_row
from src.workflow.evidence.artifacts import check_proof_references
from src.workflow.evidence.errors import EvidenceSubmissionError, evidence_repair_kind
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime  # noqa: F401


def error_payload(output):
    assert output.startswith('error:')
    assert evidence_repair_kind(output) == 'manifest'
    return json.loads(output.split('\n', 1)[1])['error']


async def test_ledger_parents_and_effect_declaration_are_independent(runtime, tmp_path):
    state, candidate, _, args, first = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, p, policy, _, sent, *_ = runtime
    ids = [first]
    for index in range(9):
        await registry.execute('http', {'url': '/fixture?q=' + str(index), 'phase': 'validation'}, None, p)
        ids.append(next(reversed(policy.observations._items)))
    # Preserve controls and inconclusive history as well as the selected pair rows.
    proof = tmp_path / 'proof.md'
    proof.write_text(f'# Fixture proof\n- candidate_id: {candidate.id}\n\n'
                     '| role | observation_id |\n|---|---|\n' +
                     ''.join(f'| fixture {i} | {oid} |\n' for i, oid in enumerate(ids)))
    original = proof.read_bytes()
    registered_before = state.evidence.copy()
    parents_before = state.evidence_sources.copy()
    selected = [ids[i] for i in [0, 1, 6, 7, 8, 9]]
    registration = {'action': 'record_evidence', 'candidate_id': candidate.id,
                    'evidence_path': 'proof.md', 'observation_ids': selected}
    expected = [{'observation_id': ids[i], 'proof_line_numbers': [6 + i]} for i in range(2, 6)]
    first_error = error_payload(await registry.execute('workflow', registration, None, p))
    assert first_error['code'] == 'PROOF_PARENT_MISMATCH'
    assert first_error['missing_primary_parent_count'] == 4
    assert first_error['missing_primary_parents'] == expected
    assert not first_error['missing_primary_parents_truncated']
    # Effects bookkeeping does not register a proof's primary parents.
    declaration = json.loads(await registry.execute('workflow', {
        'action': 'record_attempt_state', 'candidate_id': candidate.id,
        'attempt_id': args['attempt_id'], 'mutation_state': 'no-mutation-established',
        'effect_basis': 'The controlled fixture performs no persistent writes.',
        'cleanup_state': 'not-required', 'cleanup_status': 'Stateless fixture.',
        'observation_ids': ids[6:8]}, None, p))
    assert declaration['ok']
    retry = {**registration, 'observation_ids': selected[2:] + selected[:2]}
    assert error_payload(await registry.execute('workflow', retry, None, p)) == first_error
    assert proof.read_bytes() == original
    assert state.evidence == registered_before and state.evidence_sources == parents_before
    assert not state.validation_results and not state.eligible_for_finding(candidate.id)
    # A deliberate caller repair includes all ten real owned parents, with no HTTP.
    result = json.loads(await registry.execute('workflow', {**registration, 'observation_ids': ids}, None, p))
    assert result['ok'] and result['primary_parents'] == ids
    evidence = result['evidence']
    assert state.evidence_sources[evidence['id']] == ids
    assert hashlib.sha256((tmp_path / evidence['path']).read_bytes()).hexdigest() == evidence['sha256']
    assert proof.read_bytes() == original and len(sent) == 10
    assert not state.validation_results and not state.eligible_for_finding(candidate.id)


@pytest.mark.parametrize('fault,code', [('absent', 'PRIMARY_REFERENCE_UNAVAILABLE'),
                                      ('foreign-attempt', 'SOURCE_OWNERSHIP_MISMATCH')])
async def test_parent_diagnostics_never_adopt_or_rebind_sources(runtime, tmp_path, fault, code):
    state, candidate, _, _, oid = await setup(runtime, tmp_path)
    registry, p, policy, _, sent, *_ = runtime
    if fault == 'absent':
        oid = 'obs_' + 'f' * 32
    else:
        source = replace(policy.observations._items[oid], attempt_id='foreign-attempt')
        policy.observations._items[oid] = replace(source, retained_hash=digest(source_row(source)))
    (tmp_path / 'proof.md').write_text(f'# Proof\n- candidate_id: {candidate.id}\n- observation_ids: {oid}\n')
    before = state.evidence.copy()
    output = await registry.execute('workflow', {'action': 'record_evidence', 'candidate_id': candidate.id,
        'evidence_path': 'proof.md', 'observation_ids': [oid]}, None, p)
    error = error_payload(output)
    assert error['code'] == code and 'missing_primary_parents' not in error
    assert oid not in output and 'foreign-attempt' not in output
    assert state.evidence == before and not state.validation_results and len(sent) == 1


def test_parent_diagnostic_is_bounded_and_contains_no_proof_text():
    ids = ['obs_' + format(i, '032x') for i in range(20)]
    secret = 'Authorization: Bearer fixture-private-text'
    lines = ['# Proof', '- candidate_id: candidate']
    for oid in ids:
        lines.extend(f'| {oid} | {secret} |' for _ in range(10))
    with pytest.raises(EvidenceSubmissionError) as caught:
        check_proof_references('\n'.join(lines).encode(), 'candidate', [])
    output = caught.value.response('record_evidence')
    error = error_payload(output)
    assert secret not in output and 'fixture-private-text' not in output
    assert error['missing_primary_parent_count'] == 20
    assert len(error['missing_primary_parents']) == 16
    assert error['missing_primary_parents_truncated']
    assert all(len(row['proof_line_numbers']) == 8 for row in error['missing_primary_parents'])
    assert error['missing_primary_parents'][0] == {
        'observation_id': ids[0], 'proof_line_numbers': list(range(3, 11))}


def test_cited_history_requires_parents_but_examples_keep_existing_scope():
    oid = 'obs_' + 'a' * 32
    # Fences, quotes and another Candidate are not active claims for this proof.
    example = (f'# Report\n## Candidate one\n- candidate_id: candidate\n'
               f'```\n| {oid} |\n```\n> {oid}\n\n'
               f'## Candidate two\n- candidate_id: other\n| {oid} |\n')
    check_proof_references(example.encode(), 'candidate', [])
    active = f'# Proof\n- candidate_id: candidate\n| inconclusive history | {oid} |\n'
    with pytest.raises(EvidenceSubmissionError) as caught:
        check_proof_references(active.encode(), 'candidate', [])
    error = error_payload(caught.value.response('record_evidence'))
    assert error['missing_primary_parents'] == [{'observation_id': oid, 'proof_line_numbers': [3]}]
    check_proof_references(active.encode(), 'candidate', [oid])


async def test_loaded_sqli_and_workflow_contract_explain_parent_repair(runtime, tmp_path):
    _, _, workflow, _, _ = await setup(runtime, tmp_path, candidate_class='sqli')
    assert workflow.skills is not None
    loaded = ' '.join((await LoadSkillTool(workflow.skills).run({'name': 'sql-injection'})).split())
    for rule in ('inconclusive history', 'record_attempt_state', 'proof parents', 'PROOF_PARENT_MISMATCH'):
        assert rule in loaded
    description = WorkflowTool.schema(workflow)['properties']['observation_ids']['description']
    assert 'record_evidence' in description and 'table' in description and 'primary parent' in description
