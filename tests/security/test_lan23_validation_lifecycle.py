"""Offline lifecycle regressions; synthetic responses are not target evidence."""
import json

import pytest

from src.workflow.state import WorkflowState
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime  # noqa: F401


def error(output):
    assert output.startswith('error:')
    return json.loads(output.split('\n', 1)[1])['error']


async def test_truncated_history_rewrite_reuses_complete_sources_and_preserves_snapshot(runtime, tmp_path):
    state, candidate, tool, args, first = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, p, policy, _, sent, *_ = runtime
    partials = []
    for repetition in (1, 2):
        await registry.execute('http', {'url': '/fixture?q=positive' + str(repetition),
            'phase': 'validation', 'max_response_bytes': 3}, None, p)
        partials.append(next(reversed(policy.observations._items)))
    assert all(policy.observations._items[oid].truncated for oid in partials)
    good = []
    for value in ('positive1', 'negative1', 'positive2', 'negative2'):
        await registry.execute('http', {'url': '/fixture?q=' + value, 'phase': 'validation'}, None, p)
        good.append(next(reversed(policy.observations._items)))
    proof = tmp_path / 'proof.md'
    proof.write_text(f'# Proof\n- candidate_id: {candidate.id}\n' +
                     ''.join(f'| incomplete history | {oid} |\n' for oid in partials) +
                     ''.join(f'| supporting capture | {oid} |\n' for oid in good))
    registration = {'action': 'record_evidence', 'candidate_id': candidate.id,
                    'evidence_path': 'proof.md', 'observation_ids': [*partials, *good]}
    receipt = json.loads(await registry.execute('workflow', registration, None, p))
    readiness = receipt['terminal_readiness']
    assert readiness['status'] == 'unusable-primary-sources'
    assert readiness['unusable_sources'] == [
        {'observation_id': oid, 'reasons': ['truncated', 'incomplete']} for oid in partials]
    assert not receipt['terminal_assessment_accepted']
    old = receipt['evidence']
    original = (tmp_path / old['path']).read_bytes()
    rejected = await registry.execute('workflow', {**args, 'evidence_refs': [old['id']],
                                                 'observation_ids': [*partials, *good]}, None, p)
    assert error(rejected)['offending_observation_ids'] == [partials[0]]
    # Dropping a cited historical row without rewriting is still rejected.
    assert error(await registry.execute('workflow', {**registration, 'observation_ids': good}, None, p))['code'] == 'PROOF_PARENT_MISMATCH'
    # Keep the original adverse capture in the ledger, outside terminal proof.
    proof.write_text(f'# Corrected proof\n- candidate_id: {candidate.id}\n' +
                     ''.join(f'| supporting capture | {oid} |\n' for oid in good))
    repaired = json.loads(await registry.execute('workflow', {**registration, 'observation_ids': good}, None, p))
    assert repaired['terminal_readiness']['status'] == 'usable-primary-sources'
    assert repaired['evidence']['id'] != old['id']
    assert not repaired['terminal_assessment_accepted']
    declaration = {'action': 'record_attempt_state', 'candidate_id': candidate.id,
                   'mutation_state': 'no-mutation-established', 'effect_basis': 'Stateless controlled fixture.',
                   'cleanup_state': 'not-required', 'observation_ids': good}
    assert json.loads(await registry.execute('workflow', declaration, None, p))['ok']
    submitted = {**args, 'evidence_refs': [repaired['evidence']['id']], 'observation_ids': good}
    assert json.loads(await registry.execute('workflow', submitted, None, p))['ok']
    assert len(sent) == 7 and (tmp_path / old['path']).read_bytes() == original
    assert state.evidence_sources[old['id']] == [*partials, *good]
    assert all(oid in policy.observations._items for oid in partials)
    restored = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
    latest = restored.latest_result(candidate.id)
    assert latest is not None and latest.evidence_refs == [repaired['evidence']['id']]


async def test_effects_projection_changes_after_dispatch_and_redeclaration(runtime, tmp_path):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    declaration = {'action': 'record_attempt_state', 'candidate_id': candidate.id,
                   'mutation_state': 'no-mutation-established', 'effect_basis': 'Controlled stateless fixture.',
                   'cleanup_state': 'not-required', 'observation_ids': [oid]}
    await registry.execute('workflow', declaration, None, p)
    handoff = tool.validation_handoff(candidate.id, policy)
    assert handoff is not None and handoff['effects']['declaration_current']
    await registry.execute('http', {'url': '/fixture?q=repeat', 'phase': 'validation'}, None, p)
    handoff = tool.validation_handoff(candidate.id, policy)
    assert handoff is not None
    projection = handoff['effects']
    assert not projection['declaration_current'] and projection['declaration_required']
    assert projection['mutation_performed'] is None and projection['cleanup_state'] == 'unknown'
    assert projection['completed_dispatches'] == 2
    declaration['observation_ids'].append(next(reversed(policy.observations._items)))
    await registry.execute('workflow', declaration, None, p)
    handoff = tool.validation_handoff(candidate.id, policy)
    assert handoff is not None and handoff['effects']['declaration_current']
    assert json.loads(await registry.execute('workflow', args, None, p))['ok']


@pytest.mark.parametrize('oracle', [None, 'unknown', 'inconclusive'])
async def test_sql_negative_requires_established_oracle_without_false_coverage(runtime, tmp_path, oracle):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, p, *_ = runtime
    assessment = {**args['assessment'], 'oracle_status': oracle}
    rejected = await registry.execute('workflow', {**args, 'outcome': 'not-confirmed',
                                                 'assessment': assessment}, None, p)
    payload = error(rejected)
    assert payload['code'] == 'UNRESOLVED_ORACLE'
    assert payload['repair_kind'] == 'validation-step'
    assert 'reassess' in payload['repair_hint'].lower()
    assert tool.coverage is not None
    assert not state.validation_results and not await tool.coverage.list()


async def test_meaningful_sql_negative_remains_available(runtime, tmp_path):
    state, candidate, _, args, _ = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, p, *_ = runtime
    assessment = {**args['assessment'], 'oracle_status': 'established',
                  'oracle_basis': 'Synthetic fixture controls establish an applicable, interpretable test.'}
    result = json.loads(await registry.execute('workflow', {**args, 'outcome': 'not-confirmed',
                                                          'assessment': assessment}, None, p))
    latest = state.latest_result(candidate.id)
    assert result['ok'] and latest is not None and latest.outcome == 'not-confirmed'


async def test_model_receives_oracle_reassessment_and_can_stop_without_more_http(runtime, tmp_path):
    from tests.security.test_evidence_recovery_contract import agent_for
    from tests.helpers.agent_fakes import ScriptedModel, FakeSignal, collect
    state, candidate, tool, args, _ = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, p, _, _, sent, *_ = runtime
    def script():
        rejected = yield 'workflow', {**args, 'outcome': 'not-confirmed',
            'assessment': {**args['assessment'], 'oracle_status': 'inconclusive'}}
        feedback = error(rejected)
        assert feedback['code'] == 'UNRESOLVED_ORACLE'
        assert 'no mandatory technique sequence' in feedback['repair_hint']
        yield 'workflow', {**args, 'outcome': 'insufficient-evidence',
            'evidence_refs': [], 'observation_ids': [], 'deferred_reason': 'No justified interpretable oracle in remaining bounds.'}
    agent = agent_for(runtime, tool, state, args, max_steps=3)
    model = ScriptedModel(script(), prefix='oracle-review')
    agent.client = model
    agent.active_skills.add('sql-injection')
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    assert model.consumed and not model.errors
    latest = state.latest_result(candidate.id)
    assert latest is not None and latest.outcome == 'insufficient-evidence'
    assert tool.coverage is not None and not await tool.coverage.list()
    assert len(sent) == 1


async def test_closed_attempt_projection_preserves_known_write_uncertainty(runtime, tmp_path):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    declaration = {'action': 'record_attempt_state', 'candidate_id': candidate.id,
        'mutation_state': 'reported-write', 'effect_basis': 'Synthetic acknowledged fixture write.',
        'cleanup_state': 'requires-user-action', 'observation_ids': [oid]}
    assert json.loads(await registry.execute('workflow', declaration, None, p))['ok']
    assert json.loads(await registry.execute('workflow', {**args, 'outcome': 'insufficient-evidence',
        'mutation_performed': True, 'cleanup_state': 'requires-user-action',
        'deferred_reason': 'Fixture cleanup requires operator action.'}, None, p))['ok']
    handoff = tool.validation_handoff(candidate.id, policy)
    assert handoff is not None and not handoff['owned_active']
    assert handoff['effects']['mutation_performed'] is True
    assert handoff['effects']['cleanup_state'] == 'requires-user-action'
