"""Cleanup declarations through native Workflow admission, with no real I/O."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from src.llm.core.client import Client
from src.workflow.assessment import accepted_result, attempt_effects, digest, source_row
from src.workflow.state import WorkflowState
from tests.scenarios.conftest import offline_scenario
from tests.security.test_agent_assessment import setup, sql_negative_comparison
from tests.security.test_execution_policy import runtime


NEGATED_STATUS = 'Read-only GET search endpoint; no server-side state was created, modified or deleted.'


@pytest.fixture(autouse=True)
def no_provider(offline_scenario, monkeypatch):
    async def deny(*_args, **_kwargs):
        pytest.fail('cleanup regression must not call a provider')
    monkeypatch.setattr(Client, 'chat', deny)


def declaration(args, oid, **changes):
    return {
        'action': 'record_attempt_state', 'candidate_id': args['candidate_id'],
        'attempt_id': args['attempt_id'], 'mutation_state': 'no-mutation-established',
        'mutation_performed': False, 'cleanup_state': 'not-required',
        'cleanup_status': NEGATED_STATUS, 'observation_ids': [oid],
        'effect_basis': 'Explicit bounded declaration based on the owned synthetic response.',
        **changes,
    }


@pytest.mark.parametrize('status', [
    NEGATED_STATUS,
    NEGATED_STATUS[:-1] + ' by any probe.',
    'No persistent state was created, modified, or deleted.',
])
async def test_negated_declaration_only_updates_owned_attempt_bookkeeping(runtime, tmp_path, status):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, prompter, policy, _, sent, *_ = runtime
    aid = args['attempt_id']
    assert policy.observations._items[oid].attempt_id == aid
    # The GET/200 fixture alone has not established mutation absence.
    assert attempt_effects(state, state.attempts[aid], policy.observations)['mutation_performed'] is None
    before = state.to_dict()
    observations = dict(policy.observations._items)
    output = await registry.execute('workflow', declaration(args, oid, cleanup_status=status), None, prompter)
    assert not output.startswith('error:'), output
    payload = json.loads(output)
    assert payload['ok'] and payload['attempt_id'] == aid
    assert payload['effects']['mutation_performed'] is False
    assert payload['effects']['cleanup_state'] == 'not-required'
    assert payload['effects']['cleanup_status'] == status
    after = state.to_dict()
    before['attempts'][aid]['effects']['declaration'] = payload['effects']
    assert set(after['selected_sources']) == {oid}
    assert after['selected_sources'][oid]['hash'] == observations[oid].retained_hash
    before['selected_sources'] = after['selected_sources']
    assert after == before
    assert state.committed_revision > 0 and state.attempts[aid]['status'] == 'active'
    assert not state.validation_results and not state.persisted_findings
    assert not state.eligible_for_finding(candidate.id)
    assert tool.coverage is not None and not await tool.coverage.list()
    assert len(sent) == 1 and policy.observations._items == observations


@pytest.mark.parametrize('outcome', ['confirmed', 'not-confirmed', 'insufficient-evidence'])
async def test_result_inherits_negated_declaration_without_changing_outcome(runtime, tmp_path, outcome):
    state, candidate, _, args, oid = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, prompter, policy, _, sent, *_ = runtime
    if outcome == 'not-confirmed':
        args = await sql_negative_comparison(runtime, tmp_path, args)
    sent_before = len(sent)
    output = await registry.execute('workflow', declaration(args, oid), None, prompter)
    assert not output.startswith('error:'), output
    submission = {key: value for key, value in args.items() if key != 'mutation_performed'}
    output = await registry.execute('workflow', {**submission, 'outcome': outcome}, None, prompter)
    assert not output.startswith('error:'), output
    assert json.loads(output)['ok']
    result = state.latest_result(candidate.id)
    assert result is not None and result.outcome == outcome
    assert result.mutation_performed is False and result.cleanup_state == 'not-required'
    assert result.cleanup_status == NEGATED_STATUS and result.attempt_id == args['attempt_id']
    assert state.eligible_for_finding(candidate.id) is (outcome == 'confirmed')
    assert accepted_result(state, candidate, result, policy) is (outcome != 'insufficient-evidence')
    assert len(state.validation_results) == 1 and not state.persisted_findings and len(sent) == sent_before
    assert WorkflowState.from_dict(deepcopy(state.to_dict())).to_dict() == state.to_dict()


@pytest.mark.parametrize('status', [
    'Resource deleted and verified.',
    'No errors; resource deleted and verified.',
    'No state was created or deleted; resource removed and verified.',
    'Resource was not deleted; Agent cleanup restored the fixture.',
    'No state was created and the resource was deleted and verified.',
    'No state was deleted; cleanup pending; resource removed and verified.',
    'No state was deleted; parent reset succeeded; Agent cleanup restored the fixture.',
    'Resource was not deleted but was restored; verification pending.',
])
async def test_positive_or_mixed_claim_rejects_without_state_changes(runtime, tmp_path, status):
    state, _, _, args, oid = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, prompter, policy, _, sent, *_ = runtime
    before = state.to_dict()
    revision = state.committed_revision
    output = await registry.execute('workflow', declaration(args, oid, cleanup_status=status), None, prompter)
    assert 'cleanup declaration contradicts mutation_performed=false' in output
    assert state.to_dict() == before and state.committed_revision == revision
    assert len(sent) == 1 and set(policy.observations._items) == {oid}


@pytest.mark.parametrize('fault', ['missing', 'ownership', 'origin', 'incomplete', 'integrity'])
async def test_negation_does_not_bypass_source_gates(runtime, tmp_path, fault):
    state, _, _, args, oid = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, prompter, policy, _, sent, *_ = runtime
    if fault == 'missing':
        policy.observations._items.clear()
    else:
        changes = {
            'ownership': {'attempt_id': 'foreign-attempt'},
            'origin': {'url': 'http://other.test/fixture'},
            'incomplete': {'complete': False},
            'integrity': {'body': b'substituted'},
        }[fault]
        item = replace(policy.observations._items[oid], **changes)
        if fault != 'integrity':
            item = replace(item, retained_hash=digest(source_row(item)))
        policy.observations._items[oid] = item
    before = state.to_dict()
    revision = state.committed_revision
    output = await registry.execute('workflow', declaration(args, oid), None, prompter)
    assert output.startswith('error:'), output
    assert state.to_dict() == before and state.committed_revision == revision and len(sent) == 1


async def test_negation_cannot_erase_reported_write_or_replace_cleanup_readback(runtime, tmp_path):
    state, _, _, args, oid = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, prompter, _, _, sent, *_ = runtime
    reported = declaration(args, oid, mutation_state='reported-write', mutation_performed=True,
                           cleanup_state='not-attempted', cleanup_status='Agent cleanup not attempted')
    output = await registry.execute('workflow', reported, None, prompter)
    assert json.loads(output)['ok']
    before = state.to_dict()
    revision = state.committed_revision
    output = await registry.execute('workflow', declaration(args, oid), None, prompter)
    assert 'acknowledged writes cannot be erased' in output
    assert state.to_dict() == before and state.committed_revision == revision
    output = await registry.execute('workflow', {
        **reported, 'cleanup_state': 'succeeded', 'cleanup_status': 'Agent cleanup deleted and verified the resource.',
    }, None, prompter)
    assert 'owned cleanup action and subsequent verification readback' in output
    assert state.to_dict() == before and state.committed_revision == revision and len(sent) == 1
