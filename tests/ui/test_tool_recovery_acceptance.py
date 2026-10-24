"""Offline negative regressions for the official tool/recovery RCA."""
from dataclasses import replace

import pytest

from src.agent.events import Invocation, ToolCallEvent, ToolResultEvent
from src.ui.core.outcomes import OutcomeFacts
from src.ui.core.state import AgentEventAction, initial_state, reducer
from src.ui.widgets.banner import BannerData


def start():
    return initial_state('', BannerData('offline', 'fixture', '.'))


def dispatch(state, identifier, args, *, name='http'):
    event = ToolCallEvent(id=identifier, name=name, args=args,
                          invocation=Invocation(identifier, 'scope'))
    return reducer(state, AgentEventAction(event)), event


def finish(state, event, *, error=None, kind=None):
    result = ToolResultEvent(id=event.id, name=event.name, invocation=event.invocation,
        status='error' if error else 'observation' if event.name == 'http' else 'success',
        err=error or '', error_kind=kind, result='' if error else '{"ok":true}',
        http_status=None if error else 200)
    return reducer(state, AgentEventAction(result))


@pytest.mark.parametrize('change', [
    {'body': 'mode=B'}, {'url': 'https://fixture.test/form?q=B'},
    {'headers': {'Authorization': 'other-context'}},
])
def test_network_failure_is_not_recovered_by_different_request(change):
    args = {'method': 'POST', 'url': 'https://fixture.test/form?q=A', 'body': 'mode=A'}
    state, a = dispatch(start(), 'a', args)
    state = finish(state, a, error='connection failed', kind='network')
    state, b = dispatch(state, 'b', {**args, **change})
    state = finish(state, b)
    assert not state.issues[0].recovered


@pytest.mark.parametrize('kind', ['permission_denied', 'permission_pending', 'permission_timeout',
    'permission_stale', 'policy_block', 'scope_denied', 'timeout', 'cancelled',
    'tool_exception', 'unknown_effects'])
def test_authority_persistence_and_unknown_effects_do_not_generic_recover(kind):
    args = {'action': 'record_evidence', 'candidate_id': 'candidate', 'evidence_path': 'proof.md'}
    state, a = dispatch(start(), 'a', args, name='workflow')
    state = finish(state, a, error='operation rejected', kind=kind)
    state, b = dispatch(state, 'b', args, name='workflow')
    state = finish(state, b)
    assert not state.issues[0].recovered


def test_predispatched_sibling_is_not_a_retry():
    args = {'method': 'GET', 'url': 'https://fixture.test/form'}
    state, a = dispatch(start(), 'a', args)
    state, b = dispatch(state, 'b', args)
    state = finish(state, a, error='connection failed', kind='network')
    state = finish(state, b)
    assert not state.issues[0].recovered


def test_completed_direct_turn_keeps_history_without_inventing_work():
    from src.agent.events import DoneEvent
    state, a = dispatch(start(), 'a', {'url': 'https://fixture.test/form'})
    state = finish(state, a, error='connection failed', kind='network')
    facts = OutcomeFacts(scope='', completion_supported=False)
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason='final_response'), facts))
    assert 'work remains' not in state.transcript[-1].text
    assert 'operation error without a matched retry' in state.transcript[-1].text


def contract_call(state, identifier):
    facts = OutcomeFacts(scope='scope', operation_owner='owner', operation_intent='intent')
    event = ToolCallEvent(id=identifier, name='workflow',
        args={'action': 'record_result', 'candidate_id': 'candidate'},
        invocation=Invocation(identifier, 'scope'))
    return reducer(state, AgentEventAction(event, facts)), event


def contract_result(state, event, *, failed=False):
    facts = OutcomeFacts(scope='scope', accepted_call=not failed)
    result = ToolResultEvent(id=event.id, name=event.name, invocation=event.invocation,
        status='error' if failed else 'success', error_kind='invalid_args' if failed else None,
        result='error: invalid fields; token=short-secret' if failed else '{"ok":true}')
    return reducer(state, AgentEventAction(result, facts))


@pytest.mark.parametrize('timing', ['retry', 'predispatched', 'live_sibling', 'two_failures'])
def test_dispatch_edge_requires_one_unambiguous_prior_failure(timing):
    state, a = contract_call(start(), 'a')
    if timing in {'predispatched', 'two_failures'}:
        state, b = contract_call(state, 'b')
    state = contract_result(state, a, failed=True)
    if timing == 'two_failures':
        state = contract_result(state, b, failed=True)
    if timing == 'live_sibling':
        state, sibling = contract_call(state, 'sibling')
    if timing != 'predispatched':
        state, b = contract_call(state, 'retry')
    state = contract_result(state, b)
    assert state.issues[0].recovered == (timing == 'retry')
    if timing == 'retry':
        issue = state.issues[0]
        assert b.invocation is not None
        assert issue.recovered_by == b.invocation.id
        assert issue.text in state.transcript[issue.index].details
        assert 'short-secret' not in repr(state)


def test_same_turn_compaction_keeps_edge_but_new_turn_and_unknown_receipts_do_not():
    from src.agent.events import CompactEvent, DoneEvent
    from src.ui.core.state import SetBusy
    state, a = contract_call(start(), 'a')
    state = contract_result(state, a, failed=True)
    state = reducer(state, AgentEventAction(CompactEvent()))
    state, b = contract_call(state, 'b')
    fake = replace(b, invocation=Invocation('fake', 'scope'))
    assert contract_result(state, fake) is state
    state = contract_result(state, b)
    assert state.issues[0].recovered
    assert contract_result(state, b) is state
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason='final_response')))
    state = reducer(state, SetBusy(True))
    before = state
    state = contract_result(state, b)
    assert state is before and not state.issues


def test_multiple_distinct_failures_and_evicted_history_fail_closed():
    # Eviction cannot manufacture a unique retry after discarding competing failures.
    state, a = contract_call(start(), 'a')
    state = contract_result(state, a, failed=True)
    for index in range(257):
        state, call = dispatch(state, f'extra-{index}', {'url': f'/other/{index}'})
        state = finish(state, call, error='unknown effect', kind='tool_exception')
    assert len(state.issues) == 256 and len(state.call_history) <= 256
    assert state.recovery_limited
    state, b = contract_call(state, 'retry')
    assert not state.call_history[-1].retry_of
    assert not any(issue.recovered for issue in contract_result(state, b).issues)


@pytest.mark.parametrize('same_resource', [False, True])
async def test_evidence_retry_requires_same_path_parents_and_registered_snapshot(tmp_path, same_resource):
    import json
    from tests.ui.test_progress_milestones import runtime, dispatch as emit, ORIGIN
    from src.workflow.state import Candidate
    from src.permission.permission import AlwaysAllow
    app, workflow, tool = runtime(tmp_path)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='sqli', target=ORIGIN,
        method='GET', endpoint='/search', parameter='q', objective_id='fixture-objective'))
    args = {'action': 'record_evidence', 'candidate_id': candidate.id, 'evidence_path': 'proof-A.md'}
    emit(app, ToolCallEvent(id='bad', name='workflow', args=args))
    output = await tool.run(args, None, AlwaysAllow())
    from src.tools.common.outcome import ToolOutput
    assert isinstance(output, ToolOutput) and 'MISSING_EVIDENCE_FILE' in output
    emit(app, ToolResultEvent(id='bad', name='workflow', result=output,
        status=output.status, error_kind=output.error_kind))
    repaired = args if same_resource else {**args, 'evidence_path': 'proof-B.md'}
    (tmp_path / repaired['evidence_path']).write_text(f'# Proof\nCandidate: {candidate.id}\n')
    emit(app, ToolCallEvent(id='retry', name='workflow', args=repaired))
    output = await tool.run(repaired, None, AlwaysAllow())
    assert json.loads(output)['ok'] is True
    emit(app, ToolResultEvent(id='retry', name='workflow', result=output))
    assert app.state.issues[0].recovered == same_resource
    assert len(workflow.evidence) == 1


@pytest.mark.parametrize('whole', [False, True])
def test_record_result_argument_repair_retains_real_receipt_and_original_history(tmp_path, whole):
    import json
    from tests.ui.test_progress_milestones import runtime, dispatch as emit, accepted_fixture, ORIGIN
    from src.workflow.state import Candidate
    app, workflow, tool = runtime(tmp_path, whole=whole)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='sqli', target=ORIGIN,
        method='GET', endpoint='/search', parameter='q', objective_id='fixture-objective'))
    accepted = accepted_fixture(tmp_path, workflow, candidate, outcome='not-confirmed')
    args = {'action': 'record_result', 'candidate_id': candidate.id, 'attempt_id': accepted.attempt_id,
        'skill_name': accepted.skill_name, 'outcome': accepted.outcome,
        'evidence_refs': accepted.evidence_refs, 'observation_ids': [row['source']['id'] for row in accepted.evidence_manifest if row.get('source')]}
    bad = {**args, 'mutation_state': 'unknown', 'effect_basis': 'fixture'}
    emit(app, ToolCallEvent(id='bad', name='workflow', args=bad))
    emit(app, ToolResultEvent(id='bad', name='workflow', status='error', error_kind='invalid_args',
        result='error: record_result does not accept effect_basis, mutation_state; omit these arguments'))
    emit(app, ToolCallEvent(id='retry', name='workflow', args={**args, 'notes': 'corrected arguments'}))
    workflow.add_validation_result(accepted)
    emit(app, ToolResultEvent(id='retry', name='workflow',
        result=json.dumps({'ok': True, 'result': accepted.public_dict()})))
    assert app.state.issues[0].recovered
    assert app.state.issues[0].recovered_by == 'retry'
    assert app.state.issues[0].text in app.state.transcript[app.state.issues[0].index].details


@pytest.mark.parametrize('obligation', ['persistence', 'export'])
def test_finding_and_export_success_do_not_reconcile_an_unverified_transaction(obligation):
    args = {'candidate_id': 'candidate', 'title': 'Fixture'}
    state, a = dispatch(start(), 'a', args, name='confirm_finding')
    result = ToolResultEvent(id=a.id, name=a.name, invocation=a.invocation,
        status='error' if obligation == 'persistence' else 'success',
        error_kind='tool_exception' if obligation == 'persistence' else None,
        result='error: publication failed' if obligation == 'persistence' else
               'Finding persisted; compact report export failed.')
    state = reducer(state, AgentEventAction(result))
    state, b = dispatch(state, 'retry', args, name='confirm_finding')
    state = finish(state, b)
    assert len(state.issues) == 1 and not state.issues[0].recovered
    assert state.issues[0].category == ('export' if obligation == 'export' else 'failure')


@pytest.mark.parametrize('changed', ['evidence_refs', 'observation_ids', 'outcome'])
def test_stale_accepted_result_for_another_submission_cannot_recover(tmp_path, changed):
    import json
    from src.workflow.state import Candidate
    from tests.ui.test_progress_milestones import runtime, dispatch as emit, accepted_fixture, ORIGIN
    app, workflow, tool = runtime(tmp_path)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='sqli', target=ORIGIN,
        method='GET', endpoint='/search', parameter='q', objective_id='fixture-objective'))
    result = accepted_fixture(tmp_path, workflow, candidate, outcome='not-confirmed')
    args = {'action': 'record_result', 'candidate_id': candidate.id, 'attempt_id': result.attempt_id,
        'skill_name': result.skill_name, 'outcome': result.outcome, 'evidence_refs': result.evidence_refs,
        'observation_ids': [row['source']['id'] for row in result.evidence_manifest if row.get('source')]}
    args[changed] = 'confirmed' if changed == 'outcome' else ['unrelated-resource']
    emit(app, ToolCallEvent(id='bad', name='workflow', args={**args, 'mutation_state': 'unknown'}))
    emit(app, ToolResultEvent(id='bad', name='workflow', status='error', error_kind='invalid_args',
        result='error: record_result does not accept mutation_state'))
    emit(app, ToolCallEvent(id='retry', name='workflow', args=args))
    workflow.add_validation_result(result)
    emit(app, ToolResultEvent(id='retry', name='workflow',
        result=json.dumps({'ok': True, 'result': result.public_dict()})))
    assert not app.state.issues[0].recovered
