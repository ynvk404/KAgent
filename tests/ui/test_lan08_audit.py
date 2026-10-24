"""Offline presentation regressions; historical failures are not workflow state."""
import copy
import json

import pytest

from src.agent.events import DoneEvent, ToolCallEvent, ToolResultEvent
from src.ui.core.admission import call_metadata, issue_category, result_issues
from src.ui.core.outcomes import runtime_facts
from src.workflow.state import Candidate
from tests.ui.test_progress_milestones import (
    ORIGIN, accepted_fixture, complete_phase_fixtures, dispatch, runtime,
)


def test_completed_workflow_keeps_unmatched_errors_without_inventing_blockers(tmp_path):
    app, workflow, tool = runtime(tmp_path, whole=True)
    complete_phase_fixtures(workflow, tool, tmp_path)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='sqli', target=ORIGIN,
        method='GET', endpoint='/search', parameter='q', objective_id='fixture-objective'))
    # An invalid observation-as-baseline is repaired with source provenance.
    # The reducer deliberately cannot assert equivalence between changed args.
    for identifier, baseline in [('bad', 'obs_' + '1' * 32), ('fixed', None)]:
        dispatch(app, ToolCallEvent(id=identifier, name='workflow', args={
            'action': 'record_input', 'method': 'POST', 'endpoint': '/login',
            'parameter': 'email', 'location': 'json', 'source_ref': 'obs_' + '1' * 32,
            **({'baseline_request_ref': baseline} if baseline else {})}))
        dispatch(app, ToolResultEvent(id=identifier, name='workflow',
            result='error: unavailable replay baseline' if baseline else '{"ok":true}',
            status='error' if baseline else 'success'))
    result = accepted_fixture(tmp_path, workflow, candidate, outcome='not-confirmed')
    workflow.add_validation_result(result)
    dispatch(app, ToolCallEvent(id='result', name='workflow', args={
        'action': 'record_result', 'candidate_id': candidate.id, 'attempt_id': result.attempt_id}))
    dispatch(app, ToolResultEvent(id='result', name='workflow',
        result=json.dumps({'ok': True, 'result': result.public_dict()})))
    facts = runtime_facts(app.agent, None, app.state.call_history)
    assert facts.completion_supported and not facts.pending and not facts.blockers
    before = copy.deepcopy(workflow.to_dict())
    dispatch(app, DoneEvent(stop_reason='workflow_completed'))
    summary = app.state.transcript[-1].text
    assert summary.startswith('Workflow completed;')
    assert '1 validation not confirmed' in summary
    assert '1 operation error without a matched retry' in summary
    assert 'work remains' not in summary and 'unresolved operation' not in summary
    assert not app.state.issues[0].recovered  # No fabricated retry correlation.
    assert 'unavailable replay baseline' in app.state.issues[0].text
    assert workflow.to_dict() == before


@pytest.mark.parametrize('pending', ['input', 'proof', 'coverage'])
def test_actual_pending_work_still_prevents_completion(tmp_path, pending):
    from src.ui.core.state import AgentEventAction, reducer
    from src.ui.core.outcomes import OutcomeFacts
    app, _, _ = runtime(tmp_path, whole=True)
    facts = OutcomeFacts(scope=app.state.presentation_scope,
                         pending=(pending + ' pending',), completion_supported=False)
    state = reducer(app.state, AgentEventAction(DoneEvent(stop_reason='workflow_completed'), facts))
    assert 'workflow work remains' in state.transcript[-1].text
    assert pending + ' pending' in state.transcript[-1].text


@pytest.mark.parametrize('whole', [False, True])
@pytest.mark.parametrize('reason,retry', [('normal', 'same'), ('normal', 'changed'),
    ('normal', None), ('max_steps', None), ('context_capacity', None), ('all_tools_refused', None)])
def test_recovery_and_runtime_stop_remain_distinct(tmp_path, whole, reason, retry):
    app, workflow, tool = runtime(tmp_path, whole=whole)
    if whole:
        complete_phase_fixtures(workflow, tool, tmp_path)
    before = copy.deepcopy(workflow.to_dict())
    args = {'action': 'record_input', 'endpoint': '/fixture', 'method': 'POST',
            'parameter': 'email', 'location': 'json', 'baseline_request_ref': 'invalid'}
    dispatch(app, ToolCallEvent(id='bad', name='workflow', args=args))
    dispatch(app, ToolResultEvent(id='bad', name='workflow', status='error',
        error_kind='permission_denied' if reason == 'all_tools_refused' else 'invalid_args',
        err='permission denied' if reason == 'all_tools_refused' else 'invalid baseline'))
    if retry:
        repaired = args if retry == 'same' else {k: v for k, v in args.items() if k != 'baseline_request_ref'}
        dispatch(app, ToolCallEvent(id='retry', name='workflow', args=repaired))
        dispatch(app, ToolResultEvent(id='retry', name='workflow', result='{"ok":true}'))
    assert not app.state.issues[0].recovered  # An ok envelope without a runtime receipt proves no repair.
    stop = ('workflow_completed' if whole else 'final_response') if reason == 'normal' else reason
    dispatch(app, DoneEvent(stop_reason=stop))
    summary = app.state.transcript[-1].text
    if reason == 'normal':
        expected = 'Workflow completed' if whole else 'Turn completed'
        assert summary.startswith(expected)
        if whole:
            assert 'operation error without a matched retry' in summary
    else:
        expected = {'max_steps': 'Stopped at max steps', 'context_capacity': 'Context capacity failure',
                    'all_tools_refused': 'Blocked by tool refusals'}[reason]
        assert summary.startswith(expected) and not summary.startswith('Workflow completed')
        assert 'unresolved operation issue' in summary
    assert workflow.to_dict() == before


@pytest.mark.parametrize('capture_complete', [True, False])
def test_discovery_pagination_distinguishes_next_page_from_missing_capture(capture_complete):
    page = {'discovery_source_id': 'ds_' + '1' * 64, 'observation_id': 'obs_' + '2' * 32,
            'offset_unit': 'unicode_characters', 'start_char': 0, 'end_char': 700,
            'source_chars': 5457, 'next_start_char': 700,
            'complete': capture_complete, 'adapter_truncated': not capture_complete}
    event = ToolResultEvent(name='read_discovery_source', truncated=True,
                            result=json.dumps(page) + '\n' + 'x' * 700)
    original = copy.deepcopy(event)
    notices = result_issues(event, None)
    assert notices == (['Retained body · chars 0–700 of 5457 · more available']
                       if capture_complete else ['Tool output truncated. Omitted output may limit validation.'])
    assert issue_category(notices[0], event) == 'diagnostic'
    assert event == original


@pytest.mark.parametrize('field,value', [('next_start_char', 0), ('start_char', True),
    ('end_char', 9000), ('offset_unit', 'bytes'), ('adapter_truncated', True)])
def test_invalid_discovery_page_metadata_keeps_capture_warning(field, value):
    page = {'offset_unit': 'unicode_characters', 'start_char': 0, 'end_char': 3,
            'source_chars': 10, 'next_start_char': 3, 'complete': True, 'adapter_truncated': False,
            field: value}
    event = ToolResultEvent(name='read_discovery_source', truncated=True,
                            result=json.dumps(page) + '\nabc')
    assert result_issues(event, call_metadata(ToolCallEvent(name=event.name))) == [
        'Tool output truncated. Omitted output may limit validation.']
