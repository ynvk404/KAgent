import json

import pytest

from src.agent.events import ToolCallEvent, ToolResultEvent
from src.permission.permission import AlwaysAllow
from src.tools.common.outcome import ToolOutput
from src.workflow.state import Candidate
from src.ui.widgets.transcript import entry_view
from tests.ui.test_progress_milestones import runtime, dispatch, ORIGIN


@pytest.mark.parametrize('retry_candidate', ['same', 'other', 'fake_receipt', 'failed', 'other_operation'])
async def test_corrected_start_recovers_only_owned_real_transition(tmp_path, retry_candidate):
    app, state, tool = runtime(tmp_path)
    candidate, _ = state.add_candidate(Candidate(candidate_class='xss', target=ORIGIN,
        endpoint='/search', method='GET', parameter='q', objective_id='fixture-objective'))
    bad = {'action': 'start_validation', 'candidate_id': candidate.id, 'related_requests': [
        {'role': 'baseline', 'method': 'GET', 'url': '/search'},
        {'role': 'control', 'method': 'GET', 'url': '/search'}]}
    before = state.to_dict()
    dispatch(app, ToolCallEvent(id='bad', name='workflow', args=bad))
    failed = await tool.run(bad, None, AlwaysAllow())
    assert isinstance(failed, ToolOutput)
    assert failed.error_kind == 'workflow_state' and 'declare each method/URL once' in failed
    assert state.to_dict() == before
    dispatch(app, ToolResultEvent(id='bad', name='workflow', result=failed,
        status=failed.status, error_kind=failed.error_kind, err=str(failed)))
    issue = app.state.issues[0]
    if retry_candidate == 'other':
        candidate, _ = state.add_candidate(Candidate(candidate_class='xss', target=ORIGIN,
            endpoint='/other', method='GET', parameter='q', objective_id='fixture-objective'))
    corrected = {'action': 'start_validation', 'candidate_id': candidate.id,
        'related_requests': [{'role': 'baseline', 'method': 'GET', 'url': candidate.endpoint}]}
    if retry_candidate == 'failed':
        corrected = bad
    elif retry_candidate == 'other_operation':
        corrected = {'action': 'list'}
    dispatch(app, ToolCallEvent(id='good', name='workflow', args=corrected))
    if retry_candidate == 'fake_receipt':
        output = json.dumps({'ok': True, 'validation_context': {'attempt_id': 'attempt_fabricated'}})
    else:
        output = await tool.run(corrected, None, AlwaysAllow())
        if retry_candidate != 'failed':
            assert json.loads(output)['ok'] is True
    event = ToolResultEvent(id='good', name='workflow', result=output,
        status='error' if retry_candidate == 'failed' else 'success',
        error_kind='workflow_state' if retry_candidate == 'failed' else None,
        err=str(output) if retry_candidate == 'failed' else '')
    dispatch(app, event)
    dispatch(app, event)  # Redelivery must not add another failed attempt.
    updated = next(row for row in app.state.issues if row.key == issue.key)
    assert updated.recovered is (retry_candidate == 'same')
    assert updated.text == issue.text
    assert updated.count == (2 if retry_candidate == 'failed' else 1)
    entry = app.state.transcript[updated.index]
    displayed = '\n'.join(line.text for line in entry_view(entry))
    if retry_candidate == 'same':
        assert entry.kind == 'info'
        assert entry.text == 'workflow · start validation · GET /search · input q'
        assert entry.details == ('Recovered after 1 failed attempt',)
        assert 'error:' not in displayed and 'ambiguous duplicate' not in displayed
        assert 'ambiguous duplicate' in updated.text
    else:
        assert entry.kind == 'error'
        assert 'ambiguous duplicate' in displayed
        assert 'Recovered after' not in displayed
    assert sum(row.text.startswith('Validation started') for row in app.state.transcript) == (retry_candidate in {'same', 'other'})
