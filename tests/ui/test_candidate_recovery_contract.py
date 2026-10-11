"""Offline candidate creation through the runtime facts and invocation ledger."""
import json

import pytest

from src.agent.events import Invocation, ToolCallEvent, ToolResultEvent, DoneEvent
from src.agent.scope import runtime_scope
from src.agent.agent import ToolCallResult, _to_agent_event
from src.llm.core.types import FunctionCall, ToolCall
from src.permission.permission import AlwaysAllow
from src.workflow.state import WorkflowObjective
from src.tools.workflow.workflow_tool import WorkflowTool
from tests.integration.test_scope_event_lifecycle import runtime as agent_runtime
from tests.helpers.agent_fakes import FakeSignal
from tests.ui.test_progress_milestones import dispatch, ORIGIN
from src.ui.core.state import SetBusy


def runtime(tmp_path, *, whole=False):
    agent, app, _, _, _ = agent_runtime(tmp_path, initial=ORIGIN, http_enabled=False)
    agent.workflow.objective = WorkflowObjective('fixture-objective', 'whole_target' if whole else 'direct', ORIGIN)
    tool = WorkflowTool(agent.workflow, target=agent.target, skills=agent.skills, evidence_root=tmp_path)
    agent.tools.register(tool)
    return app, agent.workflow, tool


def call(app, identifier, args):
    tc = ToolCall(id=identifier, function=FunctionCall(name='workflow', arguments=json.dumps(args)))
    parsed = app.agent.parse_tool_call(tc)
    dispatch(app, _to_agent_event(app.agent._tool_call_event(tc, parsed)))
    return parsed.invocation


async def result(app, tool, identifier, args, invocation):
    tc = ToolCall(id=identifier, function=FunctionCall(name='workflow', arguments=json.dumps(args)))
    parsed = app.agent.parse_tool_call(tc)
    output = await app.agent.run_parsed_tool_call(tc, parsed, FakeSignal())
    dispatch(app, _to_agent_event(app.agent._tool_result_event(tc, output, invocation)))
    return output.result


@pytest.mark.parametrize('whole', [False, True])
async def test_corrected_candidate_retry_recovers_owned_issue_once(tmp_path, whole):
    app, state, tool = runtime(tmp_path, whole=whole)
    assert state.objective is not None
    args = {'action': 'record_candidate', 'candidate_class': 'sqli',
            'endpoint': '/login', 'method': 'POST', 'parameter': 'email'}
    if whole:
        output = await tool.run({'action': 'record_input', 'endpoint': '/login',
                                 'method': 'POST', 'parameter': 'email'}, None, AlwaysAllow())
        args = {'action': 'record_candidate', 'candidate_class': 'sqli',
                'input_id': json.loads(output)['input']['id']}
    bad = {**args, 'objective_id': state.objective.id}
    failed = await result(app, tool, 'bad', bad, call(app, 'bad', bad))
    assert 'objective_id is assigned by the runtime' in failed
    assert not state.candidates
    assert sum(not issue.recovered for issue in app.state.issues) == 1
    output = await result(app, tool, 'good', args, call(app, 'good', args))
    assert json.loads(output)['ok'] is True
    assert len(state.candidates) == 1
    assert app.state.issues[0].recovered
    assert 'objective_id is assigned by the runtime' in app.state.transcript[0].text
    await result(app, tool, 'again', args, call(app, 'again', args))
    assert len(state.candidates) == 1
    assert len(app.state.issues) == 1


async def test_canonical_aliases_and_method_endpoint_forms_share_recovery(tmp_path):
    app, state, tool = runtime(tmp_path)
    assert state.objective is not None
    bad = {'action': 'record_candidate', 'candidate_class': 'sqli',
           'endpoint': 'POST /login', 'parameter': 'email', 'objective_id': state.objective.id}
    await result(app, tool, 'bad', bad, call(app, 'bad', bad))
    args = {'action': 'record_candidate', 'candidate_class': 'sql-injection',
            'endpoint': '/login', 'method': 'post', 'parameter': 'email', 'signals': ['observed']}
    await result(app, tool, 'good', args, call(app, 'good', args))
    assert app.state.issues[0].recovered
    assert len(state.candidates) == 1


@pytest.mark.parametrize('reserved', ['candidate_id', 'attempt_id', 'scope', 'session_id'])
async def test_creation_rejects_runtime_owned_arguments(tmp_path, reserved):
    _, state, tool = runtime(tmp_path)
    output = await tool.run({'action': 'record_candidate', 'candidate_class': 'sqli',
                             reserved: 'invented'}, None, AlwaysAllow())
    assert output.startswith('error:')
    assert not state.candidates


@pytest.mark.parametrize('change', [
    {'candidate_class': 'xss'}, {'endpoint': '/other'}, {'parameter': 'password'},
    {'test_case': 'other-case'}, {'location': 'header'}, {'auth_context_ref': 'other-auth'},
    {'baseline_request_ref': 'other-capture'}, {'content_type': 'application/json'},
    {'request_template': '{"email":"{INJECTION_POINT}"}'}, {'source_ref': 'other-source'},
])
async def test_sibling_creation_never_recovers_original_candidate(tmp_path, change):
    app, state, tool = runtime(tmp_path)
    assert state.objective is not None
    args = {'action': 'record_candidate', 'candidate_class': 'sqli',
            'endpoint': '/login', 'method': 'POST', 'parameter': 'email'}
    bad = {**args, 'objective_id': state.objective.id}
    await result(app, tool, 'bad', bad, call(app, 'bad', bad))
    sibling = {**args, **change}
    output = await result(app, tool, 'sibling', sibling, call(app, 'sibling', sibling))
    assert json.loads(output)['ok'] is True
    assert not app.state.issues[0].recovered


@pytest.mark.parametrize('boundary', ['target', 'objective', 'scope', 'turn'])
async def test_recovery_never_crosses_runtime_boundary(tmp_path, boundary):
    app, state, tool = runtime(tmp_path)
    assert state.objective is not None
    args = {'action': 'record_candidate', 'candidate_class': 'sqli', 'endpoint': '/login'}
    bad = {**args, 'objective_id': state.objective.id}
    await result(app, tool, 'bad', bad, call(app, 'bad', bad))
    pending = call(app, 'pending', args)
    if boundary == 'target':
        app.agent.target.set_base_url('https://other.test')
        state.objective = WorkflowObjective('other-objective', 'direct', 'https://other.test')
    elif boundary == 'objective':
        state.objective = WorkflowObjective('other-objective', 'direct', ORIGIN)
    elif boundary == 'scope':
        app.agent.engagement_state.http_permissions.epoch = 'rotated-test-epoch'
    else:
        dispatch(app, DoneEvent(stop_reason='final_response'))
        app.dispatch(SetBusy(True))
    await result(app, tool, 'pending', args, pending)
    assert not any('recovered by' in row.text for row in app.state.transcript)
    await result(app, tool, 'new', args, call(app, 'new', args))
    assert not any('recovered by' in row.text for row in app.state.transcript)


@pytest.mark.parametrize('fabrication', ['no_state', 'existing_candidate', 'sibling', 'wrong_invocation'])
async def test_fabricated_or_unowned_receipt_cannot_recover(tmp_path, fabrication):
    app, state, tool = runtime(tmp_path)
    assert state.objective is not None
    args = {'action': 'record_candidate', 'candidate_class': 'sqli', 'endpoint': '/login'}
    bad = {**args, 'objective_id': state.objective.id}
    await result(app, tool, 'bad', bad, call(app, 'bad', bad))
    invocation = call(app, 'retry', args)
    if fabrication == 'no_state':
        receipt = json.dumps({'ok': True, 'candidate': {'id': tool.candidate_proposal(args).id}})
    else:
        actual = {**args, 'endpoint': '/sibling'} if fabrication == 'sibling' else args
        receipt = await tool.run(actual, None, AlwaysAllow())
    if fabrication == 'sibling':
        tc = ToolCall('retry', FunctionCall('workflow', json.dumps(args)))
        event = _to_agent_event(app.agent._tool_result_event(tc, ToolCallResult(receipt, '', 0), invocation))
        assert event.accepted_candidate_id is None
    else:
        if fabrication == 'wrong_invocation':
            invocation = Invocation('fabricated', runtime_scope(app.agent))
        event = ToolResultEvent(id='retry', name='workflow', result=receipt, invocation=invocation)
    dispatch(app, event)
    assert not app.state.issues[0].recovered


async def test_recovery_keeps_other_errors_and_ignores_duplicate_and_late_delivery(tmp_path):
    app, state, tool = runtime(tmp_path)
    assert state.objective is not None
    args = {'action': 'record_candidate', 'candidate_class': 'sqli', 'endpoint': '/login'}
    bad = {**args, 'objective_id': state.objective.id}
    await result(app, tool, 'bad', bad, call(app, 'bad', bad))
    for name, inputs in [('shell', {'command': 'fixture'}), ('file_read', {'path': 'missing'})]:
        invocation = Invocation(name, runtime_scope(app.agent))
        dispatch(app, ToolCallEvent(id=name, name=name, args=inputs, invocation=invocation))
        dispatch(app, ToolResultEvent(id=name, name=name, err='fixture missing', status='error', invocation=invocation))
    invocation = call(app, 'retry', args)
    receipt = await result(app, tool, 'retry', args, invocation)
    tc = ToolCall('retry', FunctionCall('workflow', json.dumps(args)))
    event = _to_agent_event(app.agent._tool_result_event(tc, ToolCallResult(receipt, '', 0), invocation))
    before = app.state
    dispatch(app, event)
    assert app.state == before
    # A later failure reopens its own issue; a retired success cannot clear it.
    await result(app, tool, 'bad-again', bad, call(app, 'bad-again', bad))
    dispatch(app, event)
    assert sum(not issue.recovered for issue in app.state.issues) == 3
    await result(app, tool, 'correct-again', args, call(app, 'correct-again', args))
    assert sum(not issue.recovered for issue in app.state.issues) == 2
    dispatch(app, DoneEvent(stop_reason='final_response'))
    assert '2 unrecovered operation issues' in app.state.transcript[-1].text
    assert len(state.candidates) == 1
