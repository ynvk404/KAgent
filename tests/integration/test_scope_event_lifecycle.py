"""Offline target/permission synchronization and result ownership regressions."""
import asyncio
import json
import socket
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from src.agent.agent import Agent, AgentOptions, ToolCallResult, _to_agent_event
from src.agent.events import DoneEvent, SkillActiveEvent, ToolCallEvent, ToolResultEvent
from src.agent.scope import runtime_scope
from src.engagement.state import EngagementState
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import AlwaysAllow, YoloPrompter
from src.permission.runtime.execution import ExecutionPolicy
from src.permission.network.grants import HTTPLimits
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.permission_status import PermissionStatusTool
from src.tools.common.registry import Registry
from src.tools.http.http_tool import HTTPTool
from src.ui.core.state import AgentEventAction, Clear, SetBusy
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.ui.test_app import make_app


A = 'http://127.0.0.1:3000'
B = 'http://127.0.0.1:3001'


def call(identifier, tool_name, **args):
    if tool_name == 'http':
        args.setdefault('phase', 'recon')
    return ToolCall(id=identifier, function=FunctionCall(name=tool_name, arguments=json.dumps(args)))


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    def unexpected_dns(*args, **kwargs):
        raise AssertionError('offline scope regression attempted DNS')
    monkeypatch.setattr(socket, 'getaddrinfo', unexpected_dns)


def runtime(tmp_path, *, initial=A, responses=None, http_enabled=True):
    target, engagement = Target(initial), EngagementState()
    if initial:
        engagement.initialize_target(initial)
    registry, skills = Registry(), SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    if http_enabled:
        registry.register(HTTPTool(target, engagement))
    registry.register(LoadSkillTool(skills))
    registry.register(PermissionStatusTool())
    prompter = YoloPrompter(AlwaysAllow(), False)
    policy = ExecutionPolicy(engagement, tmp_path)
    prompter.bind_execution_policy(policy)
    agent = Agent(AgentOptions(client=FakeClient(responses or []), tools=registry, skills=skills,
                              prompter=prompter, store=None, target=target, engagement_state=engagement))
    app = make_app()
    app.agent = agent
    app.dispatch(SetBusy(True))
    events = []

    def emit(event):
        events.append(event)
        app.dispatch(AgentEventAction(_to_agent_event(event)))

    return agent, app, policy, events, emit


@pytest.mark.parametrize('http_enabled', [True, False])
async def test_prompt_target_synchronizes_before_skill_and_status_dispatch(tmp_path, http_enabled):
    responses = [
        ChatResponse(Message('assistant', '', tool_calls=[call('load', 'load_skill', name='recon'),
                                                        call('status', 'permissions_status')]), 'tool_calls'),
        ChatResponse(Message('assistant', 'Recon playbook loaded.'), 'stop'),
    ]
    agent, app, policy, events, emit = runtime(tmp_path, initial='', responses=responses, http_enabled=http_enabled)
    await agent.run(f'Recon the authorized local lab {A}', FakeSignal(), emit)
    assert agent.target.base_url() == A
    assert sum(row.text == 'Skill activated · recon' for row in app.state.transcript) == 1
    assert sum(name == 'recon' for _, name in app.state.skill_receipts) == 1
    assert not policy.engagement.http_permissions.grants
    assert [event['status'] for event in events if event['type'] == 'tool-result'] == ['success', 'success']


async def test_turn_synchronizes_before_queued_skill_activation(tmp_path):
    responses = [ChatResponse(Message('assistant', '', tool_calls=[call('status', 'permissions_status')]), 'tool_calls'),
                 ChatResponse(Message('assistant', 'Ready.'), 'stop')]
    agent, app, _, _, emit = runtime(tmp_path, responses=responses)
    # A caller can mutate the shared Target before entering the controller turn.
    # Preserve the exact authorized origin while exercising the defensive sync.
    agent.target.set_base_url(A + '/path')
    agent.pending_skills.add('recon')
    await agent.run('Read runtime permissions.', FakeSignal(), emit)
    assert app.state.activated_skills == ('recon',)
    assert sum(row.text == 'Skill activated · recon' for row in app.state.transcript) == 1
    assert app.state.presentation_scope == runtime_scope(agent)


@pytest.mark.parametrize('order', [('one', 'two'), ('two', 'one')])
def test_stale_siblings_keep_original_scope_in_either_order(tmp_path, order):
    agent, app, _, _, _ = runtime(tmp_path)
    for identifier in order:
        app.dispatch(AgentEventAction(ToolCallEvent(id=identifier, name='http', args={'url': '/old'})))
    agent.apply_target_base_url(B)
    for identifier in order:
        app.dispatch(AgentEventAction(ToolResultEvent(id=identifier, name='http', status='error',
                                                    error_kind='network', err='old target failed')))
        assert not app.state.issues
        assert not app.state.observed and not app.state.skill_receipts
        assert app.state.presentation_scope == runtime_scope(agent)
    assert not app.state.transcript


async def test_unchanged_target_and_dispatch_do_not_advance_epoch(tmp_path):
    agent, app, policy, _, emit = runtime(tmp_path)
    rights = policy.engagement.http_permissions
    epoch, revision = rights.epoch, agent.target.revision
    await agent.set_target_base_url(A)
    await agent.set_target_base_url(A)
    await agent.execute_tool_calls([call('status', 'permissions_status')], FakeSignal(), emit, [])
    assert (rights.epoch, agent.target.revision) == (epoch, revision)
    assert app.state.presentation_scope == runtime_scope(agent)


@pytest.mark.parametrize('change', ['change', 'clear', 'same-origin-path'])
async def test_target_mutation_immediately_invalidates_old_permissions_and_events(tmp_path, change):
    agent, app, policy, _, emit = runtime(tmp_path)
    rights = policy.engagement.http_permissions
    rights.activate(A, HTTPLimits(requests=1))
    old_epoch = rights.epoch
    tc = call('old', 'load_skill', name='recon')
    parsed = agent.parse_tool_call(tc)
    emit(agent._tool_call_event(tc, parsed))
    if change == 'clear':
        await agent.clear_target()
    else:
        await agent.set_target_base_url(B if change == 'change' else A + '/path')
    assert rights.epoch != old_epoch and not rights.grants
    epoch = rights.epoch
    policy.stamp()
    assert rights.epoch == epoch
    if change == 'clear':
        await agent.clear_target()
        assert rights.epoch == epoch
    agent.record_tool_result(tc, parsed, ToolCallResult('loaded', '', 0), emit, [])
    assert not app.state.skill_receipts and not app.state.activated_skills
    assert not app.state.observed and not app.state.issues
    assert 'recon' not in agent.active_skills


@pytest.mark.parametrize('order', [(0, 1), (1, 0)])
@pytest.mark.parametrize('old_error', [False, True])
async def test_real_parallel_http_results_interleave_with_current_scope(tmp_path, monkeypatch, order, old_error):
    agent, app, policy, events, emit = runtime(tmp_path)
    policy.engagement.http_permissions.activate(A, HTTPLimits(requests=4, concurrency=4))
    started = [asyncio.Event(), asyncio.Event()]
    release = [asyncio.Event(), asyncio.Event()]
    delivered = [asyncio.Event(), asyncio.Event()]
    sent = []
    client = httpx.AsyncClient

    async def transport(request):
        sent.append(str(request.url))
        if request.url.path.startswith('/old'):
            index = int(request.url.path[-1])
            started[index].set()
            await release[index].wait()
            if old_error:
                raise httpx.ConnectError('old target failed', request=request)
        return httpx.Response(200, content=b'offline fixture', request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: client(**kw, transport=httpx.MockTransport(transport)))

    def publish(event):
        emit(event)
        if event['type'] == 'tool-result' and event['id'].startswith('old'):
            delivered[int(event['id'][-1])].set()

    batch = asyncio.create_task(agent.execute_tool_calls(
        [call(f'old{i}', 'http', url=f'/old{i}') for i in range(2)], FakeSignal(), publish, []))
    try:
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in started)), 5)
        old_scope = runtime_scope(agent)
        await agent.set_target_base_url(B)
        release[order[0]].set()
        await asyncio.wait_for(delivered[order[0]].wait(), 5)
        assert not app.state.issues and not app.state.observed
        assert app.state.presentation_scope == runtime_scope(agent)
        # Reusing a provider call ID does not transfer the old dispatch's ownership.
        await agent.execute_tool_calls([call('old0', 'http', url='/new')], FakeSignal(), emit, [])
        assert app.state.presentation_scope == runtime_scope(agent) != old_scope
        assert len(app.state.observed) == 1 and not app.state.issues
        current = app.state
        release[order[1]].set()
        await asyncio.wait_for(batch, 5)
        assert app.state == current
        old_calls = {event['id']: event for event in events
                     if event['type'] == 'tool-call' and event['args']['url'].startswith('/old')}
        for event in events[:]:
            if event['type'] == 'tool-result' and event['invocation'].scope == old_scope:
                assert event['invocation'] is old_calls[event['id']]['invocation']
                emit(event)
                emit({**event, 'err': 'changed duplicate error', 'status': 'error'})
        assert app.state == current
        assert sent == [A + '/old0', A + '/old1', B + '/new']
    finally:
        for event in release:
            event.set()
        batch.cancel()
        await asyncio.gather(batch, return_exceptions=True)


@pytest.mark.parametrize('boundary', ['cancelled', 'clear', 'busy', 'new-turn'])
@pytest.mark.parametrize('tool_name', ['http', 'load_skill'])
def test_retirement_preserves_late_result_rejection(tmp_path, boundary, tool_name):
    agent, app, _, _, emit = runtime(tmp_path)
    tc = call('late', tool_name, **({'name': 'recon'} if tool_name == 'load_skill' else {'url': '/old'}))
    parsed = agent.parse_tool_call(tc)
    emit(agent._tool_call_event(tc, parsed))
    if boundary == 'cancelled':
        app.dispatch(AgentEventAction(DoneEvent(stop_reason='cancelled')))
    elif boundary == 'clear':
        app.dispatch(Clear())
    else:
        app.dispatch(SetBusy(False))
        if boundary == 'new-turn':
            app.dispatch(SetBusy(True))
    assert not app.state.pending_calls
    current = app.state
    result = agent._tool_result_event(tc, ToolCallResult('late success', '', 0, http_status=200), parsed.invocation)
    emit(result)
    emit({**result, 'err': 'late failure', 'status': 'error'})
    app.dispatch(AgentEventAction(SkillActiveEvent(name='recon', call_id=tc.id, invocation=parsed.invocation)))
    assert app.state == current


def test_eviction_is_bounded_and_unknown_results_cannot_reacquire_scope(tmp_path):
    agent, app, _, _, emit = runtime(tmp_path)
    old_result = None
    for i in range(300):
        tc = call(str(i), 'permissions_status')
        parsed = agent.parse_tool_call(tc)
        emit(agent._tool_call_event(tc, parsed))
        result = agent._tool_result_event(tc, ToolCallResult('status', '', 0), parsed.invocation)
        if i == 0:
            old_result = result
        emit(result)
    assert len(app.state.call_history) == 256 and not app.state.pending_calls
    current = app.state
    assert old_result is not None
    emit(old_result)
    emit({**old_result, 'invocation': None, 'err': 'lost provenance', 'status': 'error'})
    app.dispatch(AgentEventAction(ToolResultEvent(id='unknown', name='http', err='unknown failure')))
    assert app.state == current
    # A new recognized call still works after eviction.
    tc = call('new', 'load_skill', name='recon')
    parsed = agent.parse_tool_call(tc)
    emit(agent._tool_call_event(tc, parsed))
    agent.record_tool_result(tc, parsed, ToolCallResult('loaded', '', 0), emit, [])
    assert app.state.active_skill == 'recon'
    assert len(app.state.call_history) == 256


async def test_success_receipts_and_activation_are_owned_and_not_replayed(tmp_path):
    agent, app, _, events, emit = runtime(tmp_path)
    await agent.execute_tool_calls([call('skill', 'load_skill', name='recon')], FakeSignal(), emit, [])
    result = next(event for event in events if event['type'] == 'tool-result')
    active = next(event for event in events if event['type'] == 'skill-active')
    current = app.state
    emit(result)
    emit({**result, 'result': 'different duplicate', 'status': 'error', 'err': 'duplicate failure'})
    emit(active)
    emit({**active, 'call_id': 'wrong-owner'})
    emit({**active, 'name': 'sql-injection'})
    emit({**result, 'invocation': replace(result['invocation'], id='wrong-owner')})
    emit({**result, 'name': 'http'})
    assert app.state == current
    await agent.set_target_base_url(B)
    await agent.execute_tool_calls([call('skill', 'load_skill', name='recon')], FakeSignal(), emit, [])
    current = app.state
    emit(result)
    emit(active)
    assert app.state == current
    assert sum(row.text == 'Skill activated · recon' for row in app.state.transcript) == 2


@pytest.mark.parametrize('restriction', ['deny', 'revoke', 'quota', 'cross-origin'])
async def test_scope_synchronization_preserves_permission_gates(tmp_path, monkeypatch, restriction):
    agent, _, policy, _, emit = runtime(tmp_path)
    rights = policy.engagement.http_permissions
    grant = rights.activate(A, HTTPLimits(requests=1))
    sent = []
    client = httpx.AsyncClient

    def transport(request):
        sent.append(str(request.url))
        return httpx.Response(200, content=b'fixture', request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: client(**kw, transport=httpx.MockTransport(transport)))
    if restriction == 'deny':
        rights.deny_session()
        await agent.set_target_base_url(B)
        await agent.set_target_base_url(A)
        assert rights.denied
    elif restriction == 'revoke':
        rights.revoke(grant.id)
        await agent.set_target_base_url(B)
        await agent.set_target_base_url(A)
        assert agent.target.origin() in rights.revoked_origins
    elif restriction == 'quota':
        batch = await agent.execute_tool_calls([call('first', 'http', url='/first')], FakeSignal(), emit, [])
        assert not batch.calls[0].result.err_str and len(sent) == 1
        await agent.set_target_base_url(A)
    batch = await agent.execute_tool_calls([call('blocked', 'http', url=B if restriction == 'cross-origin' else '/blocked')],
                                           FakeSignal(), emit, [])
    assert batch.calls[0].result.err_str
    assert len(sent) == (1 if restriction == 'quota' else 0)


async def test_target_change_invalidates_previously_issued_http_receipt(tmp_path):
    agent, _, policy, _, _ = runtime(tmp_path)
    tool = agent.tools.get('http')
    assert isinstance(tool, HTTPTool)
    action, _ = tool.prepare({'url': '/fixture', 'phase': 'recon'})
    rights = policy.engagement.http_permissions
    receipt = await rights.authorize(action, AlwaysAllow(), None, lambda: agent.target.revision)
    await agent.set_target_base_url(B)
    with pytest.raises(PermissionError):
        rights.reserve(action, receipt, None, agent.target.revision)
