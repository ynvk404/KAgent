"""Cancellation/exact DENY are invocation/turn state, never session authority."""
import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from src.agent.agent import Agent, AgentOptions
from src.engagement.state import EngagementState
from src.permission.execution import default_execution_policy, ExecutionBlocked
from src.permission.http_grants import HTTPBlocked, HTTPLimits
from src.permission.invocations import review_turn
from src.permission.permission import Decision, YoloPrompter
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.http import HTTPTool
from src.tools.registry import Registry
from src.ui.core.app import AbortEvent
from src.llm.types import ChatResponse, Message, ToolCall, FunctionCall
from tests.helpers.agent_fakes import FakeClient


ORIGIN = 'http://127.0.0.1:3000'
ARGS = {'url':'/new-endpoint', 'phase':'recon'}
REAL_CLIENT = httpx.AsyncClient


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    state = EngagementState()
    state.initialize_target(ORIGIN)
    target = Target(ORIGIN)
    tool = HTTPTool(target, state)
    policy = default_execution_policy(state, tmp_path)
    started, release = asyncio.Event(), asyncio.Event()
    control = SimpleNamespace(block=None, sent=[], closed=0, questions=[])

    class Operator:
        async def ask(self, request, signal=None):
            control.questions.append(request)
            if control.block == 'review':
                started.set()
                await release.wait()
            if control.block == 'review-timeout':
                raise TimeoutError('fixture review timeout')
            if control.block == 'review-error':
                raise RuntimeError('fixture review failure')
            return Decision.ALLOW_ONCE

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            started.set()
            await release.wait()
            yield b'fixture'

        async def aclose(self):
            control.closed += 1

    async def transport(request):
        control.sent.append(request)
        if control.block == 'send':
            started.set()
            await release.wait()
        if control.block == 'body':
            return httpx.Response(200, stream=Stream(), request=request)
        if control.block == 'timeout':
            raise httpx.ReadTimeout('fixture timeout')
        if control.block == 'error':
            raise httpx.ConnectError('fixture failure')
        return httpx.Response(200, content=b'fixture', request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw:REAL_CLIENT(transport=httpx.MockTransport(transport), **kw))
    async def private_gate(*args, **kwargs):
        if control.block == 'private':
            started.set()
            await release.wait()
        return ''
    monkeypatch.setattr('src.tools.http.gate_private_request', private_gate)
    p = YoloPrompter(Operator(), False)
    p.bind_execution_policy(policy)
    registry = Registry()
    registry.register(tool)
    return tool, registry, p, policy, control, started, release


def scripted_http():
    return FakeClient([ChatResponse(Message(role='assistant', content='', tool_calls=[
        ToolCall(id='fixture', function=FunctionCall(name='http', arguments=json.dumps(ARGS)))]), 'tool_calls')])


@pytest.mark.asyncio
@pytest.mark.parametrize('stage', ['review', 'private', 'send', 'body'])
@pytest.mark.parametrize('enable_yolo', [False, True])
@pytest.mark.parametrize('cancel_mode', ['task', 'escape'])
async def test_whole_target_cancel_then_same_http_in_new_turn(runtime, stage, enable_yolo, cancel_mode):
    tool, registry, p, policy, control, started, release = runtime
    control.block = stage
    agent = Agent(AgentOptions(client=scripted_http(), tools=registry, skills=SkillRegistry(),
        prompter=p, store=None, target=tool.target, engagement_state=tool.engagement,
        max_steps=1, streaming_enabled=False))
    signal = AbortEvent()
    task = asyncio.create_task(agent.run('Assess the entire target and all vulnerability classes.', signal, lambda e:None))
    await asyncio.wait_for(started.wait(), 3)
    assert agent.workflow.objective is not None and agent.workflow.objective.mode == 'whole_target'
    if cancel_mode == 'task':
        task.cancel()
    else:
        signal.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    assert not agent.is_running() and policy.active == 0
    assert not tool.permissions._pending and not tool.permissions._receipts
    assert not tool.permissions._inflight and not tool.permissions._declined_actions and not policy._denied
    assert not tool.permissions._blocked_gate
    if stage == 'body':
        assert control.closed == 1
    questions_before = len(control.questions)
    control.block = None
    release.set()
    p.set_yolo(enable_yolo)
    client = scripted_http()
    agent.client = client
    before = len(control.sent)
    await agent.run('Continue the whole-target assessment.', AbortEvent(), lambda e:None)
    assert len(control.sent) == before + 1 and client.idx == 1
    if enable_yolo:
        assert len(control.questions) == questions_before
    else:
        assert len(control.questions) == questions_before + 1
    assert not tool.permissions._receipts and not tool.permissions._inflight and policy.active == 0


@pytest.mark.asyncio
async def test_real_exact_deny_is_scoped_without_clearing_other_operator_rights(runtime):
    tool, registry, p, policy, control, _, _ = runtime
    original = p._inner.ask
    async def deny(request, signal=None):
        control.questions.append(request)
        return Decision.DENY
    p._inner.ask = deny
    policy.revoke('file_write')
    with review_turn():
        for _ in range(3):
            with pytest.raises(HTTPBlocked):
                await registry.execute('http', ARGS, None, p)
        assert len(control.questions) == 1 and not control.sent
    p._inner.ask = original
    await registry.execute('http', ARGS, None, p)
    assert len(control.sent) == 1 and len(control.questions) == 2
    p.set_yolo(True)
    assert 'file_write' in policy.revoked
    grant = next(iter(tool.permissions.grants.values()))
    tool.permissions.revoke(grant.id)
    with pytest.raises(ExecutionBlocked):
        await registry.execute('http', ARGS, None, p)
    assert len(control.sent) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['timeout', 'error'])
async def test_transport_failure_does_not_leave_decline_or_receipt(runtime, failure):
    tool, registry, p, policy, control, _, _ = runtime
    p.set_yolo(True)
    control.block = failure
    with pytest.raises(httpx.HTTPError):
        await registry.execute('http', ARGS, None, p)
    assert not tool.permissions._receipts and not tool.permissions._inflight and not policy._denied
    control.block = None
    await registry.execute('http', ARGS, None, p)
    assert len(control.sent) == 2 and not control.questions


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['review-timeout', 'review-error'])
async def test_review_failure_does_not_turn_into_operator_deny(runtime, failure):
    tool, registry, p, policy, control, _, _ = runtime
    control.block = failure
    with pytest.raises((RuntimeError, TimeoutError)):
        await registry.execute('http', ARGS, None, p)
    assert not tool.permissions._pending and not tool.permissions._receipts and not policy._denied
    assert not tool.permissions._declined_actions and not control.sent
    control.block = None
    await registry.execute('http', ARGS, None, p)
    assert len(control.sent) == 1 and len(control.questions) == 2


@pytest.mark.asyncio
async def test_stale_private_gate_policy_does_not_create_origin_decline(runtime, monkeypatch):
    tool, registry, p, policy, control, _, _ = runtime
    p.set_yolo(True)
    from src.permission.permission import UserControlledRefusal
    async def stale(*args, **kwargs):
        policy.revoke('http')
        raise UserControlledRefusal('blocked: policy changed during private-host gate')
    monkeypatch.setattr('src.tools.http.gate_private_request', stale)
    with pytest.raises(UserControlledRefusal):
        await registry.execute('http', ARGS, None, p)
    assert not tool.permissions._blocked_gate and not tool.permissions._receipts and not control.sent
    policy.restore_tool('http')
    async def allowed(*args, **kwargs):
        return ''
    monkeypatch.setattr('src.tools.http.gate_private_request', allowed)
    await registry.execute('http', ARGS, None, p)
    assert len(control.sent) == 1 and not control.questions


@pytest.mark.asyncio
async def test_cancel_during_reservation_wait_discards_only_own_receipt(runtime):
    tool, registry, p, policy, control, _, _ = runtime
    p.set_yolo(True)
    rights = tool.permissions
    rights.activate(ORIGIN, HTTPLimits(concurrency=1, burst=10, rate=1000))
    action, _ = tool.prepare(ARGS)
    first = await rights.authorize(action, p, None, lambda:tool.target.revision)
    occupying = rights.reserve(action, first, None, tool.target.revision)
    signal = AbortEvent()
    task = asyncio.create_task(registry.execute('http', ARGS, signal, p))
    try:
        async with asyncio.timeout(2):
            while not rights._receipts:
                await asyncio.sleep(.01)
        signal.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert not rights._receipts and not control.sent and not occupying.released
        assert next(iter(rights._inflight.values())) == 1 and policy.active == 0
        occupying.release()
        await registry.execute('http', ARGS, AbortEvent(), p)
        assert len(control.sent) == 1 and not rights._inflight and not control.questions
    finally:
        occupying.release()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_same_shape_new_invocation_cannot_use_old_http_receipt(runtime):
    tool, _, p, _, _, _, _ = runtime
    tool.permissions.activate(ORIGIN, HTTPLimits())
    first, _ = tool.prepare(ARGS)
    second, _ = tool.prepare(ARGS)
    assert first.digest == second.digest and first.invocation_id != second.invocation_id
    receipt = await tool.permissions.authorize(first, p, None, lambda:tool.target.revision)
    with pytest.raises(HTTPBlocked, match='changed'):
        tool.permissions.reserve(second, receipt, None, tool.target.revision)
    tool.permissions.discard_receipt(receipt)
    with pytest.raises(HTTPBlocked, match='replayed'):
        tool.permissions.reserve(first, receipt, None, tool.target.revision)
