import asyncio
import json

import pytest

from src.llm.core.types import FunctionCall, ToolCall
from src.permission.network.grants import HTTPBlocked, HTTPPending, HTTPReviewTimeout
from src.permission.permission import PermissionReviewStale, PermissionReviewCancelled, UserControlledRefusal
from tests.agent.test_tool_outcomes import make_agent
from tests.helpers.agent_fakes import FakeSignal


def call(identity, case):
    return ToolCall(id=identity, function=FunctionCall(name='case', arguments=json.dumps({'case': case})))


@pytest.mark.parametrize('error,kind,status,refused', [
    (HTTPPending('pending: queued'), 'permission_pending', 'pending', False),
    (HTTPReviewTimeout('pending: expired'), 'permission_timeout', 'pending', False),
    (PermissionReviewStale('stale review'), 'permission_stale', 'error', False),
    (HTTPBlocked('revoked'), 'policy_block', 'error', False),
    (UserControlledRefusal('denied'), 'permission_denied', 'error', True),
])
async def test_pending_and_policy_failures_are_not_explicit_refusals(monkeypatch, error, kind, status, refused):
    agent = make_agent()
    async def fail(*args):
        raise error
    monkeypatch.setattr(agent.tools, 'execute', fail)
    events, working = [], []
    batch = await agent.execute_tool_calls([call('one', 'success')], FakeSignal(), events.append, working)
    assert batch.all_refused is refused
    assert (working[0].tool_status, working[0].tool_error_kind) == (status, kind)
    assert events[-1]['error_kind'] == kind


async def test_fast_completion_visible_while_history_commits_in_submitted_order(monkeypatch):
    agent = make_agent()
    release = asyncio.Event()
    completed = asyncio.Event()
    events, working = [], []
    async def run(name, args, *rest):
        if args['case'] == 'slow':
            await release.wait()
            return 'slow result'
        raise HTTPPending('pending: permission queued')
    def emit(event):
        events.append(event)
        if event['type'] == 'tool-result' and event['id'] == 'fast':
            completed.set()
    monkeypatch.setattr(agent.tools, 'execute', run)
    task = asyncio.create_task(agent.execute_tool_calls(
        [call('slow', 'slow'), call('fast', 'fast')], FakeSignal(), emit, working))
    await asyncio.wait_for(completed.wait(), 2)
    assert not task.done() and not working
    assert [(e['id'], e['status']) for e in events if e['type'] == 'tool-result'] == [('fast', 'pending')]
    release.set()
    batch = await task
    assert not batch.all_refused
    assert [m.tool_call_id for m in working] == ['slow', 'fast']
    assert [e['id'] for e in events if e['type'] == 'tool-result'] == ['fast', 'slow']
    assert len([m for m in agent.history if m.role == 'tool']) == 2


async def test_escape_review_cancel_is_a_result_but_task_cancel_propagates(monkeypatch):
    agent = make_agent()
    async def escape(*args):
        raise PermissionReviewCancelled()
    monkeypatch.setattr(agent.tools, 'execute', escape)
    working = []
    batch = await agent.execute_tool_calls([call('escape', 'success')], FakeSignal(), lambda e: None, working)
    assert not batch.all_refused and working[0].tool_status == 'cancelled'
