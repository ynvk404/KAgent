"""Retired model work cannot acquire authority in a replacement session."""
import asyncio
import json
import threading

import pytest

from src.llm.core.types import ChatResponse, Message, ToolCall, FunctionCall
from src.workflow.state import WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.helpers.direct_runtime import agent_runtime


@pytest.mark.parametrize('boundary', ['reset', 'resume', 'repeated_reset', 'same_id_state'])
@pytest.mark.parametrize('streaming', [False, True])
@pytest.mark.parametrize('operation', ['run', 'compact'])
async def test_retired_response_cannot_append_dispatch_or_checkpoint(tmp_path, boundary, streaming, operation):
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    callbacks = []
    args = dict(action='record_candidate', candidate_class='sql-injection', method='GET',
                endpoint='/old-search', parameter='q', location='query', signals=['old signal'])
    response = ChatResponse(Message('assistant', 'retired response', tool_calls=[
        ToolCall('old-call', FunctionCall('workflow', json.dumps(args)))]), 'tool_calls')

    class Delayed(FakeClient):
        async def held(self, callback=None):
            entered.set()
            if callback:
                callbacks.append(callback)
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                # Simulate a provider that catches cancellation and delivers a
                # buffered final response/chunk anyway.
                if callback:
                    callback('late buffered chunk')
                return response

        async def chat(self, request, signal=None):
            return await self.held()

        async def chat_stream(self, request, on_delta, signal=None):
            return await self.held(on_delta)

    rt = agent_runtime(tmp_path, 'http://127.0.0.1:43210', Delayed([]), mode='direct')
    rt.agent.streaming_enabled = streaming
    await rt.agent.save()
    events = []
    if operation == 'compact':
        rt.agent.history.append(Message('user', 'synthetic history to compact'))
        pending = rt.agent.compact(FakeSignal(), events.append)
    else:
        pending = rt.agent.run('Record the supplied candidate only.', FakeSignal(), events.append)
    task = asyncio.create_task(pending)
    await asyncio.wait_for(entered.wait(), 5)
    if boundary in {'reset', 'repeated_reset'}:
        await rt.agent.reset()
        if boundary == 'repeated_reset':
            await rt.agent.reset()
    elif boundary == 'resume':
        rt.agent.resume_saved()
        rt.agent.resume_saved()
    else:
        rt.agent.workflow.replace_from(WorkflowState.from_dict(rt.agent.workflow.to_dict()))
    history = list(rt.agent.history)
    event_count = len(events)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    for callback in callbacks:
        callback('callback after final response')
    assert cancelled.is_set()
    assert rt.agent.history == history
    assert len(events) == event_count
    assert not rt.agent.workflow.candidates
    assert not rt.agent.workflow.evidence
    assert not rt.agent.running and rt.agent._active_turn is None
    await rt.agent.save()
    restored = rt.agent.store.load()
    assert not restored.workflow.candidates and not restored.workflow.validation_results
    assert all(m.content != 'retired response' and not m.tool_calls for m in restored.messages)
    assert not [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]


async def test_resume_rejects_background_checkpoint_before_atomic_commit(tmp_path, monkeypatch):
    import src.session.store as store_module
    rt = agent_runtime(tmp_path, 'http://127.0.0.1:43210', FakeClient([]), mode='direct')
    await rt.agent.save()
    baseline = rt.agent.store.path.read_bytes()
    entered, release = threading.Event(), threading.Event()
    original = store_module._write_session

    def held(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(store_module, '_write_session', held)
    task = asyncio.create_task(rt.agent.run('old user request', FakeSignal(), lambda e: None))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        rt.agent.resume_saved()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    assert rt.agent.store.path.read_bytes() == baseline
    assert not list(rt.agent.store.path.parent.glob('*.tmp.*'))


async def test_resume_rejects_background_context_checkpoint(tmp_path, monkeypatch):
    import src.session.store as store_module
    class SnapshotClient(FakeClient):
        async def chat(self, request, signal=None):
            await rt.agent.save_context_snapshot('old turn')
            return ChatResponse(Message('assistant', 'old response'), 'stop')
    rt = agent_runtime(tmp_path, 'http://127.0.0.1:43210', SnapshotClient([]), mode='direct')
    await rt.agent.save()
    await rt.agent.store.save_context_snapshot('baseline')
    path = rt.agent.store.context_snapshot_path()
    baseline = path.read_bytes()
    entered, release = threading.Event(), threading.Event()
    original = store_module._write_context_snapshot
    def held(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(store_module, '_write_context_snapshot', held)
    task = asyncio.create_task(rt.agent.run('old request', FakeSignal(), lambda e: None))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        rt.agent.resume_saved()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    assert path.read_bytes() == baseline
    assert not list(path.parent.glob('*.tmp.*'))
