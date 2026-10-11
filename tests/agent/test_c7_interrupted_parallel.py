import asyncio

import pytest

from src.agent.agent import AgentRunOptions
from tests.agent.test_accounting_lifecycle_regressions import setup_run, assert_resume_and_reread
from tests.helpers.agent_fakes import FakeSignal


async def test_cancel_after_fast_parallel_completion_keeps_its_original_and_single_event(tmp_path, monkeypatch):
    agent, registry, client = setup_run(tmp_path, monkeypatch, count=2)
    tool = registry.get('file_read')
    assert tool is not None
    original = tool.run
    completed = asyncio.Event()
    events = []

    async def run(args, *rest):
        if args['path'].endswith('source-1.txt'):
            await asyncio.Event().wait()
        return await original(args, *rest)

    def emit(event):
        events.append(event)
        if event.type == 'tool-result':
            completed.set()

    monkeypatch.setattr(tool, 'run', run)
    task = asyncio.create_task(agent.run('Read local fixtures', FakeSignal(), emit, AgentRunOptions(max_steps=2)))
    await asyncio.wait_for(completed.wait(), 10)
    assert not task.done()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 10)
    assert len([event for event in events if event.type == 'tool-result']) == 1
    assert len(client.requests) == 1
    assert not agent.running and not agent._tool_results_unsaved
    await assert_resume_and_reread(agent, registry, tmp_path, monkeypatch, expected=1)


async def test_repeated_parallel_cancel_joins_sibling_cleanup_before_checkpoint(tmp_path, monkeypatch):
    agent, registry, _ = setup_run(tmp_path, monkeypatch, count=2)
    tool = registry.get('file_read')
    assert tool is not None
    original = tool.run
    fast_done, cleaning, release, cleaned = (asyncio.Event() for _ in range(4))

    async def run(args, *rest):
        if args['path'].endswith('source-1.txt'):
            try:
                await asyncio.Event().wait()
            finally:
                cleaning.set()
                await release.wait()
                cleaned.set()
        return await original(args, *rest)

    monkeypatch.setattr(tool, 'run', run)
    task = asyncio.create_task(agent.run('Read fixtures', FakeSignal(),
        lambda event: fast_done.set() if event.type == 'tool-result' else None,
        AgentRunOptions(max_steps=2)))
    try:
        await asyncio.wait_for(fast_done.wait(), 10)
        task.cancel()
        await asyncio.wait_for(cleaning.wait(), 2)
        task.cancel()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not task.done() and not cleaned.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 10)
        assert cleaned.is_set()
        await assert_resume_and_reread(agent, registry, tmp_path, monkeypatch, expected=1)
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
