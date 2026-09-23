import asyncio
import sys

import pytest

from src.agent.agent import map_with_concurrency
from src.tools.plugin import run_plugin
from src.tools.shell import run_with_capture
from tests.helpers.agent_fakes import FakeSignal


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_child", [False, True])
async def test_parallel_cancellation_awaits_sibling_cleanup(cancel_child):
    both_started = asyncio.Event()
    release_child = asyncio.Event()
    sibling_stopped = asyncio.Event()
    started = set()
    side_effects = []

    async def work(item, index):
        started.add(index)
        if len(started) == 2:
            both_started.set()
        if index == 0 and cancel_child:
            await release_child.wait()
            raise asyncio.CancelledError()
        try:
            await asyncio.Future()
            side_effects.append(item)
        finally:
            if index == 1:
                sibling_stopped.set()

    task = asyncio.create_task(map_with_concurrency(["a", "b"], 2, work))
    await asyncio.wait_for(both_started.wait(), 2)
    if cancel_child:
        release_child.set()
    else:
        task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    assert sibling_stopped.is_set()
    assert side_effects == []


@pytest.mark.asyncio
async def test_shell_direct_cancellation_terminates_process(monkeypatch):
    if sys.platform == "win32":
        pytest.skip("POSIX subprocess check")
    created = asyncio.Event()
    processes = []
    original = asyncio.create_subprocess_exec

    async def create(*args, **kwargs):
        proc = await original(*args, **kwargs)
        processes.append(proc)
        created.set()
        return proc

    monkeypatch.setattr("src.tools.shell.asyncio.create_subprocess_exec", create)
    task = asyncio.create_task(run_with_capture(
        "/bin/sh", ["-c", "sleep 30"], 60, FakeSignal(),
    ))
    await asyncio.wait_for(created.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 3)
    assert processes[0].returncode is not None


@pytest.mark.asyncio
async def test_plugin_direct_cancellation_terminates_process(monkeypatch):
    created = asyncio.Event()
    processes = []
    original = asyncio.create_subprocess_exec

    async def create(*args, **kwargs):
        proc = await original(*args, **kwargs)
        processes.append(proc)
        created.set()
        return proc

    monkeypatch.setattr("src.tools.plugin.asyncio.create_subprocess_exec", create)
    task = asyncio.create_task(run_plugin(
        sys.executable, ["-c", "import time; time.sleep(30)"], {}, FakeSignal(),
    ))
    await asyncio.wait_for(created.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 3)
    assert processes[0].returncode is not None
