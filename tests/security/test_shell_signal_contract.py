"""Observed POSIX signals and relay exits stay distinct from cancellation."""
from __future__ import annotations

import asyncio
import os
import shlex
import signal
from types import SimpleNamespace

import pytest

from src.permission.permission import AlwaysAllow
from src.tools.execution.shell import BashTool, ShellTool, run_with_capture
from tests.helpers.direct_runtime import direct_runtime

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX process signal contract')


@pytest.mark.parametrize('tool_type', [ShellTool, BashTool])
@pytest.mark.parametrize('command,code,observed_signal', [
    ('kill -TERM $$', 143, signal.SIGTERM),
    ('kill -KILL $$', 137, signal.SIGKILL),
    ('exit 0', 0, None), ('exit 1', 1, None), ('exit 7', 7, None),
    ('exit 143', 143, None), ('exit 241', 241, None), ('exit 255', 255, None),
])
async def test_direct_signal_and_positive_exits(tool_type, command, code, observed_signal):
    output = await tool_type().run({'command': command}, None, AlwaysAllow())
    meta = output.runtime_metadata
    assert meta is not None and meta.process == 'exit'
    assert meta.exit_code == code and meta.termination_signal == observed_signal
    assert output.startswith(f'exit: {code}\nstdout:\n')
    assert output.status == ('success' if code == 0 else 'error')


@pytest.mark.parametrize('tool_type', [ShellTool, BashTool])
@pytest.mark.parametrize('command,code', [
    ('kill -TERM $$', 143), ('kill -KILL $$', 137),
    ('exit 0', 0), ('exit 1', 1), ('exit 7', 7),
    ('exit 143', 143), ('exit 241', 241), ('exit 255', 255),
])
async def test_bound_signal_and_positive_exits_preserve_direct_signal(direct_runtime, tool_type, command, code):
    registry, prompter, policy, operator, *_ = direct_runtime
    tool = tool_type()
    if registry.get(tool.name()) is None:
        registry.register(tool)
    output = await registry.execute(tool.name(), {'command': command}, None, prompter)
    meta = output.runtime_metadata
    assert meta is not None and meta.process == 'exit' and meta.exit_code == code
    assert meta.termination_signal == (signal.SIGTERM if command == 'kill -TERM $$' else
                                       signal.SIGKILL if command == 'kill -KILL $$' else None)
    assert output.startswith(f'exit: {code}\nstdout:\n')
    assert output.status == ('success' if code == 0 else 'error')
    assert meta.http is None
    assert policy.active == 0 and not policy._active_receipts and operator.calls == 0


@pytest.mark.parametrize('bound', [False, True])
@pytest.mark.parametrize('ending', ['timeout', 'abort', 'cancel'])
async def test_controller_timeout_and_cancellation_are_not_signal_exit(direct_runtime, bound, ending, monkeypatch):
    registry, prompter, policy, _, root, _ = direct_runtime
    real_spawn = asyncio.create_subprocess_exec
    processes = []
    def observe_process(proc):
        processes.append(proc)
        return proc
    async def spawn(*args, **kwargs):
        return observe_process(await real_spawn(*args, **kwargs))
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', spawn)
    marker = root / 'artifacts/worker/started'
    destination = 'artifacts/worker/started' if bound else str(marker)
    # Wait until execution actually starts, rather than racing worker preflight.
    command = f"printf ready > {shlex.quote(destination)}; trap '' TERM; while :; do sleep 1; done"
    abort = SimpleNamespace(aborted=False)
    if bound:
        task = asyncio.create_task(registry.execute('shell', {'command': command,
            'timeout_seconds': .2 if ending == 'timeout' else 10}, abort, prompter))
    else:
        task = asyncio.create_task(run_with_capture('/bin/sh', ['-c', command],
            .2 if ending == 'timeout' else 10, abort))
    try:
        async with asyncio.timeout(5):
            while not marker.exists():
                if task.done():
                    pytest.fail(f'process ended before fixture start: {task.result()}')
                await asyncio.sleep(.01)
        if ending == 'cancel':
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
        else:
            if ending == 'abort':
                abort.aborted = True
            output = await asyncio.wait_for(task, 5)
            meta = output.runtime_metadata
            assert meta is not None and meta.process == ('timeout' if ending == 'timeout' else 'cancelled')
            assert output.status == ('error' if ending == 'timeout' else 'cancelled')
            assert output.error_kind == ('timeout' if ending == 'timeout' else 'cancelled')
            assert meta.exit_code is None and meta.termination_signal is None
        assert processes and all(proc.returncode is not None for proc in processes)
        assert policy.active == 0 and not policy._active_receipts
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
