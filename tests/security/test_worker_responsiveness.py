"""Slow filesystem inspection must not freeze the UI loop or bypass policy."""
from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import sys
import threading
import time

import pytest

from src.engagement.state import EngagementState
from src.config.config import PluginConfig, MCPServerConfig
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy
from src.permission.permission import Decision, YoloPrompter
from src.permission.worker.worker import OfflineWorker
import src.permission.worker.worker as worker_module
from src.tools.common.registry import Registry
from src.tools.execution.shell import ShellTool
from src.tools.execution.plugin import CommandPluginTool
from src.tools.mcp.integration import discover_mcp_tools


MCP_SERVER = '''
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    ident = msg.get('id')
    if ident is None: continue
    method = msg['method']
    if method == 'initialize':
        result = {'protocolVersion':msg['params']['protocolVersion'], 'capabilities':{'tools':{}}, 'serverInfo':{'name':'fixture','version':'1'}}
    elif method == 'tools/list':
        result = {'tools':[{'name':'echo','description':'offline fixture','inputSchema':{'type':'object'}}]}
    elif method == 'tools/call':
        open('artifacts/worker/dispatched.txt','w').write('WORKER_OK')
        result = {'content':[{'type':'text','text':'WORKER_OK'}], 'isError':False}
    else: result = {}
    print(json.dumps({'jsonrpc':'2.0','id':ident,'result':result}),flush=True)
'''


class Operator:
    calls = 0

    async def ask(self, request, signal=None):
        self.calls += 1
        return Decision.DENY


@pytest.fixture
async def runtime(tmp_path):
    if sys.platform != "linux" or not shutil.which("bwrap") or not shutil.which("prlimit"):
        pytest.skip("existing real Linux worker required")
    worker = await OfflineWorker.available(tmp_path, ())
    assert worker is not None
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    policy.worker = worker
    operator = Operator()
    prompter = YoloPrompter(operator, True)
    prompter.bind_execution_policy(policy)
    registry = Registry()
    registry.register(ShellTool())
    return registry, prompter, policy, operator


async def register_process(runtime, kind):
    registry, _, policy, _ = runtime
    session = None
    if kind == 'shell':
        name = 'shell'
        args = {'command':'printf WORKER_OK; printf WORKER_OK > artifacts/worker/dispatched.txt'}
    elif kind == 'plugin':
        tool = CommandPluginTool(PluginConfig(name='slow_fixture', command='/usr/bin/python3', args=[
            '-c', "open('artifacts/worker/dispatched.txt','w').write('WORKER_OK'); print('WORKER_OK')"]))
        registry.register(tool)
        name, args = tool.name(), {}
    else:
        discovered = await discover_mcp_tools(MCPServerConfig(name='slow_fixture', command='/usr/bin/python3',
            args=['-u','-c',MCP_SERVER]), execution_policy=policy)
        session = discovered['session']
        tool = discovered['tools'][0]
        registry.register(tool)
        name, args = tool.name(), {}
    return name, args, session


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['shell', 'plugin', 'mcp'])
async def test_slow_preflight_keeps_event_loop_responsive(runtime, monkeypatch, kind):
    registry, prompter, policy, operator = runtime
    name, args, session = await register_process(runtime, kind)
    original_walk = worker_module.os.walk
    loop = asyncio.get_running_loop()
    tick = loop.create_future()
    handles = []

    def slow_walk(path, **kwargs):
        if Path(path) == policy.root:
            began = loop.time()
            loop.call_soon_threadsafe(lambda: handles.append(
                loop.call_later(0.05, lambda: tick.set_result(loop.time() - began))))
            time.sleep(0.6)  # Simulate a slow /mnt/d filesystem operation.
        yield from original_walk(path, **kwargs)

    monkeypatch.setattr(worker_module.os, "walk", slow_walk)
    try:
        output = await registry.execute(name, args, None, prompter)
        delay = await tick
        assert "WORKER_OK" in output
        assert delay < 0.4, f"event loop stalled {delay:.3f}s during worker inspection"
        assert policy.active == 0 and operator.calls == 0
        assert (policy.root / 'artifacts/worker/dispatched.txt').read_text() == 'WORKER_OK'
    finally:
        for handle in handles:
            handle.cancel()
        if session is not None:
            await session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['shell', 'plugin', 'mcp'])
@pytest.mark.parametrize('interrupt', ['escape', 'task-cancel', 'revoke', 'scope-change', 'timeout',
                                     'worker-change', 'quota-change', 'output-change'])
async def test_interrupted_preflight_never_dispatches(runtime, monkeypatch, kind, interrupt):
    registry, prompter, policy, operator = runtime
    name, args, session = await register_process(runtime, kind)
    original_walk = worker_module.os.walk
    loop = asyncio.get_running_loop()
    started = asyncio.Event()
    release = threading.Event()
    finished = threading.Event()
    signal = asyncio.Event()  # Same is_set() interface as the UI's AbortEvent.

    def paused_walk(path, **kwargs):
        if Path(path) == policy.root:
            loop.call_soon_threadsafe(started.set)
            try:
                assert release.wait(3), 'fixture did not release filesystem inspection'
                yield from original_walk(path, **kwargs)
            finally:
                finished.set()
        else:
            yield from original_walk(path, **kwargs)

    if interrupt == 'timeout':
        monkeypatch.setattr(worker_module, 'INSPECTION_TIMEOUT_SECONDS', 0.15)
    monkeypatch.setattr(worker_module.os, 'walk', paused_walk)
    task = asyncio.create_task(registry.execute(name, args, signal, prompter))
    try:
        await asyncio.wait_for(started.wait(), 2)
        if interrupt == 'escape':
            signal.set()
        elif interrupt == 'task-cancel':
            task.cancel()
        elif interrupt == 'revoke':
            policy.revoke(name)
        elif interrupt == 'scope-change':
            policy.engagement.add_origin('http://new-scope.invalid:3000')
        elif interrupt == 'worker-change':
            policy.worker = None
        elif interrupt == 'quota-change':
            policy.max_calls = policy.used
        elif interrupt == 'output-change':
            output = policy.root / 'artifacts/worker'
            output.rename(policy.root / 'artifacts/original-worker')
            outside = policy.root.parent / (policy.root.name + '-outside-worker')
            outside.mkdir()
            output.symlink_to(outside, target_is_directory=True)
            release.set()
        expected = asyncio.CancelledError if interrupt in {'escape', 'task-cancel'} else ExecutionBlocked
        with pytest.raises(expected):
            await asyncio.wait_for(task, 1)
        assert not (policy.root / 'artifacts/worker/dispatched.txt').exists()
        assert policy.active == 0 and operator.calls == 0
        release.set()
        assert await asyncio.to_thread(finished.wait, 1)
        await asyncio.sleep(0.05)
        assert not (policy.root / 'artifacts/worker/dispatched.txt').exists(), 'cancelled scan dispatched late'
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.to_thread(finished.wait, 1)
        if session is not None:
            await session.close()
