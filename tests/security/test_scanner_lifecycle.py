"""P process trees and R real scanner lifecycle through production Registry."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace

import pytest

from src.permission.network.grants import HTTPLimits
from src.permission.runtime.execution import ExecutionBlocked
from src.tools.execution.scanner_runner import ScannerHooks, hooks
from tests.security.test_scanner_end_to_end import runtime, wire, require_binaries


def assert_dead(pids):
    for pid in pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        with pytest.raises(ProcessLookupError):
            os.killpg(pid, 0)


@pytest.fixture
def processes(monkeypatch):
    original = asyncio.create_subprocess_exec
    pids = []
    async def record(*args, **kwargs):
        proc = await original(*args, **kwargs)
        pids.append(proc.pid)
        return proc
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', record)
    return pids


@pytest.mark.parametrize('action', ['cancel', 'signal', 'revoke', 'replace', 'replace_same', 'revoke_origin',
                                   'deny', 'reset', 'scope_reset', 'target', 'close', 'timeout'])
@pytest.mark.parametrize('scanner', ['nmap', 'ffuf'])
async def test_R_live_scanner_stop_and_no_wire_growth(tmp_path, wire, processes, action, scanner, record_property):
    require_binaries()
    origin, counters = wire
    rt = runtime(tmp_path / 'project', origin, tuple('slow' + str(i) for i in range(200)))
    port = int(origin.rpartition(':')[2])
    started = asyncio.Event()
    captured = []
    signal = SimpleNamespace(aborted=False)
    with socket.socket() as closed:
        closed.bind(('127.0.0.1', 0))
        closed_port = closed.getsockname()[1]
        rt.state.add_tcp('127.0.0.1', [port, closed_port])
        grant = rt.state.http_permissions.activate(origin, HTTPLimits()) if action in {'replace_same', 'revoke_origin'} else None
        args = ({'scanner': 'nmap', 'target': '127.0.0.1', 'ports': [port, closed_port], 'rate': 0.1}
                if scanner == 'nmap' else {'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture'})
        args['timeout_seconds'] = 1 if action == 'timeout' else 30
        token = hooks.set(ScannerHooks(lambda *_: started.set(), captured.append))
        try:
            task = asyncio.create_task(rt.registry.execute('shell', args, signal, rt.prompter))
        finally:
            hooks.reset(token)
        await asyncio.wait_for(started.wait(), 3)
        await asyncio.sleep(0.12)
        assert processes and not task.done(), 'fixture must observe a genuinely active scanner'
        os.kill(processes[0], 0)
        if action == 'cancel':
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
        elif action == 'signal':
            signal.aborted = True
        elif action == 'revoke':
            rt.policy.revoke('shell')
        elif action in {'replace', 'replace_same'}:
            rt.state.http_permissions.activate(origin, HTTPLimits())
        elif action == 'revoke_origin':
            assert grant is not None
            rt.state.http_permissions.revoke(grant.id)
        elif action == 'deny':
            rt.state.http_permissions.deny_session()
        elif action == 'reset':
            rt.state.http_permissions.reset()
            await rt.binding.runtime.drain()
        elif action == 'scope_reset':
            rt.state.reset_to_origin(origin)
        elif action == 'target':
            rt.target.set_base_url(origin + '/changed')
        elif action == 'close':
            await rt.binding.runtime.drain(close=True)
        if action in {'cancel', 'reset', 'close'}:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 4)
        else:
            output = await asyncio.wait_for(task, 4)
            envelope = json.loads(output)
            assert envelope['execution']['status'] in {'failed', 'cancelled', 'partial'}
            assert output.status != 'success' and envelope['parse']['coverage_complete'] is False
        assert captured and captured[0].envelope['execution']['status'] != 'completed'
        assert_dead(processes)
        await asyncio.sleep(0.15)
        count = counters['requests']
        await asyncio.sleep(0.15)
        assert counters['requests'] == count
        assert rt.policy.active == 0 and not rt.policy._active_receipts and rt.binding.runtime.task is None
        assert not list((rt.root / '.kagent/tmp/scanners').iterdir())
        produced = captured[0]
        record_property('scanner_lifecycle', json.dumps({'scanner': scanner, 'action': action, 'origin': origin,
            'pids': processes, 'pids_and_groups_dead': True, 'settled_requests': count,
            'no_post_cleanup_growth': counters['requests'] == count, 'execution': produced.envelope['execution'],
            'parse': produced.envelope['parse'], 'argv': produced.plan.command, 'binary': produced.envelope['binary']}))


async def test_R_active_receipt_outlives_dispatch_ttl_unrelated_grant_and_http_usage(tmp_path, wire, processes):
    require_binaries()
    origin, counters = wire
    rt = runtime(tmp_path / 'project', origin, tuple('slow' + str(i) for i in range(50)))
    now = [0.0]
    rt.policy.clock = lambda: now[0]
    unrelated = origin.replace('127.0.0.1', 'localhost')
    rt.state.add_origin(unrelated)
    grant = rt.state.http_permissions.activate(origin, HTTPLimits(requests=1, seconds=1))
    started = asyncio.Event()
    token = hooks.set(ScannerHooks(lambda *_: started.set(), lambda _: None))
    try:
        task = asyncio.create_task(rt.registry.execute('shell', {'scanner': 'ffuf', 'url': origin + '/FUZZ',
            'wordlist_id': 'fixture'}, None, rt.prompter))
    finally:
        hooks.reset(token)
    await asyncio.wait_for(started.wait(), 3)
    now[0] = 120.0
    rt.state.http_permissions.activate(unrelated, HTTPLimits())
    # Changing Native usage is not scanner invalidation or a reservation.
    rt.state.http_permissions._budgets[grant.id].used = 1
    await asyncio.sleep(0.25)
    assert not task.done()
    result = await asyncio.wait_for(task, 5)
    assert json.loads(result)['execution']['status'] in {'completed', 'partial'}
    assert counters['requests'] == 50 and rt.state.http_permissions._budgets[grant.id].used == 1
    assert_dead(processes)


async def test_R_busy_slot_is_not_a_queue_or_http_quota(tmp_path, wire, processes):
    require_binaries()
    origin, _ = wire
    rt = runtime(tmp_path / 'project', origin, tuple('slow' + str(i) for i in range(50)))
    from src.tools.http.http_tool import HTTPTool
    grant = rt.state.http_permissions.activate(origin, HTTPLimits.session())
    rt.registry.register(HTTPTool(rt.target, rt.state))
    started = asyncio.Event()
    token = hooks.set(ScannerHooks(lambda *_: started.set(), lambda _: None))
    args = {'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture'}
    try:
        task = asyncio.create_task(rt.registry.execute('shell', args, None, rt.prompter))
    finally:
        hooks.reset(token)
    await asyncio.wait_for(started.wait(), 3)
    with pytest.raises(ExecutionBlocked, match='Scanner is busy'):
        await rt.registry.execute('shell', args, None, rt.prompter)
    native = await rt.registry.execute('http', {'url': '/hit', 'phase': 'recon'}, None, rt.prompter)
    assert native and not task.done()
    assert rt.state.http_permissions._budgets[grant.id].used == 1
    await rt.binding.runtime.drain()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert_dead(processes)
    assert rt.policy.active == 0 and not rt.policy._active_receipts


async def process_fixture(rt, monkeypatch, code):
    """P only: substitute a controlled Python tree after exact Registry review.

    The model has no argv/executable injection field. The test's controller
    substitutes the spawn call to exercise lifecycle edge cases real scanners
    do not create; these tests are never described as R scanner evidence.
    """
    original = asyncio.create_subprocess_exec
    pids = []
    async def substitute(*args, **kwargs):
        proc = await original('/usr/bin/python3', '-I', '-S', '-c', code, **kwargs)
        pids.append(proc.pid)
        return proc
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', substitute)
    task = asyncio.create_task(rt.registry.execute('shell', {'scanner': 'nmap', 'target': '127.0.0.1',
        'ports': str(rt.target.origin().port), 'timeout_seconds': 1}, None, rt.prompter))
    return task, pids


@pytest.mark.parametrize('leader_exits', [True, False])
async def test_P_leader_exit_term_resistant_child_and_bounded_pipes(tmp_path, monkeypatch, leader_exits):
    require_binaries()
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:43210')
    child_file = tmp_path / 'child.pid'
    code = ("import os,signal,time; child=os.fork(); "
        "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
        f"open({str(child_file)!r},'w').write(str(child or os.getpid())); "
        + ('os._exit(0) if child else time.sleep(60)' if leader_exits else 'time.sleep(60)'))
    task, pids = await process_fixture(rt, monkeypatch, code)
    output = await asyncio.wait_for(task, 4)
    assert json.loads(output)['execution']['status'] != 'completed'
    assert not rt.binding.runtime.task and rt.policy.active == 0
    # A killed child can remain a zombie until the host init reaps it. It must
    # never be running or hold pipes after the finite process-group teardown.
    child = int(child_file.read_text())
    proc_stat = Path(f'/proc/{child}/stat')
    assert not proc_stat.exists() or proc_stat.read_text().split()[2] == 'Z'
    with pytest.raises(ProcessLookupError):
        os.kill(pids[0], 0)


async def test_P_cancellation_during_spawn_recovers_late_child(tmp_path, monkeypatch):
    require_binaries()
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:43210')
    original = asyncio.create_subprocess_exec
    entered, release = asyncio.Event(), asyncio.Event()
    pids = []
    async def delayed(*args, **kwargs):
        entered.set()
        await release.wait()
        proc = await original('/usr/bin/python3', '-I', '-S', '-c', 'import time;time.sleep(60)', **kwargs)
        pids.append(proc.pid)
        return proc
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', delayed)
    task = asyncio.create_task(rt.registry.execute('shell', {'scanner': 'nmap', 'target': '127.0.0.1',
        'ports': '43210'}, None, rt.prompter))
    await entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 4)
    assert_dead(pids)
    assert not rt.binding.runtime.task and rt.policy.active == 0


async def test_M_same_origin_replacement_at_scheduled_pre_spawn_never_spawns(tmp_path, monkeypatch):
    require_binaries()
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:43210')
    original = asyncio.create_task
    spawned = []
    def schedule(coroutine, *args, **kwargs):
        if getattr(coroutine, '__name__', '') == 'spawn_current':
            asyncio.get_running_loop().call_soon(rt.state.http_permissions.activate, rt.target.base_url(), HTTPLimits())
        return original(coroutine, *args, **kwargs)
    async def forbidden(*args, **kwargs):
        spawned.append(args)
        pytest.fail('pre-spawn authority replacement must not reach the subprocess API')
    monkeypatch.setattr(asyncio, 'create_task', schedule)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', forbidden)
    result = await rt.registry.execute('shell', {'scanner': 'nmap', 'target': '127.0.0.1', 'ports': '43210'}, None, rt.prompter)
    assert not spawned and json.loads(result)['execution']['reason'] == 'authority_changed'
    assert not rt.binding.runtime.task


async def test_P_actual_child_resource_limits_environment_stdin_and_large_capture(tmp_path, monkeypatch):
    require_binaries()
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:43210')
    captured = tmp_path / 'owned-child-facts.json'
    code = ("import os,resource,json,sys; "
        f"json.dump(dict(env=dict(os.environ),cwd=os.getcwd(),stdin=sys.stdin.read(),"
        "limits={str(n):resource.getrlimit(n) for n in [resource.RLIMIT_AS,resource.RLIMIT_NOFILE,resource.RLIMIT_FSIZE,resource.RLIMIT_CORE]}),"
        f"open({str(captured)!r},'w')); "
        "sys.stdout.write('x'*200000);sys.stderr.write('y'*200000)")
    original = asyncio.create_subprocess_exec
    async def substitute(*args, **kwargs):
        divider = args.index('--')
        return await original(*args[:divider + 1], '/usr/bin/python3', '-I', '-S', '-c', code, **kwargs)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', substitute)
    result = await rt.registry.execute('shell', {'scanner': 'nmap', 'target': '127.0.0.1', 'ports': '43210'}, None, rt.prompter)
    facts = json.loads(captured.read_text())
    assert facts['stdin'] == '' and facts['cwd'].startswith(str(rt.root / '.kagent/tmp/scanners'))
    assert facts['limits']['7'] == [4096, 4096]  # Linux RLIMIT_NOFILE
    assert facts['limits']['1'] == [16 * 1024**2] * 2
    assert facts['limits']['4'] == [0, 0]
    assert facts['limits']['9'] == [4 * 1024**3] * 2
    envelope = json.loads(result)
    assert envelope['execution']['status'] == 'failed' and envelope['parse']['status'] == 'missing'
    diagnostics = envelope['diagnostics']
    assert diagnostics['stdout_bytes'] == 200000 and diagnostics['stderr_bytes'] == 200000
    assert diagnostics['stdout']['capture_truncated'] and diagnostics['stderr']['capture_truncated']
    assert diagnostics['stdout']['text'] == diagnostics['stderr']['text'] == ''
    assert diagnostics['resources']['address_space'] == facts['limits']['9'][0]
    assert diagnostics['resources']['nofile'] == facts['limits']['7'][0]
    assert envelope['truncation']['diagnostics'] is True and len(result) < 12 * 1024
