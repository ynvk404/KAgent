"""Regression coverage for KSC-01..05; wire traffic stays fixture-owned loopback."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import threading
import time

import pytest

from src.agent.system_prompt import render_workflow
from src.llm.core.types import FunctionCall, ToolCall
from src.tools.discovery.scanner_results import encode, parse_nmap
from src.tools.execution.scanner_runner import normalize
from src.workflow.scanner import observation_fingerprints, project_jobs
from src.workflow.state import WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.integration.test_scanner_agent_handoff import agent_runtime
from tests.security.test_scanner_end_to_end import plan_for, require_binaries, runtime, wire
from tests.state.test_scanner_state import job, state


def add_observations(workflow, row, records):
    data = b''.join(encode(record) + b'\n' for record in records)
    assert workflow.add_scanner_job(row, observation_fingerprints=observation_fingerprints(data, row.semantic_key))
    return workflow.progress_facts()


def test_KSC01_observation_novelty_subset_reorder_new_content_and_restore(tmp_path):
    workflow = state()
    row = job(tmp_path)
    a, b = [{'id': record_id, 'status': 200} for record_id in row.sample_ids[:2]]
    first = add_observations(workflow, row, [a, b])
    assert len([fact for fact in first if fact.startswith('scanner-observations:')]) == 2
    assert add_observations(workflow, replace(row, job_id='scan_' + '1' * 32), [a]) == first
    assert add_observations(workflow, replace(row, job_id='scan_' + '2' * 32), [b, a]) == first
    restored = WorkflowState.from_dict(workflow.to_dict())
    assert restored.progress_facts() == first
    c = {'id': row.sample_ids[2], 'status': 403}
    second = add_observations(restored, replace(row, job_id='scan_' + '3' * 32), [a, b, c])
    assert len(second - first) == 1
    third = add_observations(restored, replace(row, job_id='scan_' + '4' * 32), [{**a, 'status': 401}])
    assert len(third - second) == 1
    assert add_observations(restored, row, [a, b]) == third
    # Evict historical jobs without forgetting previously credited observations.
    for index in range(5, 45):
        add_observations(restored, replace(row, job_id='scan_' + f'{index:032x}'), [])
    assert add_observations(restored, row, [a, b]) == third
    assert all(item.parse['coverage_complete'] is None for item in restored.scanner_jobs.values())


def test_KSC01_progress_memory_saturates_without_recrediting(monkeypatch, tmp_path):
    monkeypatch.setattr('src.workflow.scanner.MAX_OBSERVATION_FACTS', 2)
    workflow, row = state(), job(tmp_path)
    first = add_observations(workflow, row, [{'id': value, 'status': 200} for value in row.sample_ids])
    assert len(workflow.scanner_observations) == 2
    assert add_observations(workflow, row, [{'id': row.sample_ids[2], 'status': 403}]) == first
    assert WorkflowState.from_dict(workflow.to_dict()).progress_facts() == first


def test_KSC02_selected_identity_reasons_recency_and_bounded_readback(tmp_path):
    workflow = state()
    for index in range(8):
        row = job(tmp_path, index, count=12)
        ids = [json.loads(line)['id'] for line in row.dataset(tmp_path).splitlines()]
        for offset, record_id in enumerate(ids):
            row.triage(tmp_path, [record_id], 'selected', f'Context reason {offset}')
        workflow.add_scanner_job(row)
    restored = WorkflowState.from_dict(workflow.to_dict())
    restored.scanner_jobs[row.job_id].artifacts['result_refs'] = ['tr_' + f'{i:032x}' for i in range(12)]
    projection = project_jobs(restored.scanner_jobs, row.target_origin, row.objective_id)
    projected = json.loads(projection)
    assert len(projection) <= 4096 and len(projected) <= 5
    assert projected[0]['job_id'] == row.job_id and projected[0]['jobs_omitted'] > 0
    assert len({record['record_id'] for record in projected[0]['selected']}) == 2
    assert projected[0]['selected_omitted'] == 10
    assert projected[0]['refs_omitted'] == 4
    assert {record['reason'] for record in projected[0]['selected']} <= {f'Context reason {i}' for i in range(12)}
    from src.target.target import Target
    from src.tools.workflow.workflow_tool import WorkflowTool
    tool = WorkflowTool(restored, Target(row.target_origin), evidence_root=tmp_path)
    seen = set()
    offset = 0
    while True:
        page = json.loads(tool._list({'job_id': row.job_id, 'scanner_offset': offset}))
        assert len(page['scanner_job']['refs']) == 12 and page['scanner_job']['refs_omitted'] == 0
        seen.update(item['record_id'] for item in page['scanner_dispositions'])
        if page['next_scanner_offset'] is None:
            break
        offset = page['next_scanner_offset']
    assert seen == set(ids)
    more = json.loads(tool._list(projected[0]['read_more_jobs']))
    assert more['scanner_jobs'] and more['scanner_jobs_total'] == 8
    assert not restored.candidates and not restored.validation_results
    prompt = render_workflow(restored)
    for item in projected[0]['selected']:
        assert item['record_id'] in prompt and item['reason'] in prompt
    latest = job(tmp_path, 8)
    restored.add_scanner_job(latest)
    assert json.loads(project_jobs(restored.scanner_jobs, latest.target_origin, latest.objective_id))[0]['job_id'] == latest.job_id
    latest.wordlist = {'id': '\u4e00' * 128, 'sha256': 'b' * 64}
    latest.remaining = {'disposition': 'deferred', 'reason': '\u4e00' * 240}
    latest.dispositions = {key: {'disposition': 'selected', 'reason': '\u4e00' * 240} for key in latest.sample_ids}
    bounded = project_jobs(restored.scanner_jobs, latest.target_origin, latest.objective_id)
    assert len(bounded) <= 4096 and json.loads(bounded)[0]['job_id'] == latest.job_id
    assert json.loads(bounded)[0]['remaining']['reason_truncated'] is True
    detail = json.loads(tool._list({'job_id': latest.job_id}))['scanner_job']
    assert detail['wordlist']['id'] == latest.wordlist['id'] and detail['remaining']['reason'] == latest.remaining['reason']


async def test_KSC03_full_tcp_scope_avoids_linear_membership(tmp_path):
    _, plan = await plan_for(tmp_path)
    class NoLinearMembership(tuple):
        def __contains__(self, _value):
            raise AssertionError('per-record tuple membership is forbidden')
    plan = replace(plan, ports=NoLinearMembership(range(1, 65536)))
    ports = ''.join(f'<port protocol="tcp" portid="{i}"><state state="open"/></port>' for i in range(53536, 65536))
    data = ('<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports>' + ports +
            '</ports></host><runstats><finished exit="success"/></runstats></nmaprun>').encode()
    parsed = parse_nmap(data, plan)
    assert len(parsed.records) == 12000 and parsed.rejected == 0 and parsed.coverage_complete is False


async def spawn_xml_fixture(rt, monkeypatch, data):
    source = rt.root.parent / 'fixture.xml'
    source.write_bytes(data)
    original = asyncio.create_subprocess_exec
    async def substitute(*args, **kwargs):
        output = args[args.index('-oX') + 1]
        code = f'from pathlib import Path;Path({output!r}).write_bytes(Path({str(source)!r}).read_bytes())'
        return await original('/usr/bin/python3', '-I', '-S', '-c', code, **kwargs)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', substitute)


async def wait_thread_event(event):
    async with asyncio.timeout(4):
        while not event.is_set():
            await asyncio.sleep(0.005)


async def test_KSC03_production_normalization_keeps_heartbeat_responsive(tmp_path, monkeypatch, record_property):
    require_binaries()
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:43210')
    rt.state.add_tcp('127.0.0.1', '1-65535')
    ports = ''.join(f'<port protocol="tcp" portid="{i}"><state state="open"/></port>' for i in range(35536, 65536))
    await spawn_xml_fixture(rt, monkeypatch, ('<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports>' +
        ports + '</ports></host></nmaprun>').encode())
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    def worker(*args):
        entered.set()
        assert release.wait(4)
        try:
            return normalize(*args)
        finally:
            finished.set()
    monkeypatch.setattr('src.tools.execution.scanner_runner.normalize', worker)
    task = asyncio.create_task(rt.registry.execute('shell', {'scanner': 'nmap', 'target': '127.0.0.1',
        'ports': '1-65535'}, None, rt.prompter))
    try:
        await wait_thread_event(entered)
        release.set()
        ticks = []
        while not finished.is_set():
            ticks.append(time.monotonic())
            await asyncio.sleep(0.01)
        result = await asyncio.wait_for(task, 4)
        assert len(ticks) >= 3
        maximum_gap = max(b - a for a, b in zip(ticks, ticks[1:]))
        record_property('normalization_heartbeat', json.dumps({'records': 30000, 'ticks': len(ticks),
            'max_gap_seconds': maximum_gap, 'worker_seconds': ticks[-1] - ticks[0]}))
        assert maximum_gap < 0.25
        assert result.scanner_result.envelope['summary']['unique_records'] == 30000
        assert result.scanner_result.envelope['parse']['coverage_complete'] is False
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize('action', ['cancel', 'revoke', 'reset'])
async def test_KSC03_parse_interruption_joins_worker_and_prevents_late_observations(tmp_path, monkeypatch, action):
    require_binaries()
    rt = agent_runtime(tmp_path, 'http://127.0.0.1:43210', FakeClient([]))
    from tests.security.test_scanner_end_to_end import xml
    await spawn_xml_fixture(rt, monkeypatch, xml())
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    def worker(*args):
        entered.set()
        assert release.wait(4)
        try:
            return normalize(*args)
        finally:
            finished.set()
    monkeypatch.setattr('src.tools.execution.scanner_runner.normalize', worker)
    tc = ToolCall('parse-interruption', FunctionCall('shell', json.dumps({'scanner': 'nmap', 'target': '127.0.0.1', 'ports': '43210'})))
    parsed = rt.agent.parse_tool_call(tc)
    rt.agent._tool_call_event(tc, parsed)
    task = asyncio.create_task(rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal()))
    reset_task = None
    try:
        await wait_thread_event(entered)
        if action == 'cancel':
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
        elif action == 'revoke':
            rt.policy.revoke('shell')
        else:
            reset_task = asyncio.create_task(rt.agent.reset())
        await asyncio.sleep(0.025)
        assert not task.done(), 'the owned worker must be joined before releasing the invocation'
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        if reset_task is not None:
            await reset_task
    assert finished.is_set() and rt.binding.runtime.task is None
    assert not rt.agent.workflow.scanner_observations
    assert not rt.agent.result_retention.references
    assert not list((rt.root / '.kagent/scanners').rglob('manifest.json'))
    if action == 'reset':
        assert not rt.agent.workflow.scanner_jobs
    else:
        history = next(iter(rt.agent.workflow.scanner_jobs.values()))
        assert history.execution['status'] in {'failed', 'cancelled'}
        assert history.counts['unique_records'] == 0


async def test_KSC04_failure_diagnostics_flush_sanitize_limits_and_cleanup(tmp_path, monkeypatch):
    require_binaries()
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:43210')
    secret = 'private-provider-canary-998877'
    rt.policy.internal_secret_values = lambda: (secret,)
    original = asyncio.create_subprocess_exec
    pids = []
    async def substitute(*args, **kwargs):
        message = ('Authorization: Bearer ' + secret + '\n' + args[args.index('-o') + 1] + '\n' +
            'unlabelled sensitive payload\n' + 'x' * 100000 + '\n' +
            ':: Progress: [40/45] :: \x1b[31mfatal error: concurrent map writes\x1b[0m\n' +
            '  github.com/ffuf/ffuf/v2/pkg/output.(*Stdoutput).Result(SECRET_ARGUMENT)\n')
        code = f'import os;os.write(1,b"system error: too many open files\\n");os.write(2,{message.encode()!r});raise SystemExit(2)'
        proc = await original('/usr/bin/python3', '-I', '-S', '-c', code, **kwargs)
        pids.append(proc.pid)
        return proc
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', substitute)
    output = await rt.registry.execute('shell', {'scanner': 'ffuf', 'url': rt.target.base_url() + '/FUZZ',
        'wordlist_id': 'fixture'}, None, rt.prompter)
    envelope = json.loads(output)
    assert envelope['execution']['status'] == 'failed' and envelope['execution']['exit_code'] == 2
    assert envelope['execution']['reason'] == 'nonzero_exit' and envelope['parse']['coverage_complete'] is False
    diagnostics = envelope['diagnostics']
    assert 'fatal error: concurrent map writes' in diagnostics['stderr']['text']
    assert '(*Stdoutput).Result' in diagnostics['stderr']['text']
    assert 'too many open files' in diagnostics['stdout']['text']
    assert diagnostics['stderr_bytes'] > 100000 and diagnostics['stderr']['capture_truncated'] is True
    assert diagnostics['resources']['nofile'] == 4096 and diagnostics['resources']['address_space'] == 4 * 1024**3
    manifest = (rt.root / envelope['artifacts']['manifest']).read_text()
    assert json.loads(manifest)['diagnostics'] == diagnostics
    for value in (str(output), manifest):
        assert secret not in value and 'SECRET_ARGUMENT' not in value and 'unlabelled sensitive payload' not in value
        assert str(rt.root / '.kagent/tmp') not in value and '\\u001b' not in value
    assert not list((rt.root / '.kagent/tmp/scanners').iterdir())
    for pid in pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


@pytest.mark.parametrize('stop', ['cancel', 'signal'])
async def test_KSC05_actual_started_checkpoint_restores_interrupted_and_updates_same_job(tmp_path, wire, monkeypatch, stop):
    require_binaries()
    origin, _ = wire
    rt = agent_runtime(tmp_path, origin, FakeClient([]), enumeration=True)
    original_spawn = asyncio.create_subprocess_exec
    pids = []
    async def observe_spawn(*args, **kwargs):
        proc = await original_spawn(*args, **kwargs)
        pids.append(proc.pid)
        return proc
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', observe_spawn)
    dict(rt.binding.wordlists)['fixture'].write_text(''.join(f'slow{i}\n' for i in range(100)))
    tc = ToolCall('running-checkpoint', FunctionCall('shell', json.dumps({'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture'})))
    parsed = rt.agent.parse_tool_call(tc)
    rt.agent._tool_call_event(tc, parsed)
    signal = FakeSignal()
    actual_started = asyncio.Event()
    def emit(event):
        if event['type'] == 'tool-started':
            actual_started.set()
    task = asyncio.create_task(rt.agent.run_parsed_tool_call(tc, parsed, signal, emit=emit))
    try:
        await asyncio.wait_for(actual_started.wait(), 4)
        assert not task.done()
        assert len(rt.agent.workflow.scanner_jobs) == 1
        running = next(iter(rt.agent.workflow.scanner_jobs.values()))
        assert running.execution['status'] == 'running'
        # No explicit save: the real started callback persisted the checkpoint.
        restored = rt.agent.store.load()
        history = restored.workflow.scanner_jobs[running.job_id]
        assert history.execution['status'] == 'interrupted' and history.parse['coverage_complete'] is False
        assert history.semantic_key == running.semantic_key and history.objective_id == running.objective_id
        assert not any(key in json.dumps(restored.workflow.to_dict()) for key in ('receipt', '"pid"', 'process_handle'))
        assert 'interrupted' in render_workflow(restored.workflow)
        assert rt.binding.runtime.task is not None and not task.done()
        restored_root = tmp_path / 'restored'
        restored_root.mkdir()
        other = agent_runtime(restored_root, origin, FakeClient([]))
        other.agent.store = rt.agent.store
        other.agent.resume_saved()
        assert other.agent.workflow.scanner_jobs[running.job_id].execution['status'] == 'interrupted'
        assert len(pids) == 1 and other.binding.runtime.task is None and other.policy.active == 0
        if stop == 'cancel':
            task.cancel()
        else:
            signal.aborted = True
    finally:
        if not task.done() and not signal.aborted:
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert len(rt.agent.workflow.scanner_jobs) == 1
    terminal = rt.agent.workflow.scanner_jobs[running.job_id]
    assert terminal.execution['status'] == 'cancelled'
    await rt.agent.save()
    assert rt.agent.store.load().workflow.scanner_jobs[running.job_id].execution['status'] == 'cancelled'
    assert not rt.binding.runtime.task and rt.policy.active == 0


async def test_KSC02_selected_work_survives_real_compaction_save_load_and_reader(tmp_path):
    from src.llm.core.types import Message
    rt = agent_runtime(tmp_path, 'http://127.0.0.1:43210', FakeClient([]))
    row = job(rt.root, count=4)
    row.objective_id = rt.agent.workflow.objective.id
    a, b = row.sample_ids[:2]
    row.triage(rt.root, [a], 'selected', 'Read route A to clarify its input context')
    row.triage(rt.root, [b], 'selected', 'Read route B to resolve its authentication context')
    assert rt.agent.workflow.add_scanner_job(row)
    # Large old traffic is discarded by the real compaction implementation;
    # canonical work has to come from the state projection, not this summary.
    history = [Message('system', rt.agent.sys_prompt), Message('user', 'Earlier discovery'),
        Message('assistant', 'old observed data ' * 15000), Message('user', 'continue selected context')]
    rt.agent.history = history
    before, after = await rt.agent.apply_compaction_summary('## Plan\n- Continue the selected context task.', history, 'scanner-fix-regression')
    assert after < before
    restored = rt.agent.store.load()
    projection = render_workflow(restored.workflow)
    rt.agent.resume_saved()
    view = rt.agent._workflow_request_view('continue selected context', rt.agent.tools.as_llm_tools())
    for record_id, reason in ((a, 'route A'), (b, 'route B')):
        assert record_id in projection and reason in projection
        assert any(record_id in message.content and message.role == 'user' for message in view.blocks)
    page = json.loads(rt.workflow._list({'job_id': row.job_id}))
    assert {item['record_id'] for item in page['scanner_dispositions']} == {a, b}
    assert restored.workflow.scanner_jobs[row.job_id].unresolved_selected == 2
    assert not restored.workflow.candidates


@pytest.mark.parametrize('action', ['revoke', 'timeout', 'cancel'])
async def test_KSC05_slow_checkpoint_cannot_delay_process_stop_or_outlive_owner(tmp_path, wire, monkeypatch, action):
    require_binaries()
    origin, _ = wire
    rt = agent_runtime(tmp_path, origin, FakeClient([]), enumeration=True)
    dict(rt.binding.wordlists)['fixture'].write_text(''.join(f'slow{i}\n' for i in range(200)))
    entered, release = asyncio.Event(), asyncio.Event()
    original_save = rt.agent.save
    async def held_save(*args, **kwargs):
        entered.set()
        await release.wait()
        await original_save(*args, **kwargs)
    monkeypatch.setattr(rt.agent, 'save', held_save)
    original_spawn = asyncio.create_subprocess_exec
    pids = []
    async def observe(*args, **kwargs):
        proc = await original_spawn(*args, **kwargs)
        pids.append(proc.pid)
        return proc
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', observe)
    tc = ToolCall('slow-checkpoint', FunctionCall('shell', json.dumps({'scanner': 'ffuf', 'url': origin + '/FUZZ',
        'wordlist_id': 'fixture', 'timeout_seconds': 1 if action == 'timeout' else 30})))
    parsed = rt.agent.parse_tool_call(tc)
    rt.agent._tool_call_event(tc, parsed)
    task = asyncio.create_task(rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal()))
    try:
        await asyncio.wait_for(entered.wait(), 4)
        if action == 'revoke':
            rt.policy.revoke('shell')
        elif action == 'cancel':
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
        async with asyncio.timeout(3):
            while True:
                try:
                    os.kill(pids[0], 0)
                except ProcessLookupError:
                    break
                await asyncio.sleep(0.025)
        assert not task.done(), 'the runner must join its checkpoint writer before releasing ownership'
        assert next(iter(rt.agent.workflow.scanner_jobs.values())).execution['status'] == 'running'
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    history = next(iter(rt.agent.workflow.scanner_jobs.values()))
    assert history.execution['status'] in {'failed', 'cancelled', 'partial'}
    assert history.parse['coverage_complete'] is False
    assert rt.binding.runtime.task is None and rt.policy.active == 0
    assert not any(t.get_name() == 'scanner-running-checkpoint' for t in asyncio.all_tasks() if not t.done())
    await rt.agent.save()
    assert rt.agent.store.load().workflow.scanner_jobs[history.job_id].execution['status'] != 'interrupted'
