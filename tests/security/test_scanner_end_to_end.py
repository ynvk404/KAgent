"""U/M/P and real-binary R tests; all wire traffic is fixture-owned loopback."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest

from src.engagement.state import EngagementState
from src.permission.permission import Decision, Prompter, YoloPrompter
from src.permission.runtime.execution import ExecutionBlocked, default_execution_policy
from src.target.target import Target
from src.tools.common.capabilities import CapabilityInventory
from src.tools.common.registry import Registry
from src.tools.discovery.scanner_results import parse_ffuf, parse_nmap
from src.tools.execution.scanners import ScannerBinding
from src.tools.execution.shell import ShellTool


def runtime(root: Path, origin: str, words: tuple[str, ...] = ('hit', 'missing')):
    root.mkdir(exist_ok=True)
    wordlist = root.parent / (root.name + '-approved.txt')
    wordlist.write_text('\n'.join(words) + '\n')
    state = EngagementState()
    state.add_origin(origin)
    target = Target(origin)
    state.http_permissions.bind_target(lambda: target.revision)
    policy = default_execution_policy(state, root)
    operator = SimpleNamespace(ask=AsyncMock(return_value=Decision.ALLOW_ONCE))
    prompter = YoloPrompter(cast(Prompter, operator), False)
    prompter.bind_execution_policy(policy)
    binding = ScannerBinding(policy, target, CapabilityInventory(), (('fixture', wordlist),))
    tool = ShellTool(scanner_binding=binding)
    registry = Registry()
    registry.register(tool)
    return SimpleNamespace(root=root, state=state, target=target, policy=policy, operator=operator,
        prompter=prompter, binding=binding, tool=tool, registry=registry)


async def plan_for(tmp_path, scanner='nmap'):
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:43210')
    args = ({'scanner': 'nmap', 'target': '127.0.0.1', 'ports': '43210'} if scanner == 'nmap' else
            {'scanner': 'ffuf', 'url': rt.target.base_url() + '/FUZZ', 'wordlist_id': 'fixture'})
    plan = await rt.binding.prepare(args, None)
    return rt, plan


def xml(port=43210, state='open', extra='', address='127.0.0.1'):
    return (f'<?xml version="1.0"?><!DOCTYPE nmaprun><?xml-stylesheet href="file:///DO_NOT_READ.xsl"?>'
            f'<nmaprun><host><address addr="{address}" addrtype="ipv4"/><ports>'
            f'<port protocol="tcp" portid="{port}"><state state="{state}" reason="syn-ack"/>'
            f'<service name="unknown"/></port>{extra}</ports></host>'
            '<runstats><finished exit="success"/></runstats></nmaprun>').encode()


async def test_xml_bare_doctype_stylesheet_and_exact_records(tmp_path):
    _, plan = await plan_for(tmp_path)
    result = parse_nmap(xml(), plan)
    assert result.validity == 'valid' and result.coverage_complete is True
    assert result.records[0]['state'] == 'open'
    assert result.records[0]['port'] == 43210


@pytest.mark.parametrize('data', [
    b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd"><nmaprun/>',
    b'<!DOCTYPE nmaprun PUBLIC "x" "file:///etc/passwd"><nmaprun/>',
    b'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>',
    b'<nmaprun>' + b'<x>' * 40 + b'</x>' * 40 + b'</nmaprun>', b'<nmaprun><host>', b'',
])
async def test_unsafe_or_malformed_xml_rejected(tmp_path, data):
    _, plan = await plan_for(tmp_path)
    result = parse_nmap(data, plan)
    assert result.validity == 'invalid' and not result.records


@pytest.mark.parametrize('data', [xml(port=80), xml(address='127.0.0.2')])
async def test_out_of_scope_nmap_rows_are_not_observations(tmp_path, data):
    _, plan = await plan_for(tmp_path)
    result = parse_nmap(data, plan)
    assert result.rejected == 1 and not result.records and not result.coverage_complete


async def test_extraports_never_become_closed_per_port_facts(tmp_path):
    _, plan = await plan_for(tmp_path)
    result = parse_nmap(b'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/>'
        b'<ports><extraports state="closed" count="1"/></ports></host>'
        b'<runstats><finished exit="success"/></runstats></nmaprun>', plan)
    assert not result.records and not result.coverage_complete


async def test_unsafe_control_storage_is_unavailable_before_review_or_spawn(tmp_path, monkeypatch):
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:43210')
    control = rt.root / '.kagent'
    control.mkdir(mode=0o700)
    control.chmod(0o777)
    assert all(not item['ready'] for item in rt.binding.catalog()['binaries'].values())
    forbidden = AsyncMock(side_effect=AssertionError('unsafe storage must not spawn'))
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', forbidden)
    with pytest.raises(ExecutionBlocked, match='storage ownership/permissions'):
        await rt.registry.execute('shell', {'scanner': 'nmap', 'target': '127.0.0.1', 'ports': '43210'}, None, rt.prompter)
    assert not rt.operator.ask.called and not forbidden.called


@pytest.mark.parametrize('mutation', ['profile', 'launcher', 'argv', 'output_path'])
async def test_prepared_profile_launcher_and_argv_mutations_cannot_start_receipt(tmp_path, mutation):
    rt, plan = await plan_for(tmp_path)
    args = {'scanner': 'nmap', 'target': '127.0.0.1', 'ports': '43210'}
    tool = rt.tool.freeze_for_execution()
    tool.scanner_plan = plan
    receipt = rt.policy.prepare(tool, args)
    try:
        if mutation == 'profile':
            object.__setattr__(rt.binding, 'resources', replace(rt.binding.resources, nofile=2048))
        elif mutation == 'launcher':
            object.__setattr__(rt.binding, 'launcher_path', '/bin/true')
        elif mutation == 'argv':
            tool.scanner_plan = replace(plan, argv=(*plan.argv, '-sV'))
        else:
            tool.scanner_plan = replace(plan, directory=str(rt.root / 'foreign'))
        with pytest.raises(ExecutionBlocked):
            rt.policy.start(receipt, tool, args, None)
    finally:
        rt.policy.finish_review(receipt)
    assert not rt.policy._active_receipts and rt.policy.active == 0


async def test_ffuf_url_word_metrics_and_conflicting_duplicates(tmp_path):
    _, plan = await plan_for(tmp_path, 'ffuf')
    url = plan.argv[plan.argv.index('-u') + 1].replace('FUZZ', 'hit')
    row = {'input': {'FUZZ': 'hit'}, 'url': url, 'status': 403, 'length': 70000, 'words': 2, 'lines': 1}
    result = parse_ffuf(json.dumps({'results': [row, row, {**row, 'status': 200}]}).encode(), plan)
    assert len(result.records) == 1 and result.duplicates == 1 and result.conflicts == 1
    assert result.records[0]['verification'] == 'scanner_reported'
    assert result.records[0]['length'] > 65536
    for bad in ({**row, 'url': 'http://127.0.0.2/hit'}, {**row, 'input': {'FUZZ': 'unknown'}},
                {**row, 'status': True}, {**row, 'length': -1}):
        rejected = parse_ffuf(json.dumps({'results': [bad]}).encode(), plan)
        assert rejected.rejected == 1 and not rejected.records


@pytest.fixture
async def wire():
    counters = {'requests': 0, 'active': 0, 'peak': 0, 'paths': [], 'hosts': []}
    tasks = set()
    async def serve(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            request = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2)
            path = request.split(b' ')[1].decode()
            headers = dict(line.decode().split(': ', 1) for line in request.split(b'\r\n')[1:] if b': ' in line)
            counters['requests'] += 1
            counters['active'] += 1
            counters['peak'] = max(counters['peak'], counters['active'])
            counters['paths'].append(path)
            counters['hosts'].append(headers.get('Host'))
            await asyncio.sleep(0.12 if not path.startswith('/slow') else 1)
            code = 302 if path == '/redirect' else 401 if path == '/unauth' else 403 if path == '/forbidden' else 404 if path == '/missing' else 200
            body = b'x' * (70000 if path == '/large' else 42)
            if path == '/context':
                body = b'{"documented_operation":"GET /search","query_parameter":"q","type":"string"}'
            elif path.startswith('/search?q='):
                # Harmless synthetic syntax signal, not a real vulnerability.
                code = 400 if '%27' in path else 200
                body = b'{"error":"query syntax rejected"}' if code == 400 else b'{"query_used":true}'
            location = 'Location: ' + counters['redirect'] + '\r\n' if code == 302 else ''
            writer.write(f'HTTP/1.1 {code} Fixture\r\n{location}Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
            await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            if 'path' in locals():
                counters['active'] -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            tasks.discard(task)
    server = await asyncio.start_server(serve, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    yield f'http://127.0.0.1:{port}', counters
    server.close()
    await server.wait_closed()
    for _ in range(60):
        if counters['active'] <= 0:
            break
        await asyncio.sleep(0.025)
    for task in tasks.copy():
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def require_binaries():
    missing = [name for name in ('nmap', 'ffuf', 'prlimit') if not shutil.which(name)]
    if missing:
        pytest.skip('BLOCKED real scanner acceptance: missing installed ' + ', '.join(missing))


async def test_R_real_nmap_open_and_closed_through_registry(tmp_path, wire, record_property):
    require_binaries()
    origin, _ = wire
    rt = runtime(tmp_path / 'project', origin)
    open_port = int(origin.rpartition(':')[2])
    with socket.socket() as reserved_closed:
        reserved_closed.bind(('127.0.0.1', 0))
        closed_port = reserved_closed.getsockname()[1]
        ports = f'{open_port},{closed_port}'
        rt.state.add_tcp('127.0.0.1', ports)
        output = await rt.registry.execute('shell', {'scanner': 'nmap', 'target': '127.0.0.1', 'ports': ports}, None, rt.prompter)
    envelope = json.loads(output)
    assert envelope['execution']['status'] == 'completed', envelope
    assert envelope['execution']['started_at'].endswith('+00:00')
    assert envelope['execution']['finished_at'] >= envelope['execution']['started_at']
    records = {row['port']: row['state'] for row in envelope['records']}
    assert records == {open_port: 'open', closed_port: 'closed'}
    assert rt.operator.ask.call_count == 1
    assert rt.policy.active == 0 and not rt.binding.runtime.task
    assert not list((rt.root / '.kagent/tmp/scanners').iterdir())
    record_property('scanner_nmap', json.dumps({'origin': origin, 'open_port': open_port,
        'closed_port': closed_port, 'states': records, 'argv': output.scanner_result.plan.command,
        'binary': envelope['binary'], 'profile': output.scanner_result.plan.resources.version}))


async def test_R_real_ffuf_multi_request_body_and_concurrency(tmp_path, wire, monkeypatch, record_property):
    require_binaries()
    origin, counters = wire
    from src.tools.execution.shell import HeadTailBuffer
    buffers = []
    class FixtureCapture(HeadTailBuffer):
        def __init__(self, cap):
            super().__init__(cap)
            buffers.append(self)
    monkeypatch.setattr('src.tools.execution.shell.HeadTailBuffer', FixtureCapture)
    rt = runtime(tmp_path / 'project', origin, ('hit', 'missing', 'unauth', 'forbidden', 'large', *('wild' + str(i) for i in range(40))))
    output = await rt.registry.execute('shell', {'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture'}, None, rt.prompter)
    envelope = json.loads(output)
    # A reviewed build must retain every match at the default concurrency.
    assert envelope['execution']['status'] == 'completed', envelope
    assert envelope['summary']['unique_records'] == 45, envelope
    producer = output.scanner_result
    rows = [json.loads(line) for line in producer.dataset.splitlines()]
    assert len(rows) == 45 and all(row['status'] in {200, 401, 403, 404} for row in rows)
    assert counters['requests'] == 45 and counters['peak'] > 2
    assert rt.operator.ask.call_count == 1
    assert not rt.state.http_permissions.grants
    assert envelope['parse']['coverage_complete'] is None
    assert not list((rt.root / '.kagent/tmp/scanners').iterdir())
    record_property('scanner_ffuf_concurrency', json.dumps({'origin': origin, 'observed_requests': counters['requests'],
        'peak_overlap': counters['peak'], 'retained_records': len(rows), 'status': envelope['execution']['status'],
        'coverage_complete': envelope['parse']['coverage_complete'], 'argv': output.scanner_result.plan.command,
        'binary': envelope['binary'], 'profile': output.scanner_result.plan.resources.version}))
