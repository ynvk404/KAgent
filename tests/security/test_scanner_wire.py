"""R actual ffuf Host/SNI, config isolation, status/body metrics and redirects."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess

import pytest

from tests.security.test_scanner_end_to_end import runtime, wire, require_binaries


async def test_R_exact_argv_env_stdin_cwd_and_status_body_matrix(tmp_path, wire, monkeypatch, record_property):
    require_binaries()
    origin, counters = wire
    counters['redirect'] = origin.replace('127.0.0.1', 'localhost') + '/sink'
    rt = runtime(tmp_path / 'project', origin, ('hit', 'missing', 'unauth', 'forbidden', 'large', 'redirect'))
    captured = []
    original = asyncio.create_subprocess_exec
    async def observe(*args, **kwargs):
        captured.append((args, kwargs))
        return await original(*args, **kwargs)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', observe)
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    monkeypatch.setenv('HTTP_PROXY', 'http://127.0.0.1:1')
    monkeypatch.setenv('ALL_PROXY', 'http://127.0.0.1:1')
    monkeypatch.setenv('LD_PRELOAD', '/MUST_NOT_INHERIT')
    monkeypatch.setenv('OPENAI_API_KEY', 'fixture-secret-scanner-canary')
    # Serial semantic fixture avoids the independently measured dev-build JSON
    # row race. Concurrency40 is separately measured in test_scanner_end_to_end.
    output = await rt.registry.execute('shell', {'scanner': 'ffuf', 'url': origin + '/FUZZ',
        'wordlist_id': 'fixture', 'threads': 1}, None, rt.prompter)
    envelope = json.loads(output)
    assert envelope['execution']['status'] == 'completed', envelope
    rows = [json.loads(line) for line in output.scanner_result.dataset.splitlines()]
    assert {row['status'] for row in rows} == {200, 302, 401, 403, 404}
    assert next(row for row in rows if row['url'].endswith('/large'))['length'] == 70000
    assert counters['requests'] == 6 and '/sink' not in counters['paths']
    command, kwargs = captured[0]
    detail = json.loads(rt.operator.ask.call_args.args[0].detail)
    assert list(command) == detail['effective_command']
    assert kwargs['stdin'] == asyncio.subprocess.DEVNULL and kwargs['umask'] == 0o077
    assert kwargs['start_new_session'] is True
    assert kwargs['cwd'] == str(Path(command[command.index('-o') + 1]).parent)
    assert set(kwargs['env']) == {'PATH', 'LANG', 'LC_ALL', 'HOME', 'XDG_CONFIG_HOME', 'TMPDIR', 'GOMEMLIMIT'}
    assert kwargs['env']['HOME'].startswith(kwargs['cwd'] + '/')
    assert 'fixture-secret-scanner-canary' not in str(output)
    manifest = rt.root / envelope['artifacts']['manifest']
    assert manifest.stat().st_mode & 0o777 == 0o600
    assert manifest.parent.stat().st_mode & 0o777 == 0o700
    assert 'fixture-secret-scanner-canary' not in manifest.read_text()
    record_property('scanner_wire', json.dumps({'origin': origin, 'requests': counters['requests'],
        'hosts': sorted(set(counters['hosts'])), 'peak': counters['peak'], 'argv': command,
        'binary': envelope['binary'], 'profile': output.scanner_result.plan.resources.version,
        'large_length': 70000, 'redirect_followed': False}))


async def test_R_https_numeric_pinning_original_host_sni_and_hostile_user_config(tmp_path, monkeypatch, record_property):
    require_binaries()
    if not shutil.which('openssl'):
        pytest.skip('BLOCKED R HTTPS acceptance: installed openssl needed for private temporary test certificate')
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    result = subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=scanner.fixture.invalid'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    assert result.returncode == 0
    key.chmod(0o600)
    cert.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    sni, hosts, paths, sink_requests = [], [], [], []
    context.set_servername_callback(lambda _sock, name, _ctx: sni.append(name))
    async def sink(reader, writer):
        sink_requests.append(await reader.read(4096))
        writer.close()
        await writer.wait_closed()
    receiver = await asyncio.start_server(sink, '127.0.0.1', 0)
    sink_origin = f'http://127.0.0.1:{receiver.sockets[0].getsockname()[1]}'
    async def serve(reader, writer):
        request = await reader.readuntil(b'\r\n\r\n')
        path = request.split(b' ')[1].decode()
        paths.append(path)
        hosts.extend(line.decode().partition(': ')[2] for line in request.split(b'\r\n') if line.lower().startswith(b'host:'))
        location = 'Location: ' + sink_origin + '/sink\r\n' if path == '/redirect' else ''
        status = 302 if location else 200
        writer.write(f'HTTP/1.1 {status} Fixture\r\n{location}Content-Length: 2\r\nConnection: close\r\n\r\nok'.encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    server = await asyncio.start_server(serve, '127.0.0.1', 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    origin = f'https://scanner.fixture.invalid:{port}'
    hostile = tmp_path / 'foreign-config'
    config = hostile / 'ffuf'
    config.mkdir(parents=True)
    (config / 'ffufrc').write_text('[http]\nurl = "' + sink_origin + '/FUZZ"\nproxyurl = "' + sink_origin +
        '"\nheaders = ["Authorization: fixture-secret-config-canary"]\nfollowredirects = true\n')
    monkeypatch.setenv('HOME', str(hostile))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(hostile))
    for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
        monkeypatch.setenv(name, sink_origin)
    resolved = []
    def resolver(host):
        resolved.append(host)
        return ('127.0.0.1',)
    monkeypatch.setattr('src.tools.execution.scanners.resolve_addresses', resolver)
    rt = runtime(tmp_path / 'project', origin, ('hit', 'redirect'))
    try:
        output = await rt.registry.execute('shell', {'scanner': 'ffuf', 'url': origin + '/FUZZ',
            'wordlist_id': 'fixture', 'threads': 1}, None, rt.prompter)
        envelope = json.loads(output)
        assert envelope['execution']['status'] == 'completed', envelope
        assert resolved == ['scanner.fixture.invalid']
        assert hosts == [f'scanner.fixture.invalid:{port}'] * 2
        assert set(sni) == {'scanner.fixture.invalid'}
        assert sorted(paths) == ['/hit', '/redirect'] and not sink_requests
        assert all(row['url'].startswith(origin) for row in envelope['records'])
        assert 'fixture-secret-config-canary' not in str(output)
        plan = output.scanner_result.plan
        assert f'https://127.0.0.1:{port}/FUZZ' in plan.argv
        record_property('scanner_tls', json.dumps({'origin': origin, 'address': plan.address,
            'hosts': hosts, 'sni': sni, 'sink_requests': len(sink_requests), 'argv': plan.command,
            'binary': envelope['binary'], 'profile': plan.resources.version,
            'self_signed_certificate_accepted': True, 'foreign_config_ignored': True}))
    finally:
        server.close()
        receiver.close()
        await server.wait_closed()
        await receiver.wait_closed()


@pytest.mark.parametrize('scanner', ['nmap', 'ffuf'])
async def test_R_ipv6_loopback_exact_scope(tmp_path, scanner, record_property):
    require_binaries()
    requests = []
    async def serve(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(4096), 1)
            if data:
                requests.append(data.split(b'\r\n', 1)[0].decode())
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
                await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
    try:
        server = await asyncio.start_server(serve, '::1', 0)
    except OSError:
        pytest.skip('BLOCKED R IPv6 acceptance: fixture-owned ::1 listener unavailable')
    port = server.sockets[0].getsockname()[1]
    origin = f'http://[::1]:{port}'
    rt = runtime(tmp_path / 'project', origin, ('hit',))
    args = ({'scanner': 'nmap', 'target': '::1', 'ports': str(port)} if scanner == 'nmap' else
            {'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture', 'threads': 1})
    try:
        result = await rt.registry.execute('shell', args, None, rt.prompter)
        envelope = json.loads(result)
        assert envelope['execution']['status'] == 'completed', envelope
        assert len(envelope['records']) == 1
        if scanner == 'nmap':
            assert envelope['records'][0]['address'] == '::1' and envelope['records'][0]['state'] == 'open'
        else:
            assert envelope['records'][0]['url'] == origin + '/hit' and len(requests) == 1
        record_property('scanner_ipv6', json.dumps({'origin': origin, 'argv': result.scanner_result.plan.command,
            'binary': envelope['binary'], 'records': envelope['summary']['unique_records']}))
    finally:
        server.close()
        await server.wait_closed()
