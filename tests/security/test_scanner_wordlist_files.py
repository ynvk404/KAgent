"""Existing operator-selected files remain bound to exact scanner review."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tomllib
from unittest.mock import AsyncMock

import pytest

from src.cli.runtime import FlagParseError, parse_flags
from src.permission.runtime.execution import ExecutionBlocked
from src.tools.execution.scanners import ScannerBinding
from src.tools.execution.wordlists import BUNDLED_WORDLIST, MAX_WORDLISTS, wordlist_files
from tests.security.test_scanner_end_to_end import runtime, require_binaries, wire


def test_cli_registers_multiple_existing_file_ids_and_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    first, second = tmp_path / 'paths small.txt', tmp_path / 'api.txt'
    first.write_text('admin\n')
    second.write_text('users\n')
    flags = parse_flags(['--scanner-wordlist', 'paths-small=paths small.txt',
                         '--scanner-wordlist', 'api-words=' + str(second)])
    assert flags.scanner_wordlists == [('paths-small', first), ('api-words', second)]
    assert not parse_flags([]).scanner_wordlists  # Invocation-only, no persisted configuration.


@pytest.mark.parametrize('specs', [
    ['--scanner-wordlist'], ['--scanner-wordlist', 'missing-equals'],
    ['--scanner-wordlist', 'id='], ['--scanner-wordlist', '=words.txt'],
    ['--scanner-wordlist', 'web-common=words.txt'],
    ['--scanner-wordlist', 'bad/id=words.txt'], ['--scanner-wordlist', 'id=words\x00.txt'],
    ['--scanner-wordlist', 'id=first.txt', '--scanner-wordlist', 'id=second.txt'],
])
def test_invalid_or_duplicate_cli_registration_fails_before_runtime(specs):
    with pytest.raises(FlagParseError):
        parse_flags(specs)


def test_controller_catalog_cannot_silently_shadow_ids_or_grow_unbounded(tmp_path):
    with pytest.raises(ValueError):
        wordlist_files((('same', tmp_path / 'one'), ('same', tmp_path / 'two')))
    with pytest.raises(ValueError):
        wordlist_files(tuple((f'list-{i}', tmp_path / str(i)) for i in range(MAX_WORDLISTS + 1)))


async def test_catalog_exposes_existing_files_and_snapshot_uses_selected_contents(tmp_path):
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:8080')
    first, second = tmp_path / 'directories.txt', tmp_path / 'api.txt'
    first.write_text('admin\nlogin\n')
    second.write_text('# existing API nouns\nusers\norders\n')
    flags = parse_flags(['--scanner-wordlist', 'paths-small=' + str(first),
                         '--scanner-wordlist', 'api-words=' + str(second)])
    binding = ScannerBinding(rt.policy, rt.target, rt.binding.capabilities, tuple(flags.scanner_wordlists))
    entries = {item['id']: item for item in binding.catalog()['wordlists']}
    assert entries['paths-small']['path'] == str(first) and entries['paths-small']['available']
    assert entries['api-words']['bytes'] == second.stat().st_size
    snapshot = await binding.snapshot_wordlist('api-words')
    assert snapshot.data == b'users\norders\n' and snapshot.source is not None
    assert snapshot.source.canonical == str(second)
    assert snapshot.sha256 == hashlib.sha256(snapshot.data).hexdigest()
    assert snapshot.source.sha256 == hashlib.sha256(second.read_bytes()).hexdigest()


async def test_web_common_is_a_real_packaged_file_without_native_python_fallback(tmp_path, monkeypatch):
    import src.tools.discovery.content as native
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:8080')
    monkeypatch.setattr(native, 'DEFAULT_PATHS', ('must-not-enter-ffuf',))
    snapshot = await rt.binding.snapshot_wordlist('web-common')
    assert snapshot.source is not None and snapshot.source.canonical == str(BUNDLED_WORDLIST)
    assert b'admin\n' in snapshot.data and b'must-not-enter-ffuf' not in snapshot.data
    metadata = tomllib.loads((Path(__file__).resolve().parents[2] / 'pyproject.toml').read_text())
    assert 'wordlists/*.txt' in metadata['tool']['setuptools']['package-data']['src.tools.execution']
    monkeypatch.setattr('src.tools.execution.wordlists.BUNDLED_WORDLIST', tmp_path / 'missing.txt')
    with pytest.raises(FileNotFoundError):
        await rt.binding.snapshot_wordlist('web-common')


async def test_unregistered_paths_and_missing_or_linked_files_fail_without_review(tmp_path):
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:8080')
    binding = replace(rt.binding, wordlists=(('missing', tmp_path / 'missing.txt'),))
    assert not next(row for row in binding.catalog()['wordlists'] if row['id'] == 'missing')['available']
    with pytest.raises(ExecutionBlocked, match='wordlist_id'):
        await binding.snapshot_wordlist('/etc/passwd')
    with pytest.raises(FileNotFoundError):
        await binding.snapshot_wordlist('missing')
    source, link = tmp_path / 'source.txt', tmp_path / 'linked.txt'
    source.write_text('admin\n')
    link.symlink_to(source)
    linked = replace(binding, wordlists=(('linked', link),))
    assert not next(row for row in linked.catalog()['wordlists'] if row['id'] == 'linked')['available']
    with pytest.raises(ExecutionBlocked, match='symlink'):
        await linked.snapshot_wordlist('linked')
    assert not rt.operator.ask.called


async def test_installed_system_wordlists_are_discovered_without_install_or_cli_flags(tmp_path, monkeypatch):
    source = tmp_path / 'small.txt'
    source.write_text('admin\nlogin\n')
    monkeypatch.setattr('src.tools.execution.wordlists.SYSTEM_WORDLISTS', (
        ('dirb-small', source), ('dirb-common', tmp_path / 'not-installed.txt')))
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:8080')
    entries = {row['id']: row for row in rt.binding.catalog()['wordlists']}
    assert entries['dirb-small']['available'] and 'dirb-common' not in entries
    snapshot = await rt.binding.snapshot_wordlist('dirb-small')
    assert snapshot.data == b'admin\nlogin\n' and snapshot.source.canonical == str(source)


async def test_registered_file_change_during_review_never_spawns(tmp_path, monkeypatch):
    require_binaries()
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:8080')
    source = tmp_path / 'directories.txt'
    source.write_text('admin\n')
    binding = replace(rt.binding, wordlists=(('paths-small', source),))
    rt.tool.scanner_binding = binding
    async def review(request, signal=None):
        detail = json.loads(request.detail)
        assert detail['wordlist_source'] == str(source)
        assert detail['wordlist_source_sha256'] == hashlib.sha256(b'admin\n').hexdigest()
        source.write_text('changed\n')
        from src.permission.permission import Decision
        return Decision.ALLOW_ONCE
    rt.operator.ask.side_effect = review
    spawn = AsyncMock(side_effect=AssertionError('stale wordlist must never spawn'))
    monkeypatch.setattr('asyncio.create_subprocess_exec', spawn)
    with pytest.raises(ExecutionBlocked):
        await rt.registry.execute('shell', {'scanner': 'ffuf', 'url': rt.target.base_url() + '/FUZZ',
            'wordlist_id': 'paths-small'}, None, rt.prompter)
    spawn.assert_not_called()


async def test_registered_file_runs_real_ffuf_with_the_selected_words_only(tmp_path, wire):
    require_binaries()
    origin, counters = wire
    rt = runtime(tmp_path / 'project', origin)
    source = tmp_path / 'api-words.txt'
    source.write_text('context\nmissing\n')
    flags = parse_flags(['--scanner-wordlist', 'api-words=' + str(source)])
    rt.tool.scanner_binding = ScannerBinding(rt.policy, rt.target, rt.binding.capabilities,
                                             tuple(flags.scanner_wordlists))
    output = await rt.registry.execute('shell', {'scanner': 'ffuf', 'url': origin + '/api/FUZZ',
        'wordlist_id': 'api-words', 'threads': 1}, None, rt.prompter)
    envelope = json.loads(output)
    assert envelope['execution']['status'] == 'completed', envelope
    assert set(counters['paths']) == {'/api/context', '/api/missing'}
    assert envelope['wordlist']['id'] == 'api-words' and rt.operator.ask.call_count == 1
    assert output.scanner_result.plan.wordlist.source.canonical == str(source)
