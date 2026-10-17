"""Exact default-concurrency output and fail-closed build registration."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from unittest.mock import AsyncMock

import pytest

from src.permission.runtime.execution import ExecutionBlocked
from src.tools.execution import scanner_runner, shell
from tests.security.test_scanner_end_to_end import require_binaries, runtime, wire


async def test_R_ffuf_default40_twenty_jobs_retain_exact_native_and_normalized_sets(
    tmp_path, wire, monkeypatch, record_property,
):
    require_binaries()
    origin, counters = wire
    words = ('hit', 'missing', 'unauth', 'forbidden', 'large', *(f'wild{i}' for i in range(40)))
    rt = runtime(tmp_path / 'project', origin, words)
    buffers, captures = [], []
    original_buffer, original_normalize = shell.HeadTailBuffer, scanner_runner.normalize_capture

    class Capture(original_buffer):
        def __init__(self, cap):
            super().__init__(cap)
            buffers.append(self)

    def capture(raw, *args):
        captures.append(raw)
        return original_normalize(raw, *args)

    monkeypatch.setattr(shell, 'HeadTailBuffer', Capture)
    monkeypatch.setattr(scanner_runner, 'normalize_capture', capture)
    for attempt in range(1, 21):
        buffers.clear()
        captures.clear()
        before = counters['requests']
        counters['peak'] = 0
        output = await rt.registry.execute('shell', {
            'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture',
        }, None, rt.prompter)
        envelope = json.loads(output)
        assert envelope['execution']['exit_code'] == 0, envelope
        assert envelope['execution']['status'] == 'completed', envelope
        assert envelope['options']['threads'] == 40
        assert envelope['summary']['unique_records'] == 45
        assert envelope['summary']['rejected_records'] == 0
        assert envelope['summary']['duplicates'] == envelope['summary']['conflicts'] == 0
        assert envelope['parse'] == {'status': 'valid', 'partial': False, 'coverage_complete': None}
        assert len(captures) == 1
        native = json.loads(captures[0])['results']
        assert len(native) == 45
        assert {r['input']['FUZZ'] for r in native} == set(words)
        plain = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', buffers[0].render()).replace('\r', '\n')
        printed = {word for word in words if re.search(r'(?m)^' + re.escape(word) + r'\s+\[Status:', plain)}
        assert printed == set(words)
        rows = [json.loads(line) for line in output.scanner_result.dataset.splitlines()]
        assert len(rows) == 45
        assert {row['url'] for row in rows} == {origin + '/' + word for word in words}
        by_url = {row['url']: row for row in rows}
        for word in words:
            assert by_url[origin + '/' + word]['status'] == {
                'missing': 404, 'unauth': 401, 'forbidden': 403,
            }.get(word, 200)
            assert by_url[origin + '/' + word]['length'] == (70000 if word == 'large' else 42)
        assert counters['requests'] - before == 45
        assert counters['peak'] == 40
        assert not list((rt.root / '.kagent/tmp/scanners').iterdir())
        assert not rt.policy._active_receipts and rt.policy.active == 0
        assert rt.binding.runtime.task is None
        record_property(f'ffuf_reliability_{attempt}', json.dumps({
            'binary': envelope['binary'], 'execution': envelope['execution'],
            'native_records': len(native), 'normalized_records': len(rows),
            'raw_sha256': hashlib.sha256(captures[0]).hexdigest(),
            'requests': counters['requests'] - before, 'peak': counters['peak'],
        }))
    assert rt.operator.ask.call_count == 20


async def test_R_unreviewed_ffuf_hash_cannot_spawn_or_mint_result(tmp_path, wire, monkeypatch):
    require_binaries()
    origin, counters = wire
    rt = runtime(tmp_path / 'project', origin)
    monkeypatch.setitem(scanner_runner.SUPPORTED_BUILDS, 'ffuf', {})
    spawn = AsyncMock(side_effect=AssertionError('unreviewed build reached spawn'))
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', spawn)
    with pytest.raises(ExecutionBlocked, match='unsupported scanner build'):
        await rt.registry.execute('shell', {
            'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture',
        }, None, rt.prompter)
    spawn.assert_not_called()
    assert counters['requests'] == 0
    assert rt.binding.runtime.task is None
    assert not rt.policy._active_receipts and rt.policy.active == 0
    assert not (rt.root / '.kagent/scanners').exists()
