"""Offline transport and run designation data-contract regressions."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json

import httpx
import pytest

from benchmarks.common.contracts import CaseExecution, RuntimeMetrics, decode, digest, write_new
from benchmarks.scenario1.__main__ import parser
from benchmarks.scenario1.classification import (read_run_designation, write_run_classification,
                                                RECORD_NAME)
from benchmarks.scenario1.evaluate import evaluate
from benchmarks.scenario1.runner import run
from benchmarks.scenario1.runtime import build_agent, execute_case, request_fixture
from tests.benchmarks.test_scenario1 import (ScriptedClient, single_manifest,
    op, settings, mock_http, isolated_project_environment)


def _counts(agent, policy):
    tool = agent.tools.get('http')
    assert tool is not None
    return (sum(b.used for b in policy.engagement.http_permissions._budgets.values()),
            tool.dispatch_attempts)


@pytest.mark.asyncio
async def test_reservation_without_transport_dispatch(tmp_path, monkeypatch, op, settings):
    agent, policy, _ = build_agent(op, settings, tmp_path, ScriptedClient())
    def stop_before_send():
        raise RuntimeError('offline pre-dispatch stop')
    monkeypatch.setattr(policy.observations, 'owner_provider', stop_before_send)
    with pytest.raises(RuntimeError, match='pre-dispatch'):
        await agent.tools.execute('http', request_fixture(op, settings), None, agent.prompter)
    assert _counts(agent, policy) == (1, 0)


@pytest.mark.asyncio
async def test_transport_dispatch_success_failure_and_retry(tmp_path, monkeypatch, op, settings):
    attempts = []
    def transport(request):
        attempts.append(request)
        if len(attempts) == 2:
            raise httpx.ConnectError('offline simulated failure')
        return httpx.Response(200, content=b'offline', request=request)
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: original(transport=httpx.MockTransport(transport), **kw))
    agent, policy, _ = build_agent(op, settings, tmp_path, ScriptedClient())
    args = request_fixture(op, settings)
    await agent.tools.execute('http', args, None, agent.prompter)
    assert _counts(agent, policy) == (1, 1)
    with pytest.raises(httpx.ConnectError):
        await agent.tools.execute('http', args, None, agent.prompter)
    assert _counts(agent, policy) == (2, 2)
    await agent.tools.execute('http', args, None, agent.prompter)
    assert _counts(agent, policy) == (3, 3)
    assert len(attempts) == 3


@pytest.mark.asyncio
async def test_per_case_dispatch_metric_serializes_and_legacy_is_na(
        tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    execution = await execute_case(op, settings, tmp_path, 'run', 'ex', ScriptedClient())
    assert execution.metrics is not None
    assert execution.metrics['http_dispatch_attempts'] == len(mock_http) == 2
    path = tmp_path / 'result.json'
    write_new(path, asdict(execution))
    restored = decode(CaseExecution, json.loads(path.read_text()))
    assert restored.metrics is not None
    assert restored.metrics['http_dispatch_attempts'] == 2
    legacy = asdict(execution)
    del legacy['metrics']['http_dispatch_attempts']
    decoded = decode(CaseExecution, legacy)
    assert decoded.metrics is not None
    assert decoded.metrics['http_dispatch_attempts'] is None
    assert decode(RuntimeMetrics, decoded.metrics).http_dispatch_attempts is None


def test_run_classification_precedes_worker_and_binds_final_manifest(
        tmp_path, monkeypatch, op, settings):
    from benchmarks.scenario1 import runner
    monkeypatch.setattr(runner, 'reproducibility', lambda: {'offline': True})
    manifest = single_manifest(op, settings)
    results = []
    for kind in ('development', 'official'):
        destination = tmp_path / kind
        def launcher(payload, _seconds):
            record = read_run_designation(destination)
            assert (record.classification, record.declared) == (kind, True)
            assert 'truth' not in payload and 'expected_vulnerable' not in str(payload)
            results.append(kind)
            return -9, False
        run(manifest, settings, destination, run_kind=kind, launcher=launcher)
        record = json.loads((destination / RECORD_NAME).read_text())
        manifest_bytes = (destination / 'manifest.json').read_bytes()
        assert record == {'schema_version': 1, 'run_id': manifest.run_id,
                          'classification': kind,
                          'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
                          'manifest_identity': digest(json.loads(manifest_bytes))}
        assert not {'truth', 'operational', 'expected_vulnerable'} & record.keys()
    assert results == ['development', 'official']
    first, second = (evaluate(tmp_path / kind, publish=False) for kind in ('development', 'official'))
    assert first['metrics'] == second['metrics']
    assert first['records'] == second['records']


def test_default_run_kind_smoke_rejection_and_legacy_interpretation(
        tmp_path, monkeypatch, capsys, op, settings):
    from benchmarks.scenario1 import runner
    monkeypatch.setattr(runner, 'reproducibility', lambda: {'offline': True})
    parsed = parser().parse_args(['run', '--dataset', 'unused', '--case', op.case_id,
        '--target', settings.target, '--context-path', settings.context_path,
        '--target-state', settings.target_state])
    assert parsed.run_kind == 'development'
    assert parser().parse_args(['run', '--dataset', 'unused', '--case', op.case_id,
        '--target', settings.target, '--context-path', settings.context_path,
        '--target-state', settings.target_state, '--run-kind', 'official']).run_kind == 'official'
    manifest = single_manifest(op, settings)
    destination = tmp_path / 'default'
    run(manifest, settings, destination, launcher=lambda *_: (-9, False))
    assert read_run_designation(destination).classification == 'development'
    record_bytes = (destination / RECORD_NAME).read_bytes()
    with pytest.raises(FileExistsError):
        write_run_classification(destination, 'official')
    assert (destination / RECORD_NAME).read_bytes() == record_bytes
    with pytest.raises(ValueError, match='already exists'):
        run(manifest, settings, destination, launcher=lambda *_: pytest.fail('worker launched'))
    assert (destination / RECORD_NAME).read_bytes() == record_bytes

    legacy = tmp_path / 'legacy'
    write_new(legacy / 'manifest.json', asdict(manifest))
    assert read_run_designation(legacy).classification == 'unknown'
    assert read_run_designation(legacy).declared is False
    smoke = tmp_path / 'smoke'
    from tests.benchmarks.test_scenario1 import make_dataset
    from benchmarks.scenario1.dataset import select
    smoke_manifest = select(make_dataset(tmp_path / 'dataset'), 'smoke-run', 'smoke')
    write_new(smoke / 'manifest.json', asdict(smoke_manifest))
    designation = read_run_designation(smoke)
    assert (designation.classification, designation.qualifier, designation.declared) == ('development', 'smoke', False)
    with pytest.raises(ValueError, match='smoke run cannot be official'):
        run(smoke_manifest, settings, tmp_path / 'rejected', run_kind='official',
            launcher=lambda *_: pytest.fail('worker launched'))
    assert not (tmp_path / 'rejected').exists()
    from benchmarks.scenario1.__main__ import main
    assert main(['run', '--dataset', str(tmp_path / 'dataset'), '--manifest', str(smoke / 'manifest.json'),
        '--target', settings.target, '--context-path', settings.context_path,
        '--target-state', settings.target_state, '--authorized-lab', '--run-kind', 'official',
        '--output', str(tmp_path / 'cli-rejected')]) == 2
    assert 'smoke run cannot be official' in capsys.readouterr().err
    assert not (tmp_path / 'cli-rejected').exists()
