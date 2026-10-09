"""Two public modes, unchanged v1 selections, and offline historical readers."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, replace
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from benchmarks.common.contracts import (CLASSES, DEFAULT_SEED, RunManifest, decode,
                                        digest, file_hash, read_json, write_new)
from benchmarks.common.recorder import Recorder, read_records
from benchmarks.scenario1 import __main__ as cli
from benchmarks.scenario1.core import runner
from benchmarks.scenario1.core.classification import read_run_designation, write_run_classification
from benchmarks.scenario1.core.dataset import select
from benchmarks.scenario1.core.evaluate import evaluate
from benchmarks.scenario1.core.storage import resolve_run
from benchmarks.scenario1.reporting.loader import load_report
from tests.benchmarks.test_scenario1 import make_dataset, settings, isolated_project_environment
from tests.benchmarks.test_scenario1_cli_html import lab
from tests.benchmarks.test_scenario1_reset import Controller


@pytest.mark.parametrize('mode,wire_mode,quota,fingerprint', [
    ('smoke', 'smoke', 3, 'ce16a908f45ddb5e9f155a43b3e3f35895416d9d722896badc2e08da930a1690'),
    ('official', 'reduced', 10, '26a38aa124f09a2eb83b5b31496b96766a8ef21c673887af3d672aab242560ca'),
])
def test_public_selection_preserves_v1_rows_order_and_hashes(tmp_path, mode, wire_mode, quota, fingerprint):
    dataset = make_dataset(tmp_path / 'dataset')
    manifest = select(dataset, 'frozen', mode)
    assert manifest.mode == wire_mode and manifest.seed == DEFAULT_SEED == 1729
    assert manifest.selection_version == 'sha256-rank-v1'
    assert Counter((row['vulnerability_class'], row['expected_vulnerable']) for row in manifest.truth) == {
        (cls, vulnerable): quota for cls in CLASSES for vulnerable in (True, False)}
    assert len(manifest.execution_order) == 4 * quota
    # Golden values from the original v1 selector on this fixed 21-per-stratum fixture.
    assert digest([manifest.truth, manifest.operational, manifest.execution_order, manifest.seed,
                   manifest.mode, manifest.selection_version, manifest.dataset['artifacts']]) == fingerprint
    assert select(dataset, 'frozen', mode) == manifest
    assert select(dataset, 'frozen', wire_mode) == manifest
    assert select(dataset, 'frozen', mode, seed=91) == select(dataset, 'frozen', wire_mode, seed=91)
    assert decode(RunManifest, asdict(manifest)) == manifest
    dataset.verify(manifest)


@pytest.mark.parametrize('mode', [None, 'smoke', 'official'])
def test_cli_select_only_creates_balanced_12_or_40_case_manifests(tmp_path, monkeypatch, mode):
    dataset = make_dataset(tmp_path / 'dataset')
    monkeypatch.setattr(cli.uuid, 'uuid4', lambda: SimpleNamespace(hex='frozen'))
    output = tmp_path / 'selection.json'
    invocation = ['select', '--dataset', str(dataset.root), '--output', str(output)]
    if mode:
        invocation += ['--mode', mode]
    assert cli.main(invocation) == 0
    expected = select(dataset, 'frozen', 'reduced' if mode == 'official' else 'smoke')
    legacy_encoding = tmp_path / 'legacy-encoding.json'
    write_new(legacy_encoding, asdict(expected))
    assert output.read_bytes() == legacy_encoding.read_bytes()
    assert file_hash(output) == file_hash(legacy_encoding)
    dataset.verify(decode(RunManifest, read_json(output)))
    if mode is None:
        assert select(dataset, 'frozen') == expected


@pytest.mark.parametrize('invocation', [
    ['select', '--dataset', 'unused', '--mode', 'default'],
    ['select', '--dataset', 'unused', '--mode', 'reduced'],
    ['select', '--dataset', 'unused', '--case', 'BenchmarkTest00001'],
    ['run', '--mode', 'default'], ['run', '--mode', 'reduced'],
    ['run', '--mode', 'smoke', '--case', 'BenchmarkTest00001'],
    ['run', '--mode', 'smoke', '--run-kind', 'official'],
    ['run', '--mode', 'official', '--run-kind', 'development'],
    ['run', '--mode', 'smoke', '--run-k', 'official'],
    ['run', '--manifest', 'legacy-80.json'],
])
def test_removed_cli_paths_fail_before_selection_or_execution(monkeypatch, invocation):
    monkeypatch.setattr(cli, 'Dataset', lambda *_: pytest.fail('dataset loaded'))
    monkeypatch.setattr(cli, 'select', lambda *_: pytest.fail('selection created'))
    monkeypatch.setattr(runner, 'run', lambda *_a, **_kw: pytest.fail('execution reached'))
    with pytest.raises(SystemExit) as rejected:
        cli.main(invocation)
    assert rejected.value.code == 2


@pytest.mark.parametrize('command', ['select', 'run'])
def test_cli_help_exposes_only_two_modes(command, capsys):
    with pytest.raises(SystemExit) as result:
        cli.main([command, '--help'])
    assert result.value.code == 0
    help_text = capsys.readouterr().out
    assert '{smoke,official}' in help_text
    assert all(old not in help_text for old in ('reduced', '--case', '--run-kind', '80 case'))


@pytest.mark.parametrize('mode', ['smoke', 'official'])
@pytest.mark.parametrize('legacy_mode', ['default', 'single'])
def test_config_and_manifest_override_cannot_launch_legacy_selections(
        lab, monkeypatch, capsys, mode, legacy_mode):
    path, _ = lab
    dataset = make_dataset(path.parent / 'legacy-dataset')
    legacy = select(dataset, 'legacy', legacy_mode if legacy_mode == 'default' else 'smoke',
                    case_id=dataset.truth[0].case_id if legacy_mode == 'single' else None)
    selection = path.parent / 'legacy.json'
    write_new(selection, asdict(legacy))
    # Both the configured selection and an explicit manifest override hit the same gate.
    path.write_text(path.read_text().replace(f'{mode} = "{mode}.json"', f'{mode} = "legacy.json"'))
    monkeypatch.setattr(runner, 'run', lambda *_a, **_kw: pytest.fail('execution reached'))
    for extra in ([], ['--manifest', str(selection), '--resume-from', str(selection.parent)]):
        assert cli.main(['run', '--mode', mode, '--config', str(path), '--dataset', str(dataset.root),
                         '--authorized-lab', '--dry-run', *extra]) == 2
        assert f'{mode} mode requires the frozen' in capsys.readouterr().err
    assert not (path.parent / 'public').exists()


@pytest.mark.parametrize('section,key,value', [
    ('manifests', 'default', 'legacy.json'), ('manifests', 'reduced', 'legacy.json'),
    ('lab', 'mode', 'default'), ('lab', 'run_kind', 'official'),
])
def test_toml_cannot_override_modes_or_classification(lab, capsys, section, key, value):
    path, _ = lab
    path.write_text(path.read_text().replace(f'[{section}]', f'[{section}]\n{key} = "{value}"'))
    assert cli.main(['run', '--mode', 'smoke', '--config', str(path), '--authorized-lab', '--dry-run']) == 2
    assert f'invalid keys in Scenario 1 [{section}]' in capsys.readouterr().err
    assert not (path.parent / 'public').exists()


@pytest.mark.parametrize('mode,count,kind', [('smoke', 12, 'development'), ('official', 40, 'official')])
def test_cli_run_persists_mode_classification_and_unchanged_bindings(
        lab, monkeypatch, capsys, mode, count, kind):
    path, dataset = lab
    from benchmarks.scenario1.reset import client
    monkeypatch.setattr(client, 'ResetController', lambda _: Controller())
    monkeypatch.setattr(runner, 'reproducibility', lambda: {'offline': True})
    state = path.parent / 'reset-state.json'
    write_new(state, {})
    real_run = runner.run
    launches = []
    def launcher(payload, _):
        root = Path(payload['output']).parent.parent
        designation = read_run_designation(root)
        assert designation.classification == kind and designation.declared
        launches.append(payload['operational']['case_id'])
        return -9, False  # Offline execution failure, no worker or I/O.
    monkeypatch.setattr(runner, 'run', lambda *a, **kw: real_run(*a, **kw, launcher=launcher))
    public = path.parent / 'result'
    assert cli.main(['run', '--mode', mode, '--config', str(path), '--authorized-lab',
                     '--reset-state', str(state), '--output', str(public), '--progress', 'none']) == 4
    root = resolve_run(public)
    manifest = decode(RunManifest, read_json(root / 'manifest.json'))
    dataset.verify(manifest)
    assert launches == manifest.execution_order and len(launches) == count
    assert manifest.mode == ('reduced' if mode == 'official' else 'smoke')
    assert manifest.reproducibility['invocation']['effective_configuration']['run_kind'] == kind
    record = read_json(root / 'run-classification.json')
    assert record['manifest_sha256'] == file_hash(root / 'manifest.json')
    assert record['manifest_identity'] == digest(asdict(manifest))
    rows, _ = read_records(root / 'events.jsonl')
    assert all(row['data']['manifest_hash'] == record['manifest_identity']
               for row in rows if row['kind'] == 'scheduled')
    assert load_report(root).metadata['classification'] == kind
    assert json.loads(capsys.readouterr().out)['execution-failed'] == count


@pytest.mark.parametrize('mode', ['smoke', 'official'])
def test_dry_run_never_constructs_runtime_or_reset_controllers(lab, monkeypatch, capsys, mode):
    from src.agent.agent import Agent
    from src.llm.runtime import provider_runtime
    from benchmarks.scenario1.reset import client, operator_target
    path, _ = lab
    def forbidden(*_a, **_kw):
        pytest.fail('dry-run attempted runtime, provider, worker, reset or HTTP I/O')
    for owner, attribute in ((Agent, '__init__'), (Agent, 'run'), (runner, 'run'),
                             (runner, 'launch_worker'), (provider_runtime, 'build_startup_runtime'),
                             (httpx, 'AsyncClient'), (client, 'ResetController'),
                             (operator_target, 'OperatorResetController'), (operator_target, 'docker')):
        monkeypatch.setattr(owner, attribute, forbidden)
    before = {p: p.read_bytes() for p in path.parent.rglob('*') if p.is_file()}
    assert cli.main(['run', '--mode', mode, '--config', str(path), '--authorized-lab', '--dry-run']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['mode'] == mode
    assert result['run_classification'] == ('official' if mode == 'official' else 'development')
    assert {p: p.read_bytes() for p in path.parent.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('mode,count', [('default', 80), ('reduced', 40)])
@pytest.mark.parametrize('kind', [None, 'development', 'official'])
def test_historical_modes_and_run_kind_artifacts_verify_evaluate_and_report_unchanged(
        tmp_path, settings, mode, count, kind):
    dataset = make_dataset(tmp_path / 'dataset')
    manifest = replace(select(dataset, 'historical', mode), runtime=asdict(settings))
    root = tmp_path / 'history'
    write_new(root / 'manifest.json', asdict(manifest))
    if kind:
        write_run_classification(root, kind)  # Same record emitted by the former --run-kind CLI.
    recorder = Recorder(root / 'events.jsonl', manifest.run_id)
    operations = {row['case_id']: row for row in manifest.operational}
    for cid in manifest.execution_order:
        recorder.append('scheduled', cid, 'scheduled', data={
            'manifest_hash': digest(asdict(manifest)), 'operational_hash': digest(operations[cid])})
    frozen = {p: p.read_bytes() for p in root.iterdir() if p.is_file()}
    restored = decode(RunManifest, read_json(root / 'manifest.json'))
    assert restored == manifest
    dataset.verify(restored)
    evaluation = evaluate(root, publish=False)
    assert evaluation['metrics']['overall']['scheduled'] == count
    assert evaluation['metrics']['overall']['not-run'] == count
    write_new(root / f'evaluation-{evaluation["evaluation_identity"]}.json', evaluation)
    model = load_report(root)
    assert model.metadata['classification'] == (kind or 'unknown')
    assert model.metadata['manifest_identity'] == digest(asdict(manifest))
    assert cli.main(['report', '--run', str(root)]) == 0
    assert (root / 'report/report.json').is_file()
    assert (root / 'report/summary.csv').is_file()
    assert list((root / 'report/charts').glob('*.svg'))
    assert all(p.read_bytes() == contents for p, contents in frozen.items())
