"""Offline storage/publication regressions; all fixtures live under tmp_path."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
from threading import Barrier
import re

import pytest

from benchmarks.common.contracts import CaseExecution, digest, file_hash, read_json, write_new
from benchmarks.scenario1.core.evaluate import evaluate
from benchmarks.scenario1.core.runner import run
from benchmarks.scenario1.core.storage import (allocate_run, bind_storage, read_storage, resolve_run,
    storage_root)
from benchmarks.scenario1.reporting import writer
from benchmarks.scenario1.reporting.loader import load_report
from benchmarks.scenario1.reporting.projection import json_bytes
from tests.benchmarks.test_scenario1 import (ScriptedClient, execute_case, isolated_project_environment,
    mock_http, op, settings, single_manifest)
from tests.benchmarks.test_scenario1_reporting import _fixture
from tests.benchmarks.test_scenario1_reset import Controller


def frozen(tmp_path, op, settings):
    legacy, evaluation = _fixture(tmp_path, single_manifest(op, settings), classification='development')
    before = {p.relative_to(legacy): p.read_bytes() for p in legacy.rglob('*') if p.is_file()}
    public = tmp_path / 'artifacts/benchmarks/new-run'
    root = allocate_run(public)
    for ref, raw in before.items():
        target = root / 'evaluations' / ref if ref.name.startswith('evaluation-') else root / ref
        target.parent.mkdir(exist_ok=True, parents=True)
        target.write_bytes(raw)
    bind_storage(root, public)
    return root, public, legacy, evaluation, before


def html_payload(public):
    text = (public / 'index.html').read_text()
    match = re.search(r'<script type="application/json" id="report-data">(.*?)</script>', text)
    assert match is not None
    return json.loads(match.group(1))


def test_separated_public_tree_and_offline_roundtrip(tmp_path, op, settings):
    root, public, legacy, evaluation, before = frozen(tmp_path, op, settings)
    baseline = load_report(legacy)
    assert writer.write_report(root) == public
    assert {p.name for p in public.iterdir()} == {'index.html', 'report', 'results'}
    assert not (public / 'results/evidence').exists()
    assert not list(public.rglob('.kagent-report-*'))
    assert {'manifest.json', 'run-classification.json', 'storage.json', 'results', 'evaluations',
            'workspaces', 'publications', 'reset-evidence', 'events.jsonl'} <= {p.name for p in root.iterdir()}
    assert resolve_run(public) == resolve_run(root) == root
    assert resolve_run(legacy) == legacy
    assert load_report(public).cases == baseline.cases
    assert load_report(public).metrics == baseline.metrics
    assert {p.relative_to(legacy): p.read_bytes() for p in legacy.rglob('*') if p.is_file()} == before
    index = read_json(public / 'results/index.json')
    case = read_json(public / 'results' / f'{op.case_id}.json')
    assert case['schema'] == 'scenario1-public-case-v2'
    assert case['confusion'] == 'TP'
    assert case['case_id'] == op.case_id
    assert case['canonical']['result_sha256'] == file_hash(root / 'results' / f'{op.case_id}.json')
    assert case['projection_binding'] == digest({k: v for k, v in case.items() if k != 'projection_binding'})
    assert index['storage_id'] == root.name
    assert index['run_id'] == baseline.metadata['run_id']
    assert not Path(index['internal_ref']).is_absolute()
    for ref, hashed in index['files'].items():
        assert file_hash(public / ref) == hashed
    with pytest.raises(ValueError, match='already exists'):
        writer.write_report(root)
    # An additional export is explicit; it contains the same two namespaces.
    second = tmp_path / 'artifacts/benchmarks/explicit-second'
    writer.write_report(public, second)
    assert resolve_run(second) == root


def test_execution_ids_and_canonical_schema_are_independent(tmp_path, monkeypatch, op, settings):
    from benchmarks.scenario1.core import runner
    monkeypatch.setattr(runner, 'reproducibility', lambda: {'offline': True})
    seen = []
    def launcher(envelope, seconds):
        root = Path(envelope['output']).parents[1]
        assert read_storage(root)['run_id'] == 'run'
        assert 'truth' not in envelope and 'expected_vulnerable' not in str(envelope)
        assert Path(envelope['workspace']).parent == root / 'workspaces'
        assert not (tmp_path / 'artifacts/benchmarks/trial').exists()
        seen.append(envelope)
        return -9, False
    manifest = single_manifest(op, settings)
    public = tmp_path / 'artifacts/benchmarks/trial'
    roots = [run(manifest, settings, public, launcher=launcher) for _ in range(2)]
    assert roots[0].name != roots[1].name
    assert [read_storage(root)['run_id'] for root in roots] == ['run', 'run']
    assert len({item['workspace'] for item in seen}) == 2
    for root in roots:
        assert read_json(root / 'manifest.json')['run_id'] == 'run'
        assert (root / 'reset-policy.json').is_file()
        assert root.parent == storage_root() / 'runs'
        evaluate(root)
    assert evaluate(roots[0], publish=False)['records'] == evaluate(roots[1], publish=False)['records']
    writer.write_report(roots[0])
    with pytest.raises(ValueError, match='already exists'):
        writer.write_report(roots[1])


@pytest.mark.asyncio
async def test_public_selected_evidence_and_secrets(tmp_path, monkeypatch, op, settings, mock_http):
    workspace = tmp_path / 'fixture-workspace'
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    execution = await execute_case(op, settings, workspace, 'run', 'ex', ScriptedClient())
    secret = 'sk-' + 'S' * 40
    raw = asdict(execution)
    raw['runtime_metadata'].update(transcript=secret, provider_configuration={'api_key': secret},
                                   permission_journal=secret, workspace=str(workspace))
    def launcher(payload, _):
        raw['execution_id'] = payload['execution_id']
        raw['result']['execution_id'] = payload['execution_id']
        write_new(Path(payload['output']), raw)
        return 0, False
    public = tmp_path / 'public'
    root = run(single_manifest(op, settings), settings, public, launcher=launcher)
    canonical_bytes = (root / 'results' / f'{op.case_id}.json').read_bytes()
    baseline = evaluate(root, publish=False)
    report = evaluate(root)
    assert report['records'] == baseline['records'] and report['metrics'] == baseline['metrics']
    writer.write_report(root)
    case = read_json(public / 'results' / f'{op.case_id}.json')
    assert case['confusion'] == 'TP'
    assert case['selected_evidence']
    text = '\n'.join(p.read_text() for p in public.rglob('*') if p.is_file())
    assert secret not in text and str(workspace) not in text
    assert all(key not in text for key in ('"transcript":', '"permission_journal":', '"provider_configuration":', '"validation_results":'))
    for item in case['selected_evidence']:
        assert 'public_ref' not in item
        assert hashlib.sha256(item['content'].encode()).hexdigest() == item['public_sha256']
        parts = item['canonical_pointer'].split('/')
        source = raw['result']['workflow']['validation_results'][int(parts[4])]['evidence_manifest'][int(parts[6])]
        assert item['canonical_source_sha256'] == source['hash']
        assert item['canonical_body_sha256'] == hashlib.sha256(bytes.fromhex(source['source']['body'])).hexdigest()
    assert resolve_run(public) == root
    assert (root / 'results' / f'{op.case_id}.json').read_bytes() == canonical_bytes


def test_input_context_redaction(tmp_path, op, settings):
    op = replace(op, query=[['password', 'short'], ['q', 'bar']],
                 headers={'Authorization': 'secret-value'}, cookies={'session': 'cookie-secret'})
    root, public, *_ = frozen(tmp_path, op, settings)
    writer.write_report(root)
    case = read_json(public / 'results' / f'{op.case_id}.json')
    assert case['input']['query'][0] == ['password', '[REDACTED]']
    assert case['input']['headers']['Authorization'] == '[REDACTED]'
    assert case['input']['cookies']['session'] == '[REDACTED]'


@pytest.mark.parametrize('tamper', ['index', 'index-missing', 'canonical-missing', 'manifest',
                                  'storage', 'storage-missing', 'case', 'extra', 'rebound-case',
                                  'evaluation', 'classification', 'symlink'])
def test_resolver_fails_closed(tmp_path, op, settings, tamper):
    root, public, *_ = frozen(tmp_path, op, settings)
    writer.write_report(root)
    if tamper == 'index':
        (public / 'results/index.json').write_text('{}')
    elif tamper == 'index-missing':
        (public / 'results/index.json').unlink()
        # Even a planted legacy manifest must not override new report metadata.
        (public / 'manifest.json').write_bytes((root / 'manifest.json').read_bytes())
    elif tamper == 'canonical-missing':
        (root / 'manifest.json').unlink()
    elif tamper == 'manifest':
        (root / 'manifest.json').write_text('{}')
    elif tamper == 'storage':
        (root / 'storage.json').write_text('{}')
    elif tamper == 'storage-missing':
        (root / 'storage.json').unlink()
    elif tamper == 'classification':
        (root / 'run-classification.json').write_text('{}')
    elif tamper == 'symlink':
        (public / 'results/untrusted').symlink_to('missing')
    elif tamper == 'case':
        (public / 'results' / f'{op.case_id}.json').write_text('{}')
    elif tamper == 'extra':
        (public / 'events.jsonl').write_text('')
    elif tamper == 'evaluation':
        next((root / 'evaluations').iterdir()).unlink()
    else:
        path = public / 'results' / f'{op.case_id}.json'
        case = read_json(path)
        case['ground_truth']['expected_vulnerable'] = False
        case['projection_binding'] = digest({k: v for k, v in case.items() if k != 'projection_binding'})
        path.write_bytes(json_bytes(case))
        index = read_json(public / 'results/index.json')
        index['files'][f'results/{op.case_id}.json'] = file_hash(path)
        index['binding'] = digest({k: v for k, v in index.items() if k != 'binding'})
        (public / 'results/index.json').write_bytes(json_bytes(index))
    with pytest.raises((ValueError, OSError)):
        resolve_run(public)


@pytest.mark.parametrize('code', [errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP])
def test_wsl_backing_is_internal(tmp_path, monkeypatch, op, settings, code):
    root, public, *_ = frozen(tmp_path, op, settings)
    def unsupported(*_):
        ctypes.set_errno(code)
        return -1
    monkeypatch.setattr(writer, '_publisher', lambda: unsupported)
    writer.write_report(root)
    assert public.is_symlink()
    assert public.resolve().parent == root / 'publications'
    assert {p.name for p in public.iterdir()} == {'index.html', 'report', 'results'}
    assert resolve_run(public) == root
    assert len(list((root / 'publications').iterdir())) == 1


@pytest.mark.parametrize('fallback', [False, True])
@pytest.mark.parametrize('collision', ['directory', 'file', 'symlink'])
def test_concurrent_collision_keeps_other_owner(tmp_path, monkeypatch, op, settings, fallback, collision):
    root, public, *_ = frozen(tmp_path, op, settings)
    rename = writer._publisher()
    def collide(*args):
        if collision == 'directory':
            public.mkdir()
        elif collision == 'file':
            public.write_text('other-owner')
        else:
            public.symlink_to('absent')
        if fallback:
            ctypes.set_errno(errno.EOPNOTSUPP)
            return -1
        return rename(*args)
    monkeypatch.setattr(writer, '_publisher', lambda: collide)
    with pytest.raises(ValueError, match='already exists'):
        writer.write_report(root)
    assert not list((root / 'publications').iterdir())
    if collision == 'file':
        assert public.read_text() == 'other-owner'
    elif collision == 'symlink':
        assert public.readlink() == Path('absent')
    else:
        assert list(public.iterdir()) == []


@pytest.mark.parametrize('fallback', [False, True])
def test_two_concurrent_publications_have_one_owner(tmp_path, monkeypatch, op, settings, fallback):
    root, public, *_ = frozen(tmp_path, op, settings)
    barrier = Barrier(2)
    rename = writer._publisher()
    def race(*args):
        barrier.wait(timeout=10)
        if fallback:
            ctypes.set_errno(errno.EINVAL)
            return -1
        return rename(*args)
    monkeypatch.setattr(writer, '_publisher', lambda: race)
    def publish():
        try:
            return writer.write_report(root)
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        answers = list(executor.map(lambda _: publish(), range(2)))
    assert answers.count(public) == 1 and answers.count(None) == 1
    assert resolve_run(public) == root
    assert len(list((root / 'publications').iterdir())) == (1 if fallback else 0)


def test_interruption_after_wsl_link_preserves_backing(tmp_path, monkeypatch, op, settings):
    root, public, *_ = frozen(tmp_path, op, settings)
    def unsupported(*_):
        ctypes.set_errno(errno.EINVAL)
        return -1
    monkeypatch.setattr(writer, '_publisher', lambda: unsupported)
    symlink = os.symlink
    def interrupt(*args, **kwargs):
        symlink(*args, **kwargs)
        raise KeyboardInterrupt
    monkeypatch.setattr(writer.os, 'symlink', interrupt)
    with pytest.raises(KeyboardInterrupt):
        writer.write_report(root)
    assert resolve_run(public) == root
    assert len(list((root / 'publications').iterdir())) == 1


@pytest.mark.parametrize('phase', ['write', 'rename', 'symlink'])
def test_failed_publication_cleans_only_owned_stage(tmp_path, monkeypatch, op, settings, phase):
    root, public, *_ = frozen(tmp_path, op, settings)
    unrelated = root / 'publications/other-owner'
    unrelated.mkdir()
    (unrelated / 'keep').write_text('keep')
    def fail(*args, **kwargs):
        raise KeyboardInterrupt
    if phase == 'write':
        monkeypatch.setattr(writer, '_write_file', fail)
    elif phase == 'rename':
        monkeypatch.setattr(writer, '_publisher', lambda: fail)
    else:
        def unsupported(*_):
            ctypes.set_errno(errno.EOPNOTSUPP)
            return -1
        monkeypatch.setattr(writer, '_publisher', lambda: unsupported)
        monkeypatch.setattr(writer.os, 'symlink', fail)
    with pytest.raises(KeyboardInterrupt):
        writer.write_report(root)
    assert not public.exists()
    assert list((root / 'publications').iterdir()) == [unrelated]
    assert (unrelated / 'keep').read_text() == 'keep'


@pytest.mark.parametrize('blocked', [False, True])
def test_interrupted_and_blocked_forensics_and_resume(tmp_path, monkeypatch, op, settings, blocked):
    def interrupt(*_):
        raise KeyboardInterrupt
    public = tmp_path / 'public'
    with pytest.raises(KeyboardInterrupt):
        run(single_manifest(op, settings), settings, public, launcher=interrupt,
            reset_controller=Controller() if blocked else None)
    root = next((storage_root() / 'runs').iterdir())
    assert not public.exists()
    history = (root / 'events.jsonl').read_bytes()
    evaluation = evaluate(root)
    assert evaluation['incomplete'] and evaluation['records'][0]['partition'] == 'execution-failed'
    writer.write_report(root)
    assert html_payload(public)['metadata']['execution_state'] == ('blocked' if blocked else 'interrupted')
    assert load_report(public).metadata['incomplete'] is True
    # Resume resolves all layouts and always allocates a fresh execution.
    resumed = run(single_manifest(op, settings), settings, tmp_path / 'resumed',
                  launcher=lambda *_: (-9, False), resume_from=public)
    assert resumed != root
    assert read_json(resumed / 'manifest.json')['run_id'] == 'run'
    assert (root / 'events.jsonl').read_bytes().startswith(history)


def test_cross_filesystem_fails_without_publication(tmp_path, monkeypatch, op, settings):
    root, public, *_ = frozen(tmp_path, op, settings)
    fstat = os.fstat
    def other_device(fd):
        value = fstat(fd)
        if Path(os.readlink(f'/proc/self/fd/{fd}')) == public.parent:
            fields = list(value)
            fields[2] += 1
            return os.stat_result(fields)
        return value
    monkeypatch.setattr(writer.os, 'fstat', other_device)
    with pytest.raises(ValueError, match='cross-filesystem'):
        writer.write_report(root)
    assert not public.exists() and not list((root / 'publications').iterdir())


def test_blocked_after_all_finishes_is_not_complete(tmp_path, op, settings):
    control = Controller()
    def fail_idle():
        raise ValueError('offline idle failure')
    control.idle = fail_idle
    root = run(single_manifest(op, settings), settings, tmp_path / 'public',
               launcher=lambda *_: (-9, False), reset_controller=control)
    evaluation = evaluate(root)
    assert evaluation['incomplete'] is False  # preserve canonical v1 meaning
    public = writer.write_report(root)
    metadata = html_payload(public)['metadata']
    assert metadata['execution_state'] == 'blocked' and metadata['execution_complete'] is False


@pytest.mark.parametrize('substitution', ['stage', 'parent'])
def test_new_publication_rejects_substitution(tmp_path, monkeypatch, op, settings, substitution):
    root, public, *_ = frozen(tmp_path, op, settings)
    outside = tmp_path / 'other-owner'
    outside.mkdir()
    (outside / 'keep').write_text('keep')
    write = writer._write_file
    substituted = False
    def substitute(fd, name, contents):
        nonlocal substituted
        write(fd, name, contents)
        if not substituted:
            substituted = True
            if substitution == 'stage':
                path = Path(os.readlink(f'/proc/self/fd/{fd}'))
            else:
                path = public.parent
            path.rename(path.with_name('externally-moved'))
            path.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(writer, '_write_file', substitute)
    with pytest.raises(ValueError, match='changed'):
        writer.write_report(root)
    assert (outside / 'keep').read_text() == 'keep'
    assert list(outside.iterdir()) == [outside / 'keep']
    if substitution == 'stage':
        assert any(p.is_symlink() for p in (root / 'publications').iterdir())


def test_cli_selection_execution_evaluation_and_offline_report(tmp_path, monkeypatch, capsys):
    from benchmarks.scenario1.__main__ import main
    from benchmarks.scenario1.core import runner
    from benchmarks.scenario1.core import evaluate as evaluator
    from benchmarks.scenario1.reset import client
    from tests.benchmarks.test_scenario1 import make_dataset
    dataset = make_dataset(tmp_path / 'dataset')
    cid = dataset.truth[0].case_id
    assert main(['select', '--dataset', str(dataset.root), '--case', cid]) == 0
    selection = next((storage_root() / 'selections').iterdir())
    assert read_json(selection)['execution_order'] == [cid]
    real_run = runner.run
    monkeypatch.setattr(runner, 'reproducibility', lambda: {'offline': True})
    monkeypatch.setattr(client, 'ResetController', lambda _: Controller())
    def offline(*args, **kwargs):
        return real_run(*args, **kwargs, launcher=lambda *_: (-9, False))
    monkeypatch.setattr(runner, 'run', offline)
    public = tmp_path / 'artifacts/benchmarks/cli-run'
    reset_state = tmp_path / 'mocked-reset.json'
    write_new(reset_state, {})
    args = ['run', '--dataset', str(dataset.root), '--manifest', str(selection),
            '--target', 'http://127.0.0.1:3000', '--context-path', '/benchmark',
            '--authorized-lab', '--target-state', 'external-reset', '--reset-state', str(reset_state),
            '--output', str(public)]
    assert main(args) == 4
    root = resolve_run(public)
    assert main(['evaluate', '--run', str(public)]) == 4
    history = (root / 'events.jsonl').read_bytes()
    monkeypatch.setattr(evaluator, 'evaluate', lambda *_a, **_kw: pytest.fail('report ran evaluator'))
    second = tmp_path / 'artifacts/benchmarks/cli-offline'
    assert main(['report', '--run', str(root), '--output', str(second)]) == 0
    assert resolve_run(second) == root
    assert (root / 'events.jsonl').read_bytes() == history
    assert {p.name for p in second.iterdir()} == {'index.html', 'report', 'results'}


def test_execution_does_not_write_personal_or_original_artifacts(tmp_path, monkeypatch, op, settings):
    from benchmarks.scenario1.core import runner
    from src.paths import user_data_root
    monkeypatch.setattr(runner, 'reproducibility', lambda: {'offline': True})
    original = Path(__file__).resolve().parents[2] / 'artifacts'
    personal = user_data_root()
    def snapshot():
        return {str(base): {str(p.relative_to(base)): (p.lstat().st_size, p.lstat().st_mtime_ns)
                           for p in base.rglob('*')} if base.exists() else None
                for base in (original, personal)}
    before = snapshot()
    root = run(single_manifest(op, settings), settings, tmp_path / 'public', launcher=lambda *_: (-9, False))
    evaluate(root)
    writer.write_report(root)
    assert snapshot() == before


def test_invalid_canonical_result_keeps_safe_reason_and_no_confusion(tmp_path, monkeypatch, op, settings):
    from benchmarks.scenario1.core import runner
    monkeypatch.setattr(runner, 'reproducibility', lambda: {'offline': True})
    def launcher(payload, _):
        write_new(Path(payload['output']), asdict(CaseExecution(payload['run_id'], op.case_id,
            payload['execution_id'], 'completed', None, None, None, {})))
        return 0, False
    root = run(single_manifest(op, settings), settings, tmp_path / 'public', launcher=launcher)
    result = root / 'results' / f'{op.case_id}.json'
    # Preserve decodability but break the recorded byte hash. The evaluator's
    # existing invalid-result semantics must survive publication/resolution.
    result.write_bytes(result.read_bytes() + b'\n')
    before = result.read_bytes()
    evaluation = evaluate(root)
    public = writer.write_report(root)
    case = read_json(public / 'results' / f'{op.case_id}.json')
    assert evaluation['records'][0]['partition'] == case['evaluator_partition'] == 'invalid-result'
    assert case['evaluator_reason'] == 'result artifact hash mismatch'
    assert case['confusion'] is None and case['selected_evidence'] == []
    assert resolve_run(public) == root
    assert result.read_bytes() == before
