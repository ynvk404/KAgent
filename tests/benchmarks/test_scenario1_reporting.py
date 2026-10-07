"""Offline Scenario 1 reporting contracts; no worker or target is used."""
from __future__ import annotations

from dataclasses import asdict, replace
import csv
import hashlib
from io import StringIO
import json
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

import pytest

from benchmarks.common.contracts import (CLASSES, PARTITIONS, CanonicalResultExport, CaseExecution, RuntimeMetrics,
    decode, digest, file_hash, RunManifest, RuntimeSettings, write_new)
from benchmarks.common.recorder import Recorder, read_records, validate_lifecycle
from benchmarks.scenario1.__main__ import main
from benchmarks.scenario1.classification import write_run_classification
from benchmarks.scenario1.reporting.aggregate import partition_rows, summary_rows
from benchmarks.scenario1.reporting.charts import render_charts
from benchmarks.scenario1.reporting.loader import load_report, presentation_id
from benchmarks.scenario1.reporting.tables import render_tables
from benchmarks.scenario1.reporting.thesis import (class_cases, format_decimal,
    render_thesis_tables, resource_summary)
from benchmarks.scenario1.reporting.thesis_charts import FIGURE_NAMES, render_thesis_charts
from benchmarks.scenario1.reporting.writer import write_report
from tests.benchmarks.test_scenario1 import op, settings, single_manifest


def settings_target(manifest):
    return (manifest.runtime or {}).get('target', 'http://127.0.0.1:3000')


def _group(records):
    counts = {part: sum(r['partition'] == part for r in records) for part in PARTITIONS}
    confusion = {label: sum(r['confusion'] == label for r in records) for label in ('TP', 'TN', 'FP', 'FN')}
    tp, tn, fp, fn = (confusion[k] for k in ('TP', 'TN', 'FP', 'FN'))
    ratio = lambda n, d: n / d if d else None
    return {'scheduled': len(records), 'started': len(records), 'completed': len(records),
            **counts, **confusion, 'recall': ratio(tp, tp + fn),
            'precision': ratio(tp, tp + fp), 'fpr': ratio(fp, fp + tn),
            'evaluability': ratio(counts['evaluable'], len(records))}


def _fixture(tmp_path, manifest, *, partitions=None, result=True, parent_status='completed',
             worker_status='completed', classification=None, legacy_dispatch=False):
    root = tmp_path / 'run'
    root.mkdir()
    write_new(root / 'manifest.json', asdict(manifest))
    if classification:
        write_run_classification(root, classification)
    recorder = Recorder(root / 'events.jsonl', manifest.run_id)
    truth = {row['case_id']: row for row in manifest.truth}
    records = []
    for index, cid in enumerate(manifest.execution_order):
        partition = (partitions or {}).get(cid, 'evaluable')
        if parent_status != 'completed' and partition != 'not-run':
            partition = 'execution-failed'
        vulnerable = truth[cid]['expected_vulnerable']
        confusion = ('TP' if vulnerable else 'TN') if partition == 'evaluable' else None
        records.append({'case_id': cid, 'partition': partition,
                        'reason': ('accepted-agent-assessment' if partition == 'evaluable' else
                                   'interrupted-before-start' if partition == 'not-run' else
                                   parent_status if partition == 'execution-failed' else 'insufficient-evidence'),
                        'confusion': confusion, 'schema_version': 1})
        operation = next(row for row in manifest.operational if row['case_id'] == cid)
        recorder.append('scheduled', cid, 'scheduled', data={
            'manifest_hash': digest(asdict(manifest)), 'operational_hash': digest(operation)})
    for index, cid in enumerate(manifest.execution_order):
        if records[index]['partition'] == 'not-run':
            continue
        eid = f'ex{index}'
        recorder.append('started', cid, 'started', execution_id=eid)
        if result:
            metrics = asdict(RuntimeMetrics(1.25, 0.1, 0.1, None,
                {'total_llm_calls': 2, 'tokens': {
                    'input_tokens': {'total': None, 'observed_sum': 12, 'complete': False},
                    'output_tokens': {'total': 7, 'observed_sum': 7, 'complete': True},
                    'total_tokens': {'total': None, 'observed_sum': 19, 'complete': False}}},
                {'proposed': 3, 'executed': 2, 'result_events': 2, 'blocked': 1, 'failed': 1}, 5, 2))
            if legacy_dispatch:
                del metrics['http_dispatch_attempts']
            # Focused projection fixture: decodable frozen export; no workflow rescoring.
            canonical = asdict(CanonicalResultExport(manifest.run_id, cid, eid, 'session', 'candidate',
                None, {'base_url': settings_target(manifest), 'origin': settings_target(manifest), 'revision': 0},
                'epoch', {}, 'result', 0, True, 'a' * 64)) if records[index]['partition'] == 'evaluable' else None
            write_new(root / 'results' / f'{cid}.json', asdict(CaseExecution(
                manifest.run_id, cid, eid, worker_status, None, canonical, metrics, {})))
        status = 'crashed' if records[index]['partition'] == 'execution-failed' and parent_status == 'completed' else parent_status
        if records[index]['partition'] == 'execution-failed':
            records[index]['reason'] = status
        path = root / 'results' / f'{cid}.json'
        recorder.append('runtime-finished', cid, status, execution_id=eid,
                        data={'wall_seconds': 2.5,
                              'result_ref': f'results/{cid}.json' if result else None,
                              'result_sha256': file_hash(path) if result else None,
                              'canonical_summary': {'outcome': 'confirmed' if truth[cid]['expected_vulnerable'] else 'not-confirmed'}})
    rows, partial = read_records(root / 'events.jsonl')
    identity = digest(['offline-agent-assessment-v1', asdict(manifest), rows, partial])
    for cid in manifest.execution_order:
        group = next(r for r in records if r['case_id'] == cid)
        history = [row for row in rows if row['case_id'] == cid]
        last = history[-1]
        recorder.append('evaluated', cid, last['status'], execution_id=last['execution_id'],
                        data={**group, 'evaluation_identity': identity})
    by_class = {cls: [r for r in records if truth[r['case_id']]['vulnerability_class'] == cls] for cls in CLASSES}
    evaluation = {'schema_version': 1, 'run_id': manifest.run_id, 'evaluation_identity': identity,
                  'evaluator_version': 'offline-agent-assessment-v1', 'records': records,
                  'partial_tail_ignored': False, 'incomplete': any(r['partition'] == 'not-run' for r in records),
                  'metrics': {'overall': _group(records),
                              'classes': {cls: _group(by_class[cls]) for cls in CLASSES}}}
    histories = validate_lifecycle(rows)
    for group, ids in [(evaluation['metrics']['overall'], manifest.execution_order),
                       *[(evaluation['metrics']['classes'][cls], [r['case_id'] for r in by_class[cls]]) for cls in CLASSES]]:
        group['started'] = sum(any(e['kind'] == 'started' for e in histories[cid]) for cid in ids)
        group['completed'] = sum(any(e['kind'] == 'runtime-finished' and e['status'] == 'completed' for e in histories[cid]) for cid in ids)
    write_new(root / f'evaluation-{identity}.json', evaluation)
    return root, evaluation


def _csv(contents: bytes):
    return list(csv.DictReader(StringIO(contents.decode())))


def test_single_case_parent_status_counters_tokens_and_na(tmp_path, op, settings):
    root, evaluation = _fixture(tmp_path, single_manifest(op, settings), parent_status='crashed',
                                legacy_dispatch=True)
    model = load_report(root)
    case = model.cases[0]
    assert case['final_status'] == 'crashed' and case['worker_status'] == 'completed'
    assert case['http_admitted'] == 5 and case['http_dispatch_attempts'] is None
    assert (case['input_tokens'], case['input_tokens_complete']) == (None, False)
    assert (case['output_tokens'], case['output_tokens_complete']) == (7, True)
    assert (case['total_tokens'], case['total_tokens_complete']) == (None, False)
    assert [case[k] for k in ('tool_proposed', 'tool_executed', 'tool_result_events',
                              'tool_blocked', 'tool_failed')] == [3, 2, 2, 1, 1]
    assert 'tool_calls' not in case
    assert all(model.metrics['overall'][key] == evaluation['metrics']['overall'][key]
               for key in model.metrics['overall'])
    row = _csv(render_tables(model)['per-case.csv'])[0]
    assert row['input_tokens'] == row['total_tokens'] == row['http_dispatch_attempts'] == ''
    assert row['output_tokens'] == '7'
    absent = model.metrics['classes'][CLASSES[0]]
    assert absent['recall'] is None
    assert summary_rows(model)[1]['recall_denominator'] == 0
    assert 'NA (0/0)' in render_charts(model)['charts/class-metrics.svg'].decode()


def test_transport_dispatch_is_distinct_from_admission(tmp_path, op, settings):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    case = load_report(root).cases[0]
    assert (case['http_admitted'], case['http_dispatch_attempts']) == (5, 2)
    row = _csv(render_tables(load_report(root))['per-case.csv'])[0]
    assert (row['http_admitted'], row['http_dispatch_attempts']) == ('5', '2')


def test_invalid_result_can_have_unreadable_diagnostic_export(tmp_path, op, settings):
    root, _ = _fixture(tmp_path, single_manifest(op, settings),
                       partitions={op.case_id: 'invalid-result'})
    (root / 'results' / f'{op.case_id}.json').write_text('{invalid')
    case = load_report(root).cases[0]
    assert case['evaluator_partition'] == 'invalid-result'
    assert case['worker_status'] is None and case['http_dispatch_attempts'] is None
    assert case['confusion'] is None


def test_missing_result_not_run_and_strict_case_set(tmp_path, op, settings):
    manifest = single_manifest(op, settings)
    root, evaluation = _fixture(tmp_path, manifest, partitions={op.case_id: 'not-run'}, result=False)
    case = load_report(root).cases[0]
    assert case['final_status'] is None and case['worker_status'] is None
    assert case['agent_seconds'] is None and case['http_admitted'] is None
    path = next(root.glob('evaluation-*.json'))
    for change, match in [('missing', 'case set'), ('duplicate', 'duplicate evaluation'),
                          ('unknown', 'case set')]:
        altered = json.loads(json.dumps(evaluation))
        if change == 'missing':
            altered['records'] = []
        elif change == 'duplicate':
            altered['records'].append(altered['records'][0])
        else:
            altered['records'][0]['case_id'] = 'unknown-case'
        path.write_text(json.dumps(altered))
        with pytest.raises(ValueError, match=match):
            load_report(root)
    path.write_text(json.dumps(evaluation))
    evaluation['run_id'] = 'another-run'
    path.write_text(json.dumps(evaluation))
    with pytest.raises(ValueError, match='evaluation/run'):
        load_report(root)


def test_multiple_evaluations_and_missing_artifacts(tmp_path, monkeypatch, op, settings):
    root, evaluation = _fixture(tmp_path, single_manifest(op, settings))
    second = root / f"evaluation-{'a' * 64}.json"
    second.write_text(json.dumps({**evaluation, 'evaluation_identity': 'a' * 64}))
    with pytest.raises(ValueError, match='multiple evaluation'):
        load_report(root)
    first = next(path for path in root.glob('evaluation-*.json') if path != second)
    assert load_report(root, first).metadata['evaluation_identity'] == evaluation['evaluation_identity']
    assert load_report(root, first.relative_to(root)).metadata['evaluation_identity'] == evaluation['evaluation_identity']
    with pytest.raises(ValueError, match='identity/content'):
        load_report(root, second)
    monkeypatch.chdir(tmp_path)
    assert load_report(root, first.relative_to(tmp_path)).metadata['evaluation_identity'] == evaluation['evaluation_identity']
    second.unlink()
    (root / 'events.jsonl').unlink()
    with pytest.raises(ValueError, match='lifecycle'):
        load_report(root)
    (root / 'manifest.json').unlink()
    with pytest.raises(FileNotFoundError):
        load_report(root)


@pytest.mark.parametrize('kind,expected', [
    (None, ('unknown', None, False)),
    ('development', ('development', None, True)),
    ('official', ('official', None, True)),
])
def test_classification_compatibility_and_binding(tmp_path, op, settings, kind, expected):
    root, _ = _fixture(tmp_path, single_manifest(op, settings), classification=kind)
    metadata = load_report(root).metadata
    assert (metadata['classification'], metadata['classification_qualifier'],
            metadata['classification_declared']) == expected
    if kind:
        path = root / 'run-classification.json'
        record = json.loads(path.read_text())
        for key in ('manifest_sha256', 'manifest_identity', 'run_id'):
            modified = {**record, key: '0' * 64 if key != 'run_id' else 'other-run'}
            path.write_text(json.dumps(modified))
            with pytest.raises(ValueError, match='binding mismatch'):
                load_report(root)
        path.write_text(json.dumps(record))


def test_smoke_legacy_and_dynamic_multi_case(tmp_path):
    from benchmarks.scenario1.dataset import select
    from tests.benchmarks.test_scenario1 import make_dataset
    manifest = replace(select(make_dataset(tmp_path / 'dataset'), 'smoke-run', 'smoke'),
                       runtime=asdict(RuntimeSettings('http://127.0.0.1:3000', '/benchmark', True, 'confirmation-only')))
    partitions = {cid: ('unresolved', 'execution-failed', 'invalid-result', 'not-run')[index % 4]
                  for index, cid in enumerate(manifest.execution_order)}
    root, evaluation = _fixture(tmp_path, manifest, partitions=partitions)
    model = load_report(root)
    assert len(model.cases) == len(manifest.execution_order)
    assert [case['case_id'] for case in model.cases] == [presentation_id('case', cid) for cid in manifest.execution_order]
    assert (model.metadata['classification'], model.metadata['classification_qualifier'],
            model.metadata['classification_declared']) == ('development', 'smoke', False)
    assert all(model.metrics['overall'][key] == evaluation['metrics']['overall'][key]
               for key in model.metrics['overall'])
    for row in partition_rows(model)[1:]:
        assert sum(row[part.replace('-', '_')] for part in PARTITIONS) == row['scheduled']
    svg = render_charts(model)
    for contents in svg.values():
        ET.fromstring(contents)
    assert b'<text' in svg['charts/confusion-matrix.svg']
    assert all(case['confusion'] is None for case in model.cases)


def test_privacy_determinism_immutability_and_cli(tmp_path, op, settings, capsys):
    root, _ = _fixture(tmp_path, single_manifest(op, settings), partitions={op.case_id: 'invalid-result'})
    evaluation_path = next(root.glob('evaluation-*.json'))
    data = json.loads(evaluation_path.read_text())
    data['records'][0]['reason'] = 'fixture-secret'
    evaluation_path.write_text(json.dumps(data))
    events = root / 'events.jsonl'
    rows = [json.loads(line) for line in events.read_text().splitlines()]
    finish = next(row for row in rows if row['kind'] == 'runtime-finished')
    finish['data']['runtime_metadata'] = {'provider': 'provider-secret',
                                          'model': 'model-credential'}
    evaluated = next(row for row in rows if row['kind'] == 'evaluated')
    evaluated['data']['reason'] = data['records'][0]['reason']
    events.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    _rebind(root)
    inputs = {p.relative_to(root): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in root.rglob('*') if p.is_file()}
    first = write_report(root)
    output = {p.relative_to(first): p.read_bytes() for p in first.rglob('*') if p.is_file()}
    assert {str(path) for path in output} >= {'report.json', 'summary.csv', 'partitions.csv', 'per-case.csv',
                           'charts/confusion-matrix.svg', 'charts/class-metrics.svg',
                           'charts/evaluation-partitions.svg', 'charts/processing-time.svg',
                           'charts/total-tokens.svg'}
    for value in (settings.target, 'fixture-secret', 'provider-secret',
                  'model-credential', 'bar', 'SafeText'):
        assert all(value.encode() not in contents for contents in output.values())
    assert {p.relative_to(root): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file() and p.relative_to(root) in inputs} == inputs
    with pytest.raises(ValueError, match='already exists'):
        write_report(root)
    second = write_report(root, root / 'report-again')
    assert output == {p.relative_to(second): p.read_bytes() for p in second.rglob('*') if p.is_file()}
    assert main(['report', '--run', str(root), '--output', str(root / 'report-cli')]) == 0
    assert capsys.readouterr().out == 'Benchmark report exported.\n'
    assert output == {p.relative_to(root / 'report-cli'): p.read_bytes()
                      for p in (root / 'report-cli').rglob('*') if p.is_file()}


def _save_rows(root, rows):
    (root / 'events.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))


def _rebind(root):
    """Rebuild v1 binding for deliberate valid projection-fixture changes."""
    old = next(root.glob('evaluation-*.json'))
    evaluation = json.loads(old.read_text())
    manifest = decode(RunManifest, json.loads((root / 'manifest.json').read_text()))
    rows, partial = read_records(root / 'events.jsonl')
    operations = {op['case_id']: op for op in manifest.operational}
    for row in rows:
        if row['kind'] == 'scheduled':
            row['data'].update(manifest_hash=digest(asdict(manifest)),
                               operational_hash=digest(operations[row['case_id']]))
    identity = digest(['offline-agent-assessment-v1', asdict(manifest),
                       [row for row in rows if row['kind'] != 'evaluated'], partial])
    evaluation['evaluation_identity'] = identity
    for row in rows:
        if row['kind'] == 'evaluated':
            row['data']['evaluation_identity'] = identity
    _save_rows(root, rows)
    old.unlink()
    write_new(root / f'evaluation-{identity}.json', evaluation)
    return evaluation


def _evaluated_run(tmp_path, op, settings, *, status='completed', started=True,
                   finish=True, result=True, torn=False, partial=False, publish=True):
    """Evaluator-generated integration artifacts, with no Agent/provider/target."""
    from tests.benchmarks.test_scenario1 import schedule_run, diagnostic_execution
    from benchmarks.scenario1.evaluate import evaluate
    root = tmp_path / 'run'
    recorder = schedule_run(root, single_manifest(op, settings))
    if started:
        recorder.append('started', op.case_id, 'started', execution_id='ex')
    path = root / 'results' / f'{op.case_id}.json'
    if result:
        write_new(path, asdict(diagnostic_execution(op)))
        if torn:
            path.write_bytes(b'{invalid')
    if finish:
        recorder.append('runtime-finished', op.case_id, status, execution_id='ex', data={
            'result_ref': f'results/{op.case_id}.json' if result else None,
            'result_sha256': file_hash(path) if result else None})
    if partial:
        with (root / 'events.jsonl').open('ab') as stream:
            stream.write(b'{"partial":')
    evaluation = evaluate(root, publish=publish)
    if not publish:
        write_new(root / f"evaluation-{evaluation['evaluation_identity']}.json", evaluation)
    return root, evaluation


@pytest.mark.parametrize('status,started,finish,result,torn,partial,partition', [
    ('completed', True, True, True, False, False, 'unresolved'),
    ('crashed', True, True, True, False, False, 'execution-failed'),
    ('timeout', True, True, False, False, False, 'execution-failed'),
    ('completed', True, True, True, True, False, 'invalid-result'),
    ('completed', True, True, False, False, False, 'invalid-result'),
    ('completed', True, False, True, False, False, 'execution-failed'),
    ('completed', True, False, True, True, True, 'execution-failed'),
    ('completed', True, False, False, False, True, 'execution-failed'),
    ('completed', False, False, False, False, False, 'not-run'),
])
def test_evaluator_generated_integration_and_v1_identity(
        tmp_path, op, settings, status, started, finish, result, torn, partial, partition):
    root, evaluation = _evaluated_run(tmp_path, op, settings, status=status, started=started,
        finish=finish, result=result, torn=torn, partial=partial)
    manifest = decode(RunManifest, json.loads((root / 'manifest.json').read_text()))
    rows, tail = read_records(root / 'events.jsonl')
    original_input = ['offline-agent-assessment-v1', asdict(manifest),
                      [e for e in rows if e['kind'] != 'evaluated'], tail]
    if evaluation.get('orphan_exports'):
        original_input.append(evaluation['orphan_exports'])
    assert digest(original_input) == evaluation['evaluation_identity']
    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    model = load_report(root)
    assert model.cases[0]['evaluator_partition'] == partition
    assert model.metadata['partial_tail_ignored'] is partial
    assert model.metadata['incomplete'] is (partial or not finish)
    if not finish:
        assert model.cases[0]['final_status'] is model.cases[0]['worker_status'] is None
        assert model.cases[0]['agent_seconds'] is None
    write_report(root)
    assert all((root / name).read_bytes() == contents for name, contents in before.items())


@pytest.mark.parametrize('change', ['manifest', 'parent-status', 'missing-finish', 'parent-data',
                                   'partial-tail', 'scheduled-manifest', 'scheduled-operational'])
def test_stale_evaluation_and_scheduled_bindings_fail(tmp_path, op, settings, change):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    rows, _ = read_records(root / 'events.jsonl')
    if change == 'manifest':
        manifest = json.loads((root / 'manifest.json').read_text())
        manifest['seed'] += 1
        (root / 'manifest.json').write_text(json.dumps(manifest))
    elif change == 'partial-tail':
        with (root / 'events.jsonl').open('ab') as stream:
            stream.write(b'{unfinished')
    else:
        finish = next(e for e in rows if e['kind'] == 'runtime-finished')
        if change == 'parent-status':
            finish['status'] = 'crashed'
        elif change == 'missing-finish':
            rows.remove(finish)
            for index, row in enumerate(rows):
                row['sequence'] = index + 1
        elif change == 'parent-data':
            finish['data']['wall_seconds'] = 123
        else:
            key = 'manifest_hash' if change == 'scheduled-manifest' else 'operational_hash'
            rows[0]['data'][key] = '0' * 64
        _save_rows(root, rows)
    with pytest.raises(ValueError):
        load_report(root)
    assert not (root / 'report').exists()


@pytest.mark.parametrize('change', ['identity', 'partition', 'reason', 'confusion', 'schema_version'])
def test_recorded_evaluation_conflicts_fail(tmp_path, op, settings, change):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    rows, _ = read_records(root / 'events.jsonl')
    evaluated = next(e for e in rows if e['kind'] == 'evaluated')
    key = 'evaluation_identity' if change == 'identity' else change
    evaluated['data'][key] = {'identity': 'b' * 64, 'partition': 'unresolved',
        'reason': 'blocked', 'confusion': 'FN', 'schema_version': 99}[change]
    _save_rows(root, rows)
    with pytest.raises(ValueError, match='conflicting'):
        load_report(root)


def test_fail_fast_exception_and_multiple_valid_evaluations(tmp_path, op, settings, monkeypatch):
    root, evaluation = _evaluated_run(tmp_path, op, settings, started=False, finish=False,
                                     result=False, publish=False)
    recorder = Recorder(root / 'events.jsonl', 'run')
    recorder.append('evaluated', op.case_id, 'not-run', data={
        'partition': 'not-run', 'reason': 'fail-fast', 'evaluation_identity': 'fail-fast-v1'})
    from benchmarks.scenario1.evaluate import evaluate
    # Non-evaluated rows are unchanged: fail-fast reason can legitimately replace
    # the read-only interruption reason, but the old evaluation must be rejected.
    with pytest.raises(ValueError, match='interruption mismatch'):
        load_report(root)
    old = next(root.glob('evaluation-*.json'))
    old.unlink()
    updated = evaluate(root)
    assert updated['evaluation_identity'] == evaluation['evaluation_identity']
    assert load_report(root).cases[0]['evaluator_reason'] == 'fail-fast'
    rows, _ = read_records(root / 'events.jsonl')
    _save_rows(root, rows)
    with (root / 'events.jsonl').open('ab') as stream:
        stream.write(b'{partial')
    new = evaluate(root)
    assert new['evaluation_identity'] != updated['evaluation_identity']
    with pytest.raises(ValueError, match='multiple'):
        load_report(root)
    selected = root / f"evaluation-{new['evaluation_identity']}.json"
    assert load_report(root, selected).metadata['partial_tail_ignored']
    monkeypatch.chdir(tmp_path)
    assert load_report(root, selected.relative_to(tmp_path)).metadata['partial_tail_ignored']
    with pytest.raises(ValueError, match='identity/content'):
        load_report(root, old)


@pytest.mark.parametrize('change', ['unknown', 'duplicate', 'reference', 'run_id', 'case_id',
                                   'execution_id', 'canonical-run', 'missing', 'hash', 'symlink'])
def test_result_inventory_and_bindings(tmp_path, op, settings, change):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    path = root / 'results' / f'{op.case_id}.json'
    if change in {'unknown', 'duplicate'}:
        write_new(root / 'results' / f'{change}.json', json.loads(path.read_text()))
    elif change == 'reference':
        rows, _ = read_records(root / 'events.jsonl')
        next(e for e in rows if e['kind'] == 'runtime-finished')['data']['result_ref'] = 'results/other.json'
        _save_rows(root, rows)
    elif change in {'missing', 'symlink'}:
        raw = path.read_bytes()
        path.unlink()
        if change == 'symlink':
            outside = tmp_path / 'outside.json'
            outside.write_bytes(raw)
            path.symlink_to(outside)
    elif change == 'hash':
        path.write_bytes(path.read_bytes() + b'\n')
    else:
        raw = json.loads(path.read_text())
        if change == 'canonical-run':
            raw['result']['run_id'] = 'other'
        else:
            raw[change] = 'other'
        path.write_text(json.dumps(raw))
    with pytest.raises(ValueError):
        load_report(root)


@pytest.mark.parametrize('partition', ['invalid-result', 'execution-failed'])
@pytest.mark.parametrize('change', ['missing', 'bad-json', 'nonutf8', 'hash', 'run_id', 'execution_id'])
def test_diagnostics_na_does_not_mask_binding_conflicts(tmp_path, op, settings, partition, change):
    root, _ = _fixture(tmp_path, single_manifest(op, settings), partitions={op.case_id: partition})
    path = root / 'results' / f'{op.case_id}.json'
    if change == 'missing':
        path.unlink()
    elif change == 'bad-json':
        path.write_bytes(b'{bad')
    elif change == 'nonutf8':
        path.write_bytes(b'\xff')
    elif change == 'hash':
        path.write_bytes(path.read_bytes() + b'\n')
    else:
        raw = json.loads(path.read_text())
        raw[change] = 'other'
        path.write_text(json.dumps(raw))
    if change in {'run_id', 'execution_id'}:
        with pytest.raises(ValueError, match='identity mismatch'):
            load_report(root)
    else:
        case = load_report(root).cases[0]
        assert case['worker_status'] is case['agent_seconds'] is case['total_tokens'] is None


@pytest.mark.parametrize('torn', [False, True])
@pytest.mark.parametrize('change', ['content', 'binding', 'remove', 'unlisted'])
def test_orphan_bindings_reject_changes(tmp_path, op, settings, torn, change):
    root, evaluation = _evaluated_run(tmp_path, op, settings, finish=False, torn=torn)
    path = root / 'results' / f'{op.case_id}.json'
    if change == 'content':
        path.write_bytes(path.read_bytes() + b'\n')
    elif change == 'remove':
        path.unlink()
    elif change == 'binding':
        evaluation['orphan_exports'][0]['result_sha256'] = '0' * 64
        next(root.glob('evaluation-*.json')).write_text(json.dumps(evaluation))
    else:
        write_new(root / 'results/unknown.json', {})
    with pytest.raises(ValueError):
        load_report(root)


@pytest.mark.parametrize('change', ['matrix-swap', 'overall', 'class', 'partition', 'started',
                                   'completed', 'rate', 'zero-denominator', 'truth', 'outcome'])
def test_metrics_and_record_invariants(tmp_path, op, settings, change):
    root, evaluation = _fixture(tmp_path, single_manifest(op, settings))
    path = next(root.glob('evaluation-*.json'))
    overall = evaluation['metrics']['overall']
    if change == 'matrix-swap':
        for group in (overall, evaluation['metrics']['classes'][op.vulnerability_class]):
            group['TP'], group['FN'] = group['FN'], group['TP']
            group['recall'] = 0
            group['precision'] = None
    elif change == 'overall':
        overall['TP'] += 1
    elif change == 'class':
        evaluation['metrics']['classes'][op.vulnerability_class]['FN'] += 1
    elif change in {'partition', 'started', 'completed'}:
        key = 'unresolved' if change == 'partition' else change
        overall[key] += 1
    elif change == 'rate':
        overall['recall'] = .5
    elif change == 'zero-denominator':
        overall['fpr'] = 0
    elif change == 'truth':
        evaluation['records'][0]['confusion'] = 'TN'
    else:
        rows, _ = read_records(root / 'events.jsonl')
        next(e for e in rows if e['kind'] == 'runtime-finished')['data']['canonical_summary']['outcome'] = 'not-confirmed'
        _save_rows(root, rows)
    path.write_text(json.dumps(evaluation))
    with pytest.raises(ValueError):
        load_report(root)


def test_missing_outcome_is_not_inferred(tmp_path, op, settings):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    rows, _ = read_records(root / 'events.jsonl')
    del next(e for e in rows if e['kind'] == 'runtime-finished')['data']['canonical_summary']
    _save_rows(root, rows)
    _rebind(root)
    case = load_report(root).cases[0]
    assert case['agent_outcome'] is None and case['confusion'] == 'TP'


@pytest.mark.parametrize('field,bad,missing', [
    ('llm', [1], ('llm_calls', 'input_tokens', 'output_tokens', 'total_tokens')),
    ('llm', 'opaque', ('llm_calls', 'total_tokens')),
    ('tools', [1], ('tool_proposed', 'tool_executed', 'tool_failed')),
    ('tokens', [1], ('input_tokens', 'output_tokens', 'total_tokens')),
    ('input_tokens', [1], ('input_tokens', 'input_tokens_complete')),
    ('output_tokens', {'complete': 'true', 'total': 7}, ('output_tokens', 'output_tokens_complete')),
    ('total_tokens', {'complete': False, 'total': 19, 'observed_sum': 19}, ('total_tokens',)),
])
def test_malformed_nested_diagnostics_become_na(tmp_path, op, settings, field, bad, missing, capsys):
    root, _ = _fixture(tmp_path, single_manifest(op, settings), partitions={op.case_id: 'invalid-result'})
    path = root / 'results' / f'{op.case_id}.json'
    raw = json.loads(path.read_text())
    if field in {'llm', 'tools'}:
        raw['metrics'][field] = bad
    elif field == 'tokens':
        raw['metrics']['llm'][field] = bad
    else:
        raw['metrics']['llm']['tokens'][field] = bad
    path.write_text(json.dumps(raw))
    rows, _ = read_records(root / 'events.jsonl')
    next(e for e in rows if e['kind'] == 'runtime-finished')['data']['result_sha256'] = file_hash(path)
    _save_rows(root, rows)
    _rebind(root)
    case = load_report(root).cases[0]
    assert all(case[key] is None for key in missing)
    if field != 'tools':
        assert case['tool_proposed'] == 3
    assert main(['report', '--run', str(root)]) == 0
    assert 'Traceback' not in capsys.readouterr().err


def test_opaque_credentials_fixture_aliases_and_metadata_projection(tmp_path, op, settings):
    secret = 'Orbit987654321'
    operation = replace(op, case_id='sk-' + secret, headers={'X-Api-Key': secret})
    manifest = replace(single_manifest(operation, settings), run_id='sk-' + secret,
        dataset={'version': secret, 'git_commit': secret, 'artifacts': {'truth.csv': 'a' * 64}},
        reproducibility={'kagent_commit': secret, 'python': secret, 'capability_profile': secret,
                         'arbitrary': {'password': secret}})
    root, evaluation = _fixture(tmp_path, manifest, partitions={operation.case_id: 'invalid-result'})
    path = next(root.glob('evaluation-*.json'))
    evaluation['records'][0]['reason'] = secret
    path.write_text(json.dumps(evaluation))
    rows, _ = read_records(root / 'events.jsonl')
    finish = next(e for e in rows if e['kind'] == 'runtime-finished')
    finish['data']['runtime_metadata'] = {'provider': secret, 'model': 'sk-' + secret,
                                          'raw_message': secret, 'base_url': settings.target}
    next(e for e in rows if e['kind'] == 'evaluated')['data']['reason'] = secret
    _save_rows(root, rows)
    _rebind(root)
    destination = write_report(root)
    contents = [p.read_bytes() for p in destination.rglob('*') if p.is_file()]
    for forbidden in (secret, settings.target, 'X-Api-Key', 'raw_message', 'base_url'):
        assert all(forbidden.encode() not in content for content in contents)
    model = load_report(root)
    assert model.cases[0]['case_id'] == presentation_id('case', operation.case_id)
    assert model.metadata['run_id'] == presentation_id('run', manifest.run_id)
    assert model.metadata['dataset']['version'] is None
    assert model.metadata['provider_models'] == [{'provider': presentation_id('provider', secret),
                                                'model': presentation_id('model', 'sk-' + secret)}]
    assert model.metadata['evaluation_identity'] == _rebind(root)['evaluation_identity']


def test_semantic_metadata_positive_and_fixture_alias_filter(tmp_path, op, settings):
    manifest = replace(single_manifest(op, settings),
        dataset={'version': '1.2', 'git_commit': 'c' * 40, 'dirty': False, 'artifacts': {'truth.csv': 'a' * 64}},
        reproducibility={'kagent_commit': 'd' * 40, 'kagent_dirty': True, 'python': '3.11.9',
                         'capability_profile': 'scenario1-native-http-confirmation-v1'})
    root, _ = _fixture(tmp_path, manifest)
    metadata = load_report(root).metadata
    assert metadata['dataset'] == {'version': '1.2', 'git_commit': presentation_id('commit', 'c' * 40), 'dirty': False}
    assert metadata['reproducibility']['python'] == '3.11.9'
    raw = json.loads((root / 'manifest.json').read_text())
    raw['operational'][0]['headers']['X-Api-Key'] = '1.2'
    (root / 'manifest.json').write_text(json.dumps(raw))
    _rebind(root)
    assert load_report(root).metadata['dataset']['version'] is None


@pytest.mark.parametrize('bad', ['http://[alice:Orbit987654321]', 'http://alice:Orbit987654321@host',
                               'http://host:Orbit987654321'])
def test_cli_malformed_urls_are_sanitized(tmp_path, op, settings, bad, capsys):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    manifest = json.loads((root / 'manifest.json').read_text())
    manifest['runtime']['target'] = bad
    (root / 'manifest.json').write_text(json.dumps(manifest))
    assert main(['report', '--run', str(root)]) == 2
    captured = capsys.readouterr()
    assert 'benchmark report error:' in captured.err
    assert 'Orbit987654321' not in captured.err + captured.out
    assert 'Traceback' not in captured.err
    assert not (root / 'report').exists()


@pytest.mark.parametrize('error', [ValueError, OSError, TypeError, KeyError, UnicodeError])
def test_cli_never_echoes_input_errors(tmp_path, monkeypatch, error, capsys):
    import benchmarks.scenario1.reporting as reporting
    def fail(*args):
        raise error('http://alice:Orbit987654321@secret/path')
    monkeypatch.setattr(reporting, 'write_report', fail)
    assert main(['report', '--run', str(tmp_path / 'Orbit987654321')]) == 2
    captured = capsys.readouterr()
    assert 'Orbit987654321' not in captured.err + captured.out


@pytest.mark.parametrize('reserved', ['manifest.json', 'events.jsonl', 'run-classification.json',
                                     'results', 'results/nested', 'workspaces/new-report',
                                     'evaluation-future.json', 'evaluation-future.json/nested'])
def test_reserved_output_namespaces_even_when_absent(tmp_path, op, settings, reserved):
    root, _ = _evaluated_run(tmp_path, op, settings, started=False, finish=False, result=False)
    first = root / reserved.split('/')[0]
    if first.is_file():
        first.unlink()  # Deliberately absent input in this disposable fixture.
    assert not first.exists()
    with pytest.raises(ValueError, match='reserved input namespace'):
        write_report(root, root / reserved)
    assert not first.exists()
    assert not list(root.glob('.kagent-report-*'))


@pytest.mark.parametrize('change', ['root', 'outside', 'traversal', 'symlink-outside',
                                   'symlink-reserved', 'broken-symlink', 'existing-file', 'existing-directory'])
def test_output_paths_reject_without_mutation(tmp_path, op, settings, change):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    if change == 'root':
        output = root
    elif change == 'outside':
        output = tmp_path / 'outside'
    elif change == 'traversal':
        output = root / '..' / 'escape'
    elif change == 'symlink-outside':
        (root / 'link').symlink_to(tmp_path, target_is_directory=True)
        output = root / 'link' / 'outside'
    elif change == 'symlink-reserved':
        (root / 'link').symlink_to(root / 'results', target_is_directory=True)
        output = root / 'link' / 'report'
    elif change == 'broken-symlink':
        output = root / 'broken'
        output.symlink_to(root / 'absent', target_is_directory=True)
    elif change == 'existing-file':
        output = root / 'report'
        output.write_bytes(b'unrelated')
    else:
        output = root / 'report'
        output.mkdir()
    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file() and not p.is_symlink()}
    with pytest.raises(ValueError):
        write_report(root, output)
    assert all((root / name).read_bytes() == content for name, content in before.items())
    assert not (tmp_path / 'outside').exists() and not (tmp_path / 'escape').exists()


def test_new_nested_output_and_safe_inside_symlink(tmp_path, op, settings):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    destination = write_report(root, root / 'exports' / 'draft')
    assert destination == root / 'exports/draft'
    (root / 'alias').symlink_to(root / 'exports', target_is_directory=True)
    assert write_report(root, root / 'alias' / 'second') == root / 'exports/second'


def test_invalid_inputs_do_not_create_output_or_parent(tmp_path, op, settings):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    (root / 'events.jsonl').unlink()
    with pytest.raises(ValueError):
        write_report(root, root / 'new-parent' / 'report')
    assert not (root / 'new-parent').exists()


@pytest.mark.parametrize('failed_index', [0, 3, 7])
@pytest.mark.parametrize('error', [OSError, KeyboardInterrupt])
def test_staging_failure_and_interruption_are_clean_and_retryable(tmp_path, op, settings, monkeypatch, failed_index, error):
    from benchmarks.scenario1.reporting import writer
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    unrelated = root / '.kagent-report-unrelated'
    unrelated.mkdir()
    (unrelated / 'marker').write_text('preserve')
    original = writer._write_file
    count = 0
    def fail(stage_fd, name, contents):
        nonlocal count
        index = count
        count += 1
        if index == failed_index:
            raise error('injected write interruption')
        original(stage_fd, name, contents)
    monkeypatch.setattr(writer, '_write_file', fail)
    with pytest.raises(error):
        write_report(root)
    assert not (root / 'report').exists()
    assert list(root.glob('.kagent-report-*')) == [unrelated]
    assert (unrelated / 'marker').read_text() == 'preserve'
    monkeypatch.setattr(writer, '_write_file', original)
    destination = write_report(root)
    inventory = json.loads((destination / 'report.json').read_text())['output_files']
    assert inventory == sorted(str(p.relative_to(destination)) for p in destination.rglob('*') if p.is_file())
    for path in destination.rglob('*'):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)


@pytest.mark.parametrize('collision', ['empty-directory', 'directory', 'file', 'symlink'])
def test_atomic_publication_collision_preserves_other_owner(tmp_path, op, settings, monkeypatch, collision):
    from benchmarks.scenario1.reporting import writer
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    publish = writer._publish
    def collide(rename, parent_fd, staging_name, name):
        destination = root / name
        if collision in {'directory', 'empty-directory'}:
            destination.mkdir()
            if collision == 'directory':
                (destination / 'marker').write_text('preserve')
        elif collision == 'file':
            destination.write_text('preserve')
        else:
            destination.symlink_to(tmp_path / 'absent')
        publish(rename, parent_fd, staging_name, name)
    monkeypatch.setattr(writer, '_publish', collide)
    with pytest.raises(ValueError, match='already exists'):
        write_report(root)
    assert not list(root.glob('.kagent-report-*'))
    destination = root / 'report'
    if collision == 'directory':
        assert list(destination.iterdir()) == [destination / 'marker']
        assert (destination / 'marker').read_text() == 'preserve'
    elif collision == 'empty-directory':
        assert list(destination.iterdir()) == []
    elif collision == 'file':
        assert destination.read_text() == 'preserve'
    else:
        assert destination.is_symlink()


def test_publication_failure_cleans_owned_staging(tmp_path, op, settings, monkeypatch):
    from benchmarks.scenario1.reporting import writer
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    def fail(*args):
        raise OSError('unsupported filesystem publication')
    monkeypatch.setattr(writer, '_publish', fail)
    with pytest.raises(OSError):
        write_report(root)
    assert not (root / 'report').exists() and not list(root.glob('.kagent-report-*'))


@pytest.mark.parametrize('substitution', ['symlink', 'reserved'])
def test_concurrent_parent_substitution_is_detected(tmp_path, op, settings, monkeypatch, substitution):
    from benchmarks.scenario1.reporting import writer
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    parent = root / 'exports'
    parent.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'marker').write_text('preserve')
    original = writer._write_file
    substituted = False
    def substitute(stage_fd, name, contents):
        nonlocal substituted
        original(stage_fd, name, contents)
        if not substituted:
            substituted = True
            parent.rename(root / ('results/moved-parent' if substitution == 'reserved' else 'moved-parent'))
            if substitution == 'symlink':
                parent.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(writer, '_write_file', substitute)
    with pytest.raises(ValueError, match='parent changed'):
        write_report(root, parent / 'report')
    assert not list(root.rglob('.kagent-report-*'))
    assert list(outside.iterdir()) == [outside / 'marker']
    assert (outside / 'marker').read_text() == 'preserve'
    assert not (parent / 'report').exists()


@pytest.mark.parametrize('counts', [(37, 1, 1, 1, 0), (0, 0, 0, 0, 0), (1, 999, 0, 0, 0)])
def test_partition_chart_counts_patterns_and_geometry(counts):
    from benchmarks.scenario1.reporting.charts import evaluation_partitions
    from benchmarks.scenario1.reporting.model import ReportModel
    group = {'scheduled': sum(counts), **dict(zip(PARTITIONS, counts))}
    model = ReportModel({'classification': 'development', 'classification_qualifier': 'smoke'},
                        {'classes': {cls: group for cls in CLASSES}}, ())
    tree = ET.fromstring(evaluation_partitions(model))
    namespace = {'s': 'http://www.w3.org/2000/svg'}
    for cls in CLASSES:
        cells = [t for t in tree.findall('s:text', namespace) if t.get('data-class') == cls]
        assert [cell.get('data-partition') for cell in cells] == list(PARTITIONS)
        assert [int(cell.text or '') for cell in cells] == list(counts)
        rects = [r for r in tree.findall('s:rect', namespace) if r.get('data-class') == cls]
        assert sum(int(r.attrib['data-count']) for r in rects) == group['scheduled']
        if group['scheduled']:
            assert sum(float(r.attrib['width']) for r in rects) == pytest.approx(500, abs=.001)
        for rect in rects:
            assert 105 <= float(rect.attrib['x']) < 605
            assert float(rect.attrib['x']) + float(rect.attrib['width']) <= 605.001
            # No segment label can overlap or be clipped: counts sit in the table.
            assert all(float(t.attrib['y']) > float(rect.attrib['y']) + 30 for t in cells)
        assert all(24 <= float(t.attrib['x']) < 920 and 0 < float(t.attrib['y']) < 450 for t in cells)
    patterns = tree.findall('s:defs/s:pattern', namespace)
    assert len(patterns) == len(PARTITIONS)
    marks = [p.find('s:g', namespace) for p in patterns]
    assert all(mark is not None for mark in marks)
    assert len({ET.tostring(mark) for mark in marks if mark is not None}) == len(PARTITIONS)
    text = ' '.join(t.text or '' for t in tree.findall('s:text', namespace))
    assert all(label in text for label in ('Evaluable', 'Unresolved', 'Execution failed', 'Invalid result', 'Not run'))
    assert 'Development / smoke' in text and 'N scheduled' in text
    assert 'sum to N scheduled' in text and 'not negative labels' in text
    style = tree.find('s:style', namespace)
    assert style is not None and 'fill:#171717' in (style.text or '')


def test_reporting_fresh_process_imports_no_execution_runtime(tmp_path, op, settings):
    import subprocess
    import sys
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    code = '''
import sys
from benchmarks.scenario1.__main__ import main
assert main(['report', '--run', sys.argv[1]]) == 0
prefixes = ('src.agent', 'src.config', 'src.llm', 'src.report', 'benchmarks.scenario1.runtime',
            'benchmarks.scenario1.runner', 'benchmarks.scenario1.worker', 'benchmarks.scenario1.evaluate')
assert not [m for m in sys.modules if m.startswith(prefixes)]
'''
    completed = subprocess.run([sys.executable, '-B', '-c', code, str(root)], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize('arguments', [
    ['report', '--unexpected', 'http://alice:Orbit987654321@host'],
    ['report', '--run', 'opaque', '--unexpected', 'Orbit987654321'],
    ['report', '--run'],
])
def test_reporting_argument_errors_are_sanitized(arguments, capsys):
    with pytest.raises(SystemExit) as error:
        main(arguments)
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert 'Orbit987654321' not in captured.err + captured.out
    assert captured.err == 'benchmark report error: invalid arguments\n'


@pytest.mark.parametrize('bad', [[1], 'opaque', {'llm': [1]}, None])
def test_unusable_outer_diagnostic_metrics_are_na(tmp_path, op, settings, bad):
    root, _ = _evaluated_run(tmp_path, op, settings, status='crashed')
    path = root / 'results' / f'{op.case_id}.json'
    raw = json.loads(path.read_text())
    raw['metrics'] = bad
    path.write_text(json.dumps(raw))
    rows, _ = read_records(root / 'events.jsonl')
    next(e for e in rows if e['kind'] == 'runtime-finished')['data']['result_sha256'] = file_hash(path)
    _save_rows(root, rows)
    _rebind(root)
    case = load_report(root).cases[0]
    assert case['agent_seconds'] is case['llm_calls'] is case['http_admitted'] is None
    assert case['final_status'] == 'crashed'


@pytest.mark.parametrize('field', ['schema_version', 'evaluator_version', 'incomplete', 'partial_tail_ignored'])
def test_evaluation_version_and_recovery_flags_fail_closed(tmp_path, op, settings, field):
    root, evaluation = _evaluated_run(tmp_path, op, settings)
    evaluation[field] = {'schema_version': True, 'evaluator_version': 'opaque',
                         'incomplete': True, 'partial_tail_ignored': True}[field]
    next(root.glob('evaluation-*.json')).write_text(json.dumps(evaluation))
    with pytest.raises(ValueError):
        load_report(root)


def test_csv_quotes_utf8_and_deterministic_order():
    from benchmarks.scenario1.reporting.tables import csv_bytes
    data = csv_bytes(('first', 'second'), [{'first': 'một, hai', 'second': 'quote " here\nnew line'}])
    assert data.decode().startswith('first,second\n"một, hai",')
    assert _csv(data) == [{'first': 'một, hai', 'second': 'quote " here\nnew line'}]


def test_exported_case_strings_cannot_start_csv_formulas(tmp_path, op, settings):
    root, _ = _fixture(tmp_path, single_manifest(op, settings), partitions={op.case_id: 'invalid-result'})
    evaluation = json.loads(next(root.glob('evaluation-*.json')).read_text())
    evaluation['records'][0]['reason'] = '=HYPERLINK("opaque")'
    next(root.glob('evaluation-*.json')).write_text(json.dumps(evaluation))
    rows, _ = read_records(root / 'events.jsonl')
    next(e for e in rows if e['kind'] == 'evaluated')['data']['reason'] = evaluation['records'][0]['reason']
    _save_rows(root, rows)
    model = load_report(root)
    for row in _csv(render_tables(model)['per-case.csv']):
        assert all(not value.startswith(('=', '+', '-', '@', '\t', '\r')) for value in row.values())
    assert model.cases[0]['evaluator_reason'] == '[redacted]'


def test_commit_shaped_opaque_credentials_are_pseudonymized(tmp_path, op, settings):
    secret = '0123456789abcdef' * 2 + '01234567'
    manifest = replace(single_manifest(op, settings),
        dataset={'version': '1.2', 'git_commit': secret, 'artifacts': {'truth.csv': 'a' * 64}},
        reproducibility={'kagent_commit': secret})
    root, _ = _fixture(tmp_path, manifest)
    destination = write_report(root)
    assert all(secret.encode() not in p.read_bytes() for p in destination.rglob('*') if p.is_file())
    assert load_report(root).metadata['dataset']['git_commit'] == presentation_id('commit', secret)


def test_staging_substitution_preserves_other_owner(tmp_path, op, settings, monkeypatch):
    import os
    from benchmarks.scenario1.reporting import writer
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    original = writer._write_file
    replacement = None
    def substitute(stage_fd, name, contents):
        nonlocal replacement
        original(stage_fd, name, contents)
        if replacement is None:
            stage = Path(os.readlink(f'/proc/self/fd/{stage_fd}'))
            stage.rename(root / 'externally-moved-stage')
            stage.mkdir()
            (stage / 'marker').write_text('preserve other owner')
            replacement = stage
    monkeypatch.setattr(writer, '_write_file', substitute)
    with pytest.raises(ValueError, match='staging ownership changed'):
        write_report(root)
    assert not (root / 'report').exists()
    assert replacement is not None
    assert list(replacement.iterdir()) == [replacement / 'marker']
    assert (replacement / 'marker').read_text() == 'preserve other owner'


@pytest.mark.parametrize('outcome', ['blocked', 'browser-required', 'opaque', [1]])
def test_evaluable_records_reject_unscorable_supplied_outcomes(tmp_path, op, settings, outcome):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    rows, _ = read_records(root / 'events.jsonl')
    next(e for e in rows if e['kind'] == 'runtime-finished')['data']['canonical_summary']['outcome'] = outcome
    _save_rows(root, rows)
    _rebind(root)
    with pytest.raises(ValueError, match='provided outcome'):
        load_report(root)


def test_semantic_manifest_binding_allows_legacy_byte_format_changes(tmp_path, op, settings):
    root, evaluation = _evaluated_run(tmp_path, op, settings)
    path = root / 'manifest.json'
    raw = json.loads(path.read_text())
    before_hash = file_hash(path)
    path.write_text(json.dumps(raw, sort_keys=True, separators=(',', ':')) + '\n')
    assert file_hash(path) != before_hash
    model = load_report(root)
    assert model.metadata['evaluation_identity'] == evaluation['evaluation_identity']
    assert model.metadata['manifest_sha256'] == file_hash(path)


def test_partial_tail_contents_remain_ignored_by_v1_identity(tmp_path, op, settings):
    root, evaluation = _evaluated_run(tmp_path, op, settings, finish=False, partial=True)
    path = root / 'events.jsonl'
    complete = path.read_bytes().rsplit(b'\n', 1)[0] + b'\n'
    path.write_bytes(complete + b'{different uncommitted tail')
    assert load_report(root).metadata['evaluation_identity'] == evaluation['evaluation_identity']


SVG_NS = {'s': 'http://www.w3.org/2000/svg'}


def _chart_model(cases):
    from benchmarks.scenario1.reporting.model import ReportModel
    records = [{'partition': 'evaluable', 'confusion': 'TP'} for _ in cases]
    return ReportModel({'classification': 'development', 'classification_qualifier': 'smoke'},
        {'overall': _group(records), 'classes': {cls: _group([
            r for r, c in zip(records, cases) if c['vulnerability_class'] == cls]) for cls in CLASSES}}, tuple(cases))


def _chart_case(index, *, seconds: float | None = 2.5, tokens=100, complete=True, status='completed'):
    return {'case_id': presentation_id('case', f'observation-{index}'),
            'vulnerability_class': CLASSES[index % 2], 'agent_seconds': seconds,
            'wall_seconds': 9999, 'total_tokens': tokens, 'total_tokens_complete': complete,
            'final_status': status}


def _observations(contents):
    return ET.fromstring(contents).findall('s:g[@data-case]', SVG_NS)


def _svg_text(contents):
    return ' '.join(t.text or '' for t in ET.fromstring(contents).iterfind('.//s:text', SVG_NS))


def _element(parent, query):
    element = parent.find(query, SVG_NS)
    assert element is not None
    return element


def test_processing_chart_measured_interval_order_units_and_geometry():
    # Deliberately nonmonotonic values/identities: preserve manifest/CSV order,
    # rather than ranking by duration, grouping classes or sorting pseudonyms.
    cases = [_chart_case(7, seconds=10), _chart_case(2, seconds=20, status='crashed'),
             _chart_case(5, seconds=None), _chart_case(0, seconds=0)]
    charts = render_charts(_chart_model(cases))
    data = charts['charts/processing-time.svg']
    observations = _observations(data)
    assert [o.get('data-case') for o in observations] == [c['case_id'] for c in cases]
    assert [o.get('data-ordinal') for o in observations] == ['1', '2', '3', '4']
    assert [_element(o, 's:text').text for o in observations] == ['10.0', '20.0 *', 'NA', '0.0']
    bars = [o.find('s:rect', SVG_NS) for o in observations]
    assert bars[0] is not None and bars[1] is not None
    assert float(bars[0].attrib['width']) == pytest.approx(float(bars[1].attrib['width']) / 2)
    assert bars[2] is bars[3] is None
    assert observations[2].get('data-available') == 'false'
    assert observations[3].get('data-available') == 'true'
    assert [float(b.attrib['y']) for b in bars if b is not None] == sorted(float(b.attrib['y']) for b in bars if b is not None)
    assert all(float(b.attrib['x']) + float(b.attrib['width']) <= 760 for b in bars if b is not None)
    text = _svg_text(data)
    assert 'Processing time by benchmark case' in text and 'Processing time (s)' in text
    assert 'Case 01 · XSS' in text and 'Case 02 · SQLi' in text
    assert 'retained Agent interval' in text and '9999' not in text
    assert 'agent_seconds' not in text and 'latency' not in text.lower()


@pytest.mark.parametrize('tokens,complete,expected', [
    (1234, True, '1,234'), (0, True, '0'), (1234, False, 'NA'),
    (1234, None, 'NA'), (None, True, 'NA'), (True, True, 'NA'),
])
def test_token_chart_requires_complete_full_total(tokens, complete, expected):
    case = _chart_case(0, tokens=tokens, complete=complete)
    # An observed sum must never be used as a replacement for a full total.
    case['observed_sum'] = 987654
    data = render_charts(_chart_model([case]))['charts/total-tokens.svg']
    observation = _observations(data)[0]
    assert _element(observation, 's:text').text == expected
    assert observation.get('data-available') == str(expected != 'NA').lower()
    rect = observation.find('s:rect', SVG_NS)
    assert (rect is not None) is (expected == '1,234')
    text = _svg_text(data)
    assert 'Total tokens' in text and 'partial sums are excluded' in text
    assert f"Complete totals: {0 if expected == 'NA' else 1}/1 cases" in text
    assert '987654' not in text and 'total_tokens_complete' not in text


@pytest.mark.parametrize('count', [0, 1, 20, 21, 47, 101])
def test_case_chart_pagination_inventory_and_common_scale(count):
    cases = [_chart_case(i, seconds=(i + 1) * 2, tokens=(i + 1) * 100) for i in range(count)]
    model = _chart_model(cases)
    charts = render_charts(model)
    assert charts == render_charts(model)
    pages = max(1, (count + 19) // 20)
    expected = {'charts/class-metrics.svg', 'charts/evaluation-partitions.svg', 'charts/confusion-matrix.svg'}
    expected.update({'charts/scenario1-validation-quality.svg',
                     'charts/scenario1-processing-time-median.svg',
                     'charts/scenario1-total-tokens-median.svg'})
    for stem in ('processing-time', 'total-tokens'):
        names = [f'charts/{stem}.svg', *[f'charts/{stem}-{p:02d}.svg' for p in range(2, pages + 1)]]
        expected.update(names)
        all_observations = []
        tick_sets = []
        for name in names:
            tree = ET.fromstring(charts[name])
            observations = _observations(charts[name])
            assert len(observations) <= 20
            all_observations.extend(observations)
            width, height = map(int, tree.attrib['viewBox'].split()[2:])
            assert width == 920 and height <= 934
            for observation in observations:
                rect = observation.find('s:rect', SVG_NS)
                assert rect is not None
                assert 220 == float(rect.attrib['x'])
                assert 0 < float(rect.attrib['width']) <= 540
                assert float(rect.attrib['y']) + float(rect.attrib['height']) < height - 100
            tick_sets.append([t.text for t in tree.findall('s:text', SVG_NS) if t.get('class') == 'small center number'])
            if count == 0:
                assert 'No scheduled cases' in _svg_text(charts[name])
        assert all(ticks == tick_sets[0] for ticks in tick_sets)
        assert [o.get('data-case') for o in all_observations] == [c['case_id'] for c in cases]
        assert [int(o.attrib['data-ordinal']) for o in all_observations] == list(range(1, count + 1))
    assert set(charts) == expected


def test_chart_visual_language_metric_casing_and_class_colors():
    from benchmarks.scenario1.reporting.charts import COLORS
    charts = render_charts(_chart_model([_chart_case(0), _chart_case(1)]))
    styles = []
    for name, contents in charts.items():
        if name.startswith('charts/scenario1-'):
            continue  # Selected thesis typography is checked separately below.
        tree = ET.fromstring(contents)
        styles.append(_element(tree, 's:style').text)
        texts = tree.findall('s:text', SVG_NS)
        assert any(t.get('class') == 'title' and t.get('x') == '32' and t.get('y') == '44' for t in texts)
        assert any(t.text == 'Development / smoke' and t.get('y') == '72' for t in texts)
        assert all(0 < float(t.attrib['x']) < 920 and 0 < float(t.attrib['y']) < int(tree.attrib['height']) for t in texts)
        text = _svg_text(contents)
        assert not any(field in text for field in ('evaluator_partition', 'agent_seconds', 'http_dispatch_attempts',
                                                 'total_tokens_complete', 'tool_result_events', 'Fpr'))
    assert len(set(styles)) == 1
    assert 'Arial,sans-serif' in styles[0]
    metric_text = _svg_text(charts['charts/class-metrics.svg'])
    assert metric_text.count('FPR') >= 2
    assert 'NA (0/0)' in metric_text
    colors = [[_element(o, 's:rect').attrib['fill'] for o in _observations(charts[f'charts/{stem}.svg'])]
              for stem in ('processing-time', 'total-tokens')]
    assert colors[0] == colors[1]
    positive_pattern = _element(ET.fromstring(charts['charts/evaluation-partitions.svg']), 's:defs/s:pattern/s:rect')
    assert positive_pattern.attrib['fill'] == COLORS['positive']
    assert COLORS['positive'].encode() in charts['charts/class-metrics.svg']


def test_case_chart_integration_na_pseudonyms_and_token_completeness(tmp_path, op, settings):
    root, _ = _fixture(tmp_path, single_manifest(op, settings), legacy_dispatch=True)
    model = load_report(root)
    charts = render_charts(model)
    assert _observations(charts['charts/processing-time.svg'])[0].get('data-case') == presentation_id('case', op.case_id)
    assert _element(_observations(charts['charts/total-tokens.svg'])[0], 's:text').text == 'NA'
    assert op.case_id.encode() not in b''.join(charts.values())
    assert not any('dispatch' in name or 'llm-call' in name for name in charts)


@pytest.mark.parametrize('seconds,tokens', [(0, 0), (None, None), (1e308, 10 ** 400)])
def test_case_chart_empty_zero_and_large_values_keep_finite_geometry(seconds, tokens):
    charts = render_charts(_chart_model([_chart_case(0, seconds=seconds, tokens=tokens)]))
    for stem in ('processing-time', 'total-tokens'):
        tree = ET.fromstring(charts[f'charts/{stem}.svg'])
        for rect in tree.iterfind('.//s:rect', SVG_NS):
            width = float(rect.attrib['width'])
            assert 0 <= width <= 920
        observation = _observations(charts[f'charts/{stem}.svg'])[0]
        assert observation.get('data-available') == str(seconds is not None).lower()
        assert 'inf' not in _svg_text(charts[f'charts/{stem}.svg']).lower()


def test_confusion_matrix_preserves_truth_rows_assessment_columns_and_counts():
    from benchmarks.scenario1.reporting.charts import confusion_matrix
    model = _chart_model([])
    model.metrics['overall'].update(TP=3, FN=1, FP=2, TN=4, evaluable=10, scheduled=12)
    tree = ET.fromstring(confusion_matrix(model))
    labels = {t.text: t for t in tree.findall('s:text', SVG_NS) if t.text in ('TP', 'FN', 'FP', 'TN')}
    assert labels['TP'].get('x') == labels['FP'].get('x')
    assert labels['FN'].get('x') == labels['TN'].get('x')
    assert float(labels['TP'].attrib['x']) < float(labels['FN'].attrib['x'])
    assert labels['TP'].get('y') == labels['FN'].get('y')
    assert labels['FP'].get('y') == labels['TN'].get('y')
    assert float(labels['TP'].attrib['y']) < float(labels['FP'].attrib['y'])
    for label, text in labels.items():
        counts = [t for t in tree.findall('s:text', SVG_NS) if t.get('class') == 'title center number'
                  and t.get('x') == text.get('x') and float(t.attrib['y']) > float(text.attrib['y'])]
        count = min(counts, key=lambda t: float(t.attrib['y']))
        assert count.text == str(model.metrics['overall'][label])


def test_class_metrics_bar_lengths_and_displayed_fractions_use_canonical_rates():
    from benchmarks.scenario1.reporting.charts import class_metrics
    model = _chart_model([])
    group = {'TP': 3, 'FN': 1, 'FP': 2, 'TN': 4, 'evaluable': 10, 'scheduled': 12,
             'recall': .75, 'precision': .6, 'fpr': 2 / 6, 'evaluability': 10 / 12}
    model.metrics['classes'] = {cls: group.copy() for cls in CLASSES}
    data = class_metrics(model)
    tree = ET.fromstring(data)
    filled = [r for r in tree.findall('s:rect', SVG_NS) if r.get('x') == '190' and r.get('fill') != '#f1f3f5']
    assert [float(r.attrib['width']) for r in filled] == pytest.approx([470 * r for r in (.75, .6, 2 / 6, 10 / 12)] * 2, abs=.001)
    text = _svg_text(data)
    assert all(text.count(fraction) == 2 for fraction in ('75.0% (3/4)', '60.0% (3/5)', '33.3% (2/6)', '83.3% (10/12)'))


def _thesis_case(index, **changes):
    from benchmarks.scenario1.reporting.tables import CASE_FIELDS
    case: dict[str, Any] = {field: None for field in CASE_FIELDS}
    case.update(_chart_case(index), expected_vulnerable=True, agent_outcome='confirmed',
                evaluator_partition='evaluable', evaluator_reason='accepted-agent-assessment',
                confusion='TP', worker_status='completed', llm_calls=2, tool_executed=3,
                http_dispatch_attempts=4, http_admitted=999)
    case.update(changes)
    return case


def _thesis_model(cases):
    model = _chart_model(cases)
    records = [{'partition': c['evaluator_partition'], 'confusion': c['confusion']} for c in cases]
    model.metrics['overall'] = _group(records)
    model.metrics['classes'] = {cls: _group([r for r, c in zip(records, cases)
        if c['vulnerability_class'] == cls]) for cls in CLASSES}
    return model


def _md_rows(contents, panel):
    section = contents.decode().split(f'## {panel} — ', 1)[1].split('\n## ', 1)[0]
    return [[cell.strip() for cell in line.strip('|').split('|')]
            for line in section.splitlines() if line.startswith('|')][2:]


def _thesis_values(contents):
    tree = ET.fromstring(contents)
    groups = tree.findall('s:g[@data-class]', SVG_NS)
    return [_element(g, 's:text[@class="right number"]').text for g in groups]


def test_thesis_quality_canonical_fractions_geometry_and_zero_denominator():
    model = _thesis_model([])
    model.metrics['classes'][CLASSES[0]] = {'TP': 3, 'FN': 1, 'FP': 2, 'TN': 4,
        'evaluable': 10, 'scheduled': 12, 'recall': .75, 'precision': .6,
        'fpr': 2 / 6, 'evaluability': 10 / 12}
    data = render_thesis_charts(model)['charts/scenario1-validation-quality.svg']
    tree = ET.fromstring(data)
    groups = tree.findall('s:g', SVG_NS)
    assert [(g.get('data-class'), g.get('data-metric')) for g in groups] == [
        (cls, rate) for cls in CLASSES for rate in ('recall', 'precision', 'fpr', 'evaluability')]
    widths = [float(r.attrib['width']) for r in tree.findall('.//s:rect[@class="filled"]', SVG_NS)]
    assert widths == pytest.approx([295 * r for r in (.75, .6, 2 / 6, 10 / 12)], abs=.001)
    assert len(tree.findall('.//s:rect[@class="track"]', SVG_NS)) == 8
    text = _svg_text(data)
    assert all(label in text for label in ('75,0% (3/4)', '60,0% (3/5)', '33,3% (2/6)', '83,3% (10/12)'))
    assert text.count('NA (0/0)') == 4
    zero = _thesis_model([_thesis_case(0, confusion='TN', expected_vulnerable=False)])
    text = _svg_text(render_thesis_charts(zero)['charts/scenario1-validation-quality.svg'])
    assert '0,0% (0/1)' in text and 'NA (0/0)' in text
    assert all(text.count(label) == 2 for label in ('Recall', 'Precision', 'FPR', 'Evaluability'))


def test_thesis_parent_completed_cohort_includes_unresolved_invalid_and_retains_failures():
    cases = [_thesis_case(0, agent_seconds=10, total_tokens=1000),
             _thesis_case(2, agent_seconds=20, total_tokens=2000,
                          evaluator_partition='unresolved', confusion=None),
             _thesis_case(4, agent_seconds=30, total_tokens=3000,
                          evaluator_partition='invalid-result', confusion=None),
             _thesis_case(6, final_status='budget-exhausted', agent_seconds=1000,
                          total_tokens=8000, evaluator_partition='execution-failed', confusion=None),
             _thesis_case(1, final_status='crashed', agent_seconds=0, total_tokens=0,
                          evaluator_partition='execution-failed', confusion=None)]
    model = _thesis_model(cases)
    charts = render_thesis_charts(model)
    assert _thesis_values(charts[f'charts/{FIGURE_NAMES[1]}.svg']) == ['20,0', 'NA']
    assert _thesis_values(charts[f'charts/{FIGURE_NAMES[2]}.svg']) == ['2,0', 'NA']
    md = render_thesis_tables(model)
    assert _md_rows(md, 'T2A')[0] == ['SQLi', '3/3', '20,0', '20,0', '30,0', '10,0–30,0']
    assert _md_rows(md, 'T2C') == [
        ['SQLi / Hết ngân sách', '1', '1000,0<br>1/1', '8,0<br>1/1'],
        ['XSS / Sự cố', '1', '0,0<br>1/1', '0,0<br>1/1']]
    assert _md_rows(md, 'T3')[0] == ['SQLi', '14.000<br>4/4', '8<br>4/4', '12<br>4/4', '16<br>4/4']
    assert 'Execution chưa hoàn tất xem T2C.' in md.decode()


def test_thesis_metric_specific_coverage_fractional_median_pooled_and_shared_p95():
    from benchmarks.common.metrics import distribution
    cases = [_thesis_case(0, agent_seconds=None, total_tokens=100),
             _thesis_case(2, agent_seconds=10, total_tokens=101),
             _thesis_case(1, agent_seconds=100, total_tokens=300, total_tokens_complete=False),
             _thesis_case(3, agent_seconds=200, total_tokens=None)]
    model = _thesis_model(cases)
    sql = class_cases(model, CLASSES[0], completed=True)
    assert resource_summary(sql, 'total_tokens').median == 100.5
    md = render_thesis_tables(model)
    assert _md_rows(md, 'T2A')[0][1:] == ['1/2', '10,0', '10,0', '10,0', '10,0–10,0']
    assert _md_rows(md, 'T2B')[0][1:] == ['2/2', '0,1', '0,1', '0,1', '0,1–0,1']
    pooled = resource_summary(class_cases(model, None, completed=True), 'agent_seconds')
    assert (pooled.median, pooled.mean, pooled.p95) == (100, 310 / 3, 200)
    assert _md_rows(md, 'T2A')[2][1:] == ['3/4', '100,0', '103,3', '200,0', '10,0–200,0']
    # 20 values distinguish nearest-rank from interpolation and max.
    stats = resource_summary([_thesis_case(i, agent_seconds=i + 1) for i in range(20)], 'agent_seconds')
    assert (stats.median, stats.p95) == (10.5, distribution(list(range(1, 21)))['p95'])
    assert stats.p95 == 19
    fractional = _thesis_model([_thesis_case(0, total_tokens=1050), _thesis_case(2, total_tokens=1051)])
    assert resource_summary(fractional.cases, 'total_tokens').median == 1050.5
    assert _thesis_values(render_thesis_charts(fractional)[f'charts/{FIGURE_NAMES[2]}.svg'])[0] == '1,1'


@pytest.mark.parametrize('metric', ['total_tokens', 'llm_calls', 'tool_executed', 'http_dispatch_attempts'])
@pytest.mark.parametrize('bad', [None, True, -1, 1.5, '2'])
def test_thesis_all_workload_metrics_require_complete_schedule(metric, bad):
    cases = [_thesis_case(0), _thesis_case(2, **{metric: bad}), _thesis_case(1)]
    model = _thesis_model(cases)
    stats = resource_summary(class_cases(model, CLASSES[0]), metric)
    assert (stats.available, stats.eligible, stats.total) == (1, 2, None)
    position = ('total_tokens', 'llm_calls', 'tool_executed', 'http_dispatch_attempts').index(metric) + 1
    rows = _md_rows(render_thesis_tables(model), 'T3')
    assert rows[0][position] == 'NA<br>1/2'
    assert rows[2][position] == 'NA<br>2/3'
    assert all(rows[0][i] != 'NA<br>1/2' for i in range(1, 5) if i != position)


@pytest.mark.parametrize('complete', [False, None, 'true', 1])
def test_thesis_partial_tokens_and_admissions_never_substitute(complete):
    case = _thesis_case(0, total_tokens=8888, total_tokens_complete=complete,
                        input_tokens=8000, output_tokens=888, http_dispatch_attempts=None,
                        observed_sum=8888)
    model = _thesis_model([case])
    md = render_thesis_tables(model)
    assert _md_rows(md, 'T3')[0] == ['SQLi', 'NA<br>0/1', '2<br>1/1', '3<br>1/1', 'NA<br>0/1']
    assert _thesis_values(render_thesis_charts(model)[f'charts/{FIGURE_NAMES[2]}.svg']) == ['NA', 'NA']


def test_thesis_noncompleted_status_groups_have_independent_availability():
    cases = [_thesis_case(0, final_status='timeout', agent_seconds=5, total_tokens_complete=False),
             _thesis_case(2, final_status='timeout', agent_seconds=None, total_tokens=2000),
             _thesis_case(4, final_status='crashed', agent_seconds=40, total_tokens=4000)]
    md = render_thesis_tables(_thesis_model(cases))
    assert _md_rows(md, 'T2C') == [['SQLi / Sự cố', '1', '40,0<br>1/1', '4,0<br>1/1'],
                                ['SQLi / Quá thời gian', '2', '5,0<br>1/2', '2,0<br>1/2']]


def test_thesis_missing_final_status_ledger_preserves_partitions_and_source():
    cases = [_thesis_case(0, final_status=None, evaluator_partition='execution-failed', confusion=None,
                          agent_seconds=None, total_tokens=None),
             _thesis_case(2, final_status=None, evaluator_partition='not-run', confusion=None,
                          agent_seconds=None, total_tokens=None)]
    model = _thesis_model(cases)
    before = json.dumps(model.cases, sort_keys=True)
    md = render_thesis_tables(model)
    assert _md_rows(md, 'T1A')[0] == ['SQLi', '2', '0', '0', '1', '0', '1']
    assert _md_rows(md, 'Ledger') == [
        ['SQLi', 'Lỗi thực thi', '1', 'NA<br>0/1', 'NA<br>0/1'],
        ['SQLi', 'Chưa chạy', '1', 'NA<br>0/1', 'NA<br>0/1']]
    assert _md_rows(md, 'T2A')[0][1] == '0/0'
    assert _md_rows(md, 'T3')[0][1] == 'NA<br>0/2'
    assert '## T2C' not in md.decode() and 'Case thiếu trạng thái kết thúc xem Ledger.' in md.decode()
    assert json.dumps(model.cases, sort_keys=True) == before
    assert all(c['final_status'] is None for c in model.cases)


@pytest.mark.parametrize('started', [True, False])
def test_thesis_no_finish_and_not_run_bound_loader_integration(tmp_path, op, settings, started):
    root, _ = _evaluated_run(tmp_path, op, settings, started=started, finish=False, result=started)
    model = load_report(root)
    md = render_thesis_tables(model)
    partition_label = 'Lỗi thực thi' if started else 'Chưa chạy'
    assert _md_rows(md, 'Ledger')[0][1:3] == [partition_label, '1']
    assert model.cases[0]['final_status'] is None
    assert model.cases[0]['agent_seconds'] is None  # Unbound orphan cannot supply resources.
    assert _md_rows(md, 'T3')[2][1:] == ['NA<br>0/1'] * 4


def test_thesis_parent_precedence_bound_loader_integration(tmp_path, op, settings):
    root, _ = _fixture(tmp_path, single_manifest(op, settings), parent_status='crashed', worker_status='completed')
    model = load_report(root)
    assert _md_rows(render_thesis_tables(model), 'T2A')[2][1:] == ['0/0', 'NA', 'NA', 'NA', 'NA']
    assert _md_rows(render_thesis_tables(model), 'T2C')[0][1:] == ['1', '1,2<br>1/1', 'NA<br>0/1']


@pytest.mark.parametrize('mode', ['empty', 'zero', 'missing'])
def test_thesis_empty_all_na_and_measured_zero_render_without_fake_marks(mode):
    cases = [] if mode == 'empty' else [_thesis_case(0, agent_seconds=0 if mode == 'zero' else None,
        total_tokens=0 if mode == 'zero' else None, llm_calls=0 if mode == 'zero' else None,
        tool_executed=0 if mode == 'zero' else None, http_dispatch_attempts=0 if mode == 'zero' else None)]
    model = _thesis_model(cases)
    md = render_thesis_tables(model)
    assert _md_rows(md, 'T3')[0][1:] == [
        '0<br>1/1' if mode == 'zero' else 'NA<br>0/0' if mode == 'empty' else 'NA<br>0/1'] * 4
    charts = render_thesis_charts(model)
    for name in FIGURE_NAMES[1:]:
        data = charts[f'charts/{name}.svg']
        assert _thesis_values(data) == (['0,0', 'NA'] if mode == 'zero' else ['NA', 'NA'])
        assert not ET.fromstring(data).findall('.//s:rect[@class="filled"]', SVG_NS)
        assert '0' in _svg_text(data)
        if name == FIGURE_NAMES[2]:
            assert '0,25' in _svg_text(data) and '0,75' in _svg_text(data)


@pytest.mark.parametrize('value,expected', [(0, '0,0'), (.0001, '<0,1'), (.05, '<0,1'), (.1, '0,1')])
def test_thesis_small_positive_rounding_does_not_claim_zero(value, expected):
    assert format_decimal(value) == expected
    model = _thesis_model([_thesis_case(0, agent_seconds=value)])
    assert _thesis_values(render_thesis_charts(model)[f'charts/{FIGURE_NAMES[1]}.svg'])[0] == expected


def test_thesis_visible_text_physical_size_typography_and_colors():
    import re
    cases = [_thesis_case(0, agent_seconds=20, total_tokens=200000),
             _thesis_case(1, agent_seconds=40, total_tokens=400000)]
    charts = render_thesis_charts(_thesis_model(cases))
    assert set(charts) == {f'charts/{name}.svg' for name in FIGURE_NAMES}
    resource_colors = []
    for name, contents in charts.items():
        tree = ET.fromstring(contents)
        validation = name.endswith('validation-quality.svg')
        assert tree.attrib['width'] == '16.5cm'
        assert tree.attrib['height'] == ('11cm' if validation else '5cm')
        assert tree.attrib['viewBox'] == ('0 0 660 440' if validation else '0 0 660 200')
        style = _element(tree, 's:style').text or ''
        assert 'Arial,sans-serif' in style
        printed_fonts = [float(s) * 16.5 / 2.54 * 72 / 660 for s in re.findall(r'font-size:([\d.]+)px', style)]
        assert min(printed_fonts) >= 10 and 10.5 <= printed_fonts[0] <= 11
        assert 11 <= printed_fonts[1] <= 12
        assert _element(tree, 's:title').text and _element(tree, 's:desc').text
        visible = _svg_text(contents)
        assert all(label in visible for label in ('SQLi', 'XSS'))
        forbidden = ('Overall', 'Tổng', 'Development', 'smoke', 'completed', 'retained',
                     'agent_seconds', 'total_tokens', 'provider', 'model', 'scenario1-',
                     'report', 'Ledger', 'canonical', 'data-', 'Case ', 'latency', 'QA', 'T2')
        assert not any(word in visible for word in forbidden)
        assert not re.search(r'[0-9a-f]{32,}|\b\d+[a-f][0-9a-f]{15,}', visible)
        assert all(c['case_id'] not in visible for c in cases)
        # Hidden accessibility metadata is intentionally allowed to mention cohorts.
        if not validation:
            assert 'Parent-completed' in (_element(tree, 's:desc').text or '')
            resource_colors.append([r.attrib['fill'] for r in tree.findall('.//s:rect[@class="filled"]', SVG_NS)])
            assert len(resource_colors[-1]) == 2
        assert not tree.findall('.//s:circle', SVG_NS) and not tree.findall('.//s:path', SVG_NS)
    assert resource_colors == [['#285c79', '#6b5b83']] * 2
    assert 'Trung vị thời gian (s)' in _svg_text(charts[f'charts/{FIGURE_NAMES[1]}.svg'])
    assert 'Trung vị tổng token (nghìn)' in _svg_text(charts[f'charts/{FIGURE_NAMES[2]}.svg'])


@pytest.mark.parametrize('count', [40, 80])
def test_thesis_large_schedule_accounting_determinism_and_csv_preservation(count):
    from benchmarks.scenario1.reporting.tables import CASE_FIELDS, csv_bytes
    cases = [_thesis_case(i, agent_seconds=i + 1, total_tokens=(i + 1) * 1000,
                          evaluator_partition=PARTITIONS[i % 5],
                          confusion='TP' if i % 5 == 0 else None,
                          final_status='completed' if i % 5 < 3 else 'timeout' if i % 5 == 3 else None)
             for i in range(count)]
    model = _thesis_model(cases)
    before = json.dumps({'cases': model.cases, 'metrics': model.metrics}, sort_keys=True)
    files = {**render_tables(model), **render_charts(model)}
    assert files == {**render_tables(model), **render_charts(model)}
    assert files['per-case.csv'] == csv_bytes(CASE_FIELDS, cases)
    assert list(_csv(files['per-case.csv'])[0]) == list(CASE_FIELDS)
    assert _csv(files['summary.csv']) == [{k: '' if v is None else str(v) for k, v in r.items()} for r in summary_rows(model)]
    assert _csv(files['partitions.csv']) == [{k: str(v) for k, v in r.items()} for r in partition_rows(model)]
    expected_abnormal = [{'case_id': c['case_id'], 'partition': c['evaluator_partition'],
                         'reason': c['evaluator_reason'], 'manual_root_cause': ''}
                        for c in cases if c['evaluator_partition'] != 'evaluable']
    assert _csv(files['abnormal-analysis-template.csv']) == expected_abnormal
    md = files['thesis-tables.md']
    for row in _md_rows(md, 'T1A'):
        assert sum(map(int, row[2:])) == int(row[1])
    assert _md_rows(md, 'T1A')[2][1:] == [str(count), *[str(count // 5)] * 5]
    assert _md_rows(md, 'T1B')[2][1:] == [str(count // 5), '0', '0', '0']
    assert int(_md_rows(md, 'T2A')[2][1].split('/')[1]) + sum(int(r[1]) for r in _md_rows(md, 'T2C')) + sum(int(r[2]) for r in _md_rows(md, 'Ledger')) == count
    assert _md_rows(md, 'T3')[2][1:] == [f'{count * (count + 1) // 2 * 1000:,}'.replace(',', '.') + f'<br>{count}/{count}',
                                       f'{count * 2}<br>{count}/{count}', f'{count * 3}<br>{count}/{count}', f'{count * 4}<br>{count}/{count}']
    assert json.dumps({'cases': model.cases, 'metrics': model.metrics}, sort_keys=True) == before


def test_thesis_writer_new_inventory_and_repeatable_bytes(tmp_path, op, settings):
    root, _ = _fixture(tmp_path, single_manifest(op, settings))
    first = write_report(root)
    inventory = json.loads((first / 'report.json').read_text())['output_files']
    assert inventory == sorted(str(p.relative_to(first)) for p in first.rglob('*') if p.is_file())
    assert len(inventory) == 14 and 'thesis-tables.md' in inventory
    assert all(f'charts/{name}.svg' in inventory for name in FIGURE_NAMES)
    second = write_report(root, root / 'thesis-again')
    assert all((first / name).read_bytes() == (second / name).read_bytes() for name in inventory)


@pytest.mark.parametrize('classification,qualifier,label', [
    ('development', 'smoke', 'Development / smoke'), ('development', None, 'Development'),
    ('official', None, 'Official — phân loại do người vận hành'),
    ('unknown', None, 'Chưa khai báo trạng thái Official')])
def test_thesis_companion_classification_and_captions(classification, qualifier, label):
    model = _thesis_model([])
    model.metadata.update(classification=classification, classification_qualifier=qualifier)
    md = render_thesis_tables(model).decode()
    assert label in md
    assert all(f'**F{i} — ' in md for i in (1, 2, 3))
    if qualifier == 'smoke':
        assert 'không phải kết quả luận văn chính thức' in md


def test_thesis_large_integer_tokens_keep_exact_fractional_median_and_finite_geometry():
    from decimal import Decimal
    a = 2 ** 54
    cases = [_thesis_case(0, total_tokens=a), _thesis_case(2, total_tokens=a + 1)]
    assert resource_summary(cases, 'total_tokens').median == Decimal(a) + Decimal('.5')
    huge = 10 ** 400
    stats = resource_summary([_thesis_case(0, total_tokens=huge),
                              _thesis_case(2, total_tokens=huge + 1)], 'total_tokens')
    assert stats.median == Decimal(str(huge) + '.5')
    model = _thesis_model([_thesis_case(0, total_tokens=huge, agent_seconds=1e308),
                          _thesis_case(2, total_tokens=huge + 1, agent_seconds=1e308)])
    charts = render_thesis_charts(model)
    for name in FIGURE_NAMES[1:]:
        data = charts[f'charts/{name}.svg']
        assert 'inf' not in _svg_text(data).lower()
        assert all(0 <= float(r.attrib['width']) <= 400 for r in ET.fromstring(data).findall('.//s:rect[@class="filled"]', SVG_NS))
