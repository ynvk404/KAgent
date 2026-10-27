"""Offline evaluation v2: one record with independent execution and assessment status."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

from benchmarks.common.contracts import (CLASSES, EVALUATION_SCHEMA, EvaluationRecord, GroundTruth,
    OperationalCaseInput, RunManifest, RuntimeSettings, decode, digest, write_new, read_json)
from benchmarks.common.metrics import distribution
from benchmarks.common.recorder import Recorder, read_records, validate_lifecycle
from .assessment import assessment_metrics, confusion, inspect_assessment, read_bound_execution
from .bindings import EVALUATOR, evaluation_identity, orphan_binding, validate_recorded_evaluations
from .storage import evaluation_root, resolve_run


def summarize(records: list[dict], truth: dict, executions: dict, histories: dict) -> dict:
    def group(ids):
        chosen = [r for r in records if r['case_id'] in ids]
        timing = defaultdict(list)
        for cid in ids:
            ex = executions.get(cid)
            finish = next((e for e in histories[cid] if e['kind'] == 'runtime-finished'), None)
            if finish and ex and ex.metrics and ex.metrics['agent_seconds'] is not None:
                timing[finish['status']].append(ex.metrics['agent_seconds'])
        return {**assessment_metrics(chosen),
                'agent_seconds_by_status': {k: distribution(v) for k, v in sorted(timing.items())}}
    return {'overall': group(set(truth)),
            'classes': {cls: group({k for k, v in truth.items() if v.vulnerability_class == cls}) for cls in CLASSES},
            'strata': {f'{cls}/{"vulnerable" if vulnerable else "safe"}': group({k for k, v in truth.items()
                       if v.vulnerability_class == cls and v.expected_vulnerable == vulnerable})
                       for cls in CLASSES for vulnerable in (True, False)}}


def evaluate(directory: Path, *, publish=True) -> dict:
    directory = resolve_run(directory)
    for path in evaluation_root(directory).glob('evaluation-*.json'):
        previous = read_json(path)
        if (not isinstance(previous, dict) or previous.get('schema_version') != EVALUATION_SCHEMA
                or previous.get('evaluator_version') != EVALUATOR):
            raise ValueError('incompatible historical evaluation; v2 never rescores or migrates v1')
    manifest = decode(RunManifest, read_json(directory / 'manifest.json'))
    if manifest.runtime is None:
        raise ValueError('run has no runtime settings')
    settings = decode(RuntimeSettings, manifest.runtime)
    if (directory / 'events.jsonl').is_symlink() or (directory / 'results').is_symlink():
        raise ValueError('untrusted lifecycle/results namespace')
    rows, partial = read_records(directory / 'events.jsonl')
    histories = validate_lifecycle(rows)
    truths = {r['case_id']: decode(GroundTruth, r) for r in manifest.truth}
    ops = {r['case_id']: decode(OperationalCaseInput, r) for r in manifest.operational}
    if ([e['case_id'] for e in rows if e['kind'] == 'scheduled'] != manifest.execution_order
            or set(histories) != set(truths)):
        raise ValueError('schedule is incomplete/unexpected or differs from manifest')
    if any(e['run_id'] != manifest.run_id for e in rows):
        raise ValueError('wrong run lifecycle')
    expected_results = set()
    orphan_exports = []
    executions = {}
    records = []
    for cid in manifest.execution_order:
        events = histories[cid]
        if events[0]['data'].get('operational_hash') != digest(asdict(ops[cid])):
            raise ValueError('scheduled operational hash mismatch')
        if events[0]['data'].get('manifest_hash') != digest(asdict(manifest)):
            raise ValueError('scheduled manifest hash mismatch')
        finish = next((e for e in events if e['kind'] == 'runtime-finished'), None)
        start = next((e for e in events if e['kind'] == 'started'), None)
        path = directory / 'results' / f'{cid}.json'
        if not finish:
            if start and (path.exists() or path.is_symlink()):
                expected_results.add(path)
                orphan_exports.append(orphan_binding(directory, cid, manifest.run_id, start['execution_id']))
            previous = next((e for e in events if e['kind'] == 'evaluated'), None)
            reason = ('missing-parent-receipt' if start else
                      previous['data']['assessment_reason'] if previous else 'not-run')
            records.append(asdict(EvaluationRecord(cid, 'started' if start else 'not-run',
                'unavailable', reason, None, None)))
            continue
        data = finish['data']
        ref = data.get('result_ref')
        execution, error = None, None
        if ref:
            if ref != f'results/{cid}.json':
                raise ValueError('unexpected result artifact reference')
            expected_results.add(path)
            execution, error = read_bound_execution(path, run_id=manifest.run_id, case_id=cid,
                execution_id=finish['execution_id'], parent_status=finish['status'],
                expected_hash=data.get('result_sha256'))
            if execution is not None:
                executions[cid] = execution
        records.append(asdict(inspect_assessment(cid, execution, execution_status=finish['status'],
            run_id=manifest.run_id, op=ops[cid], settings=settings, truth=truths[cid], export_error=error)))
    if set((directory / 'results').glob('*.json')) - expected_results:
        raise ValueError('unexpected/duplicate final execution export')
    identity = evaluation_identity(manifest, rows, partial, orphan_exports)
    validate_recorded_evaluations(records, histories, identity)
    report = {'schema_version': EVALUATION_SCHEMA, 'evaluator_version': EVALUATOR,
              'evaluation_identity': identity, 'run_id': manifest.run_id,
              'incomplete': partial or any(not any(e['kind'] == 'runtime-finished' for e in h) for h in histories.values()),
              'partial_tail_ignored': partial, 'records': records,
              'metrics': summarize(records, truths, executions, histories)}
    if orphan_exports:
        report['orphan_exports'] = orphan_exports
    if publish:
        path = evaluation_root(directory) / f'evaluation-{identity}.json'
        if path.exists():
            if read_json(path) != report:
                raise ValueError('conflicting evaluation artifact')
        else:
            write_new(path, report)
        if not partial:
            recorder = Recorder(directory / 'events.jsonl', manifest.run_id)
            for record in records:
                cid = record['case_id']
                if any(e['kind'] == 'evaluated' for e in histories[cid]):
                    continue
                last = histories[cid][-1]
                recorder.append('evaluated', cid, record['execution_status'], execution_id=last['execution_id'],
                                data={**record, 'evaluation_identity': identity})
    return report
