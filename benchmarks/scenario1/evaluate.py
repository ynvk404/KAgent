"""Offline evaluator: accepted Agent labels joined with external truth after execution."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
import json
from pathlib import Path

from benchmarks.common.contracts import (CaseExecution, CLASSES, EvaluationRecord, GroundTruth,
    OperationalCaseInput, PARTITIONS, RunManifest, RuntimeSettings, decode, digest, file_hash, write_new, read_json)
from benchmarks.common.metrics import distribution
from benchmarks.common.recorder import Recorder, read_records, validate_lifecycle
from .canonical import inspect_case_evidence, inspect_export
from .runtime import candidate_arguments

EVALUATOR = 'offline-agent-assessment-v1'


def confusion(vulnerable: bool, outcome: str) -> str:
    if type(vulnerable) is not bool or outcome not in {'confirmed', 'not-confirmed'}:
        raise ValueError('unscorable truth/outcome')
    return ('TP' if vulnerable else 'FP') if outcome == 'confirmed' else ('FN' if vulnerable else 'TN')


def summarize(records: list[dict], truth: dict, executions: dict, histories: dict) -> dict:
    def group(ids):
        chosen = [r for r in records if r['case_id'] in ids]
        counts = Counter(r['partition'] for r in chosen)
        matrix = Counter(r['confusion'] for r in chosen if r['confusion'])
        def ratio(n, d):
            return n / d if d else None
        timing = defaultdict(list)
        for cid in ids:
            ex = executions.get(cid)
            finish = next((e for e in histories[cid] if e['kind'] == 'runtime-finished'), None)
            if finish and ex and ex.metrics and ex.metrics['agent_seconds'] is not None:
                # A parent crash/timeout overrides the worker's diagnostic status.
                timing[finish['status']].append(ex.metrics['agent_seconds'])
        return {'scheduled': len(chosen), 'started': sum(any(e['kind'] == 'started' for e in histories[cid]) for cid in ids),
                'completed': sum(any(e['kind'] == 'runtime-finished' and e['status'] == 'completed' for e in histories[cid]) for cid in ids),
                **{p: counts[p] for p in PARTITIONS}, **{k: matrix[k] for k in ('TP', 'FP', 'TN', 'FN')},
                'recall': ratio(matrix['TP'], matrix['TP'] + matrix['FN']),
                'fpr': ratio(matrix['FP'], matrix['FP'] + matrix['TN']),
                'precision': ratio(matrix['TP'], matrix['TP'] + matrix['FP']),
                'evaluability': ratio(counts['evaluable'], len(chosen)),
                'reasons': dict(Counter(r['reason'] for r in chosen if r['partition'] != 'evaluable')),
                'agent_seconds_by_status': {k: distribution(v) for k, v in sorted(timing.items())}}
    return {'overall': group(set(truth)), 'classes': {cls: group({k for k, v in truth.items() if v.vulnerability_class == cls}) for cls in CLASSES},
            'strata': {f'{cls}/{"vulnerable" if vulnerable else "safe"}': group({k for k, v in truth.items() if v.vulnerability_class == cls and v.expected_vulnerable == vulnerable})
                       for cls in CLASSES for vulnerable in (True, False)}}


def evaluate(directory: Path, *, publish=True) -> dict:
    directory = directory.resolve()
    manifest = decode(RunManifest, read_json(directory / 'manifest.json'))
    if manifest.runtime is None:
        raise ValueError('run has no runtime settings')
    settings = decode(RuntimeSettings, manifest.runtime)
    rows, partial = read_records(directory / 'events.jsonl')
    histories = validate_lifecycle(rows)
    truths = {r['case_id']: decode(GroundTruth, r) for r in manifest.truth}
    ops = {r['case_id']: decode(OperationalCaseInput, r) for r in manifest.operational}
    schedule = [e['case_id'] for e in rows if e['kind'] == 'scheduled']
    if schedule != manifest.execution_order or set(histories) != set(truths):
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
        if not finish:
            path = directory / 'results' / f'{cid}.json'
            if start and (path.exists() or path.is_symlink()):
                # Export precedes the parent's completion append. A torn export
                # is diagnostic only; complete exports must match the start.
                try:
                    raw = read_json(path)
                except (json.JSONDecodeError, UnicodeError):
                    export_state = 'incomplete'
                else:
                    orphan = decode(CaseExecution, raw)
                    if (orphan.run_id, orphan.case_id, orphan.execution_id) != (manifest.run_id, cid, start['execution_id']):
                        raise ValueError('orphan execution export identity mismatch')
                    export_state = 'diagnostic'
                expected_results.add(path)
                orphan_exports.append({'case_id': cid, 'execution_id': start['execution_id'],
                    'result_ref': str(path.relative_to(directory)), 'result_sha256': file_hash(path),
                    'export_state': export_state})
                # No orphan enters executions: neither scoring nor timing can
                # infer a completed execution from an uncommitted export.
            previous_eval = next((e for e in events if e['kind'] == 'evaluated'), None)
            partition = 'execution-failed' if start else 'not-run'
            reason = 'interrupted-after-start' if start else (previous_eval['data']['reason'] if previous_eval else 'interrupted-before-start')
            records.append(asdict(EvaluationRecord(cid, partition, reason, None)))
            continue
        data = finish['data']
        result_ref = data.get('result_ref')
        ex = None
        export_error = None
        if result_ref:
            if result_ref != f'results/{cid}.json':
                raise ValueError('unexpected result artifact reference')
            expected_results.add(directory / result_ref)
            try:
                path = directory / result_ref
                if path.is_symlink() or file_hash(path) != data.get('result_sha256'):
                    raise ValueError('result artifact hash mismatch')
                ex = decode(CaseExecution, read_json(path))
                if (ex.run_id, ex.case_id, ex.execution_id) != (manifest.run_id, cid, finish['execution_id']):
                    raise ValueError('execution export identity mismatch')
                # Parent may terminate/crash a worker after it writes a diagnostic export.
                if finish['status'] == 'completed' and ex.status != finish['status']:
                    raise ValueError('execution status conflict')
                executions[cid] = ex
            except (ValueError, TypeError, KeyError, OSError) as err:
                export_error = str(err)
        if finish['status'] != 'completed':
            records.append(asdict(EvaluationRecord(cid, 'execution-failed', finish['status'], None)))
            continue
        if export_error or ex is None:
            records.append(asdict(EvaluationRecord(cid, 'invalid-result', export_error or 'missing-execution-export', None)))
            continue
        if ex.result is None:
            records.append(asdict(EvaluationRecord(cid, 'unresolved', 'missing-canonical-result', None)))
            continue
        outcome, error = inspect_export(ex.result, run_id=manifest.run_id, case_id=cid, execution_id=ex.execution_id,
                            candidate_args=candidate_arguments(ops[cid], settings),
                            target=settings.target.rstrip('/') + settings.context_path.rstrip('/'))
        if not error and outcome in {'confirmed', 'not-confirmed'}:
            error = inspect_case_evidence(ex.result, op=ops[cid],
                                          candidate_args=candidate_arguments(ops[cid], settings))
        for key in ('session_id', 'candidate_id', 'objective_id'):
            if ex.runtime_metadata.get(key) != ex.result.get(key):
                error = f'runtime/{key} mismatch'
        if error:
            record = EvaluationRecord(cid, 'invalid-result', error, None)
        elif outcome is None:
            record = EvaluationRecord(cid, 'unresolved', 'missing-canonical-result', None)
        elif outcome not in {'confirmed', 'not-confirmed'}:
            record = EvaluationRecord(cid, 'unresolved', outcome, None)
        else:
            record = EvaluationRecord(cid, 'evaluable', 'accepted-agent-assessment', confusion(truths[cid].expected_vulnerable, outcome))
        records.append(asdict(record))
    if set((directory / 'results').glob('*.json')) - expected_results:
        raise ValueError('unexpected/duplicate final execution export')
    identity_input = [EVALUATOR, asdict(manifest), [e for e in rows if e['kind'] != 'evaluated'], partial]
    if orphan_exports:
        identity_input.append(orphan_exports)
    identity = digest(identity_input)
    for record in records:
        previous = next((e for e in histories[record['case_id']] if e['kind'] == 'evaluated'), None)
        if previous:
            data = previous['data']
            if data.get('evaluation_identity') not in {identity, 'fail-fast-v1'}:
                raise ValueError('conflicting evaluation identity/version')
            if data.get('partition') != record['partition'] or data.get('reason') != record['reason']:
                raise ValueError('conflicting recorded evaluation')
            if data.get('evaluation_identity') != 'fail-fast-v1' and any(data.get(k) != v for k, v in record.items()):
                raise ValueError('conflicting evaluation record fields')
    report = {'schema_version': 1, 'evaluator_version': EVALUATOR, 'evaluation_identity': identity,
              'run_id': manifest.run_id, 'incomplete': partial or any(not any(e['kind'] == 'runtime-finished' for e in h) for h in histories.values()),
              'partial_tail_ignored': partial, 'records': records,
              'metrics': summarize(records, truths, executions, histories)}
    if orphan_exports:
        report['orphan_exports'] = orphan_exports
    if sum(report['metrics']['overall'][p] for p in PARTITIONS) != len(truths):
        raise ValueError('evaluation partition does not account for schedule')
    if publish:
        path = directory / f'evaluation-{identity}.json'
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
                    continue  # v1 immutable history; no double counting/evaluation records
                last = histories[cid][-1]
                recorder.append('evaluated', cid, last['status'], execution_id=last['execution_id'],
                                data={**record, 'evaluation_identity': identity})
    return report
