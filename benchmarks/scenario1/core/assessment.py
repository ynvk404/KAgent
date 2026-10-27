"""Current offline assessment contract, independent of parent execution success."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from benchmarks.common.contracts import (ASSESSMENT_STATUSES, EvaluationRecord, CaseExecution,
    GroundTruth, OperationalCaseInput, RuntimeSettings, decode, file_hash, read_json)
from .canonical import inspect_case_evidence, inspect_export, projection
from .runtime import candidate_arguments


def read_bound_execution(path: Path, *, run_id: str, case_id: str, execution_id: str,
                         parent_status: str, expected_hash: str | None) -> tuple[CaseExecution | None, str | None]:
    try:
        if path.is_symlink() or path.parent.is_symlink() or file_hash(path) != expected_hash:
            raise ValueError('result artifact hash mismatch')
        execution = decode(CaseExecution, read_json(path))
        if (execution.run_id, execution.case_id, execution.execution_id) != (run_id, case_id, execution_id):
            raise ValueError('execution export identity mismatch')
        if parent_status == 'completed' and execution.status != 'completed':
            raise ValueError('execution status conflict')
        return execution, None
    except (ValueError, TypeError, KeyError, OSError) as err:
        return None, str(err)


def confusion(vulnerable: bool, outcome: str) -> str:
    if type(vulnerable) is not bool or outcome not in {'confirmed', 'not-confirmed'}:
        raise ValueError('unscorable truth/outcome')
    return ('TP' if vulnerable else 'FP') if outcome == 'confirmed' else ('FN' if vulnerable else 'TN')


def inspect_assessment(case_id: str, execution: CaseExecution | None, *, execution_status: str,
                       run_id: str, op: OperationalCaseInput, settings: RuntimeSettings,
                       truth: GroundTruth, export_error: str | None = None) -> EvaluationRecord:
    def record(status, reason, outcome=None, label=None):
        return EvaluationRecord(case_id, execution_status, status, reason, outcome, label)

    if export_error:
        return record('invalid', export_error)
    if execution is None:
        return record('unavailable', 'missing-execution-export')
    if execution.status in {'scheduled', 'started', 'not-run'}:
        return record('invalid', 'nonfinal-execution-export')
    raw = execution.result
    if raw is None:
        return record('unavailable', 'missing-canonical-result')
    args = candidate_arguments(op, settings)
    outcome, error = inspect_export(raw, run_id=run_id, case_id=case_id,
        execution_id=execution.execution_id, candidate_args=args,
        target=settings.target.rstrip('/') + settings.context_path.rstrip('/'))
    if not error and outcome in {'confirmed', 'not-confirmed'}:
        error = inspect_case_evidence(raw, op=op, candidate_args=args)
        if not error:
            state = projection(raw['workflow'])
            candidate = state.candidates[raw['candidate_id']]
            latest = state.latest_result(candidate.id)
            if (candidate.status not in {'validated', 'dismissed'} or latest is None
                    or state.attempts.get(latest.attempt_id or '', {}).get('status') != 'completed'
                    or any(a.get('candidate_id') == candidate.id and a.get('status') == 'active'
                           for a in state.attempts.values())):
                error = 'assessment-attempt-incomplete'
    for key in ('session_id', 'candidate_id', 'objective_id'):
        if execution.runtime_metadata.get(key) != raw.get(key):
            error = f'runtime/{key} mismatch'
    if error:
        return record('invalid', error)
    if outcome is None:
        return record('unavailable', 'missing-canonical-result')
    if outcome not in {'confirmed', 'not-confirmed'}:
        return record('unresolved', outcome, outcome)
    return record('accepted', 'accepted-agent-assessment', outcome, confusion(truth.expected_vulnerable, outcome))


def assessment_metrics(records: list[dict]) -> dict:
    """Every scheduled case contributes once to each independent dimension."""
    counts = Counter(r['assessment_status'] for r in records)
    matrix = Counter(r['assessment_confusion'] for r in records if r['assessment_confusion'])
    statuses = Counter(r['execution_status'] for r in records)
    n = len(records)
    ratio = lambda a, b: a / b if b else None
    return {
        'scheduled': n, 'started': n - statuses['not-run'], 'completed': statuses['completed'],
        'execution_failed': n - statuses['not-run'] - statuses['completed'], 'not_run': statuses['not-run'],
        **{k: matrix[k] for k in ('TP', 'FP', 'TN', 'FN')},
        'precision': ratio(matrix['TP'], matrix['TP'] + matrix['FP']),
        'recall': ratio(matrix['TP'], matrix['TP'] + matrix['FN']),
        'fpr': ratio(matrix['FP'], matrix['FP'] + matrix['TN']),
        'assessment_accepted': counts['accepted'], 'assessment_coverage': ratio(counts['accepted'], n),
        'completion_rate': ratio(statuses['completed'], n),
        'execution_status_counts': dict(sorted(statuses.items())),
        'assessment_status_counts': {k: counts[k] for k in ASSESSMENT_STATUSES},
        'assessment_reasons': dict(Counter(r['assessment_reason'] for r in records if r['assessment_status'] != 'accepted')),
    }
