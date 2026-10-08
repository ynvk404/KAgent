"""Read and validate existing run artifacts without invoking the evaluator."""
from __future__ import annotations

from dataclasses import asdict
import math
from pathlib import Path
import re
from typing import Any

from benchmarks.common.contracts import (CLASSES, PARTITIONS, CaseExecution, EvaluationRecord,
    RunManifest, decode, digest, file_hash, identifier, read_json)
from benchmarks.common.recorder import read_records, validate_lifecycle
from benchmarks.scenario1.core.classification import read_run_designation
from benchmarks.scenario1.core.bindings import (EVALUATOR, evaluation_identity, orphan_binding,
    validate_recorded_evaluations)
from .model import ReportModel


def _semantic_text(value: Any, pattern: str, forbidden: tuple[str, ...]) -> str | None:
    # A field-specific format, plus known fixture aliases. Arbitrary labels never pass.
    if (not isinstance(value, str) or not re.fullmatch(pattern, value)
            or any(item.casefold() in value.casefold() for item in forbidden)):
        return None
    return value


def presentation_id(kind: str, value: str) -> str:
    """Stable domain-separated pseudonym; raw identities remain internal for validation."""
    return kind + '-' + digest(['scenario1-report-' + kind + '-v1', value])


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


_REASONS = frozenset({
    'accepted-agent-assessment', 'interrupted-after-start', 'interrupted-before-start',
    'fail-fast', 'missing-execution-export', 'missing-canonical-result',
    'insufficient-evidence', 'browser-required', 'budget-exhausted',
    'not-confirmed', 'confirmed', 'invalid-result',
    'blocked', 'deferred', 'authorization-required', 'timeout', 'crashed',
    'runtime-error', 'provider-error', 'setup-error',
    *('evidence-case-binding:' + name for name in (
        'unsupported-input-component', 'malformed-source', 'unsupported-evidence-source',
        'missing-native-http-evidence', 'candidate-ownership-mismatch',
        'missing-semantic-request-binding', 'wrong-input-name', 'wrong-input-location',
        'wrong-input-component', 'request-identity-mismatch', 'invalid-evidence-url',
        'wrong-http-method', 'wrong-route', 'missing-input-slot', 'malformed-input-slot',
        'ambiguous-input-slot', 'missing-name-mutation-semantics',
        'invalid-name-mutation-baseline', 'unproven-name-mutation',
        'designated-input-not-mutated', 'malformed-canonical-evidence')),
})


def _safe_reason(value: Any) -> str:
    # Reasons can contain exception text. A closed vocabulary prevents fixture,
    # URL, credential, and response-body leakage through that channel.
    return value if isinstance(value, str) and value in _REASONS else '[redacted]'


def _safe_identity(value: Any) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) else None


def _number(value: Any) -> int | float | None:
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def _counter(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _case_metrics(execution: CaseExecution | None) -> dict[str, Any]:
    output: dict[str, Any] = {key: None for key in (
        'agent_seconds', 'http_admitted', 'http_dispatch_attempts', 'llm_calls',
        'tool_proposed', 'tool_executed', 'tool_result_events', 'tool_blocked',
        'tool_failed', 'input_tokens', 'output_tokens', 'total_tokens',
        'input_tokens_complete', 'output_tokens_complete', 'total_tokens_complete')}
    if execution is None or execution.metrics is None:
        return output
    metrics = execution.metrics
    output['agent_seconds'] = _number(metrics.get('agent_seconds'))
    output['http_admitted'] = _counter(metrics.get('http_admitted'))
    output['http_dispatch_attempts'] = _counter(metrics.get('http_dispatch_attempts'))
    llm = _mapping(metrics.get('llm'))
    tools = _mapping(metrics.get('tools'))
    output['llm_calls'] = _counter(llm.get('total_llm_calls'))
    for target, source in (('tool_proposed', 'proposed'), ('tool_executed', 'executed'),
                           ('tool_result_events', 'result_events'), ('tool_blocked', 'blocked'),
                           ('tool_failed', 'failed')):
        output[target] = _counter(tools.get(source))
    tokens = _mapping(llm.get('tokens'))
    for name in ('input_tokens', 'output_tokens', 'total_tokens'):
        token = _mapping(tokens.get(name))
        complete = token.get('complete')
        output[f'{name}_complete'] = complete if type(complete) is bool else None
        output[name] = _counter(token.get('total')) if complete is True else None
    return output


def _diagnostic(path: Path, run_id: str, case_id: str, execution_id: str,
                expected_hash: Any) -> CaseExecution | None:
    try:
        raw = read_json(path)
    except (ValueError, UnicodeError, OSError):
        return None
    # Binding conflicts are fatal even in otherwise unusable diagnostics. Keep
    # this check outside the decode/hash error path; never mask another execution.
    for binding in (raw, raw.get('result') if isinstance(raw, dict) else None):
        if isinstance(binding, dict):
            for key, expected in (('run_id', run_id), ('case_id', case_id), ('execution_id', execution_id)):
                if key in binding and binding[key] != expected:
                    raise ValueError('result/run/case/execution identity mismatch')
    try:
        if file_hash(path) != expected_hash:
            return None
        return decode(CaseExecution, raw)
    except (ValueError, UnicodeError, TypeError, KeyError, AttributeError, OverflowError, OSError):
        # Only diagnostic parsing is recoverable. Lifecycle/identity checks above
        # and canonical binding validation below are deliberately not caught.
        return None


def _validate_metrics(metrics: dict, records: dict[str, EvaluationRecord],
                      truths: dict, histories: dict) -> None:
    counts = ('scheduled', 'started', 'completed', *PARTITIONS, 'TP', 'TN', 'FP', 'FN')
    groups = [('overall', metrics['overall'], list(records))]
    if set(metrics['classes']) != set(CLASSES):
        raise ValueError('unexpected evaluator classes')
    for cls in CLASSES:
        groups.append((cls, metrics['classes'][cls],
                       [cid for cid in records if truths[cid]['vulnerability_class'] == cls]))
    if 'strata' in metrics:
        strata = metrics['strata']
        keys = {f'{cls}/{label}' for cls in CLASSES for label in ('vulnerable', 'safe')}
        if not isinstance(strata, dict) or set(strata) != keys:
            raise ValueError('invalid evaluator strata')
        for cls in CLASSES:
            for vulnerable, label in ((True, 'vulnerable'), (False, 'safe')):
                key = f'{cls}/{label}'
                groups.append((key, strata[key], [cid for cid in records
                    if truths[cid]['vulnerability_class'] == cls
                    and truths[cid]['expected_vulnerable'] is vulnerable]))
    for label, group, ids in groups:
        if not isinstance(group, dict) or any(type(group.get(k)) is not int or group[k] < 0 for k in counts):
            raise ValueError('invalid evaluator count')
        expected = {'scheduled': len(ids),
                    'started': sum(any(e['kind'] == 'started' for e in histories[cid]) for cid in ids),
                    'completed': sum(any(e['kind'] == 'runtime-finished' and e['status'] == 'completed'
                                         for e in histories[cid]) for cid in ids),
                    **{p: sum(records[cid].partition == p for cid in ids) for p in PARTITIONS},
                    **{k: sum(records[cid].confusion == k for cid in ids) for k in ('TP', 'TN', 'FP', 'FN')}}
        if any(group[k] != expected[k] for k in counts):
            raise ValueError('evaluator count/record/lifecycle mismatch')
        if sum(group[p] for p in PARTITIONS) != group['scheduled'] or sum(group[k] for k in ('TP', 'TN', 'FP', 'FN')) != group['evaluable']:
            raise ValueError('evaluator partition/confusion total mismatch')
        fractions = {'recall': (group['TP'], group['TP'] + group['FN']),
                     'precision': (group['TP'], group['TP'] + group['FP']),
                     'fpr': (group['FP'], group['FP'] + group['TN']),
                     'evaluability': (group['evaluable'], group['scheduled'])}
        for key, (numerator, denominator) in fractions.items():
            if key not in group:
                raise ValueError('missing evaluator rate')
            value = group[key]
            expected_rate = numerator / denominator if denominator else None
            if (value is not None and (type(value) not in (int, float) or not math.isfinite(value))
                    or value != expected_rate):
                raise ValueError('evaluator rate/denominator mismatch')
    if any(metrics['overall'][k] != sum(metrics['classes'][cls][k] for cls in CLASSES) for k in counts):
        raise ValueError('overall/class evaluator count mismatch')


def _select_evaluation(directory: Path, selected: Path | None) -> Path:
    if selected is not None:
        path = directory / selected if selected.parent == Path('.') else selected
        if path.is_symlink():
            raise ValueError('untrusted evaluation artifact')
        path = path.resolve()
        if path.parent.resolve() != directory.resolve() or not path.name.startswith('evaluation-') or path.suffix != '.json':
            raise ValueError('evaluation must be an evaluation artifact in the run directory')
        return path
    choices = sorted(directory.glob('evaluation-*.json'))
    if len(choices) != 1:
        raise ValueError('no evaluation artifact found' if not choices else
                         'multiple evaluation artifacts; specify --evaluation')
    if choices[0].is_symlink():
        raise ValueError('untrusted evaluation artifact')
    return choices[0]


def load_report(directory: Path, evaluation: Path | None = None) -> ReportModel:
    directory = directory.resolve()
    manifest_path = directory / 'manifest.json'
    manifest = decode(RunManifest, read_json(manifest_path))
    if manifest.runtime is None:
        raise ValueError('run has no runtime settings')
    designation = read_run_designation(directory)  # verifies both manifest bindings
    evaluation_path = _select_evaluation(directory, evaluation)
    raw_evaluation = read_json(evaluation_path)
    if (not isinstance(raw_evaluation, dict) or type(raw_evaluation.get('schema_version')) is not int
            or raw_evaluation.get('schema_version') != 1):
        raise ValueError('invalid evaluation artifact')
    if raw_evaluation.get('evaluator_version') != EVALUATOR:
        raise ValueError('unsupported evaluator version')
    if raw_evaluation.get('run_id') != manifest.run_id:
        raise ValueError('evaluation/run identity mismatch')
    identity = _safe_identity(raw_evaluation.get('evaluation_identity'))
    if identity is None or evaluation_path.name != f'evaluation-{identity}.json':
        raise ValueError('evaluation identity mismatch')
    raw_records = raw_evaluation.get('records')
    if not isinstance(raw_records, list):
        raise ValueError('missing evaluation records')
    records: dict[str, EvaluationRecord] = {}
    for raw in raw_records:
        record = decode(EvaluationRecord, raw)
        identifier(record.case_id)
        if (record.partition not in PARTITIONS or not isinstance(record.reason, str)
                or (record.partition == 'evaluable' and record.confusion not in ('TP', 'TN', 'FP', 'FN'))
                or (record.partition != 'evaluable' and record.confusion is not None)):
            raise ValueError('invalid evaluation record values')
        if record.case_id in records:
            raise ValueError('duplicate evaluation case')
        records[record.case_id] = record
    schedule = manifest.execution_order
    if set(records) != set(schedule):
        raise ValueError('evaluation case set differs from manifest schedule')
    if (directory / 'events.jsonl').is_symlink() or (directory / 'results').is_symlink():
        raise ValueError('untrusted lifecycle/results namespace')
    if (directory / 'results').exists() and not (directory / 'results').is_dir():
        raise ValueError('invalid results namespace')
    rows, partial = read_records(directory / 'events.jsonl')
    histories = validate_lifecycle(rows)
    scheduled = [row['case_id'] for row in rows if row['kind'] == 'scheduled']
    if scheduled != schedule or set(histories) != set(schedule) or any(row['run_id'] != manifest.run_id for row in rows):
        raise ValueError('lifecycle schedule/run mismatch')
    if list(records) != schedule:
        raise ValueError('evaluation record order differs from manifest schedule')
    metrics = raw_evaluation.get('metrics')
    if not isinstance(metrics, dict) or not isinstance(metrics.get('overall'), dict) or not isinstance(metrics.get('classes'), dict):
        raise ValueError('missing canonical evaluator metrics')
    for cls in CLASSES:
        if not isinstance(metrics['classes'].get(cls), dict):
            raise ValueError('missing class evaluator metrics')
    truths = {row['case_id']: row for row in manifest.truth}
    cases = []
    expected_results: set[Path] = set()
    orphan_exports = []
    manifest_identity = digest(asdict(manifest))
    operations = {row['case_id']: row for row in manifest.operational}
    for case_id in schedule:
        record = records[case_id]
        history = histories[case_id]
        finish = next((row for row in history if row['kind'] == 'runtime-finished'), None)
        start = next((row for row in history if row['kind'] == 'started'), None)
        if (history[0]['data'].get('manifest_hash') != manifest_identity
                or history[0]['data'].get('operational_hash') != digest(operations[case_id])):
            raise ValueError('scheduled manifest/operational hash mismatch')
        path = directory / 'results' / f'{case_id}.json'
        execution = None
        if not finish:
            expected_partition = 'execution-failed' if start else 'not-run'
            previous = next((row for row in history if row['kind'] == 'evaluated'), None)
            expected_reason = ('interrupted-after-start' if start else
                               previous['data']['reason'] if previous else 'interrupted-before-start')
            if (record.partition, record.reason) != (expected_partition, expected_reason):
                raise ValueError('evaluation/parent interruption mismatch')
            if start and (path.exists() or path.is_symlink()):
                expected_results.add(path)
                orphan_exports.append(orphan_binding(directory, case_id, manifest.run_id, start['execution_id']))
            # Orphans never supply worker metrics or imply completion.
        else:
            if finish['status'] != 'completed':
                if (record.partition, record.reason) != ('execution-failed', finish['status']):
                    raise ValueError('evaluation/parent failure mismatch')
            elif record.partition in {'execution-failed', 'not-run'}:
                raise ValueError('evaluation/parent completion mismatch')
            ref = finish['data'].get('result_ref')
            if ref:
                if ref != f'results/{case_id}.json':
                    raise ValueError('unexpected result reference')
                expected_results.add(path)
                execution = _diagnostic(path, manifest.run_id, case_id, finish['execution_id'],
                                        finish['data'].get('result_sha256'))
            if record.partition in {'evaluable', 'unresolved'} and (
                    execution is None or execution.status != 'completed'):
                raise ValueError('missing/unusable result for evaluated case')
        if record.partition == 'evaluable' and execution and (
                execution.result is None or execution.result.get('accepted_at_freeze') is not True
                or execution.result.get('result_id') is None):
            raise ValueError('missing accepted canonical export for evaluable case')
        summary = finish['data'].get('canonical_summary') if finish else None
        outcome = summary.get('outcome') if isinstance(summary, dict) else None
        outcome = outcome if isinstance(outcome, str) else None
        truth = truths[case_id]
        if record.partition == 'evaluable':
            if record.reason != 'accepted-agent-assessment':
                raise ValueError('invalid evaluable reason')
            allowed = {'TP', 'FN'} if truth['expected_vulnerable'] else {'FP', 'TN'}
            if record.confusion not in allowed:
                raise ValueError('evaluation truth/confusion mismatch')
            if (isinstance(summary, dict) and summary.get('outcome') is not None
                    and outcome not in {'confirmed', 'not-confirmed'}):
                raise ValueError('unscorable provided outcome for evaluable case')
            if outcome in {'confirmed', 'not-confirmed'} and ((outcome == 'confirmed') != (record.confusion in {'TP', 'FP'})):
                raise ValueError('evaluation outcome/confusion mismatch')
        cases.append({
            'case_id': presentation_id('case', case_id), 'vulnerability_class': truth['vulnerability_class'],
            'expected_vulnerable': truth['expected_vulnerable'],
            'agent_outcome': outcome if outcome in {
                'confirmed', 'not-confirmed', 'blocked', 'insufficient-evidence',
                'deferred', 'browser-required', 'authorization-required'} else None,
            'evaluator_partition': record.partition,
            'evaluator_reason': _safe_reason(record.reason), 'confusion': record.confusion,
            'final_status': finish['status'] if finish else None,
            'worker_status': execution.status if execution else None,
            'wall_seconds': _number(finish['data'].get('wall_seconds')) if finish else None,
            **_case_metrics(execution),
        })
    if set((directory / 'results').glob('*.json')) - expected_results:
        raise ValueError('unexpected/duplicate final execution export')
    expected_identity = evaluation_identity(manifest, rows, partial, orphan_exports)
    if identity != expected_identity:
        raise ValueError('stale evaluation identity/content mismatch')
    if raw_evaluation.get('orphan_exports', []) != orphan_exports:
        raise ValueError('orphan diagnostic binding mismatch')
    incomplete = partial or any(not any(row['kind'] == 'runtime-finished' for row in h) for h in histories.values())
    if (type(raw_evaluation.get('partial_tail_ignored')) is not bool
            or raw_evaluation['partial_tail_ignored'] != partial
            or type(raw_evaluation.get('incomplete')) is not bool
            or raw_evaluation['incomplete'] != incomplete):
        raise ValueError('evaluation recovery state mismatch')
    validate_recorded_evaluations(raw_records, histories, identity)
    _validate_metrics(metrics, records, truths, histories)
    runtime = manifest.runtime or {}
    fixture_values = tuple(value for op in manifest.operational for value in (
        [pair[1] for pair in op['query'] + op['body']] + list(op['headers'].values()) + list(op['cookies'].values()))
        if value)
    provider_models = sorted({(p, m) for case_id in schedule for metadata in [
        _mapping(next((row for row in histories[case_id] if row['kind'] == 'runtime-finished'),
                      {}).get('data', {}).get('runtime_metadata'))]
        for p, m in [(metadata.get('provider'), metadata.get('model'))]
        if isinstance(p, str) and isinstance(m, str)})
    repro = _mapping(manifest.reproducibility)
    semantic = lambda value, pattern: _semantic_text(value, pattern, fixture_values)
    def commit(value):
        validated = semantic(value, r'[0-9a-f]{40}')
        return presentation_id('commit', validated) if validated is not None else None
    metadata = {
        'report_schema_version': 1, 'run_id': presentation_id('run', manifest.run_id),
        'identifier_representation': 'sha256-domain-separated-v1',
        'classification': designation.classification, 'classification_qualifier': designation.qualifier,
        'classification_declared': designation.declared,
        'manifest_sha256': file_hash(manifest_path), 'manifest_identity': digest(asdict(manifest)),
        'evaluation_identity': identity, 'evaluator_version': EVALUATOR,
        'incomplete': incomplete, 'partial_tail_ignored': partial,
        'mode': manifest.mode, 'seed': manifest.seed,
        'dataset': {'version': semantic(manifest.dataset.get('version'), r'1\.2'),
                    'git_commit': commit(manifest.dataset.get('git_commit')),
                    'dirty': manifest.dataset.get('dirty') if type(manifest.dataset.get('dirty')) is bool else None},
        'reproducibility': {'kagent_commit': commit(repro.get('kagent_commit')),
                            'kagent_dirty': repro.get('kagent_dirty') if type(repro.get('kagent_dirty')) is bool else None,
                            'python': semantic(repro.get('python'), r'3\.[0-9]{1,2}\.[0-9]{1,3}'),
                            'capability_profile': semantic(repro.get('capability_profile'), r'scenario1-native-http-confirmation-v1')},
        'runtime_limits': {key: _number(runtime.get(key)) for key in ('timeout_seconds', 'http_requests', 'tool_calls', 'agent_calls')},
        'provider_models': [{'provider': presentation_id('provider', p), 'model': presentation_id('model', m)} for p, m in provider_models],
        'scheduled': metrics['overall']['scheduled'], 'evaluable': metrics['overall']['evaluable'],
    }
    public_keys = ('scheduled', 'evaluable', 'TP', 'TN', 'FP', 'FN', *PARTITIONS,
                   'recall', 'precision', 'fpr', 'evaluability')
    normalized_metrics = {
        'overall': {key: metrics['overall'][key] for key in public_keys},
        'classes': {cls: {key: metrics['classes'][cls][key] for key in public_keys}
                    for cls in CLASSES},
    }
    return ReportModel(metadata, normalized_metrics, tuple(cases))
