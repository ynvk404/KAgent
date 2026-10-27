"""Evaluation v2 through real workflow acceptance, parent receipts and reporting."""
from copy import deepcopy
from dataclasses import asdict, replace
import csv
from io import StringIO
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from benchmarks.common.contracts import RuntimeMetrics, read_json, write_new
from benchmarks.scenario1.core.evaluate import evaluate
from benchmarks.scenario1.core.runner import run
from benchmarks.scenario1.reporting.loader import load_report
from benchmarks.scenario1.reporting.writer import write_report
from tests.benchmarks.test_scenario1 import (FindingClient, ScriptedClient, execute_case,
    mock_http, op, settings, single_manifest, schedule_run, recorded_run)


@pytest.mark.parametrize('status,outcome,vulnerable,label', [
    ('completed', 'confirmed', True, 'TP'),
    ('budget-exhausted', 'confirmed', True, 'TP'),
    ('budget-exhausted', 'confirmed', False, 'FP'),
    ('timeout', 'not-confirmed', False, 'TN'),
    ('timeout', 'not-confirmed', True, 'FN'),
    ('provider-error', 'confirmed', True, 'TP'),
    ('runtime-error', 'not-confirmed', False, 'TN'),
    ('crashed', 'confirmed', True, 'TP'),
])
async def test_accepted_assessment_survives_parent_execution_failure(
        tmp_path, monkeypatch, op, settings, mock_http, status, outcome, vulnerable, label):
    workspace = tmp_path / 'fixture'
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    execution = await execute_case(op, settings, workspace, 'run', 'ex', FindingClient(outcome))
    assert execution.result is not None
    assert execution.status == 'completed' and execution.result['accepted_at_freeze']
    # Only the external worker termination is simulated. Acceptance/evidence/seals
    # come from the production Agent, workflow and persistence path above.
    def launcher(payload, _):
        data = asdict(execution)
        data['execution_id'] = payload['execution_id']
        data['result']['execution_id'] = payload['execution_id']
        data['status'] = status if status not in {'timeout', 'crashed'} else 'completed'
        write_new(Path(payload['output']), data)
        return (-15, True) if status == 'timeout' else (-9, False) if status == 'crashed' else (0, False)
    root = run(single_manifest(op, settings, vulnerable), settings, tmp_path / 'public', launcher=launcher)
    before = (root / 'results' / f'{op.case_id}.json').read_bytes()
    report = evaluate(root)
    record = report['records'][0]
    assert set(record) == {'case_id', 'execution_status', 'assessment_status', 'assessment_reason',
                           'assessment_outcome', 'assessment_confusion', 'schema_version'}
    assert record['execution_status'] == status and record['assessment_status'] == 'accepted'
    assert record['assessment_confusion'] == label and record['assessment_outcome'] == outcome
    counts = report['metrics']['overall']
    assert counts['completed'] == (status == 'completed')
    assert counts['execution_failed'] == (status != 'completed')
    assert counts['completion_rate'] == (status == 'completed')
    assert counts['assessment_coverage'] == counts['assessment_accepted'] == 1
    assert sum(counts[k] for k in ('TP', 'FP', 'TN', 'FN')) == counts[label] == 1
    assert sum(counts['execution_status_counts'].values()) == sum(counts['assessment_status_counts'].values()) == 1
    assert 'assessment_records' not in report and 'evaluable' not in counts
    assert load_report(root).cases[0]['assessment_confusion'] == label
    assert evaluate(root) == report and (root / 'results' / f'{op.case_id}.json').read_bytes() == before


@pytest.mark.parametrize('damage,expected', [
    ('no-export', 'unavailable'), ('no-result', 'unavailable'),
    ('hash', 'invalid'), ('identity', 'invalid'), ('stale', 'invalid'),
    ('unaccepted', 'invalid'), ('seal', 'invalid'), ('binding', 'invalid'),
    ('evidence', 'invalid'), ('active-attempt', 'invalid'),
])
async def test_failed_execution_cannot_rescue_untrusted_or_superseded_result(
        tmp_path, monkeypatch, op, settings, mock_http, damage, expected):
    workspace = tmp_path / 'fixture'
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    execution = await execute_case(op, settings, workspace, 'run', 'ex', FindingClient())
    assert execution.result is not None
    assert execution.result['accepted_at_freeze']
    data = deepcopy(asdict(execution))
    canonical = data['result']
    result = canonical['workflow']['validation_results'][-1]
    if damage == 'no-result':
        data['result'] = None
    elif damage == 'identity':
        canonical['execution_id'] = 'other-execution'
    elif damage == 'stale':
        canonical['result_id'] = 'older-result'
    elif damage == 'unaccepted':
        canonical['accepted_at_freeze'] = False
    elif damage == 'seal':
        result['assessment_binding'] = '0' * 64
    elif damage == 'binding':
        canonical['candidate_binding'] = '0' * 64
    elif damage == 'evidence':
        result['evidence_manifest'][0]['source']['body'] = '00'
    elif damage == 'active-attempt':
        canonical['workflow']['attempts'][result['attempt_id']]['status'] = 'active'
    data['status'] = 'runtime-error'
    from benchmarks.common.contracts import decode, CaseExecution
    root = tmp_path / 'run'
    if damage == 'no-export':
        root = run(single_manifest(op, settings), settings, root, launcher=lambda *_: (-9, False))
    else:
        recorded_run(root, single_manifest(op, settings), decode(CaseExecution, data))
        if damage == 'hash':
            path = root / 'results' / f'{op.case_id}.json'
            path.write_bytes(path.read_bytes() + b'\n')
    report = evaluate(root)
    record = report['records'][0]
    assert record['assessment_status'] == expected and record['assessment_confusion'] is None
    counts = report['metrics']['overall']
    assert sum(counts[k] for k in ('TP', 'FP', 'TN', 'FN')) == counts['assessment_accepted'] == 0
    # Reporting revalidates the same canonical inputs, rather than trusting a
    # fabricated accepted flag in an evaluation artifact.
    if damage == 'identity':
        with pytest.raises(ValueError, match='identity mismatch'):
            load_report(root)
    else:
        assert load_report(root).cases[0]['assessment_status'] == expected


async def test_unresolved_failed_execution_is_not_negative(tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    execution = await execute_case(op, settings, tmp_path, 'run', 'ex', ScriptedClient('insufficient-evidence'))
    recorded_run(tmp_path / 'run', single_manifest(op, settings), replace(execution, status='provider-error'))
    record = evaluate(tmp_path / 'run')['records'][0]
    assert record['execution_status'] == 'provider-error' and record['assessment_status'] == 'unresolved'
    assert record['assessment_outcome'] == 'insufficient-evidence' and record['assessment_confusion'] is None


async def test_accepted_export_without_parent_receipt_stays_unavailable(
        tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    execution = await execute_case(op, settings, tmp_path, 'run', 'ex', FindingClient())
    root = tmp_path / 'run'
    recorder = schedule_run(root, single_manifest(op, settings))
    recorder.append('started', op.case_id, 'started', execution_id='ex')
    write_new(root / 'results' / f'{op.case_id}.json', asdict(execution))
    report = evaluate(root)
    record = report['records'][0]
    assert record['execution_status'] == 'started' and record['assessment_status'] == 'unavailable'
    assert record['assessment_reason'] == 'missing-parent-receipt' and record['assessment_confusion'] is None
    assert report['metrics']['overall']['agent_seconds_by_status'] == {}


async def test_reporting_contract_and_resource_cohorts(tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    execution = await execute_case(op, settings, tmp_path, 'run', 'ex', ScriptedClient())
    assert execution.result is not None
    assert execution.status == 'budget-exhausted' and execution.result['accepted_at_freeze']
    metrics = RuntimeMetrics(10, 1, 1, 5, {'total_llm_calls': 2, 'tokens': {
        'total_tokens': {'complete': True, 'total': 900}}}, {'executed': 3}, 4, 4)
    root = tmp_path / 'run'
    recorded_run(root, single_manifest(op, settings), replace(execution, metrics=asdict(metrics)))
    report = evaluate(root)
    destination = write_report(root)
    summary = list(csv.DictReader(StringIO((destination / 'summary.csv').read_text())))[0]
    case = list(csv.DictReader(StringIO((destination / 'per-case.csv').read_text())))[0]
    assert summary['TP'] == summary['assessment_accepted'] == summary['execution_failed'] == '1'
    assert summary['completed'] == '0' and float(summary['assessment_coverage']) == 1
    assert float(summary['completion_rate']) == 0 and case['execution_status'] == 'budget-exhausted'
    assert case['assessment_status'] == 'accepted' and case['assessment_confusion'] == 'TP'
    public = read_json(destination / 'report.json')
    assert public['canonical_evaluator_metrics']['Overall']['TP'] == report['metrics']['overall']['TP']
    md = (destination / 'thesis-tables.md').read_text()
    assert 'Completion Rate' in md and 'Assessment Coverage' in md
    assert '900<br>1/1' in md  # Total tokens includes the failed execution.
    from benchmarks.scenario1.reporting.thesis import resource_summary, class_cases
    model = load_report(root)
    for metric in ('total_tokens', 'agent_seconds'):
        assert resource_summary(class_cases(model, None, completed=True), metric).median is None
    assert resource_summary(model.cases, 'total_tokens').total == 900
    for path in destination.rglob('*.svg'):
        ET.fromstring(path.read_bytes())
    quality = (destination / 'charts/scenario1-validation-quality.svg').read_text()
    assert '100,0% (1/1)' in quality and 'assessment_coverage' not in quality
    assert not list(destination.glob('charts/*completion*'))


def test_v1_is_explicitly_rejected_without_rewriting(tmp_path, op, settings):
    root = tmp_path / 'run'
    schedule_run(root, single_manifest(op, settings))
    path = root / ('evaluation-' + 'a' * 64 + '.json')
    write_new(path, {'schema_version': 1, 'evaluator_version': 'offline-agent-assessment-v1'})
    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    with pytest.raises(ValueError, match='incompatible historical evaluation'):
        evaluate(root)
    with pytest.raises(ValueError, match='unsupported evaluation contract'):
        load_report(root)
    assert all(p.read_bytes() == raw for p, raw in before.items())
