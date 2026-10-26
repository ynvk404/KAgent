"""Historical v8 exports keep the same evidence and scoring requirements."""
from copy import deepcopy
from dataclasses import replace

import pytest

from benchmarks.scenario1.core.canonical import inspect_export, projection
from benchmarks.scenario1.core.evaluate import evaluate
from benchmarks.scenario1.core.runtime import candidate_arguments, execute_case
from src.workflow.state import WorkflowState
from tests.benchmarks.test_scenario1 import (
    ASSESSMENT, FindingClient, ScriptedClient, isolated_project_environment, mock_http,
    op, recorded_run, settings, single_manifest,
)


@pytest.mark.parametrize('legacy', [True, False])
async def test_v8_retry_metadata_compatibility_preserves_evaluation(
        tmp_path, monkeypatch, op, settings, mock_http, legacy):
    monkeypatch.chdir(tmp_path)
    execution = await execute_case(op, settings, tmp_path, 'run', 'ex', FindingClient())
    assert execution.status == 'completed' and execution.result is not None
    exported = deepcopy(execution.result)
    if legacy:
        exported['workflow'].pop('retry_decisions')
    original = deepcopy(exported)
    outcome, error = inspect_export(exported, run_id='run', case_id=op.case_id,
        execution_id='ex', candidate_args=candidate_arguments(op, settings),
        target=settings.target + settings.context_path)
    assert (outcome, error) == ('confirmed', None)
    assert projection(exported['workflow']).retry_decisions == {}
    assert exported == original
    root = tmp_path / 'recorded'
    recorded_run(root, single_manifest(op, settings), replace(execution, result=exported))
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    report = evaluate(root, publish=False)
    assert report == evaluate(root, publish=False)
    assert report['records'][0]['partition'] == 'evaluable'
    assert report['metrics']['overall']['TP'] == 1
    assert {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('legacy', [True, False])
@pytest.mark.parametrize('fault', ['unknown-field', 'missing-attempts', 'missing-version', 'wrong-version'])
def test_v8_compatibility_does_not_relax_other_schema_fields(legacy, fault):
    raw = WorkflowState().to_dict()
    if legacy:
        raw.pop('retry_decisions')
    if fault == 'unknown-field':
        raw['unrecognized_metadata'] = {}
    elif fault == 'wrong-version':
        raw['version'] = 9
    else:
        raw.pop('attempts' if fault == 'missing-attempts' else 'version')
    with pytest.raises(ValueError, match='unsupported frozen workflow schema'):
        projection(raw)


@pytest.mark.parametrize('legacy', [True, False])
@pytest.mark.parametrize('fault', ['binding', 'seal', 'source-ownership'])
async def test_compatible_v8_exports_still_reject_invalid_assessments(
        tmp_path, monkeypatch, op, settings, mock_http, legacy, fault):
    monkeypatch.chdir(tmp_path)
    execution = await execute_case(op, settings, tmp_path, 'run', 'ex', FindingClient())
    assert execution.result is not None
    exported = deepcopy(execution.result)
    if legacy:
        exported['workflow'].pop('retry_decisions')
    result = exported['workflow']['validation_results'][-1]
    if fault == 'binding':
        exported['candidate_binding'] = '0' * 64
    elif fault == 'seal':
        result['assessment_binding'] = '0' * 64
    else:
        result['evidence_manifest'][0]['source']['candidate_id'] = 'foreign-candidate'
    outcome, error = inspect_export(exported, run_id='run', case_id=op.case_id,
        execution_id='ex', candidate_args=candidate_arguments(op, settings),
        target=settings.target + settings.context_path)
    assert outcome is None and error is not None


class RetryingClient(ScriptedClient):
    """Existing scripted native revisions, with Finding finalization on success."""
    def __init__(self, outcome):
        super().__init__(outcome=outcome, mode='revisions')

    async def chat(self, request, signal=None):
        response = await super().chat(request, signal)
        if self.step == 13 and self.outcome == 'confirmed':
            return self.tool('confirm_finding', {
                'candidate_id': self.candidate, 'title': 'Confirmed retry fixture',
                'severity': ASSESSMENT['severity'], 'url': 'http://127.0.0.1:3000/benchmark/fixture',
                'method': 'GET', 'parameter': 'q', 'vuln_class': self.skill,
                'observed_impact': ASSESSMENT['observed_impact'],
                'potential_impact': 'No additional impact assessed.',
            })
        return response


@pytest.mark.parametrize('outcome,confusion', [('confirmed', 'TP'), ('not-confirmed', 'FN')])
async def test_optional_retry_uses_latest_attempt_once(
        tmp_path, monkeypatch, op, settings, mock_http, outcome, confusion):
    monkeypatch.chdir(tmp_path)
    client = RetryingClient(outcome)
    execution = await execute_case(op, settings, tmp_path, 'run', 'ex', client)
    assert execution.status == 'completed' and execution.result is not None
    exported = execution.result
    results = exported['workflow']['validation_results']
    assert [r['outcome'] for r in results] == ['insufficient-evidence', outcome]
    assert len(exported['workflow']['attempts']) == 2
    assert results[0]['attempt_id'] != results[1]['attempt_id']
    assert exported['result_id'] == results[1]['result_id'] and exported['latest_position'] == 1
    assert exported['accepted_at_freeze']
    assert bool(exported['workflow']['persisted_findings']) is (outcome == 'confirmed')
    if outcome == 'confirmed':
        final_guidance = [m.content for m in client.requests[-1].messages
                          if m.content.startswith('Decision planner guidance for this turn:')]
        assert final_guidance and all('start_validation' not in text for text in final_guidance)
    root = tmp_path / 'recorded'
    recorded_run(root, single_manifest(op, settings), execution)
    report = evaluate(root, publish=False)
    assert len(report['records']) == 1 and report['records'][0]['confusion'] == confusion
    counts = report['metrics']['overall']
    assert counts['evaluable'] == sum(counts[key] for key in ('TP', 'TN', 'FP', 'FN')) == 1


async def test_retry_at_step_limit_keeps_prior_result_and_never_becomes_negative(
        tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    settings = replace(settings, agent_calls=8)
    execution = await execute_case(op, settings, tmp_path, 'run', 'ex', RetryingClient('confirmed'))
    assert (execution.status, execution.stop_reason) == ('budget-exhausted', 'max_steps')
    assert execution.result is not None
    results = execution.result['workflow']['validation_results']
    assert [r['outcome'] for r in results] == ['insufficient-evidence', 'insufficient-evidence']
    assert results[0]['attempt_id'] != results[1]['attempt_id']
    assert not execution.result['accepted_at_freeze']
    root = tmp_path / 'recorded'
    recorded_run(root, single_manifest(op, settings), execution)
    record = evaluate(root, publish=False)['records'][0]
    assert record['partition'] == 'execution-failed' and record['reason'] == 'budget-exhausted'
    assert record['confusion'] is None


class ReopeningClient(FindingClient):
    async def chat(self, request, signal=None):
        response = await super().chat(request, signal)
        if self.step == 9 and request.tools:
            return self.tool('workflow', {'action': 'start_validation', 'candidate_id': self.candidate})
        return response


async def test_reopen_after_saved_finding_cannot_create_unresolved_second_attempt(
        tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    execution = await execute_case(op, replace(settings, agent_calls=9), tmp_path, 'run', 'ex', ReopeningClient())
    assert (execution.status, execution.stop_reason) == ('completed', 'final_response')
    assert execution.result is not None and execution.result['accepted_at_freeze']
    workflow = execution.result['workflow']
    assert len(workflow['attempts']) == len(workflow['validation_results']) == 1
    assert workflow['validation_results'][0]['outcome'] == 'confirmed'
    assert workflow['persisted_findings']
    root = tmp_path / 'recorded'
    recorded_run(root, single_manifest(op, settings), execution)
    assert evaluate(root, publish=False)['records'][0]['confusion'] == 'TP'
