"""Real offline HTTP/workflow dispatch with SQLite, no external model or target.

The scripted validator tests evidence plumbing, not an LLM's technique choice.
Discovery coverage is explicitly skipped by the existing consumer fixture.
"""
import json
import sqlite3
from copy import deepcopy
from pathlib import Path
from urllib.parse import parse_qsl, urlencode

import httpx
import pytest

from src.browser.store import CaptureStore
from src.coverage.store import CoverageStore
from src.findings.store import Store, read_report
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as Skills
from src.tools.http.http_tool import HTTPTool
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.assessment import accepted_result
from src.workflow.state import WorkflowObjective, WorkflowState
from tests.helpers.workflow import prepare_validation_prerequisites
from tests.security.test_execution_policy import ORIGIN, REAL_CLIENT, runtime  # noqa: F401


@pytest.mark.parametrize('component,replay', [('value', False), ('value', True), ('name', False)])
async def test_analysis_candidate_to_sql_proof_result_and_finding(runtime, tmp_path, monkeypatch, component, replay):  # noqa: F811
    registry, p, policy, _, sent, _, target = runtime
    skills = Skills()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    loaded = await LoadSkillTool(skills).run({'name': 'sql-injection'})
    assert '### Input component checkpoint' in loaded
    state = WorkflowState(objective=WorkflowObjective('whole-target-fixture', 'whole_target', ORIGIN))
    coverage = CoverageStore(str(tmp_path / 'coverage.json'))
    http = registry.get('http')
    assert isinstance(http, HTTPTool)
    http.workflow = state
    tool = WorkflowTool(state, target, coverage, skills, tmp_path, http_tool=http)
    registry.register(tool)
    parameter = 'q' if component == 'value' else 'moss'
    baseline_pairs = [('limit', '1'), (parameter, 'moss' if component == 'value' else 'fixed')]
    baseline_body = urlencode(baseline_pairs)
    template = ('limit=1&q={INJECTION_POINT}' if component == 'value'
                else 'limit=1&{INJECTION_POINT}=fixed')
    media = 'application/x-www-form-urlencoded'

    def handler(request):
        sent.append(request)
        pairs = parse_qsl(request.content.decode(), keep_blank_values=True)
        assert pairs[:1] == baseline_pairs[:1]
        if component == 'value':
            assert pairs[1][0] == parameter
            value = pairs[1][1]
        else:
            assert pairs[1][1] == baseline_pairs[1][1]
            value = pairs[1][0]
        with sqlite3.connect(':memory:') as db:
            rows = db.execute("SELECT '" + value + "'").fetchall()
        return httpx.Response(200, json={'rows': rows}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(
        transport=httpx.MockTransport(handler), **kw))

    async def workflow(**args):
        output = await registry.execute('workflow', args, None, p)
        assert not output.startswith('error:'), output
        return json.loads(output)

    async def direct(body, phase):
        output = await registry.execute('http', {'method': 'POST', 'url': '/lookup',
            'headers': {'Content-Type': media}, 'body': body, 'phase': phase}, None, p)
        assert 'runtime observation:' in output, output
        return next(reversed(policy.observations._items))

    await workflow(action='list')  # bind the objective before analysis traffic
    analysis = await direct(baseline_body, 'recon')
    baseline_ref = None
    if replay:
        http.capture_store = CaptureStore()
        capture = http.capture_store.ingest({'id': 'lookup-control', 'kind': 'browser',
            'url': ORIGIN + '/lookup', 'method': 'POST',
            'reqHeaders': [{'name': 'Content-Type', 'value': media}], 'reqBody': baseline_body})
        baseline_ref = capture['baseline_request_ref']
    recorded = await workflow(action='record_input', method='POST', endpoint='/lookup',
        parameter=parameter, location='body', content_type=media, sample_payload=baseline_body,
        baseline_request_ref=baseline_ref, source_ref=analysis)
    input_id = recorded['input']['id']
    created = await workflow(action='record_candidate', candidate_class='sql-injection',
        source_skill='web-input-analysis', input_id=input_id, request_template=template,
        signals=[f'Designated parameter {component}; scalar/projection hypothesis, one output slot.'],
        observation_ids=[analysis])
    candidate_id = created['candidate']['id']
    assert created['analysis_observations'][0]['observation_id'] == analysis
    assert not created['analysis_observations'][0]['terminal_evidence']
    await prepare_validation_prerequisites(tool, candidate_id)
    candidate_before = deepcopy(state.candidates[candidate_id].to_dict())
    input_before = deepcopy(state.attack_surface_inputs[input_id].to_dict())
    started = await workflow(action='start_validation', candidate_id=candidate_id)
    context = started['validation_context']
    assert context['input_ids'] == [input_id]
    assert context['request_template'] == template and context['sample_payload'] == baseline_body
    assert context['provenance']['source_ref'] == analysis
    assert context['baseline_request_ref'] == baseline_ref
    assert context['baseline']['available'] is replay
    assert (context['method'], context['parameter'], context['location']) == ('POST', parameter, 'body')

    # Known, single-slot SELECT projection; only harmless constant evaluation.
    payload = "' UNION SELECT (7 * 7) --"
    ids = []
    for value in (None, payload, payload):
        if replay:
            args = {'phase': 'validation', 'candidate_id': candidate_id}
            if value is not None:
                args['mutation_value'] = value
            output = await registry.execute('http', args, None, p)
            assert 'runtime observation:' in output, output
            oid = next(reversed(policy.observations._items))
        else:
            pairs = baseline_pairs if value is None else [('limit', '1'),
                (parameter, value) if component == 'value' else (value, 'fixed')]
            oid = await direct(urlencode(pairs), 'validation')
        ids.append(oid)
    assert len(set(ids)) == 3 and analysis not in ids
    assert b'49' not in policy.observations._items[ids[0]].body
    assert all(b'49' in policy.observations._items[oid].body for oid in ids[1:])
    assert policy.observations._items[analysis].attempt_id is None
    assert all(policy.observations._items[oid].attempt_id == context['attempt_id'] for oid in ids)
    # Finalize immediately: no further HTTP after the repeated computed marker.
    dispatch_count = len(sent)
    await workflow(action='record_attempt_state', candidate_id=candidate_id,
        mutation_state='no-mutation-established', effect_basis='Read-only in-memory SELECT fixture.',
        observation_ids=ids, cleanup_state='not-required')
    proof = tmp_path / 'sql-proof.md'
    proof.write_text('Owned control lacks 49; two constant UNION evaluations return 49.\n'
                     + '\n'.join(ids), encoding='utf-8')
    evidence = await workflow(action='record_evidence', candidate_id=candidate_id,
        evidence_path=proof.name, observation_ids=ids)
    evidence_id = evidence['evidence']['id']
    result = await workflow(action='record_result', candidate_id=candidate_id,
        attempt_id=context['attempt_id'], skill_name='sql-injection', outcome='confirmed',
        observation_ids=ids, evidence_refs=[evidence_id], techniques=['SQLI-2', 'bounded-union-based'],
        repeatable=True, assessment={
            'hypothesis': 'The designated component reaches a known one-slot SELECT projection.',
            'criteria': 'Owned control lacks 49; two constant-expression requests reproduce computed 49.',
            'limitations': 'Offline SQLite fixture only; no external model, real rows or impact validation.',
            'observed_impact': 'Controlled constant evaluation in the local fixture.', 'severity': 'low'})
    latest = state.latest_result(candidate_id)
    assert result['ok'] and result['eligible_for_confirm_finding'] and latest is not None
    assert latest.result_id and latest.evidence_refs == [evidence_id] and latest.coverage_synced
    assert accepted_result(state, state.candidates[candidate_id], latest, policy)
    assert await coverage.list()
    assert state.attack_surface_inputs[input_id].to_dict() == input_before
    candidate_after = state.candidates[candidate_id].to_dict()
    assert {k: v for k, v in candidate_after.items() if k != 'status'} == {
        k: v for k, v in candidate_before.items() if k != 'status'}
    store = Store(project_directory=tmp_path)
    registry.register(ConfirmFindingTool(store, workflow=state))
    output = await registry.execute('confirm_finding', {'candidate_id': candidate_id,
        'title': 'Local constant evaluation', 'url': ORIGIN + '/lookup', 'severity': 'low',
        'observed_impact': latest.assessment['observed_impact'],
        'potential_impact': 'No additional impact assessed.'}, None, p)
    assert 'written to' in output and state.finding_is_persisted(candidate_id)
    saved = read_report(store.report_for_candidate(candidate_id))
    assert saved.evidence_refs == [evidence_id] and saved.assessment_result_id == latest.result_id
    assert len(sent) == dispatch_count == 4
