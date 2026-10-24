"""Offline regressions for the production handoff failures observed in lan-06."""
import json
from copy import deepcopy
from typing import Any, cast

import httpx
import pytest

from src.agent.decision_planner import build_decision_plan
from src.llm.core.types import ChatRequest
from src.skills.artifacts import completion_artifact_path
from src.workflow.state import WorkflowObjective, WorkflowPhase, WorkflowState
from src.workflow.assessment import candidate_binding, digest
from tests.helpers.burp_selection import make_runtime, ORIGIN
from tests.helpers.discovery_calls import execute
from tests.helpers.workflow import record_completed_phase
from tests.helpers.agent_fakes import FakeSignal, ScriptedModel


def complete_phase(rt, phase, name):
    skill = rt.skills.get(name)
    assert skill is not None and skill.completion_artifact
    ref = completion_artifact_path(skill.completion_artifact, ORIGIN)
    path = rt.policy.root / ref
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('Offline synthetic prerequisite; no target assessment.')
    record_completed_phase(rt.workflow, cast(WorkflowPhase, phase), objective_id='handoff',
                           target_origin=ORIGIN, artifact_ref=ref)
    rt.workflow.completed_skills.add(name)
    rt.workflow.completed_artifacts[name] = ref


@pytest.fixture
async def analysis(tmp_path, monkeypatch):
    sent = []
    real = httpx.AsyncClient

    def respond(request):
        sent.append(str(request.url))
        return httpx.Response(200, json={'status': 'success', 'data': []}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real(transport=httpx.MockTransport(respond), **kw))
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('handoff', 'whole_target', ORIGIN)
    rt.workflow.objective.add_requested_goal('sql-injection')
    complete_phase(rt, 'recon', 'recon')
    complete_phase(rt, 'enumeration', 'web-enumeration')
    rt.workflow.current_phase = 'analysis'
    await execute(rt, 'load_skill', {'name': 'web-input-analysis'})
    await execute(rt, 'http', {'url': '/records/123', 'phase': 'validation', 'max_response_bytes': 1000})
    source = next(iter(rt.workflow.discovery_sources.values()))
    inp = json.loads((await execute(rt, 'workflow', {'action': 'record_input',
        'endpoint': '/records/123', 'method': 'GET', 'parameter': 'id', 'location': 'path',
        'source_ref': source.retained_ref})).result)['input']
    return rt, inp, source, sent


def proposal(inp, **changes):
    return {'action': 'record_candidate', 'candidate_class': 'sql-injection',
            'source_skill': 'web-input-analysis', 'input_id': inp['id'],
            'signals': ['Syntax-sensitive response; SQL construction remains unknown.'], **changes}


async def test_supported_unreasoned_deferral_is_consistently_queued_and_routes_to_validation(analysis):
    rt, inp, source, sent = analysis
    args = proposal(inp, status='deferred')
    first = json.loads((await execute(rt, 'workflow', args)).result)
    assert first['supported'] and first['candidate']['status'] == 'queued'
    second = json.loads((await execute(rt, 'workflow', args)).result)
    assert not second['created'] and second['candidate'] == first['candidate']
    cid = first['candidate']['id']
    assert first['candidate']['source_ref'] == source.retained_ref
    assert rt.workflow.attack_surface_inputs[inp['id']].candidate_ids == [cid]
    early = await execute(rt, 'workflow', {'action': 'start_validation', 'candidate_id': cid}, success=False)
    assert early.status == 'error' and 'input_analysis must complete' in early.result
    await execute(rt, 'workflow', {'action': 'set_input_disposition', 'input_id': inp['id'],
                                  'disposition': 'analyzed'})
    skill = rt.skills.get('web-input-analysis')
    assert skill is not None and skill.completion_artifact
    ref = completion_artifact_path(skill.completion_artifact, ORIGIN)
    path = rt.policy.root / ref
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('One bounded hypothesis; no confirmed finding.')
    await execute(rt, 'workflow', {'action': 'complete_skill', 'skill_name': 'web-input-analysis',
                                  'artifact_ref': ref, 'current_phase': 'validation'})
    assert rt.agent._whole_target_state()[0] == 'actionable'
    plan = build_decision_plan('continue', rt.skills.list_enabled(), rt.target, rt.agent._planner_context())
    assert plan is not None and plan.recommended_skill == 'sql-injection' and plan.candidate_id == cid
    await execute(rt, 'load_skill', {'name': 'sql-injection'})
    started = json.loads((await execute(rt, 'workflow', {'action': 'start_validation', 'candidate_id': cid})).result)
    assert started['ok'] and rt.workflow.candidates[cid].status == 'validating'
    assert len(sent) == 1 and not rt.workflow.validation_results and not rt.workflow.persisted_findings
    # The discovery capture never becomes owned terminal evidence through handoff.
    item = rt.policy.observations._items[source.retained_ref]
    assert item.candidate_id is None and item.attempt_id is None


async def test_explicit_deferral_survives_enrichment_resume_and_requires_dependency_repair(analysis):
    rt, inp, _, sent = analysis
    args = proposal(inp, status='deferred', deferred_reason='Required request context is unavailable')
    first = json.loads((await execute(rt, 'workflow', args)).result)['candidate']
    assert first['status'] == 'deferred'
    assert first['deferred_reason'] == args['deferred_reason']
    enriched = json.loads((await execute(rt, 'workflow', proposal(inp))).result)['candidate']
    assert enriched['status'] == 'deferred' and enriched['deferred_reason'] == first['deferred_reason']
    restored = WorkflowState.from_dict(rt.workflow.to_dict())
    assert restored.candidates[first['id']].deferred_reason == first['deferred_reason']
    handoff = rt.workflow_tool.validation_handoff(first['id'], rt.policy)
    assert handoff is not None and handoff['next_action'] == 'resolve_dependency'
    complete_phase(rt, 'input_analysis', 'web-input-analysis')
    await execute(rt, 'workflow', {'action': 'set_input_disposition', 'input_id': inp['id'], 'disposition': 'analyzed'})
    blocked = await execute(rt, 'workflow', {'action': 'start_validation', 'candidate_id': first['id']}, success=False)
    assert blocked.status == 'error' and 'dependency' in blocked.result
    assert not rt.workflow.attempts and len(sent) == 1
    repaired = json.loads((await execute(rt, 'workflow', proposal(inp, status='queued', deferred_reason=None))).result)
    assert repaired['candidate']['status'] == 'queued' and repaired['candidate'].get('deferred_reason') is None


async def test_path_mismatch_cannot_be_recovered_by_dropping_input_and_provenance(analysis):
    rt, inp, source, sent = analysis
    before = deepcopy(rt.workflow.to_dict())
    wrong = await execute(rt, 'workflow', proposal(inp, endpoint='/records/{id}'), success=False)
    assert wrong.status == 'error' and 'path does not match' in wrong.result
    assert 'get_input' in wrong.result and 'input_id' in wrong.result and 'Do not drop' in wrong.result
    assert rt.workflow.to_dict() == before
    bypass = proposal(inp, endpoint='/records/{id}', method='GET', parameter='id', location='path')
    del bypass['input_id']
    rejected = await execute(rt, 'workflow', bypass, success=False)
    assert rejected.status == 'error' and 'input_id' in rejected.result
    assert rt.workflow.to_dict() == before
    fixed = json.loads((await execute(rt, 'workflow', proposal(inp))).result)['candidate']
    assert fixed['endpoint'] == inp['endpoint'] and fixed['source_ref'] == source.retained_ref
    enriched = dict(proposal(inp), endpoint=fixed['endpoint'])
    del enriched['input_id']
    # Exact existing, already-linked enrichment remains backward compatible.
    enriched.update(method='GET', parameter='id', location='path')
    same = json.loads((await execute(rt, 'workflow', enriched)).result)['candidate']
    assert same['id'] == fixed['id'] and same['source_ref'] == source.retained_ref and len(sent) == 1


async def test_analysis_request_exposes_correct_readers_and_schema_recovery(analysis):
    rt, inp, source, sent = analysis
    request = ChatRequest(rt.client.model(), [], tools=rt.agent.tools.as_llm_tools())
    await rt.agent._prepare_turn_request(request, lambda _: None)
    specs = {x['function']['name']: x['function'] for x in cast(Any, request.tools) or []}
    assert {'workflow', 'read_discovery_source', 'read_http_observation', 'read_tool_result'} <= specs.keys()
    guidance = next(m.content for m in request.messages if m.content.startswith('Workflow action guidance:'))
    for expected in ['read_discovery_source', 'read_tool_result', 'read_http_observation', 'input_id',
                     'reflection', 'sibling', 'Shell', 'queued']:
        assert expected.lower() in guidance.lower()
    schema = specs['workflow']['parameters']['properties']
    assert 'deferred_reason' in schema['action']['description'].split('record_candidate(')[1].split(')')[0]
    assert 'input_id' in schema['input_id']['description'] and 'canonical' in schema['input_id']['description']
    wrong = await execute(rt, 'read_http_observation', {'observation_id': source.retained_ref,
        'start_char': 0, 'max_chars': 1000}, success=False)
    assert wrong.status == 'error'
    read = await execute(rt, 'read_discovery_source', {'discovery_source_id': source.id,
        'start_char': 0, 'max_chars': 1000})
    assert '"data":[]' in read.result.replace(' ', '') and len(sent) == 1
    assert not rt.workflow.attempts and not rt.workflow.evidence


async def test_coverage_wrong_argument_reports_exact_allowed_fields(analysis):
    rt, _, _, sent = analysis
    before = deepcopy(rt.workflow.to_dict())
    result = await execute(rt, 'workflow', {'action': 'record_phase_coverage', 'phase': 'enumeration',
        'coverage_phase': 'enumeration', 'coverage_dimension': 'api_documentation', 'coverage_status': 'observed'}, success=False)
    assert result.status == 'error' and 'coverage_phase' in result.result
    assert 'Allowed fields' in result.result and 'coverage_reason' in result.result
    assert rt.workflow.to_dict() == before and len(sent) == 1


async def test_enumeration_request_carries_grounding_and_reading_contract(tmp_path):
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('handoff', 'whole_target', ORIGIN)
    complete_phase(rt, 'recon', 'recon')
    await execute(rt, 'load_skill', {'name': 'web-enumeration'})
    request = ChatRequest(rt.client.model(), [], tools=rt.agent.tools.as_llm_tools())
    await rt.agent._prepare_turn_request(request, lambda _: None)
    guidance = next(m.content for m in request.messages if m.content.startswith('Workflow action guidance:'))
    for term in ['each retained discovery row', 'JSON', '401/403', '500', 'SPA', 'methods/fields',
                 'totals', 'quote/syntax', 'Shell HTTP', 'read_tool_result', 'read_discovery_source']:
        assert term in guidance
    assert not rt.workflow.candidates and not rt.workflow.attempts


async def test_autonomous_loop_crosses_analysis_handoff_and_preserves_unresolved_stop(analysis):
    rt, inp, source, sent = analysis
    skill = rt.skills.get('web-input-analysis')
    assert skill is not None and skill.completion_artifact
    ref = completion_artifact_path(skill.completion_artifact, ORIGIN)
    candidate_ids = []

    def script():
        recorded = json.loads((yield 'workflow', proposal(inp, status='deferred')))
        cid = recorded['candidate']['id']
        candidate_ids.append(cid)
        assert recorded['candidate']['status'] == 'queued'
        yield 'workflow', {'action': 'set_input_disposition', 'input_id': inp['id'], 'disposition': 'analyzed'}
        written = yield 'file_write', {'path': str(rt.policy.root / ref), 'content': 'Offline hypothesis, not a finding.'}
        assert 'wrote' in written, written
        feedback = yield 'workflow', {'action': 'complete_skill', 'skill_name': 'web-input-analysis',
                                     'artifact_ref': ref, 'current_phase': 'validation'}
        assert not feedback.startswith('error:'), feedback
        closed = json.loads(feedback)
        assert closed['ok']
        yield 'load_skill', {'name': 'sql-injection'}
        started = json.loads((yield 'workflow', {'action': 'start_validation', 'candidate_id': cid}))
        assert started['ok'] and started['validation_context']['attempt_id']
        result = json.loads((yield 'workflow', {'action': 'record_result', 'candidate_id': cid,
            'skill_name': 'sql-injection', 'outcome': 'deferred',
            'deferred_reason': 'Offline scenario has no validation evidence; stop without target probes.'}))
        assert result['ok'] and result['result']['outcome'] == 'deferred'

    client = ScriptedModel(script(), prefix='handoff')
    rt.agent.set_client(client)
    events = []
    await rt.agent.run('continue', FakeSignal(), events.append)
    assert not client.errors and len(client.calls) == 7
    assert len(rt.workflow.attempts) == 1 and len(rt.workflow.validation_results) == 1
    assert rt.workflow.candidates[candidate_ids[0]].status == 'deferred'
    assert rt.workflow.attempts[rt.workflow.validation_results[0].attempt_id]['status'] == 'unresolved'
    assert not rt.workflow.evidence and not rt.workflow.persisted_findings and len(sent) == 1
    assert rt.policy.observations._items[source.retained_ref].attempt_id is None
    assert any(e.get('type') == 'done' and e.get('stop_reason') == 'workflow_blocked' for e in events)


@pytest.mark.parametrize('reason', ['Needs an account', 'Dependency still unavailable'])
async def test_declared_deferral_cannot_be_reopened_by_default_or_queued_enrichment(analysis, reason):
    rt, inp, _, _ = analysis
    first = json.loads((await execute(rt, 'workflow', proposal(inp, status='deferred', deferred_reason=reason))).result)
    cid = first['candidate']['id']
    for extra in [{}, {'status': 'queued'}, {'status': 'deferred'}]:
        result = json.loads((await execute(rt, 'workflow', proposal(inp, **extra))).result)['candidate']
        assert result['status'] == 'deferred' and result['deferred_reason'] == reason
    context = rt.agent._planner_context()
    assert next(c for c in context.candidates if c.id == cid).deferred_reason == reason
    assert not rt.workflow.attempts


@pytest.mark.parametrize('replacement', ['', 'manual:unverified'])
async def test_input_source_provenance_cannot_be_cleared_or_replaced(analysis, replacement):
    rt, inp, _, sent = analysis
    before = deepcopy(rt.workflow.to_dict())
    rejected = await execute(rt, 'workflow', proposal(inp, source_ref=replacement), success=False)
    assert rejected.status == 'error' and 'source_ref conflicts' in rejected.result
    assert rt.workflow.to_dict() == before and len(sent) == 1


async def test_legacy_exact_geometry_links_unique_input_without_guessing_templates(analysis):
    rt, inp, source, _ = analysis
    legacy = proposal(inp, endpoint=inp['endpoint'], method='GET', parameter='id', location='path')
    del legacy['input_id']
    result = json.loads((await execute(rt, 'workflow', legacy)).result)['candidate']
    assert result['source_ref'] == source.retained_ref
    assert rt.workflow.attack_surface_inputs[inp['id']].candidate_ids == [result['id']]
    await execute(rt, 'workflow', {'action': 'record_input', 'endpoint': '/records/123', 'method': 'GET',
        'parameter': 'id', 'location': 'path', 'input_type': 'integer', 'source_ref': source.retained_ref})
    before = deepcopy(rt.workflow.to_dict())
    # An independent class cannot choose between multiple input variants.
    ambiguous = await execute(rt, 'workflow', {**legacy, 'candidate_class': 'xss'}, success=False)
    assert ambiguous.status == 'error' and 'input_id' in ambiguous.result
    assert rt.workflow.to_dict() == before


async def test_deferral_metadata_preserves_legacy_request_binding_and_resume(analysis):
    rt, inp, _, _ = analysis
    row = json.loads((await execute(rt, 'workflow', proposal(inp))).result)['candidate']
    candidate = rt.workflow.candidates[row['id']]
    # Persisted request bindings predate Candidate.deferred_reason. This
    # annotation must not invalidate observation ownership or immutable proof.
    legacy = {k: v for k, v in row.items() if k not in
              {'status', 'priority', 'signals', 'source_skill', 'deferred_reason'}}
    binding = digest(legacy)
    assert candidate_binding(candidate) == binding
    candidate.deferred_reason = 'A session-only dependency'
    assert candidate_binding(candidate) == binding
    restored = WorkflowState.from_dict(rt.workflow.to_dict())
    assert candidate_binding(restored.candidates[candidate.id]) == binding
