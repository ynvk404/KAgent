"""Discovery coverage comes from executed adapters, never model claims."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from src.engagement.state import EngagementState
from src.permission.runtime.execution import ExecutionPolicy
from src.permission.network.grants import HTTPLimits
from src.permission.permission import AlwaysAllow, UserControlledRefusal, YoloPrompter
from src.target.target import Target
from src.tools.http.http_tool import HTTPTool
from src.tools.common.registry import Registry
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowObjective, WorkflowState
from tests.helpers.workflow import record_completed_phase

ORIGIN = 'http://127.0.0.1:3000'
REAL_CLIENT = httpx.AsyncClient


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    target = Target(ORIGIN)
    engagement = EngagementState()
    engagement.initialize_target(ORIGIN)
    state = WorkflowState(objective=WorkflowObjective(
        id='attestation', mode='whole_target', target_origin=ORIGIN,
    ))
    policy = ExecutionPolicy(engagement, tmp_path)
    prompter = YoloPrompter(AlwaysAllow(), True)
    prompter.bind_execution_policy(policy)
    engagement.http_permissions.activate(ORIGIN, HTTPLimits(requests=50, rate=1000, burst=50))
    registry = Registry()
    registry.register(HTTPTool(target, engagement, state))
    registry.register(WorkflowTool(state, target, evidence_root=tmp_path))
    response_spec = {'status': 200, 'body': b'<html><a href="/search?q=x">Search</a></html>',
                     'content_type': 'text/html'}
    sent = []

    def handler(request):
        sent.append(request)
        return httpx.Response(response_spec['status'], content=response_spec['body'],
                              headers={'content-type': response_spec['content_type']}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: REAL_CLIENT(
        transport=httpx.MockTransport(handler), **kwargs))
    monkeypatch.setattr('src.tools.http.http_tool.gate_private_request', AsyncMock(return_value=''))
    return registry, prompter, policy, state, response_spec, sent, target


@pytest.mark.asyncio
async def test_http_attests_core_dimensions_only_after_observed_response(runtime):
    registry, p, policy, state, _, sent, _ = runtime
    for dimension in ('target_resolution', 'reachability', 'http_fingerprint'):
        result = await registry.execute('workflow', {
            'action': 'record_phase_coverage', 'phase': 'recon',
            'coverage_dimension': dimension, 'coverage_status': 'performed',
        }, None, p)
        assert result.status == 'error' and 'execution adapter observation' in result
        assert state.phase_coverage_record('recon', dimension) is None
    result = await registry.execute('http', {'url': '/', 'phase': 'recon',
                                           'max_response_bytes': 0, 'evidence_mode': 'metadata-only'}, None, p)
    assert result.truncated and len(sent) == 1
    observations = policy.observations._items
    assert len(observations) == 1
    observation = next(iter(observations.values()))
    for dimension in ('target_resolution', 'reachability', 'http_fingerprint'):
        coverage = state.phase_coverage_record('recon', dimension)
        assert coverage is not None and coverage.status == 'performed'
        assert coverage.reason and observation.id in coverage.reason
    assert state.phase_coverage_record('enumeration', 'html_navigation') is None
    facts = state.progress_facts()
    await registry.execute('http', {'url': '/', 'phase': 'recon'}, None, p)
    assert state.progress_facts() == facts


@pytest.mark.asyncio
@pytest.mark.parametrize('status', ['skipped', 'not_applicable', 'failed', 'cancelled'])
async def test_model_cannot_replace_attested_execution_with_workaround(runtime, status):
    registry, p, _, state, _, _, _ = runtime
    await registry.execute('http', {'url': '/', 'phase': 'recon'}, None, p)
    before = state.progress_facts()
    result = await registry.execute('workflow', {
        'action': 'record_phase_coverage', 'phase': 'recon',
        'coverage_dimension': 'reachability', 'coverage_status': status,
        'coverage_reason': 'executed but adapter unavailable',
    }, None, p)
    assert result.status == 'error'
    assert state.progress_facts() == before
    assert state.phase_coverage_record('recon', 'reachability').status == 'performed'


@pytest.mark.asyncio
@pytest.mark.parametrize('requested', ['performed', 'observed'])
async def test_attested_coverage_replay_is_successful_noop(runtime, requested):
    registry, p, _, state, _, _, _ = runtime
    await registry.execute('http', {'url': '/', 'phase': 'recon'}, None, p)
    before = state.to_dict()
    result = await registry.execute('workflow', {
        'action': 'record_phase_coverage', 'phase': 'recon',
        'coverage_dimension': 'reachability', 'coverage_status': requested,
    }, None, p)
    payload = json.loads(str(result))
    assert result.status == 'success'
    assert payload['requested_status'] == requested
    assert payload['status'] == 'performed'
    assert payload['changed'] is False and payload['already_recorded'] is True
    assert state.to_dict() == before


@pytest.mark.asyncio
async def test_completed_phase_replay_reports_completion_without_recompletion_guidance(runtime):
    registry, p, _, state, _, _, _ = runtime
    await registry.execute('http', {'url': '/', 'phase': 'recon'}, None, p)
    state.record_phase_coverage('recon', 'service_discovery', 'not_applicable',
                                objective_id='attestation', target_origin=ORIGIN,
                                reason='web port already known')
    state.record_phase_completion('recon', objective_id='attestation',
                                  target_origin=ORIGIN, artifact_ref='artifacts/recon.md')
    before = state.to_dict()
    result = await registry.execute('workflow', {
        'action': 'record_phase_coverage', 'phase': 'recon',
        'coverage_dimension': 'reachability', 'coverage_status': 'observed',
    }, None, p)
    payload = json.loads(str(result))
    assert payload['phase_completed'] is True
    assert 'already completed' in payload['message']
    assert 'complete_skill' not in payload['message']
    assert state.to_dict() == before


@pytest.mark.asyncio
async def test_missing_or_denied_http_observation_never_attests(runtime, monkeypatch):
    registry, p, policy, state, _, sent, _ = runtime
    monkeypatch.setattr(REAL_CLIENT, 'send',
                        AsyncMock(side_effect=httpx.ConnectError('fixture failure')))
    with pytest.raises(httpx.ConnectError):
        await registry.execute('http', {'url': '/', 'phase': 'recon'}, None, p)
    assert not state.phase_coverage and not policy.observations._items and not sent
    policy.engagement.http_permissions.deny_session()
    with pytest.raises(UserControlledRefusal):
        await registry.execute('http', {'url': '/', 'phase': 'recon'}, None, p)
    assert not state.phase_coverage


@pytest.mark.asyncio
@pytest.mark.parametrize('body,media,status,cap,expected', [
    (b'<html><form action="/login"></form></html>', 'text/html', 200, 1000, True),
    (b'<html><script src="/app.js"></script></html>', 'text/html', 200, 1000, True),
    (b'<html><style>' + b'x' * 200 + b'</style><a href="/login">x</a>', 'text/html', 200, 30, False),
    (b'<a href="/login">x</a>', 'application/json', 200, 1000, False),
    (b'<a href="/login">x</a>', 'text/html', 500, 1000, False),
    (b'<html><p>no references</p></html>', 'text/html', 200, 1000, False),
])
async def test_html_navigation_requires_captured_parsed_references(runtime, body, media, status, cap, expected):
    registry, p, _, state, spec, _, _ = runtime
    record_completed_phase(state, 'recon', objective_id='attestation',
                           target_origin=ORIGIN, artifact_ref='artifacts/recon.md')
    spec.update(body=body, content_type=media, status=status)
    await registry.execute('http', {'url': '/', 'phase': 'recon', 'max_response_bytes': cap}, None, p)
    coverage = state.phase_coverage_record('enumeration', 'html_navigation')
    assert (coverage is not None) == expected
    if coverage:
        assert coverage.status == 'performed'
    assert state.phase_coverage_record('enumeration', 'api_documentation') is None


@pytest.mark.asyncio
async def test_unattested_review_remains_observed_and_roundtrips(runtime):
    registry, p, _, state, _, _, _ = runtime
    record_completed_phase(state, 'recon', objective_id='attestation',
                           target_origin=ORIGIN, artifact_ref='artifacts/recon.md')
    args = {'action': 'record_phase_coverage', 'phase': 'enumeration',
            'coverage_dimension': 'api_documentation', 'coverage_status': 'observed'}
    result = await registry.execute('workflow', args, None, p)
    assert result.status == 'error'
    result = await registry.execute('workflow', {**args, 'coverage_reason':
        'reviewed artifacts/spec-notes.md; schema extraction has no execution adapter'}, None, p)
    assert json.loads(result)['status'] == 'observed'
    restored = WorkflowState.from_dict(state.to_dict())
    coverage = restored.phase_coverage_record('enumeration', 'api_documentation')
    assert coverage is not None and coverage.status == 'observed'
    assert restored.phase_coverage_record('enumeration', 'html_navigation') is None


@pytest.mark.asyncio
async def test_http_other_engagement_origin_cannot_attest_active_objective(runtime):
    registry, p, policy, state, _, _, _ = runtime
    other = 'http://127.0.0.1:3001'
    policy.engagement.add_origin(other)
    policy.engagement.http_permissions.activate(other, HTTPLimits(rate=1000, burst=50))
    await registry.execute('http', {'url': other, 'phase': 'recon'}, None, p)
    assert not state.phase_coverage


@pytest.mark.asyncio
@pytest.mark.parametrize('status', ['skipped', 'not_applicable'])
async def test_genuinely_omitted_dimension_requires_reason_under_policy(runtime, status):
    registry, p, _, state, _, _, _ = runtime
    args = {'action': 'record_phase_coverage', 'phase': 'recon',
            'coverage_dimension': 'service_discovery', 'coverage_status': status}
    assert (await registry.execute('workflow', args, None, p)).status == 'error'
    result = await registry.execute('workflow', {**args, 'coverage_reason':
        'active URL already identifies the web port; no separate TCP survey requested'}, None, p)
    assert json.loads(result)['status'] == status
    assert state.phase_coverage_record('recon', 'service_discovery').status == status
    assert state.phase_coverage_record('recon', 'reachability') is None


@pytest.mark.asyncio
async def test_observed_coverage_completion_preserves_distinction_in_session_state(runtime, tmp_path):
    from src.skills.registry import Registry as SkillRegistry
    from src.workflow.state import PHASE_COVERAGE_DIMENSIONS

    registry, p, _, state, _, _, target = runtime
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    workflow_tool = registry.get('workflow')
    assert isinstance(workflow_tool, WorkflowTool)
    workflow_tool.skills = skills
    record_completed_phase(state, 'recon', objective_id='attestation',
                           target_origin=ORIGIN, artifact_ref='artifacts/recon.md')
    await registry.execute('http', {'url': '/', 'phase': 'recon'}, None, p)
    for dimension in PHASE_COVERAGE_DIMENSIONS['enumeration']:
        if dimension == 'html_navigation':
            continue
        omitted = dimension in {'browser_burp_capture', 'active_content_discovery'}
        await registry.execute('workflow', {'action': 'record_phase_coverage',
            'phase': 'enumeration', 'coverage_dimension': dimension,
            'coverage_status': 'not_applicable' if omitted else 'observed',
            'coverage_reason': ('no capture/discovery gap in this bounded pass' if omitted else
                                'reviewed inventory source; extraction has no attestation adapter')}, None, p)
    artifact = tmp_path / 'artifacts/web-enumeration/127-0-0-1-3000/inventory.md'
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text('Bounded source inventory; no candidates created.')
    result = await registry.execute('workflow', {'action': 'complete_skill',
                                                'skill_name': 'web-enumeration'}, None, p)
    assert json.loads(result)['ok'] is True
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.is_next_phase('input_analysis')
    for dimension, expected in [('html_navigation', 'performed'),
                                ('api_documentation', 'observed'),
                                ('active_content_discovery', 'not_applicable')]:
        record = restored.phase_coverage_record('enumeration', dimension)
        assert record is not None and record.status == expected
    assert not restored.candidates
