"""Offline production contracts, not a prediction of model compliance."""
import json
from copy import deepcopy
from dataclasses import replace
from typing import Any, cast

import httpx
import pytest

from src.agent.agent import _exploration_fingerprint, ExecutedToolCall, WholeTargetStallTracker
from src.llm.core.types import ChatRequest, FunctionCall, Message, ToolCall
from src.permission.permission import Decision
from src.skills.artifacts import completion_artifact_path
from src.workflow.assessment import resolve_sources
from src.workflow.state import WorkflowObjective
from tests.helpers.burp_selection import make_runtime, ORIGIN
from tests.helpers.discovery_calls import execute, attribution, captured
from tests.helpers.workflow import record_completed_phase


@pytest.fixture
async def discovery(tmp_path, monkeypatch):
    # Deliberately put paths between the context guard's distributed windows.
    spec = {'openapi': '3.0.3', 'info': {'description': 'description ' * 50},
            'servers': [{'url': '/b2b/v2'}],
            'paths': {'/orders': {'post': {'requestBody': {'content': {'application/json': {
                'schema': {'type': 'object', 'properties': {'cid': {'type': 'string'}}}}}}}}},
            'components': {'schemas': {'Note': {'description': 'schema ' * 500}}}}
    body = 'const options = {swaggerDoc: ' + json.dumps(spec) + '}; SwaggerUIBundle(options);'
    sent = []
    real_client = httpx.AsyncClient

    def respond(request):
        sent.append(str(request.url))
        return httpx.Response(200, content=body.encode(), headers={'content-type': 'application/javascript'}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real_client(transport=httpx.MockTransport(respond), **kw))
    runtime = make_runtime(tmp_path)
    runtime.workflow.objective = WorkflowObjective('discovery', 'whole_target', ORIGIN)
    runtime.workflow.objective.add_requested_goal('sqli')
    recon = runtime.skills.get('recon')
    assert recon is not None and recon.completion_artifact
    artifact = completion_artifact_path(recon.completion_artifact, ORIGIN)
    path = tmp_path / artifact
    path.parent.mkdir(parents=True)
    path.write_text('Synthetic offline recon prerequisite, not a target assessment.')
    record_completed_phase(runtime.workflow, 'recon', objective_id='discovery', target_origin=ORIGIN,
                           artifact_ref=artifact)
    runtime.workflow.completed_skills.add('recon')
    runtime.workflow.completed_artifacts['recon'] = artifact
    runtime.workflow.current_phase = 'enumeration'
    await execute(runtime, 'load_skill', {'name': 'web-enumeration'})
    output = await execute(runtime, 'http', {'url': '/docs/init.js', 'phase': 'recon', 'max_response_bytes': 8192})
    source = next(iter(runtime.workflow.discovery_sources.values()))
    return runtime, source, body, output, sent


def read_args(source, start=0):
    return {'discovery_source_id': source.id, 'start_char': start, 'max_chars': 2000}


async def test_metadata_wrong_reader_and_authorized_content_are_distinct(discovery):
    rt, source, body, _, sent = discovery
    metadata = json.loads((await execute(rt, 'workflow', {'action': 'get_source',
                          'discovery_source_id': source.id})).result)
    assert metadata['ok'] and metadata['discovery_source'] == source.to_dict()
    assert 'content' not in metadata and body not in json.dumps(metadata)
    before = deepcopy(rt.workflow.to_dict())
    rights = rt.engagement.http_permissions
    authorization = dict(rights.grants), rights.epoch
    wrong = await execute(rt, 'read_http_observation', {'observation_id': source.retained_ref,
                          'start_char': 0, 'max_chars': 2000}, success=False)
    assert wrong.status == 'error' and 'ownership or scope is unavailable' in wrong.result
    assert 'read_discovery_source' in wrong.result and 'Do not repeat' in wrong.result
    chunks, start = [], 0
    while True:
        result = await execute(rt, 'read_discovery_source', read_args(source, start))
        header, content = str(result.result).split('\n', 1)
        page = json.loads(header)
        assert len(result.result) <= 2000
        assert page['discovery_source_id'] == source.id and page['retained_hash'] == source.retained_hash
        assert page['complete'] and not page['adapter_truncated']
        assert content == body[page['start_char']:page['end_char']]
        chunks.append(content)
        if page['next_start_char'] is None:
            break
        assert page['next_start_char'] > start
        start = page['next_start_char']
    assert ''.join(chunks) == body and len(sent) == 1
    assert rt.workflow.to_dict() == before and not source.selected
    assert (rights.grants, rights.epoch) == authorization
    item = rt.policy.observations._items[source.retained_ref]
    assert item.candidate_id is item.attempt_id is None
    assert not rt.workflow.candidates and not rt.workflow.attempts and not rt.workflow.evidence


async def test_production_reduction_and_request_expose_bounded_recovery(discovery):
    rt, source, body, output, _ = discovery
    agent = rt.agent
    assert agent._planner_context().structured_phase == 'enumeration'
    call = ToolCall('capture', FunctionCall('http', json.dumps({'url': '/docs/init.js', 'phase': 'recon'})))
    parsed = agent.parse_tool_call(call)
    agent._tool_call_event(call, parsed)
    working = [Message('system', 'fixed context ' * 2000)]
    agent.record_tool_result(call, parsed, output, lambda _: None, working, defer_admission=True)
    original = working[-1].content
    agent.set_auto_compact_threshold(1000)
    req = ChatRequest(agent.client.model(), working, tools=agent.tools.as_llm_tools())
    agent.guard_working_context(working, lambda _: None, request=req)
    assert len(working[-1].content) < len(original) and 'omitted' in working[-1].content
    assert '"paths"' not in working[-1].content and '"cid"' not in working[-1].content
    assert rt.policy.observations._items[source.retained_ref].body.decode() == body
    await agent._prepare_turn_request(req, lambda _: None)
    specs = cast(Any, req.tools)
    names = {s['function']['name'] for s in specs or []}
    assert {'http', 'read_discovery_source', 'read_http_observation', 'workflow'} <= names
    workflow = next(s['function'] for s in specs or [] if s['function']['name'] == 'workflow')
    assert 'record_input' in workflow['parameters']['properties']['action']['enum']
    guidance = next(m.content for m in req.messages if m.content.startswith('Workflow action guidance:'))
    assert 'read_discovery_source' in guidance and 'metadata' in guidance
    assert 'prior knowledge' in guidance.lower() and 'record_input' in guidance
    result = await execute(rt, 'read_discovery_source', read_args(source, body.index('"paths"')))
    assert '"/orders"' in result.result and '"post"' in result.result and '"cid"' in result.result
    assert '/rest/user/login' not in result.result and '/rest/products/search' not in result.result


async def test_inspected_unselected_document_can_record_grounded_input(discovery):
    rt, source, body, _, sent = discovery
    await execute(rt, 'read_discovery_source', read_args(source, body.index('"paths"')))
    before = rt.workflow.progress_facts()
    result = json.loads((await execute(rt, 'workflow', {'action': 'record_input', 'method': 'POST',
        'endpoint': '/b2b/v2/orders', 'parameter': 'cid', 'location': 'json', 'input_type': 'string',
        'content_type': 'application/json', 'source_attribution': attribution(source, 'paths./orders.post.requestBody')})).result)
    assert result['created'] and result['attribution_kind'] == 'manual_declaration'
    assert result['input']['source_ref'] is None and result['input']['baseline_request_ref'] is None
    assert rt.workflow.progress_facts() - before
    assert not rt.workflow.discovery_sources[source.id].selected and len(sent) == 1
    assert not rt.workflow_tool.phase_completion_readiness('web-enumeration')['ready']
    assert not rt.workflow.candidates and not rt.workflow.evidence
    # Production evidence resolution still rejects this discovery observation.
    with pytest.raises(ValueError, match='ownership mismatch'):
        resolve_sources(rt.policy, rt.workflow, None, None, [source.retained_ref], terminal=True, negative=False)


@pytest.mark.parametrize('fault', ['hash', 'body', 'session', 'epoch', 'objective', 'scope',
                                 'revoked', 'reader-revoked', 'secret', 'missing', 'owner'])
async def test_discovery_read_rechecks_authorization_and_provenance(discovery, fault):
    rt, source, _, _, sent = discovery
    item = rt.policy.observations._items[source.retained_ref]
    if fault == 'hash': item = replace(item, retained_hash='0' * 64)
    if fault == 'body': item = replace(item, body=b'tampered')
    if fault == 'session': item = replace(item, source_details={**item.source_details, 'analysis_session': 'foreign'})
    if fault == 'epoch': rt.engagement.http_permissions.epoch = 'foreign'
    if fault == 'objective': rt.workflow.objective.id = 'foreign'
    if fault == 'scope': rt.engagement.remove_origin(ORIGIN)
    if fault == 'revoked': rt.policy.revoke('http')
    if fault == 'reader-revoked': rt.policy.revoke('read_discovery_source')
    if fault == 'owner': item = replace(item, candidate_id='owned-candidate', attempt_id='owned-attempt')
    if fault == 'secret': rt.policy.internal_secret_values = lambda: ('swaggerDoc',)
    rt.policy.observations._items[source.retained_ref] = item
    if fault == 'missing': rt.policy.observations._items.pop(source.retained_ref)
    before = deepcopy(rt.workflow.to_dict())
    result = await execute(rt, 'read_discovery_source', read_args(source), success=False)
    assert result.status == 'error' and 'swaggerDoc' not in result.result
    assert rt.workflow.to_dict() == before and len(sent) == 1


async def test_range_requires_fresh_permission_and_rechecks_after_review(discovery):
    rt, source, _, _, sent = discovery
    rt.prompter.set_yolo(False)
    rt.operator.decision = Decision.DENY
    denied = await execute(rt, 'read_discovery_source', read_args(source), success=False)
    assert denied.status == 'error'
    assert rt.operator.requests[-1].tool == 'read_discovery_source'
    assert rt.operator.requests[-1].no_session_cache
    rt.policy.retry()
    rt.operator.decision = Decision.ALLOW_ONCE

    async def revoke(_):
        rt.policy.revoke('http')

    rt.operator.review = revoke
    denied = await execute(rt, 'read_discovery_source', read_args(source), success=False)
    assert denied.status == 'error' and len(sent) == 1


async def test_repeated_pages_and_wrong_reads_cannot_manufacture_progress(discovery):
    rt, source, _, _, _ = discovery
    good = await execute(rt, 'read_discovery_source', read_args(source))
    call = ExecutedToolCall('read_discovery_source', read_args(source), True, good)
    fingerprint = _exploration_fingerprint(call, ORIGIN)
    assert fingerprint is not None
    tracker = WholeTargetStallTracker()
    assert tracker.record_iteration(new_facts=frozenset(), activity_fingerprints=[fingerprint]) == 'novel_exploration'
    for _ in range(4):
        assert tracker.record_iteration(new_facts=frozenset(), activity_fingerprints=[fingerprint]) == 'no_progress'
    assert tracker.consecutive_no_progress == 4
    failed = await execute(rt, 'read_http_observation', {'observation_id': source.retained_ref,
        'start_char': 0, 'max_chars': 2000}, success=False)
    assert _exploration_fingerprint(ExecutedToolCall('read_http_observation', {}, True, failed), ORIGIN) is None


async def test_read_pages_are_preserved_then_revalidated_before_outbound(discovery):
    rt, source, _, _, _ = discovery
    await execute(rt, 'read_discovery_source', read_args(source))
    message = deepcopy(rt.agent.history[-1])
    assert message.http_response_sources == [source.retained_ref]
    working = [Message('system', 'fixed' * 2000), message]
    rt.agent.set_auto_compact_threshold(1000)
    rt.agent.guard_working_context(working, lambda _: None)
    assert working[-1].content == message.content  # bounded reader pages stay whole
    rt.agent._protect_http_context(working)
    assert working[-1].content == message.content
    rt.policy.revoke('http')
    rt.agent._protect_http_context(working)
    assert 'HTTP analysis omitted' in working[-1].content


async def test_imported_discovery_capture_uses_its_own_gate_without_ownership(tmp_path):
    rt, source = await captured(tmp_path)
    result = await execute(rt, 'read_discovery_source', read_args(source))
    assert '<form' in result.result and not rt.workflow.attempts
    rt.policy.revoke('browser_capture_get')
    refused = await execute(rt, 'read_discovery_source', read_args(source), success=False)
    assert refused.status == 'error'


async def test_truncated_source_preserves_adapter_limits(discovery):
    rt, _, _, _, sent = discovery
    # A separate bounded capture; the mock transport sends no network traffic.
    await execute(rt, 'http', {'url': '/docs/partial.js', 'phase': 'recon', 'max_response_bytes': 1024})
    source = next(s for s in rt.workflow.discovery_sources.values() if s.document_url.endswith('/partial.js'))
    result = await execute(rt, 'read_discovery_source', read_args(source))
    header, content = result.result.split('\n', 1)
    page = json.loads(header)
    assert not page['complete'] and page['adapter_truncated']
    assert len(content.encode()) <= 1024 and len(result.result) <= 2000 and len(sent) == 2


@pytest.mark.parametrize('changes', [
    {'start_char': -1}, {'max_chars': 0}, {'max_chars': 2001}, {'start_char': 1.5},
    {'observation_id': 'obs_' + '0' * 32}, {'discovery_source_id': 'obs_' + '0' * 32},
])
async def test_malformed_range_rejected_before_permission_or_read(discovery, changes):
    rt, source, _, _, sent = discovery
    before = len(rt.operator.requests), rt.workflow.to_dict()
    result = await execute(rt, 'read_discovery_source', {**read_args(source), **changes}, success=False)
    assert result.status == 'error' and result.error_kind == 'invalid_args'
    assert (len(rt.operator.requests), rt.workflow.to_dict()) == before and len(sent) == 1


async def test_content_failure_does_not_block_other_observed_input(discovery):
    rt, source, _, _, sent = discovery
    rt.policy.observations._items.pop(source.retained_ref)
    failed = await execute(rt, 'read_discovery_source', read_args(source), success=False)
    assert failed.status == 'error'
    # A form already captured independently; no Swagger or source selection is needed.
    from tests.helpers.burp_selection import ingest
    row = ingest(rt, id_='fallback', path='/app/form', respBody='<form method="get"><input name="q"></form>',
                 responseComplete=True, status=200)
    await execute(rt, 'browser_capture_get', {'id': row['id']})
    form = next(s for s in rt.workflow.discovery_sources.values() if s.kind == 'capture')
    before = rt.workflow.progress_facts()
    await execute(rt, 'workflow', {'action': 'record_input', 'method': 'GET', 'endpoint': '/app/form',
        'parameter': 'q', 'location': 'query', 'source_attribution': attribution(form, 'form input[name=q]')})
    assert rt.workflow.progress_facts() - before and len(sent) == 1
    assert all(not s.selected for s in rt.workflow.discovery_sources.values())
    assert not rt.workflow.candidates and not rt.workflow.attempts


async def test_every_range_requires_review_and_obeys_session_call_budget(discovery):
    rt, source, _, _, sent = discovery
    rt.prompter.set_yolo(False)
    for start in (0, 100):
        await execute(rt, 'read_discovery_source', read_args(source, start))
    requests = [r for r in rt.operator.requests if r.tool == 'read_discovery_source']
    assert len(requests) == 2 and all(r.no_session_cache for r in requests)
    rt.policy.max_calls = rt.policy.used
    failed = await execute(rt, 'read_discovery_source', read_args(source, 200), success=False)
    assert failed.status == 'error' and 'session-call-budget-exhausted' in failed.result
    assert len(sent) == 1


async def test_discovery_reader_is_not_available_outside_whole_target(discovery):
    rt, source, _, _, sent = discovery
    rt.workflow.objective = WorkflowObjective('direct-fixture', 'direct', ORIGIN)
    req = ChatRequest(rt.agent.client.model(), [Message('user', 'continue')], tools=rt.agent.tools.as_llm_tools())
    await rt.agent._prepare_turn_request(req, lambda _: None)
    assert 'read_discovery_source' not in {s['function']['name'] for s in cast(Any, req.tools) or []}
    refused = await execute(rt, 'read_discovery_source', read_args(source), success=False)
    assert refused.status == 'error' and len(sent) == 1
