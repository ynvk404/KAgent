"""Admitted scoped capture -> local syntax -> existing input analysis contract."""
import json

import pytest

from src.llm.core.types import ToolCall, FunctionCall
from src.permission.permission import Decision
from src.workflow.state import WorkflowObjective
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.burp_selection import make_runtime, ingest, ORIGIN


async def execute(runtime, name, args, *, success=True):
    agent = runtime.agent
    call = ToolCall('discovery-call', FunctionCall(name, json.dumps(args)))
    parsed = agent.parse_tool_call(call)
    agent._tool_call_event(call, parsed)
    output = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    agent.record_tool_result(call, parsed, output, lambda _: None, [])
    if success: assert output.status in {'success', 'observation'}, output.result
    return output


async def captured(tmp_path, body='<form method="post" action="submit"><input name="q"></form>', *, yolo=True,
                   content_type=None):
    runtime = make_runtime(tmp_path, yolo=yolo)
    runtime.workflow.objective = WorkflowObjective('discovery', 'whole_target', ORIGIN)
    row = ingest(runtime, path='/app/document.html', respBody=body, responseComplete=True, status=200,
                  respHeaders=[{'name': 'Content-Type', 'value': content_type}] if content_type else [])
    await execute(runtime, 'browser_capture_get', {'id': row['id']})
    assert len(runtime.workflow.discovery_sources) == 1
    source = next(iter(runtime.workflow.discovery_sources.values()))
    await execute(runtime, 'workflow', {'action': 'select_source', 'discovery_source_id': source.id})
    return runtime, source


async def process(runtime, source, *, success=True, **changes):
    return await execute(runtime, 'workflow', {'action': 'process_source', 'discovery_source_id': source.id,
        'retained_ref': source.retained_ref, 'extractor': 'html', **changes}, success=success)


async def test_capture_source_extraction_handoff_repeated_processing_and_session(tmp_path):
    runtime, source = await captured(tmp_path)
    await process(runtime, source)
    item = next(iter(runtime.workflow.attack_surface_inputs.values()))
    assert item.endpoint == ORIGIN + '/app/submit' and item.method == 'POST' and item.location == 'form'
    assert item.parameter == 'q' and item.source_ref is None and item.baseline_request_ref is None
    assert runtime.workflow.discovery_sources[source.id].disposition == 'processed'
    before = runtime.workflow.to_dict()
    await process(runtime, source)
    assert runtime.workflow.to_dict() == before
    await runtime.agent.save()
    restored = runtime.agent.store.load().workflow
    assert restored.to_dict() == before
    assert not restored.candidates and not restored.evidence and not restored.attempts


@pytest.mark.parametrize('attack', ['wrong_ref', 'wrong_source', 'revoke', 'capture_replaced', 'source_evicted', 'foreign_scope', 'secret'])
async def test_source_read_failure_is_atomic_without_replacement_or_authority(tmp_path, attack):
    runtime, source = await captured(tmp_path)
    changes = {}
    if attack == 'wrong_ref': changes['retained_ref'] = 'obs_' + 'f' * 32
    if attack == 'wrong_source': changes['discovery_source_id'] = 'ds_' + 'f' * 64
    if attack == 'revoke': runtime.policy.revoke('browser_capture_get')
    if attack == 'capture_replaced':
        ingest(runtime, path='/app/document.html', respBody='<form><input name="different"></form>', status=200)
    if attack == 'source_evicted': runtime.policy.observations._items.clear()
    if attack == 'foreign_scope': runtime.target.set_base_url('http://other.test')
    if attack == 'secret':
        runtime.agent._managed_http_secrets = lambda: ('submit',)
    before = runtime.workflow.to_dict()
    output = await process(runtime, source, success=False, **changes)
    assert output.status == 'error'
    assert runtime.workflow.to_dict() == before
    assert not runtime.workflow.attack_surface_inputs and not runtime.workflow.candidates and not runtime.workflow.evidence


async def test_extraction_registry_review_is_one_action_not_durable_policy(tmp_path):
    runtime, source = await captured(tmp_path, yolo=False)
    runtime.operator.requests.clear()
    runtime.operator.decision = Decision.DENY
    before = runtime.workflow.to_dict()
    output = await process(runtime, source, success=False)
    assert output.status == 'error' and runtime.workflow.to_dict() == before
    assert any(request.tool == 'workflow' and request.no_session_cache for request in runtime.operator.requests)
    runtime.operator.decision = Decision.ALLOW_ONCE
    await process(runtime, source)
    assert runtime.workflow.attack_surface_inputs


async def test_restore_does_not_restore_source_execution_authority(tmp_path):
    runtime, source = await captured(tmp_path)
    from src.workflow.state import WorkflowState
    restored = WorkflowState.from_dict(runtime.workflow.to_dict())
    runtime.workflow.replace_from(restored)
    runtime.engagement.http_permissions.reset()
    before = runtime.workflow.to_dict()
    result = await process(runtime, source, success=False)
    assert result.status == 'error' and runtime.workflow.to_dict() == before


async def test_openapi_runtime_retained_source_to_input_analysis_without_fetch(tmp_path):
    doc = {'openapi': '3.1.0', 'paths': {'/api/items/{id}': {'get': {'parameters': [
        {'in': 'path', 'name': 'id', 'required': True}, {'in': 'query', 'name': 'q'}]}}}}
    runtime, source = await captured(tmp_path, json.dumps(doc))
    await process(runtime, source, extractor='openapi')
    items = tuple(runtime.workflow.attack_surface_inputs.values())
    assert len(items) == 2 and {row.parameter for row in items} == {'id', 'q'}
    assert all(row.endpoint == ORIGIN + '/api/items/{id}' and row.disposition == 'pending' for row in items)
    listed = await execute(runtime, 'workflow', {'action': 'list', 'view': 'inputs'})
    assert json.loads(listed.result)['input_counts']['pending'] == 2
    assert not runtime.workflow.candidates and not runtime.workflow.validation_results and not runtime.workflow.evidence


async def test_native_http_source_bytes_use_actual_document_url_without_another_request(tmp_path, monkeypatch):
    import httpx
    real_client = httpx.AsyncClient
    sent = []
    def handler(request):
        sent.append(request)
        return httpx.Response(200, content=b'<form action="submit"><input name="q"></form>',
                              headers={'Content-Type': 'text/html'}, request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    runtime = make_runtime(tmp_path)
    runtime.workflow.objective = WorkflowObjective('discovery', 'whole_target', ORIGIN)
    await execute(runtime, 'http', {'url': '/app/document.html', 'phase': 'recon'})
    source = next(iter(runtime.workflow.discovery_sources.values()))
    assert source.kind == 'http' and source.document_url == ORIGIN + '/app/document.html'
    await execute(runtime, 'workflow', {'action': 'select_source', 'discovery_source_id': source.id})
    await process(runtime, source)
    item = next(iter(runtime.workflow.attack_surface_inputs.values()))
    assert item.endpoint == ORIGIN + '/app/submit' and item.method == 'GET'
    assert len(sent) == 1


async def test_truncated_native_discovery_uses_extraction_without_unowned_readback(tmp_path, monkeypatch):
    import httpx
    real_client = httpx.AsyncClient
    sent = []
    body = (b'<html><head><style>' + b'/* retained CSS */' * 600
            + b'</style></head><body><script src="/unseen.js"></script></body></html>')

    def handler(request):
        sent.append(request)
        return httpx.Response(200, content=body, headers={'Content-Type': 'text/html'}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    runtime = make_runtime(tmp_path)
    runtime.workflow.objective = WorkflowObjective('discovery', 'whole_target', ORIGIN)
    await execute(runtime, 'http', {'url': '/', 'phase': 'recon', 'max_response_bytes': 8192})
    source = next(iter(runtime.workflow.discovery_sources.values()))
    item = runtime.policy.observations._items[source.retained_ref]
    assert item.body == body[:8192] and item.truncated and not item.complete
    assert item.candidate_id is None and item.attempt_id is None
    await execute(runtime, 'workflow', {'action': 'select_source', 'discovery_source_id': source.id})
    await process(runtime, source)
    metadata = await execute(runtime, 'workflow', {'action': 'get_source', 'discovery_source_id': source.id})
    row = json.loads(metadata.result)['discovery_source']
    assert row['disposition'] == 'partial' and row['limitations'] and not row['bounded_stop']
    assert not runtime.workflow.attack_surface_inputs
    assert not any(endpoint.url.endswith('/unseen.js') for endpoint in runtime.workflow.endpoints.values())
    before = runtime.workflow.to_dict()
    await process(runtime, source)
    assert runtime.workflow.to_dict() == before
    # Even schema-correct raw readback cannot borrow discovery observations.
    refused = await execute(runtime, 'read_http_observation', {'observation_id': item.id,
        'start_char': 0, 'max_chars': 2000}, success=False)
    assert refused.status == 'error' and 'ownership or scope is unavailable' in str(refused.result)
    assert runtime.workflow.to_dict() == before and len(sent) == 1
    assert runtime.policy.observations._items[item.id] == item
    assert not runtime.workflow.candidates and not runtime.workflow.attempts and not runtime.workflow.evidence


@pytest.mark.parametrize('format', ['html', 'openapi'])
async def test_processing_cancelled_signal_does_not_publish(tmp_path, format):
    runtime, source = await captured(tmp_path)
    before = runtime.workflow.to_dict()
    signal = FakeSignal()
    signal.aborted = True
    call = ToolCall('cancel', FunctionCall('workflow', json.dumps({'action': 'process_source',
        'discovery_source_id': source.id, 'retained_ref': source.retained_ref, 'extractor': format})))
    result = await runtime.agent.run_parsed_tool_call(call, runtime.agent.parse_tool_call(call), signal)
    assert result.status == 'cancelled' and runtime.workflow.to_dict() == before


async def test_known_json_response_cannot_be_interpreted_as_live_html_form(tmp_path):
    runtime, source = await captured(tmp_path, json.dumps({'example': '<form><input name="fake"></form>'}),
                                      content_type='application/json')
    await process(runtime, source)
    assert not runtime.workflow.attack_surface_inputs
    assert runtime.workflow.discovery_sources[source.id].disposition == 'not_applicable'


async def test_restore_during_source_review_cannot_reuse_old_generation_approval(tmp_path):
    from src.workflow.state import WorkflowState
    runtime, source = await captured(tmp_path, yolo=False)
    before = runtime.workflow.to_dict()
    async def replace_during_review(request):
        if request.tool == 'workflow':
            runtime.workflow.replace_from(WorkflowState.from_dict(before))
    runtime.operator.review = replace_during_review
    result = await process(runtime, source, success=False)
    assert result.status == 'error'
    assert runtime.workflow.to_dict() == before and not runtime.workflow.attack_surface_inputs
