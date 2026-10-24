"""Simulated caller declarations exercise runtime contracts, never LLM accuracy."""
import asyncio
import json

import httpx
import pytest

from src.llm.core.types import ToolCall, FunctionCall
from src.workflow.state import WorkflowObjective, WorkflowState
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.burp_selection import make_runtime, ORIGIN
from tests.helpers.discovery_calls import execute, captured, attribution


async def record(runtime, source, **changes):
    return await execute(runtime, 'workflow', {'action': 'record_input', 'method': 'POST',
        'endpoint': ORIGIN + '/app/submit', 'parameter': 'q', 'location': 'form',
        'content_type': 'application/x-www-form-urlencoded', 'source_attribution': attribution(source),
        **changes})


async def test_process_source_is_neither_advertised_nor_executable(tmp_path):
    from src.tools.workflow.action_view import ActionView
    runtime, source = await captured(tmp_path)
    tool = runtime.workflow_tool
    assert 'process_source' not in tool.schema()['properties']['action']['enum']
    assert 'extractor' not in tool.schema()['properties']
    assert 'process_source' not in tool.schema()['properties']['action']['description']
    for mode in ('direct', 'candidate_validation', 'whole_target', None):
        assert 'process_source' not in ActionView.for_objective(mode).available
    before = runtime.workflow.to_dict()
    result = await execute(runtime, 'workflow', {'action': 'process_source',
        'discovery_source_id': source.id, 'retained_ref': source.retained_ref, 'extractor': 'html'}, success=False)
    assert result.status == 'error' and runtime.workflow.to_dict() == before


async def test_capture_document_attribution_session_dedup_and_no_reader_rights(tmp_path):
    runtime, source = await captured(tmp_path)
    first = json.loads((await record(runtime, source)).result)
    assert first['attribution_kind'] == 'manual_declaration'
    item = first['input']
    assert item['source_ref'] is item['baseline_request_ref'] is item['auth_context_ref'] is None
    before = runtime.workflow.to_dict()
    assert not json.loads((await record(runtime, source)).result)['created']
    assert runtime.workflow.to_dict() == before
    refused = await execute(runtime, 'read_http_observation', {'observation_id': source.retained_ref,
        'start_char': 0, 'max_chars': 100}, success=False)
    assert refused.status == 'error' and 'ownership or scope is unavailable' in refused.result
    assert runtime.workflow.to_dict() == before
    await runtime.agent.save()
    assert runtime.store.load().workflow.to_dict() == before
    runtime.workflow.replace_from(WorkflowState.from_dict(before))
    runtime.engagement.http_permissions.reset()
    runtime.policy.observations._items.clear()
    # Metadata remains usable as historical attribution, never authority to read/replay.
    await record(runtime, source, parameter='documented_field')
    denied = await execute(runtime, 'read_http_observation', {'observation_id': source.retained_ref,
        'start_char': 0, 'max_chars': 100}, success=False)
    assert denied.status == 'error'
    assert not runtime.workflow.attempts and not runtime.workflow.evidence and not runtime.workflow.candidates


async def test_native_http_retention_manual_inputs_and_html_navigation_attestation(tmp_path, monkeypatch):
    from tests.helpers.workflow import record_completed_phase
    real_client, sent = httpx.AsyncClient, []
    body = '<form method="post" action="submit"><input name="q"><input name="password"></form>'
    def handler(request):
        sent.append(request)
        return httpx.Response(200, content=body.encode(), headers={'Content-Type': 'text/html'}, request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    runtime = make_runtime(tmp_path)
    runtime.workflow.objective = WorkflowObjective('discovery', 'whole_target', ORIGIN)
    record_completed_phase(runtime.workflow, 'recon', objective_id='discovery', target_origin=ORIGIN,
                           artifact_ref='artifacts/recon.md')
    output = await execute(runtime, 'http', {'url': '/app/document.html', 'phase': 'recon'})
    source = next(iter(runtime.workflow.discovery_sources.values()))
    observation = runtime.policy.observations._items[source.retained_ref]
    assert body in output.result and observation.complete and not observation.truncated
    assert not runtime.workflow.attack_surface_inputs  # no automatic form extraction
    coverage = runtime.workflow.phase_coverage_record('enumeration', 'html_navigation')
    assert coverage is not None and coverage.status == 'performed'
    await record(runtime, source)
    await record(runtime, source, parameter='password', source_attribution=attribution(source, 'input[name=password]'))
    assert {row.parameter for row in runtime.workflow.objective_inputs()} == {'q', 'password'}
    assert source.document_url == ORIGIN + '/app/document.html' and len(sent) == 1
    assert runtime.workflow.discovery_sources[source.id] == source and not source.selected


async def test_documented_json_fields_media_variants_use_separate_canonical_records(tmp_path):
    # Caller-authored declarations follow the fixture; the runtime never parses it.
    spec = {'openapi': '3.1.0', 'paths': {'/orders': {'post': {'requestBody': {'content': {
        media: {'schema': {'properties': {name: {'type': kind} for name, kind in
            [('cid', 'string'), ('orderLines', 'array'), ('orderLinesData', 'string')]}}}
        for media in ('application/json', 'application/x-www-form-urlencoded')}}}}}}
    runtime, source = await captured(tmp_path, json.dumps(spec))
    assert not runtime.workflow.attack_surface_inputs
    ids = set()
    for media, location in [('application/json', 'json'), ('application/x-www-form-urlencoded', 'form')]:
        for name, kind in [('cid', 'string'), ('orderLines', 'array'), ('orderLinesData', 'string')]:
            result = json.loads((await record(runtime, source, endpoint=ORIGIN + '/orders',
                parameter=name, input_type=kind, content_type=media, location=location,
                source_attribution=attribution(source, f'/paths/~1orders/post/requestBody/content/{media}/{name}'))).result)
            ids.add(result['input']['id'])
    assert len(ids) == 6
    assert all(item.disposition == 'pending' for item in runtime.workflow.objective_inputs())
    assert len([link for link in runtime.workflow.discovery_provenance.values() if link.input_id]) == 6
    assert runtime.workflow.discovery_sources[source.id] == source
    assert not runtime.workflow.candidates and not runtime.workflow.evidence


async def test_manual_attribution_cannot_override_concrete_http_source_binding(tmp_path):
    from tests.helpers.burp_selection import ingest
    runtime = make_runtime(tmp_path)
    runtime.workflow.objective = WorkflowObjective('discovery', 'whole_target', ORIGIN)
    row = ingest(runtime, path='/products/1/reviews', respBody='[]', responseComplete=True, status=200)
    await execute(runtime, 'browser_capture_get', {'id': row['id']})
    source = next(iter(runtime.workflow.discovery_sources.values()))
    args = {'action': 'record_input', 'method': 'GET', 'endpoint': ORIGIN + '/products/{id}/reviews',
        'parameter': 'id', 'location': 'path', 'source_ref': source.retained_ref,
        'source_attribution': attribution(source, 'concrete request path')}
    before = runtime.workflow.to_dict()
    refused = await execute(runtime, 'workflow', args, success=False)
    assert refused.status == 'error' and 'path does not match' in refused.result
    assert runtime.workflow.to_dict() == before
    args['endpoint'] = ORIGIN + '/products/1/reviews'
    accepted = json.loads((await execute(runtime, 'workflow', args)).result)
    assert accepted['input']['source_ref'] == source.retained_ref


@pytest.mark.parametrize('fault', ['hash', 'ref', 'source', 'origin', 'objective', 'secret', 'null'])
async def test_invalid_attribution_tool_call_rejects_input_atomically(tmp_path, fault):
    runtime, source = await captured(tmp_path)
    declaration = attribution(source)
    args = {'action': 'record_input', 'method': 'POST', 'endpoint': ORIGIN + '/orders',
        'parameter': 'cid', 'location': 'json', 'source_attribution': declaration}
    if fault == 'hash': declaration['retained_hash'] = 'f' * 64
    if fault == 'ref': declaration['retained_ref'] = 'obs-wrong'
    if fault == 'source': declaration['discovery_source_id'] = 'ds_' + 'f' * 64
    if fault == 'origin': args['endpoint'] = 'http://other.test/orders'
    if fault == 'objective': args['objective_id'] = 'other'
    if fault == 'secret': declaration['document_location'] = 'password=fixture-secret'
    if fault == 'null': args['source_attribution'] = None
    before, revision = runtime.workflow.to_dict(), runtime.workflow.committed_revision
    refused = await execute(runtime, 'workflow', args, success=False)
    assert refused.status == 'error' and runtime.workflow.to_dict() == before
    assert runtime.workflow.committed_revision == revision and not runtime.workflow.attack_surface_inputs
    assert 'fixture-secret' not in refused.result


async def test_truncated_unowned_source_stays_limited_without_fetch_or_extraction(tmp_path):
    runtime, source = await captured(tmp_path)
    await execute(runtime, 'workflow', {'action': 'select_source', 'discovery_source_id': source.id})
    await execute(runtime, 'workflow', {'action': 'set_source_disposition', 'discovery_source_id': source.id,
        'source_disposition': 'partial', 'source_reason': 'Only visible prefix reviewed',
        'source_limitations': ['unavailable remainder'], 'source_bounds': {'max_bytes': 8192}})
    await record(runtime, source)
    assert runtime.workflow.discovery_sources[source.id].unresolved
    assert not runtime.workflow_tool.phase_completion_readiness('web-enumeration')['ready']


async def test_overlapping_duplicate_attribution_has_one_atomic_commit(tmp_path):
    runtime, source = await captured(tmp_path)
    tool, state = runtime.workflow_tool, runtime.workflow
    from src.permission.permission import AlwaysAllow
    args = {'action': 'record_input', 'method': 'POST', 'endpoint': '/app/submit',
            'parameter': 'q', 'location': 'form', 'source_attribution': attribution(source)}
    await state.mutation_lock.acquire()
    tasks = [asyncio.create_task(tool.run(args, FakeSignal(), AlwaysAllow())) for _ in range(2)]
    await asyncio.sleep(0)
    revision = state.committed_revision
    assert not state.attack_surface_inputs
    state.mutation_lock.release()
    results = [json.loads(row) for row in await asyncio.gather(*tasks)]
    assert sorted(row['created'] for row in results) == [False, True]
    assert state.committed_revision == revision + 1
    assert len(state.attack_surface_inputs) == 1
    assert len([row for row in state.discovery_provenance.values() if row.input_id]) == 1


@pytest.mark.parametrize('stop', ['cancel', 'generation'])
async def test_queued_attribution_cancel_or_restore_cannot_publish_orphans(tmp_path, stop):
    from src.permission.permission import AlwaysAllow
    runtime, source = await captured(tmp_path)
    state = runtime.workflow
    await state.mutation_lock.acquire()
    task = asyncio.create_task(runtime.workflow_tool.run({'action': 'record_input', 'method': 'POST',
        'endpoint': '/app/submit', 'parameter': 'q', 'location': 'form',
        'source_attribution': attribution(source)}, FakeSignal(), AlwaysAllow()))
    await asyncio.sleep(0)
    before = state.to_dict()
    if stop == 'cancel':
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        state.replace_from(WorkflowState.from_dict(before))
    state.mutation_lock.release()
    if stop == 'generation':
        assert 'generation' in await task
    assert state.to_dict() == before and not state.attack_surface_inputs


async def test_cancelled_signal_does_not_admit_input_or_provenance(tmp_path):
    runtime, source = await captured(tmp_path)
    before = runtime.workflow.to_dict()
    signal = FakeSignal()
    signal.aborted = True
    call = ToolCall('cancel', FunctionCall('workflow', json.dumps({'action': 'record_input',
        'method': 'POST', 'endpoint': '/submit', 'parameter': 'q', 'location': 'form',
        'source_attribution': attribution(source)})))
    result = await runtime.agent.run_parsed_tool_call(call, runtime.agent.parse_tool_call(call), signal)
    assert result.status == 'cancelled' and runtime.workflow.to_dict() == before
