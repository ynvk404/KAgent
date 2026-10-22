"""Request-context consistency through production discovery, with no real I/O."""
from copy import deepcopy
from dataclasses import replace
import json
import socket

import httpx
import pytest

from src.workflow.state import WorkflowObjective
from src.workflow.assessment import digest, source_row
from tests.helpers.burp_selection import make_runtime, ingest, ORIGIN
from tests.helpers.discovery_calls import execute, attribution


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny(*_args, **_kwargs):
        raise AssertionError('real network forbidden')
    monkeypatch.setattr(socket.socket, 'connect', deny)
    monkeypatch.setattr(socket.socket, 'connect_ex', deny)
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', 0))])
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200,
            headers={'content-type': 'text/plain'}, content=b'bounded discovery response', request=req)), **kwargs))


async def source_runtime(tmp_path, producer='http', path='/search?q=baseline'):
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('input-sources', 'whole_target', ORIGIN)
    if producer == 'http':
        await execute(rt, 'http', {'url': path, 'phase': 'recon'})
    else:
        row = ingest(rt, path=path, kind=producer, respBody='capture response', responseComplete=True, status=200)
        await execute(rt, 'browser_capture_get', {'id': row['id']})
    source = next(iter(rt.workflow.discovery_sources.values()))
    item = rt.policy.observations._items[source.retained_ref]
    assert item.candidate_id is None and item.attempt_id is None
    assert not rt.workflow.attempts
    return rt, source


async def record(rt, ref, **changes):
    args = {'action': 'record_input', 'method': 'GET', 'endpoint': ORIGIN + '/search?q=other',
            'parameter': 'q', 'location': 'query', **changes}
    if ref is not None:
        args['source_ref'] = ref
    return await execute(rt, 'workflow', args, success=False)


@pytest.mark.parametrize('producer', ['http', 'burp', 'browser'])
async def test_unowned_recon_and_capture_sources_match_without_reading_evidence(tmp_path, producer, monkeypatch):
    rt, source = await source_runtime(tmp_path, producer)
    def forbidden(*_args, **_kwargs):
        raise AssertionError('discovery input must not use terminal evidence/observation reader')
    monkeypatch.setattr('src.tools.common.tool_result.ReadHTTPObservation.validate_rights', forbidden)
    monkeypatch.setattr('src.tools.workflow.workflow_tool.resolve_sources', forbidden)
    before_sources = deepcopy(rt.workflow.discovery_sources)
    output = await record(rt, source.retained_ref)
    assert json.loads(output.result)['input']['source_ref'] == source.retained_ref
    assert rt.workflow.discovery_sources == before_sources
    assert not rt.workflow.attempts and not rt.workflow.evidence and not rt.workflow.candidates
    # Input-linked Candidate inherits the checked input identity.
    iid = json.loads(output.result)['input']['id']
    candidate = await execute(rt, 'workflow', {'action': 'record_candidate', 'input_id': iid, 'candidate_class': 'xss'})
    assert json.loads(candidate.result)['candidate']['endpoint'] == ORIGIN + '/search?q=other'


@pytest.mark.parametrize('fault,reason', [
    ('method', 'method'), ('path', 'path'), ('robots', 'path'), ('origin', 'origin'),
    ('missing', 'unavailable'), ('evicted', 'unavailable'), ('session', 'provenance'),
    ('epoch', 'provenance'), ('metadata', 'metadata'), ('method-metadata', 'metadata'),
    ('kind', 'metadata'), ('producer', 'metadata'), ('integrity', 'provenance'),
    ('revoked', 'access unavailable'), ('source-provenance', 'metadata'), ('denied', 'revoked'),
    ('unknown-kind', 'metadata'), ('url-metadata', 'metadata'),
])
async def test_http_source_rejection_is_atomic_and_never_drops_ref(tmp_path, fault, reason):
    rt, source = await source_runtime(tmp_path, path='/robots.txt' if fault == 'robots' else '/search')
    ref = source.retained_ref
    changes = {}
    item = rt.policy.observations._items[ref]
    if fault == 'method': changes['method'] = 'POST'
    elif fault == 'path': changes['endpoint'] = ORIGIN + '/other'
    elif fault == 'robots': changes['endpoint'] = ORIGIN + '/rest/product/search'
    elif fault == 'origin': changes['endpoint'] = 'http://other.test/search'
    elif fault == 'missing': ref = 'obs_' + 'f' * 32
    elif fault == 'evicted': rt.policy.observations._items.clear()
    elif fault == 'session': rt.policy.observations._items[ref] = replace(item, source_details={'analysis_session': 'other'})
    elif fault == 'epoch': rt.policy.observations._items[ref] = replace(item, epoch='old')
    elif fault == 'metadata': rt.policy.observations._items[ref] = replace(item, source_details={})
    elif fault == 'method-metadata': rt.policy.observations._items[ref] = replace(item, method='')
    elif fault == 'kind': rt.policy.observations._items[ref] = replace(item, source_kind=None)
    elif fault == 'unknown-kind': rt.policy.observations._items[ref] = replace(item, source_kind='unknown')
    elif fault == 'url-metadata': rt.policy.observations._items[ref] = replace(item, url='')
    elif fault == 'producer': rt.policy.observations._items[ref] = replace(item, producer='plugin')
    elif fault == 'integrity': rt.policy.observations._items[ref] = replace(item, url=ORIGIN + '/other')
    elif fault == 'revoked': rt.policy.revoke('http')
    elif fault == 'source-provenance':
        rt.workflow.discovery_sources.clear()
        damaged = replace(source, retained_hash='f' * 64, id='')
        rt.workflow.discovery_sources[damaged.id] = damaged
    elif fault == 'denied': rt.engagement.http_permissions.denied = True
    before = deepcopy(rt.workflow.to_dict())
    revision = rt.workflow.committed_revision
    output = await record(rt, ref, **changes)
    assert output.status == 'error' and reason in output.result, output.result
    assert rt.workflow.to_dict() == before and rt.workflow.committed_revision == revision
    assert rt.workflow_tool.active_attempt is None
    assert not rt.workflow.attack_surface_inputs


async def test_resolution_and_source_kind_identify_http_without_obs_prefix(tmp_path):
    rt, source = await source_runtime(tmp_path)
    old_ref = source.retained_ref
    item = replace(rt.policy.observations._items.pop(old_ref), id='opaque-http-reference')
    item = replace(item, retained_hash=digest(source_row(item)))
    rt.policy.observations._items[item.id] = item
    rt.workflow.discovery_sources.clear()
    from src.workflow.discovery.inventory import observation_handoff
    observation_handoff(rt.workflow, item)
    before = deepcopy(rt.workflow.to_dict())
    output = await record(rt, item.id, method='POST')
    assert output.status == 'error' and 'method does not match' in output.result
    assert rt.workflow.to_dict() == before
    assert json.loads((await record(rt, item.id)).result)['ok']


@pytest.mark.parametrize('producer', ['http', 'burp', 'browser'])
async def test_live_trusted_observation_metadata_does_not_require_frontier_publication(tmp_path, producer):
    rt, source = await source_runtime(tmp_path, producer)
    rt.workflow.discovery_sources.clear()
    output = await record(rt, source.retained_ref)
    assert json.loads(output.result)['ok'] and not rt.workflow.attempts


@pytest.mark.parametrize('ref', [None, 'documented-request-context'])
async def test_documentation_and_non_http_context_preserve_contract(tmp_path, ref):
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('input-sources', 'whole_target', ORIGIN)
    output = await record(rt, ref)
    assert json.loads(output.result)['input']['source_ref'] == ref


async def test_capture_manual_attribution_keeps_document_provenance_separate_from_request_context(tmp_path):
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('input-sources', 'whole_target', ORIGIN)
    row = ingest(rt, path='/document', respBody='<form action="/submit" method="post"><input name="q"></form>',
                 responseComplete=True, status=200)
    await execute(rt, 'browser_capture_get', {'id': row['id']})
    source = next(iter(rt.workflow.discovery_sources.values()))
    await execute(rt, 'workflow', {'action': 'record_input', 'method': 'POST', 'endpoint': ORIGIN + '/submit',
        'parameter': 'q', 'location': 'form', 'source_attribution': attribution(source)})
    item = next(iter(rt.workflow.attack_surface_inputs.values()))
    assert item.method == 'POST' and item.endpoint == ORIGIN + '/submit' and item.source_ref is None
    assert not rt.workflow.attempts


async def test_resolved_non_http_observation_keeps_contract_even_with_obs_namespace(tmp_path):
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('input-sources', 'whole_target', ORIGIN)
    ref = rt.policy.observations.capture_output('fixture-tool', 'bounded local fixture', owner={})
    assert ref.startswith('obs_')
    assert rt.policy.observations._items[ref].source_kind == 'tool-output'
    output = await record(rt, ref)
    assert json.loads(output.result)['input']['source_ref'] == ref


async def test_redacted_query_values_do_not_replace_or_obscure_http_source_geometry(tmp_path):
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('input-sources', 'whole_target', ORIGIN)
    await execute(rt, 'http', {'url': '/search?token=fixture-sensitive-value', 'phase': 'recon'})
    item = next(iter(rt.policy.observations._items.values()))
    assert 'fixture-sensitive-value' not in item.url
    assert item.candidate_id is None and item.attempt_id is None
    output = await record(rt, item.id)
    assert json.loads(output.result)['input']['source_ref'] == item.id
    assert 'fixture-sensitive-value' not in output.result
