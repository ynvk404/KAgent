"""Offline playbook/action contracts, not evidence of an LLM following the playbook.

The fixture's literal definition and review facts are supplied by the test.
No JavaScript parser, evaluation, derived source or provider is involved.
"""
from __future__ import annotations

import json
import re
import socket
from typing import Any

import httpx
import pytest

from src.skills.artifacts import completion_artifact_path
from src.workflow.discovery.extraction import extract_html
from src.workflow.discovery.openapi import extract_openapi
from src.workflow.state import WorkflowObjective
from tests.helpers.burp_selection import make_runtime
from tests.integration.test_discovery_extraction import execute
from tests.skills.test_web_enumeration import read_skill

ORIGIN = 'http://catalog.test'
DOCUMENT = ORIGIN + '/docs/ui/initializer.js'
SPEC: dict[str, Any] = {
    'openapi': '3.0.3',
    'servers': [{'url': '/service/v4'}],
    'security': [{'BearerAuth': []}],
    'components': {'securitySchemes': {
        'BearerAuth': {'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'JWT'},
        'HeaderAuth': {'type': 'apiKey', 'in': 'header', 'name': 'X-Access'},
    }},
    'paths': {
        '/widgets': {'post': {'requestBody': {'required': True, 'content': {
            'application/json': {'schema': {'type': 'object', 'required': ['label'],
                'properties': {'label': {'type': 'string'}}}},
        }}}},
        '/status': {'servers': [{'url': '../path-api'}], 'get': {'security': []}},
        '/widgets/{widgetId}': {
            'parameters': [
                {'in': 'path', 'name': 'widgetId', 'required': True, 'schema': {'type': 'integer'}},
                {'in': 'query', 'name': 'q', 'schema': {'type': 'string'}},
            ],
            'get': {
                'servers': [{'url': '/service/preview'}],
                'security': [{'HeaderAuth': []}],
                'parameters': [
                    {'in': 'query', 'name': 'q', 'required': True, 'schema': {'type': 'string'}},
                    {'in': 'header', 'name': 'X-Mode', 'schema': {'type': 'string'}},
                ],
            },
        },
    },
}
OPERATIONS = {
    ('POST', '/service/v4/widgets'),
    ('GET', '/docs/path-api/status'),
    ('GET', '/service/preview/widgets/{widgetId}'),
}


def initializer(binding: str) -> str:
    literal = json.dumps(SPEC)
    if binding == 'literal':
        return 'SwaggerUIBundle({spec: ' + literal + ', url: "/unused-definition.json"});'
    return ('const options = {swaggerDoc: ' + literal + '};\n'
            'const definition = options.swaggerDoc;\n'
            'const swaggerOptions = {spec: definition};\nSwaggerUIBundle(swaggerOptions);')


@pytest.mark.parametrize('concepts', [
    ('swaggeruibundle', 'options.swaggerdoc', 'intermediate', 'swaggeroptions.spec', 'paths'),
    ('urls[].url', 'definition', 'servers[].url', 'api base', 'spec url'),
    ('url-only', '401', '403', 'documented', 'reachability', 'authenticated'),
    ('path-item', 'parameters', 'requestbody.content', 'security: []', 'securityschemes', 'credentials'),
    ('servers', 'operation', 'path-item', 'document', 'prefix', 'relative', 'off-origin', 'scope'),
    ('process_source', 'json', 'javascript', 'authoritative', 'read_http_observation', 'ownership', 'validation attempt'),
    ('record_input', 'inventory', 'without inputs', 'record_endpoint', 'provenance', 'request-context'),
    ('set_source_disposition', 'partial', 'blocked', 'source_limitations', 'source_bounds', 'complete_skill'),
])
def test_guidance_covers_inline_contract_without_layout_dependency(concepts):
    _, body, _ = read_skill()
    # Paragraphs may be rewrapped or reformatted; only semantic anchors matter.
    text = ' '.join(body.replace('`', '').lower().split())
    assert all(concept in text for concept in concepts)
    if 'source_bounds' in concepts:
        assert 'never invent bounds' in text and 'unresolved sources' in text
    if 'read_http_observation' in concepts:
        assert 'without executing javascript' in text and 'do not create a validation attempt' in text


@pytest.mark.parametrize('binding', ['literal', 'intermediate'])
def test_inline_literals_are_not_json_sources_or_absent_operations(binding):
    raw = initializer(binding).encode()
    # A URL-only HTML pass cannot see these operations. It is not a JS parser.
    assert not extract_html(raw, DOCUMENT).records
    rejected = extract_openapi(raw, DOCUMENT)
    assert not rejected.records and rejected.limitations and not rejected.not_applicable
    # A separately supplied JSON fixture verifies the existing extractor contract;
    # it is never registered as a replacement for the admitted JS source.
    parsed = extract_openapi(json.dumps(SPEC).encode(), DOCUMENT)
    assert not parsed.limitations
    assert {(r.method, r.url.removeprefix(ORIGIN)) for r in parsed.records} == OPERATIONS
    fields = [r for r in parsed.records if r.parameter is not None]
    assert {(r.parameter, r.location) for r in fields} == {
        ('label', 'json'), ('widgetId', 'path'), ('q', 'query'), ('X-Mode', 'header')}
    assert next(r for r in fields if r.parameter == 'q').required
    label = next(r for r in fields if r.parameter == 'label')
    assert label.required and label.input_type == 'string' and label.content_type == 'application/json'
    assert any(r.url.endswith('/status') and r.parameter is None for r in parsed.records)


async def retained_initializer(tmp_path, monkeypatch, body: str, *, cap=8192):
    real_client = httpx.AsyncClient
    requests: list[httpx.Request] = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, content=body.encode(),
                              headers={'Content-Type': 'application/javascript'}, request=request)

    def resolve(host, port, *args, **kwargs):
        assert host == 'catalog.test', 'Unexpected DNS lookup in an offline fixture'
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', port or 80))]

    monkeypatch.setattr(socket, 'getaddrinfo', resolve)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(
        transport=httpx.MockTransport(handler), **kwargs))
    runtime = make_runtime(tmp_path, origin=ORIGIN)
    runtime.workflow.objective = WorkflowObjective('inline-review', 'whole_target', ORIGIN)
    await execute(runtime, 'http', {'method': 'GET', 'url': '/docs/ui/initializer.js',
                                  'phase': 'recon', 'max_response_bytes': cap})
    source = next(iter(runtime.workflow.discovery_sources.values()))
    listed = await execute(runtime, 'workflow', {'action': 'list', 'view': 'sources'})
    assert source.id in {row['id'] for row in json.loads(listed.result)['sources']}
    info = await execute(runtime, 'workflow', {'action': 'get_source', 'discovery_source_id': source.id})
    assert json.loads(info.result)['discovery_source']['retained_ref'] == source.retained_ref
    await execute(runtime, 'workflow', {'action': 'select_source', 'discovery_source_id': source.id,
                                       'retained_ref': source.retained_ref})
    assert source.document_url == DOCUMENT
    return runtime, source, requests


@pytest.mark.parametrize('binding', ['literal', 'intermediate'])
async def test_visible_review_uses_existing_actions_and_inventory_not_fake_provenance(tmp_path, monkeypatch, binding):
    runtime, source, requests = await retained_initializer(tmp_path, monkeypatch, initializer(binding))
    graph = (dict(runtime.workflow.endpoints), dict(runtime.workflow.discovery_provenance))
    _, guidance, _ = read_skill()
    examples = [json.loads(block) for block in re.findall(r'```json\s*\n(.*?)\n```', guidance, re.S)]
    example = next(row for row in examples if row.get('arguments', {}).get('parameter') == 'label'
                   and row['arguments'].get('endpoint') == '/service/v4/widgets')
    # Exercise the guidance's actual tool example, then the other visible fields.
    first = json.loads((await execute(runtime, example['tool'], example['arguments'])).result)
    again = json.loads((await execute(runtime, example['tool'], example['arguments'])).result)
    assert first['created'] and not again['created'] and first['input']['id'] == again['input']['id']
    for parameter, location, input_type in [('widgetId', 'path', 'integer'), ('q', 'query', 'string'),
                                             ('X-Mode', 'header', 'string')]:
        await execute(runtime, 'workflow', {'action': 'record_input', 'method': 'GET',
            'endpoint': '/service/preview/widgets/{widgetId}', 'parameter': parameter,
            'location': location, 'input_type': input_type})
    inputs = tuple(runtime.workflow.attack_surface_inputs.values())
    assert len(inputs) == 4 and all(row.disposition == 'pending' for row in inputs)
    assert all(row.source_ref is row.baseline_request_ref is row.auth_context_ref is None for row in inputs)
    assert not any(row.endpoint.endswith('/status') for row in inputs)  # no dummy input
    assert (runtime.workflow.endpoints, runtime.workflow.discovery_provenance) == graph

    # Test-authored review facts: root inheritance, operation override, empty security.
    assert SPEC['security'] == [{'BearerAuth': []}]
    assert SPEC['paths']['/status']['get']['security'] == []
    assert SPEC['paths']['/widgets/{widgetId}']['get']['security'] == [{'HeaderAuth': []}]
    inventory = '\n'.join([
        '# Documented inventory', f'Source: {DOCUMENT}; {source.id}; {source.retained_ref}',
        f'Binding: {"literal spec" if binding == "literal" else "options.swaggerDoc -> definition -> swaggerOptions.spec"}',
        'POST /service/v4/widgets — paths./widgets.post; JSON label:string required; inherited BearerAuth (JWT).',
        'GET /docs/path-api/status — paths./status.get; no inputs; security: [] overrides document security.',
        'GET /service/preview/widgets/{widgetId} — operation server/security overrides: HeaderAuth; path widgetId, query q required, header X-Mode.',
        'Documented only. Reachability unknown; authenticated access unknown; no credentials supplied.',
    ])
    skill = runtime.skills.get('web-enumeration')
    relative = completion_artifact_path(skill.completion_artifact, ORIGIN)
    await execute(runtime, 'file_write', {'path': str(tmp_path / relative), 'content': inventory})
    saved = (tmp_path / relative).read_text()
    assert all(f'{method} {path}' in saved for method, path in OPERATIONS)
    assert source.retained_ref in saved and DOCUMENT in saved
    await execute(runtime, 'workflow', {'action': 'set_source_disposition', 'discovery_source_id': source.id,
        'retained_ref': source.retained_ref, 'source_disposition': 'processed',
        'source_reason': 'Complete visible literal reviewed; all operations attributed in inventory'})
    assert not runtime.workflow.discovery_sources[source.id].unresolved
    assert not runtime.workflow_tool.phase_completion_readiness('web-enumeration')['ready']
    assert not runtime.workflow.phase_completions  # artifact/source review alone cannot complete the phase
    assert len(requests) == 1  # no spec, API-base, documented-operation or replacement fetch
    assert not runtime.workflow.candidates and not runtime.workflow.attempts and not runtime.workflow.evidence


@pytest.mark.parametrize('case', ['url-only', 'dynamic', 'truncated', 'unavailable'])
async def test_incomplete_review_preserves_reader_rights_and_frontier(tmp_path, monkeypatch, case):
    bodies = {
        'url-only': 'SwaggerUIBundle({url: "/definition.json"});',
        'dynamic': 'SwaggerUIBundle({spec: buildDefinition()});',
        'truncated': '/*' + 'padding ' * 1500 + '*/' + initializer('intermediate'),
        'unavailable': initializer('intermediate'),
    }
    runtime, source, requests = await retained_initializer(tmp_path, monkeypatch, bodies[case])
    item = runtime.policy.observations._items[source.retained_ref]
    if case == 'truncated':
        assert item.truncated and not item.complete and len(item.body) == 8192
    if case == 'unavailable':
        before = runtime.workflow.to_dict()
        refused = await execute(runtime, 'read_http_observation', {'observation_id': source.retained_ref,
            'start_char': 0, 'max_chars': 2000}, success=False)
        assert refused.status == 'error' and 'ownership or scope is unavailable' in str(refused.result)
        assert runtime.workflow.to_dict() == before
    result = extract_openapi(item.body, DOCUMENT, complete=item.complete)
    assert not result.records and result.limitations and not result.not_applicable
    args = {'action': 'set_source_disposition', 'discovery_source_id': source.id,
        'retained_ref': source.retained_ref, 'source_disposition': 'partial' if case == 'truncated' else 'blocked',
        'source_reason': f'Inline review limited: {case}', 'source_limitations': [f'{case} source not fully reviewable']}
    await execute(runtime, 'workflow', args)
    assert runtime.workflow.discovery_sources[source.id].unresolved
    assert not runtime.workflow_tool.phase_completion_readiness('web-enumeration')['ready']
    if case == 'truncated':
        before = runtime.workflow.to_dict()
        invalid = await execute(runtime, 'workflow', {**args, 'acknowledge_bounded_stop': True}, success=False)
        assert invalid.status == 'error' and runtime.workflow.to_dict() == before
        await execute(runtime, 'workflow', {**args, 'acknowledge_bounded_stop': True,
                                            'source_bounds': {'max_bytes': 8192}})
        assert not runtime.workflow.discovery_sources[source.id].unresolved
        assert not runtime.workflow_tool.phase_completion_readiness('web-enumeration')['ready']
    assert len(requests) == 1 and not runtime.workflow.attack_surface_inputs
    assert not runtime.workflow.candidates and not runtime.workflow.attempts and not runtime.workflow.evidence


async def test_external_servers_are_not_rebased_or_admitted_as_target_inputs(tmp_path, monkeypatch):
    external = {'openapi': '3.0.3', 'servers': [{'url': 'http://external.test/service'}],
                'paths': {'/widgets': {'get': {'parameters': [{'in': 'query', 'name': 'q'}]}}}}
    parsed = extract_openapi(json.dumps(external).encode(), DOCUMENT)
    assert not parsed.records and parsed.limitations
    runtime, _, requests = await retained_initializer(tmp_path, monkeypatch, initializer('literal'))
    before = runtime.workflow.to_dict()
    refused = await execute(runtime, 'workflow', {'action': 'record_input', 'method': 'GET',
        'endpoint': 'http://external.test/service/widgets', 'parameter': 'q', 'location': 'query'}, success=False)
    assert refused.status == 'error' and runtime.workflow.to_dict() == before
    assert len(requests) == 1 and not runtime.workflow.attack_surface_inputs
