"""Offline playbook/action contracts, not evidence of an LLM following the playbook.

The fixture's literal definition and review facts are supplied by the test.
No JavaScript parser, evaluation, derived source or provider is involved.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import socket
from typing import Any

import httpx
import pytest

from src.skills.artifacts import completion_artifact_path
from src.workflow.state import WorkflowObjective
from tests.helpers.burp_selection import make_runtime
from tests.helpers.discovery_calls import attribution, execute
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
    ('source_attribution', 'json', 'javascript', 'authoritative', 'read_http_observation', 'ownership', 'validation attempt'),
    ('record_input', 'inventory', 'without inputs', 'record_endpoint', 'provenance', 'request-context'),
    ('set_source_disposition', 'partial', 'blocked', 'source_limitations', 'source_bounds', 'complete_skill'),
])
async def test_guidance_covers_inline_contract_without_layout_dependency(concepts):
    from src.permission.permission import AlwaysAllow
    from src.skills.registry import Registry
    from src.tools.skills.skill_file import ReadSkillFileTool
    _, body, path = read_skill()
    assert 'read_skill_file(skill="web-enumeration", path="source-reference.md")' in body
    skills = Registry()
    skills.load_dir(path.parent.parent)
    reference = await ReadSkillFileTool(skills).run(
        {'skill': 'web-enumeration', 'path': 'source-reference.md'}, None, AlwaysAllow())
    body += str(reference)
    # Paragraphs may be rewrapped or reformatted; only semantic anchors matter.
    text = ' '.join(body.replace('`', '').lower().split())
    assert all(concept in text for concept in concepts)
    if 'source_bounds' in concepts:
        assert 'never invent bounds' in text and 'selected unresolved sources' in text
    if 'read_http_observation' in concepts:
        assert 'without executing javascript' in text and 'gain read rights' in text


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
    # No HTML/OpenAPI/JS parsing or execution occurs during source admission.
    assert not runtime.workflow.attack_surface_inputs
    assert {row.url for row in runtime.workflow.endpoints.values()} == {DOCUMENT}
    assert runtime.workflow.discovery_sources[source.id].content_identity is None
    _, guidance, _ = read_skill()
    examples = [json.loads(block) for block in re.findall(r'```json\s*\n(.*?)\n```', guidance, re.S)]
    example = next(row for row in examples if row.get('arguments', {}).get('parameter') == 'label'
                   and row['arguments'].get('endpoint') == '/service/v4/widgets')
    # Exercise the guidance's actual tool example, then the other visible fields.
    example['arguments']['source_attribution'] = attribution(source, 'options.swaggerDoc.paths./widgets.post.label')
    first = json.loads((await execute(runtime, example['tool'], example['arguments'])).result)
    again = json.loads((await execute(runtime, example['tool'], example['arguments'])).result)
    assert first['created'] and not again['created'] and first['input']['id'] == again['input']['id']
    for parameter, location, input_type in [('widgetId', 'path', 'integer'), ('q', 'query', 'string'),
                                             ('X-Mode', 'header', 'string')]:
        await execute(runtime, 'workflow', {'action': 'record_input', 'method': 'GET',
            'endpoint': '/service/preview/widgets/{widgetId}', 'parameter': parameter,
            'location': location, 'input_type': input_type,
            'source_attribution': attribution(source, f'paths./widgets/{{widgetId}}.get.{parameter}')})
    inputs = tuple(runtime.workflow.attack_surface_inputs.values())
    assert len(inputs) == 4 and all(row.disposition == 'pending' for row in inputs)
    assert all(row.source_ref is row.baseline_request_ref is row.auth_context_ref is None for row in inputs)
    assert not any(row.endpoint.endswith('/status') for row in inputs)  # no dummy input
    links = [row for row in runtime.workflow.discovery_provenance.values() if row.input_id]
    assert len(links) == 4 and all(row.locator.startswith('manual:') for row in links)
    assert {row.source_id for row in links} == {source.id}
    assert not any(row.url.endswith('/status') for row in runtime.workflow.endpoints.values())
    assert runtime.workflow.discovery_sources[source.id].content_identity is None

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
    assert not runtime.workflow.attack_surface_inputs
    assert runtime.workflow.discovery_sources[source.id].content_identity is None
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
    assert external['servers'][0]['url'].startswith('http://external.test')
    runtime, _, requests = await retained_initializer(tmp_path, monkeypatch, initializer('literal'))
    before = runtime.workflow.to_dict()
    refused = await execute(runtime, 'workflow', {'action': 'record_input', 'method': 'GET',
        'endpoint': 'http://external.test/service/widgets', 'parameter': 'q', 'location': 'query'}, success=False)
    assert refused.status == 'error' and runtime.workflow.to_dict() == before
    assert len(requests) == 1 and not runtime.workflow.attack_surface_inputs


@pytest.mark.parametrize('skill', ['web-enumeration', 'web-input-analysis'])
async def test_handoff_checks_reuse_context_and_reserve_mutations_for_recovery(skill):
    from src.skills.load_skill import LoadSkillTool
    from src.skills.registry import Registry
    skills = Registry()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    text = ' '.join(str(await LoadSkillTool(skills).run({'name': skill})).replace('`', '').lower().split())
    # Contract coverage only: this cannot demonstrate that a real model complies.
    if skill == 'web-enumeration':
        check = text.split('before handoff, check', 1)[1].split('source_ref', 1)[0]
        for concept in ('only for missing details', 'newly discovered fields', 'arrays',
                        'a string containing json remains a string', 'incomplete interpretation'):
            assert concept in check
        assert 'exceptional recovery' in text and 'terminal' in text and 'identity' in text
    else:
        check = text.split('before triage, check', 1)[1].split('prefer record_candidate', 1)[0]
        assert 'available source information' in check and 'only missing details' in check
    for concept in ('canonical', 'input names', 'types', 'context', 'actual discrepancy',
                    'existing correction/recovery'):
        assert concept in check, (skill, concept)
    # The short check refers to the existing recovery contract instead of
    # duplicating replacement/drop steps in the normal registration path.
    assert not any(procedure in check for procedure in ('set_input_disposition', 'dropped', 'replacement'))


def lan23_initializer():
    # Sanitized retained obs_b189c919c7644e228abc03f20dd21a6d; no historical file
    # is needed at test time. Only inert example values differ from that source.
    return (Path(__file__).resolve().parents[1] / 'fixtures/lan23-swagger-initializer.js').read_text()


async def read_page(runtime, source, start=0, **kwargs):
    output = await execute(runtime, 'read_discovery_source', {
        'discovery_source_id': source.id, 'start_char': start, 'max_chars': 2000, **kwargs})
    header, content = output.result.split('\n', 1)
    page = json.loads(header)
    assert len(output.result) <= 2000
    assert page['discovery_source_id'] == source.id and page['retained_hash'] == source.retained_hash
    return page, content


async def test_lan23_read_first_records_correct_types_without_replacement(tmp_path, monkeypatch):
    body = lan23_initializer()
    rt, source, requests = await retained_initializer(tmp_path, monkeypatch, body)
    visible, pages = {}, []
    for label, clue in [('endpoint', None), ('request', '"requestBody": {'),
                        ('fields', '"Order": {'), ('types', '"OrderLines": {')]:
        page, content = await read_page(rt, source, **({'find_text': clue} if clue else {}))
        pages.append(page)
        visible[label] = ' '.join(content.split())
    assert '/b2b/v2' in visible['endpoint'] and '/orders' in visible['endpoint']
    assert '#/components/schemas/Order"' in visible['request']
    assert all(f'"{name}"' in visible['fields'] for name in ('cid', 'orderLines', 'orderLinesData'))
    assert '"OrderLines": { "type": "array"' in visible['types']
    assert ('"OrderLinesData": { "description": "Order line(s) in customer specific JSON format", '
            '"type": "string"') in visible['types']
    assert sum(page['end_char'] - page['start_char'] for page in pages) < len(body)
    assert not rt.workflow.objective_inputs()
    # Scripted read-first compliance using fixture facts; no model interprets
    # the schema, and neither whole-document reading nor repair calls are needed.
    expected = {'cid': 'string', 'orderLines': 'array', 'orderLinesData': 'string'}
    for parameter, input_type in expected.items():
        await execute(rt, 'workflow', {'action': 'record_input', 'method': 'POST',
            'endpoint': '/b2b/v2/orders', 'parameter': parameter, 'location': 'json',
            'input_type': input_type, 'content_type': 'application/json', 'source_attribution':
            attribution(source, f'options.swaggerDoc.components.schemas.Order.properties.{parameter}')})
    inputs = rt.workflow.objective_inputs()
    assert len(inputs) == 3 and {row.parameter: row.input_type for row in inputs} == expected
    assert all(row.disposition == 'pending' and not row.disposition_transitions for row in inputs)
    links = [row for row in rt.workflow.discovery_provenance.values() if row.input_id]
    assert len(links) == 3 and all(row.source_id == source.id for row in links)
    assert len(requests) == 1 and not rt.workflow.candidates and not rt.workflow.attempts


@pytest.mark.parametrize('premature_type', ['object', None])
async def test_lan23_existing_premature_input_uses_recovery_after_later_definitions(
        tmp_path, monkeypatch, premature_type):
    body = lan23_initializer()
    rt, source, requests = await retained_initializer(tmp_path, monkeypatch, body)
    # Only bounded reading/search remains; there is no document interpretation flag.
    reader = rt.agent.tools.get('read_discovery_source')
    assert reader is not None
    assert set(reader.schema()['properties']) == {
        'discovery_source_id', 'start_char', 'max_chars', 'find_text'}
    first, properties = await read_page(rt, source, find_text='"orderLinesData": {')
    assert first['literal_match'] and first['complete'] and first['next_start_char'] is not None
    assert '"#/components/schemas/OrderLinesData"' in properties
    assert '"OrderLinesData": {' not in properties

    async def record(parameter, input_type):
        return json.loads((await execute(rt, 'workflow', {
            'action': 'record_input', 'method': 'POST', 'endpoint': '/b2b/v2/orders',
            'parameter': parameter, 'location': 'json', 'input_type': input_type,
            'content_type': 'application/json', 'source_attribution': attribution(
                source, f'options.swaggerDoc.components.schemas.Order.properties.{parameter}')})).result)

    await record('cid', 'string')
    premature = await record('orderLinesData', premature_type)
    old_id = premature['input']['id']
    assert len(rt.workflow.objective_inputs()) == 2  # omitted array, as in lan-23
    before = rt.workflow.to_dict()
    start, chunks = 0, []
    while True:
        page, content = await read_page(rt, source, start)
        chunks.append(content)
        if page['next_start_char'] is None:
            break
        assert page['next_start_char'] > start
        start = page['next_start_char']
    assert ''.join(chunks) == body
    assert '"OrderLines": {\n          "type": "array"' in body
    assert '"OrderLinesData": {\n          "description": "Order line(s) in customer specific JSON format",\n          "type": "string"' in body
    assert 'var spec1 = options.swaggerDoc' in body and 'spec: spec1' in body
    assert rt.workflow.to_dict() == before  # reading alone never repairs records
    detail = json.loads((await execute(rt, 'workflow', {'action': 'get_input', 'input_id': old_id})).result)
    assert detail['input']['input_type'] == premature_type

    # Scripted compliance: known facts are supplied by this test, never extracted
    # by the runtime or inferred by an external model.
    array = await record('orderLines', 'array')
    replacement = await record('orderLinesData', 'string')
    new_id = replacement['input']['id']
    assert new_id != old_id and replacement['created'] and array['created']
    assert not (await record('orderLinesData', 'string'))['created']
    await execute(rt, 'workflow', {'action': 'set_input_disposition', 'input_id': old_id,
        'disposition': 'dropped', 'disposition_reason':
        f'Reviewed schema OrderLinesData declares string; replaces premature type with {new_id}.'})
    listed = json.loads((await execute(rt, 'workflow', {'action': 'list', 'view': 'inputs'})).result)
    assert listed['inputs_complete']
    active = [row for row in listed['attack_surface_inputs'] if row['disposition'] != 'dropped']
    assert {row['parameter']: row['input_type'] for row in active} == {
        'cid': 'string', 'orderLines': 'array', 'orderLinesData': 'string'}
    old = rt.workflow.attack_surface_inputs[old_id]
    assert old.input_type == premature_type and old.disposition == 'dropped'
    assert new_id in (old.disposition_reason or '') and old.disposition_transitions == ['pending>dropped']
    links = [row for row in rt.workflow.discovery_provenance.values() if row.input_id]
    assert {row.input_id for row in links} == {row.id for row in rt.workflow.objective_inputs()}
    assert all(row.source_id == source.id and row.locator.startswith('manual:options.swaggerDoc') for row in links)
    assert all(row.source_ref is row.baseline_request_ref is row.auth_context_ref is None
               for row in rt.workflow.objective_inputs())
    assert len(requests) == 1 and not rt.workflow.candidates and not rt.workflow.attempts and not rt.workflow.evidence


@pytest.mark.parametrize('case', ['unread', 'truncated', 'unresolved-ref', 'unknown-type'])
async def test_lan23_incomplete_interpretation_keeps_type_and_source_uncertain(tmp_path, monkeypatch, case):
    body = lan23_initializer()
    if case == 'unresolved-ref':
        body = body.replace('#/components/schemas/OrderLinesData', '#/components/schemas/Unavailable')
    if case == 'unknown-type':
        body = body.replace('"description": "Order line(s) in customer specific JSON format",\n          "type": "string",',
                            '"description": "Order line(s) in customer specific JSON format",')
    cap = body.index('"OrderConfirmation":') if case == 'truncated' else 8192
    rt, source, requests = await retained_initializer(tmp_path, monkeypatch, body, cap=cap)
    page, content = await read_page(rt, source, find_text='"orderLinesData": {')
    assert page['literal_match'] and '"orderLinesData"' in content
    assert page['complete'] is (case != 'truncated')
    assert page['adapter_truncated'] is (case == 'truncated')
    if case in {'unread', 'truncated'}:
        assert '"OrderLinesData": {' not in content
    else:
        _, definition = await read_page(rt, source, find_text='"OrderLinesData": {')
        if case == 'unknown-type':
            assert '"type": "string"' not in definition
        else:
            assert '#/components/schemas/Unavailable' in content
            missing, _ = await read_page(rt, source, find_text='"Unavailable": {')
            assert not missing['literal_match']
    # The caller records only the established name/location, and explicitly
    # retains its interpretation limit rather than guessing object from $ref.
    recorded = json.loads((await execute(rt, 'workflow', {'action': 'record_input',
        'method': 'POST', 'endpoint': '/b2b/v2/orders', 'parameter': 'orderLinesData',
        'location': 'json', 'content_type': 'application/json', 'source_attribution': attribution(
            source, 'options.swaggerDoc.components.schemas.Order.properties.orderLinesData')})).result)
    assert recorded['input']['input_type'] is None and recorded['input']['disposition'] == 'pending'
    limitation = f'{case}: declared type unknown; document interpretation incomplete.'
    await execute(rt, 'workflow', {'action': 'set_source_disposition', 'discovery_source_id': source.id,
        'retained_ref': source.retained_ref, 'source_disposition': 'partial',
        'source_reason': limitation, 'source_limitations': [limitation]})
    current = rt.workflow.discovery_sources[source.id]
    assert current.unresolved and limitation in current.limitations
    assert not rt.workflow_tool.phase_completion_readiness('web-enumeration')['ready']
    assert len(requests) == 1 and not rt.workflow.candidates and not rt.workflow.attempts and not rt.workflow.evidence
