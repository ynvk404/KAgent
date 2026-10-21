import json
from typing import Any

import pytest

from src.workflow.discovery.openapi import extract_openapi
from tests.state.test_html_extraction import prepared, apply, DOCUMENT


def document(paths=None, **changes):
    return {'openapi': '3.0.3', 'paths': paths or {}, **changes}


def parse(doc, **kwargs):
    return extract_openapi(json.dumps(doc).encode(), DOCUMENT, **kwargs)


def fields(result):
    return [row for row in result.records if row.parameter is not None]


def test_methods_paths_parameters_override_and_request_media_variants():
    doc = document({'/pets/{id}': {
        'parameters': [{'in': 'path', 'name': 'id', 'required': True, 'schema': {'type': 'integer'}},
                       {'in': 'query', 'name': 'q', 'schema': {'type': 'string'}}],
        'get': {'parameters': [{'in': 'query', 'name': 'q', 'required': True, 'schema': {'type': 'string'}},
                              {'in': 'header', 'name': 'X-Feature'}, {'in': 'cookie', 'name': 'session'}]},
        'post': {'requestBody': {'content': {
            'application/json': {'schema': {'type': 'object', 'required': ['name'], 'properties': {'name': {'type': 'string'}}}},
            'application/x-www-form-urlencoded': {'schema': {'properties': {'name': {'type': 'string'}}}}}}}}})
    result = parse(doc)
    rows = fields(result)
    assert {row.url for row in result.records} == {'http://target.test/pets/{id}'}
    assert {row.method for row in result.records} == {'GET', 'POST'}
    assert {(row.location, row.parameter) for row in rows} >= {('path', 'id'), ('query', 'q'), ('header', 'X-Feature'), ('cookie', 'session'), ('json', 'name'), ('form', 'name')}
    get_q = [row for row in rows if row.parameter == 'q' and row.method == 'GET']
    assert len(get_q) == 1 and get_q[0].required
    assert any(row.parameter == 'name' and row.content_type == 'application/json' and row.required for row in rows)
    assert not result.limitations


def test_local_nested_refs_request_fields_and_required_arrays():
    doc = document({'/users': {'post': {'requestBody': {'$ref': '#/components/requestBodies/User'}}}},
        components={'requestBodies': {'User': {'content': {'application/json': {'schema': {'$ref': '#/components/schemas/User'}}}}},
                    'schemas': {'User': {'required': ['profile'], 'properties': {'profile': {'$ref': '#/components/schemas/Profile'}}},
                                'Profile': {'required': ['name'], 'properties': {'name': {'type': 'string'}}}}})
    result = parse(doc)
    assert {row.parameter for row in fields(result)} == {'profile', '/profile/name'}
    assert all(row.required for row in fields(result))
    assert not result.limitations


@pytest.mark.parametrize('ref', ['https://foreign.test/schema.json', 'other.json#/schema', '#/missing', '#/bad~2pointer'])
def test_external_missing_invalid_refs_partial_no_fetch(ref):
    result = parse(document({'/users': {'post': {'requestBody': {'$ref': ref}}}}))
    assert not fields(result) and result.limitations


def test_ref_cycles_depth_and_schema_node_bounds_terminate():
    doc = document({'/users': {'post': {'requestBody': {'content': {'application/json': {'schema': {'$ref': '#/components/schemas/A'}}}}}}},
        components={'schemas': {'A': {'properties': {'child': {'$ref': '#/components/schemas/A'}}}}})
    assert any('cycle' in note for note in parse(doc).limitations)
    schemas: dict[str, Any] = {str(index): {'$ref': f'#/components/schemas/{index + 1}'} for index in range(10)}
    schemas['10'] = {'properties': {'q': {'type': 'string'}}}
    doc['components']['schemas'] = {**schemas, 'A': {'$ref': '#/components/schemas/0'}}
    assert any('depth' in note for note in parse(doc).limitations)


def test_external_servers_do_not_invent_current_origin_operations():
    result = parse(document({'/foreign': {'get': {}}}, servers=[{'url': 'https://external.test/api'}]))
    assert not result.records and result.limitations
    result = parse(document({'/pets': {'get': {}}}, servers=[{'url': '/api/v1/'}]))
    assert result.records[0].url == 'http://target.test/api/v1/pets'
    result = parse(document({'/pets': {'servers': [{'url': '../v2'}], 'get': {}}}))
    assert result.records[0].url == 'http://target.test/app/v2/pets'


def test_operation_servers_override_external_parent_without_scope_expansion():
    result = parse(document({'/pets': {'get': {'servers': [{'url': '/scoped'}]}, 'post': {}}},
                            servers=[{'url': 'https://external.test'}]))
    assert {(row.method, row.url) for row in result.records} == {('GET', 'http://target.test/scoped/pets')}
    assert result.limitations


@pytest.mark.parametrize('raw', [b'{', b'{"openapi":"3.0.3","paths":{"/a":{"get":{},"get":{}}}}',
    b'{"openapi":"3.0.3","paths":null}', b'{"openapi":"3.0.3","paths":{"/a":{"get":NaN}}}'])
def test_malformed_duplicate_operation_and_non_json_constants_partial(raw):
    result = extract_openapi(raw, DOCUMENT)
    assert result.limitations


def test_arbitrary_response_properties_and_swagger_are_not_request_schemas():
    assert parse({'properties': {'password': {'type': 'string'}}}).not_applicable
    assert parse({'swagger': '2.0', 'paths': {}}).not_applicable
    result = parse(document({'/read': {'get': {'responses': {'200': {'content': {
        'application/json': {'schema': {'properties': {'response_only': {'type': 'string'}}}}}}}}}}))
    assert not fields(result)


def test_values_examples_secrets_not_in_output_or_syntax_identity():
    def doc(secret):
        return document({'/login': {'post': {'requestBody': {'content': {'application/json': {'schema': {
            'properties': {'password': {'type': 'string', 'default': secret, 'example': secret}}}}}}}}})
    first, second = parse(doc('SECRET-ONE')), parse(doc('SECRET-TWO'))
    assert first.content_identity == second.content_identity and first.records == second.records
    assert 'SECRET' not in str(first)


@pytest.mark.parametrize('malformation', ['path', 'operation', 'parameter', 'schema', 'type', 'required', 'media'])
def test_malformed_shapes_do_not_crash_or_infer_missing_fields(malformation):
    operation = {'parameters': [{'in': 'query', 'name': 'q', 'schema': {'type': 'string'}}],
                 'requestBody': {'content': {'application/json': {'schema': {'properties': {'name': {'type': 'string'}}}}}}}
    doc = document({'/a': {'post': operation}})
    if malformation == 'path': doc['paths']['/a'] = []
    if malformation == 'operation': doc['paths']['/a']['post'] = []
    if malformation == 'parameter': operation['parameters'][0]['in'] = []
    if malformation == 'schema': operation['requestBody']['content']['application/json']['schema']['properties'] = []
    if malformation == 'type': operation['parameters'][0]['schema']['type'] = ['string', 'null']
    if malformation == 'required': operation['requestBody']['content']['application/json']['schema']['required'] = 'name'
    if malformation == 'media': operation['requestBody']['content'] = []
    assert parse(doc).limitations


def test_explicit_bounds_large_paths_operations_parameters_and_oversized_source():
    parameters = [{'in': 'query', 'name': f'q{index}'} for index in range(300)]
    paths = {f'/p{index}': {method: {} for method in ('get', 'post', 'put')} for index in range(70)}
    results = [parse(document(paths)), parse(document({'/a': {'get': {'parameters': parameters}}})),
               extract_openapi(b' ' * 65537, DOCUMENT), parse(document(), complete=False)]
    for result in results:
        assert result.limitations and len(result.records) <= 255
        assert result.bounds['max_ref_depth'] == 8 and result.bounds['max_schema_nodes'] == 1024


def test_openapi_atomic_admission_provenance_media_and_legacy_linkage():
    s, src = prepared()
    doc = document({'/login': {'post': {'requestBody': {'content': {
        media: {'schema': {'properties': {'q': {'type': 'string'}}}} for media in
        ('application/json', 'application/x-www-form-urlencoded')}}}}})
    result = parse(doc)
    apply(s, src, result)
    assert len(s.attack_surface_inputs) == 2
    assert {row.content_type for row in s.attack_surface_inputs.values()} == {'application/json', 'application/x-www-form-urlencoded'}
    assert all(row.source_ref is None and row.auth_context_ref is None and row.baseline_request_ref is None
               for row in s.attack_surface_inputs.values())
    assert s.discovery_sources[src.id].disposition == 'processed'
    before = s.to_dict()
    apply(s, src, parse(doc))
    assert s.to_dict() == before and not s.candidates and not s.evidence


def test_document_member_order_does_not_create_source_progress():
    paths = {'/a': {'get': {}}, '/b': {'post': {}}}
    assert parse(document(paths)).content_identity == parse(document(dict(reversed(list(paths.items()))))).content_identity
