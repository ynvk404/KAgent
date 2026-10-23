import json
from pathlib import Path

import pytest

from components.cwe_mcp.catalog import Catalog, CatalogError
from components.cwe_mcp.contract import (RESPONSE_BYTES,
                                        SearchResponse, LookupResponse, tokens, validate_query)
from tests.cwe.conftest import entry, xml_document


def test_official_structure_and_exact_types(make_catalog):
    catalog = make_catalog()
    for ident, kind in [(862, 'Weakness'), (1, 'Category'), (1000, 'View')]:
        response = LookupResponse.model_validate(catalog.get({'id': ident}))
        assert response.found and response.candidate is not None
        assert response.candidate.entry_type == kind
        if kind == 'Weakness':
            assert response.candidate.abstraction == 'Base'
            assert response.candidate.structure == 'Simple'
            assert response.candidate.mapping_notes.reasons == ['Acceptable-Use']
            assert response.candidate.mapping_notes.suggestions[0].id == 863
        else:
            assert response.candidate.abstraction is None and response.candidate.structure is None
    missing = catalog.get({'id': 999999})
    assert missing['found'] is False and missing['candidate'] is None


def test_catalog_reuses_the_bounded_parse_without_building_a_second_tree(make_catalog, monkeypatch):
    import components.cwe_mcp.catalog as module
    def second_parse(*args, **kwargs):
        raise AssertionError('full XML must only be parsed once')
    monkeypatch.setattr(module.ET, 'fromstring', second_parse)
    catalog = make_catalog()
    assert catalog.get({'id': 862})['candidate']['id'] == 862
    assert catalog.search({'query': 'authorization'})['candidates']


@pytest.mark.parametrize('usage', ['Allowed', 'Allowed-with-Review', 'Discouraged', 'Prohibited'])
@pytest.mark.parametrize('status', ['Deprecated', 'Obsolete', 'Draft', 'Incomplete', 'Usable', 'Stable'])
def test_status_and_mapping_usage_never_coerced(make_catalog, usage, status):
    catalog = make_catalog(xml_document(entry(42, usage=usage, status=status, abstraction='Variant', structure='Chain')))
    c = catalog.entries[42]
    assert c.mapping_usage == usage and c.status == status
    assert c.deprecated == (status == 'Deprecated') and c.obsolete == (status == 'Obsolete')
    assert c.abstraction == 'Variant' and c.structure == 'Chain'


def test_missing_mapping_metadata_incomplete(make_catalog):
    c = make_catalog(xml_document(entry(42, notes=False))).entries[42]
    assert not c.metadata_complete and c.mapping_usage is None


def test_fixed_tokenization_score_ties_and_exact_priority(make_catalog):
    raw = xml_document(entry(3, name='Access', alternate='control', description='access control')
                       + entry(2, name='Access', alternate='control', description='access control')
                       + entry(4, name='Other', description='unrelated'))
    c = make_catalog(raw)
    assert tokens('ＡＣＣＥＳＳ_access Access') == {'access'}
    result = c.search({'query': 'access control access', 'max_results': 1})
    assert result['results_limited'] is True
    assert [(x['id'], x['score']) for x in result['candidates']] == [(2, 14)]
    assert [x['id'] for x in c.search({'query': 'access control'})['candidates']] == [2, 3]
    exact = c.search({'query': ' CWE-4 '})['candidates']
    assert exact[0]['id'] == 4 and exact[0]['exact_id_match'] and exact[0]['score'] == 0
    assert c.search({'query': 'zzzz'})['candidates'] == []


@pytest.mark.parametrize('query', ['CWE-89', 'cwe-89', ' CwE-89 ', 'ＣＷＥ－８９'])
def test_exact_id_priority_uses_query_normalization(make_catalog, query):
    catalog = make_catalog(xml_document(
        entry(89, name='SQL Injection', description='SQL query injection.')
        + entry(2, name='CWE 89', description='CWE 89 lexical distractor.')))
    response = SearchResponse.model_validate(catalog.search({'query': query, 'max_results': 1}))
    assert [(c.id, c.score, c.exact_id_match) for c in response.candidates] == [(89, 0, True)]
    assert response.results_limited
    lookup = LookupResponse.model_validate(catalog.get({'id': 89}))
    assert lookup.candidate is not None and lookup.candidate.cwe_id == response.candidates[0].cwe_id


@pytest.mark.parametrize('query', ['CWE-1', 'cwe-1000', 'CWE-999999', 'CWE-',
                                 'CWE-089', 'CWE-+89', 'CWE-89x', 'CWE-1000000',
                                 'CWE-' + '9' * 500, 'prefix CWE-89'])
def test_non_weakness_or_noncanonical_id_has_no_exact_search_candidate(make_catalog, query):
    catalog = make_catalog()
    response = SearchResponse.model_validate(catalog.search({'query': query}))
    assert not any(c.exact_id_match for c in response.candidates)
    assert all(c.entry_type == 'Weakness' for c in response.candidates)


@pytest.mark.parametrize('query', ['', '   ', 'x\n', 'a\x1b', 'a\u202e', 'a' * 513,
                                       '😀' * 513, ' '.join(f't{i}' for i in range(33)), True])
def test_query_bounds(query):
    with pytest.raises((ValueError, TypeError)):
        validate_query(query)


@pytest.mark.parametrize('name,args', [('get_cwe', {'id': True}), ('get_cwe', {'id': '862'}),
    ('get_cwe', {'id': 0}), ('get_cwe', {'id': 1000000}), ('get_cwe', {'id': 862, 'extra': 1}),
    ('search_cwe', {'query': 'access', 'max_results': True}), ('search_cwe', {'query': 'access', 'max_results': 6}),
    ('search_cwe', {'query': 'access', 'extra': 'x'})])
def test_catalog_rejects_invalid_arguments(make_catalog, name, args):
    catalog = make_catalog()
    operation = catalog.get if name == 'get_cwe' else catalog.search
    with pytest.raises(ValueError):
        operation(args)


def test_field_bounds_and_local_response_limit(make_catalog, monkeypatch):
    from src.findings import cwe_enrichment
    from src.findings.cwe_enrichment import validate_payload
    c = make_catalog(xml_document(''.join(entry(i, name='Access' + '😀' * 600, description='😀' * 1500)
                                        for i in range(1, 6))))
    result = c.search({'query': 'access'})
    for item in result['candidates']:
        assert len(item['name']) <= 512 and len(item['description']) <= 1024
        assert set(item['truncated_fields']) == {'name', 'description'} and not item['metadata_complete']
    SearchResponse.model_validate(result)
    monkeypatch.setattr(cwe_enrichment, 'EXPECTED_CORPUS', c.identity)
    assert validate_payload({**result, 'candidates': result['candidates'][:1]}, 'search')
    assert len(json.dumps(result, ensure_ascii=True).encode()) > RESPONSE_BYTES
    with pytest.raises(ValueError, match='invalid pinned CWE response'):
        validate_payload(result, 'search')


def test_mapping_guidance_flatten_and_combined_bound(make_catalog):
    raw = xml_document(entry(42)).decode().replace('Suitable mechanism.', '<p xmlns="http://www.w3.org/1999/xhtml">' + 'a' * 2000 + '</p>')
    raw = raw.replace('Review evidenced mechanism.', 'b' * 2000)
    c = make_catalog(raw.encode()).entries[42]
    assert c.mapping_notes.rationale == 'a' * 1024
    assert c.mapping_notes.comments == 'b' * 1024
    assert not c.metadata_complete and c.truncated_fields


@pytest.mark.parametrize('change', ['version', 'date', 'namespace', 'schema', 'duplicate', 'bad-status',
                                    'bad-structure', 'bad-abstraction', 'bad-view-type', 'doctype', 'malformed', 'unknown-group'])
def test_startup_rejects_bad_corpus_structure(make_catalog, change):
    raw = xml_document(entry(42), views=entry(1000, kind='View'))
    changes = {
        'version': (b'Version="4.20"', b'Version="4.19"'),
        'date': (b'Date="2026-04-30"', b'Date="2025-01-01"'),
        'namespace': (b'http://cwe.mitre.org/cwe-7', b'http://invalid.example/cwe'),
        'schema': (b'cwe_schema_v7.3.xsd', b'cwe_schema_v7.2.xsd'),
        'duplicate': (b'ID="1000"', b'ID="42"'), 'bad-status': (b'Status="Stable"', b'Status="Unknown"'),
        'bad-structure': (b'Structure="Simple"', b'Structure="Weakness"'),
        'bad-abstraction': (b'Abstraction="Base"', b'Abstraction="Unknown"'),
        'bad-view-type': (b'Type="Graph"', b'Type="Bogus"'),
        'unknown-group': (b'External_References', b'Unsupported'),
    }
    if change == 'doctype':
        raw = b'<!DOCTYPE foo [<!ENTITY bar "bad">]>' + raw
    elif change == 'malformed':
        raw = raw[:-10]
    else:
        raw = raw.replace(*changes[change])
    with pytest.raises(CatalogError, match='pinned corpus invalid'):
        make_catalog(raw)


@pytest.mark.parametrize('failure', ['missing', 'hash', 'manifest', 'oversized'])
def test_startup_missing_identity_and_size_fail(make_catalog, tmp_path, failure):
    make_catalog()
    xml, manifest = tmp_path / 'corpus.xml', tmp_path / 'manifest.json'
    if failure == 'missing':
        xml.unlink()
    elif failure == 'hash':
        xml.write_bytes(xml.read_bytes() + b' ')
    elif failure == 'manifest':
        manifest.write_text('{}')
    else:
        with xml.open('wb') as stream:
            stream.truncate(32 * 1024 * 1024 + 1)
    with pytest.raises(CatalogError):
        Catalog(xml, manifest)


def test_loaded_operations_do_not_write_read_network_log_or_retain_queries(make_catalog, monkeypatch):
    import logging
    import socket
    catalog = make_catalog()
    before = repr(catalog.__dict__)
    def blocked(*args, **kwargs):
        raise AssertionError('unexpected operation I/O or query log')
    monkeypatch.setattr(Path, 'open', blocked)
    monkeypatch.setattr(socket, 'socket', blocked)
    monkeypatch.setattr(logging.Logger, '_log', blocked)
    search = catalog.search({'query': 'authorization resource synthetic'})
    lookup = catalog.get({'id': 862})
    assert search['candidates'] and lookup['found']
    assert repr(catalog.__dict__) == before



def test_duplicate_manifest_keys_are_rejected(make_catalog, tmp_path):
    make_catalog()
    manifest = tmp_path / 'manifest.json'
    raw = manifest.read_text()
    manifest.write_text(raw.replace('{', '{"manifest_schema_version":"1",', 1))
    with pytest.raises(CatalogError, match='pinned corpus invalid'):
        Catalog(tmp_path / 'corpus.xml', manifest)


def test_search_budget_is_still_enforced(make_catalog, monkeypatch):
    import components.cwe_mcp.catalog as module
    catalog = make_catalog()
    clock = iter((0, 3))
    monkeypatch.setattr(module.time, 'monotonic', lambda: next(clock))
    with pytest.raises(TimeoutError, match='query budget'):
        catalog.search({'query': 'authorization'})
