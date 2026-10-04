import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from components.cwe_mcp.catalog import Catalog, CatalogError
from components.cwe_mcp.contract import (EXPECTED_MANIFEST, GET_SCHEMA, SEARCH_SCHEMA,
                                        SearchResponse, LookupResponse, tokens, validate_query)
from components.cwe_mcp.server import execute, envelope_size, error_result
from tests.cwe.conftest import entry, xml_document


def payload(result):
    assert len(result.content) == 1 and result.content[0].type == 'text'
    assert envelope_size(result) <= 65536
    return json.loads(result.content[0].text)


def test_official_structure_and_exact_types(make_catalog):
    catalog = make_catalog()
    for ident, kind in [(862, 'Weakness'), (1, 'Category'), (1000, 'View')]:
        response = LookupResponse.model_validate(payload(execute(catalog, 'get_cwe', {'id': ident})))
        assert response.found and response.candidate is not None
        assert response.candidate.entry_type == kind
        if kind == 'Weakness':
            assert response.candidate.abstraction == 'Base'
            assert response.candidate.structure == 'Simple'
            assert response.candidate.mapping_notes.reasons == ['Acceptable-Use']
            assert response.candidate.mapping_notes.suggestions[0].id == 863
        else:
            assert response.candidate.abstraction is None and response.candidate.structure is None
    missing = payload(execute(catalog, 'get_cwe', {'id': 999999}))
    assert missing['found'] is False and missing['candidate'] is None


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
    response = SearchResponse.model_validate(payload(execute(
        catalog, 'search_cwe', {'query': query, 'max_results': 1})))
    assert [(c.id, c.score, c.exact_id_match) for c in response.candidates] == [(89, 0, True)]
    assert response.results_limited
    lookup = LookupResponse.model_validate(payload(execute(catalog, 'get_cwe', {'id': 89})))
    assert lookup.candidate is not None and lookup.candidate.cwe_id == response.candidates[0].cwe_id


@pytest.mark.parametrize('query', ['CWE-1', 'cwe-1000', 'CWE-999999', 'CWE-',
                                 'CWE-089', 'CWE-+89', 'CWE-89x', 'CWE-1000000',
                                 'CWE-' + '9' * 500, 'prefix CWE-89'])
def test_non_weakness_or_noncanonical_id_has_no_exact_search_candidate(make_catalog, query):
    catalog = make_catalog()
    response = SearchResponse.model_validate(payload(execute(catalog, 'search_cwe', {'query': query})))
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
    ('search_cwe', {'query': 'access', 'extra': 'x'}), ('other', {})])
def test_stable_argument_errors(make_catalog, name, args):
    result = execute(make_catalog(), name, args)
    assert result.isError and payload(result)['error'] == {'code': 'INVALID_ARGUMENT', 'message': 'Invalid tool arguments.'}


def test_field_and_escaped_envelope_bounds(make_catalog):
    c = make_catalog(xml_document(''.join(entry(i, name='Access' + '😀' * 600, description='😀' * 1500)
                                        for i in range(1, 6))))
    result = payload(execute(c, 'search_cwe', {'query': 'access'}))
    assert result['results_limited'] is True
    assert len(result['candidates']) < 5
    for item in result['candidates']:
        assert len(item['name']) <= 512 and len(item['description']) <= 1024
        assert set(item['truncated_fields']) == {'name', 'description'} and not item['metadata_complete']
    SearchResponse.model_validate(result)


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


def test_stable_controller_safe_internal_and_timeout_errors(make_catalog, monkeypatch):
    c = make_catalog()
    monkeypatch.setattr(c, 'search', Mock(side_effect=RuntimeError('/secret/path?password=secret')))
    assert 'secret' not in payload(execute(c, 'search_cwe', {'query': 'access'}))['error']['message']
    monkeypatch.setattr(c, 'search', Mock(side_effect=TimeoutError))
    assert payload(execute(c, 'search_cwe', {'query': 'access'}))['error']['code'] == 'QUERY_TIMEOUT'
    for code in ('CORPUS_INVALID', 'RESPONSE_LIMIT', 'INTERNAL_ERROR'):
        assert error_result(code).isError


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
    search = execute(catalog, 'search_cwe', {'query': 'authorization resource synthetic'})
    lookup = execute(catalog, 'get_cwe', {'id': 862})
    assert not search.isError and not lookup.isError
    assert repr(catalog.__dict__) == before


@pytest.mark.parametrize('failure', ['missing-dependencies', 'missing-corpus'])
def test_launcher_startup_errors_have_no_traceback_or_paths(tmp_path, failure):
    import shutil
    import subprocess
    import sys
    source = Path(__file__).parents[2] / 'components/cwe_mcp'
    shutil.copy2(source / 'launch.py', tmp_path / 'launch.py')
    if failure == 'missing-corpus':
        package = tmp_path / 'server/cwe_mcp'
        package.mkdir(parents=True)
        for name in ('__init__.py', 'contract.py', 'catalog.py', 'server.py'):
            shutil.copy2(source / name, package / name)
    completed = subprocess.run([sys.executable, '-I', '-B', str(tmp_path / 'launch.py')],
                               capture_output=True, text=True, timeout=15)
    assert completed.returncode == 1 and not completed.stdout
    assert str(tmp_path) not in completed.stderr and 'Traceback' not in completed.stderr
    assert len(completed.stderr) < 128
    assert ('INTERNAL_ERROR' if failure == 'missing-dependencies' else 'CORPUS_INVALID') in completed.stderr
    assert not list(tmp_path.rglob('*.pyc'))
