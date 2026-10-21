from dataclasses import replace

import pytest

from src.workflow.discovery.inventory import EndpointRecord, ProvenanceRecord
from src.workflow.discovery.extraction import extract_html, apply_extraction, Extraction, ExtractedRecord
from tests.state.test_discovery_inventory import state, source

DOCUMENT = 'http://target.test/app/pages/document.html'


def parse(html, **kwargs):
    return extract_html(html.encode(), DOCUMENT, **kwargs)


def test_actual_document_relative_urls_src_and_first_base_semantics():
    result = parse('<a href="child?q=1&q=2">child</a><img src="../image.png"><base href="/assets/"><base href="/ignored/">')
    assert {row.url for row in result.records} == {'http://target.test/assets/child?q=1&q=2', 'http://target.test/image.png'}
    queries = [row for row in result.records if row.location == 'query']
    assert [(row.parameter, row.occurrence) for row in queries] == [('q', 0), ('q', 1)]
    assert not result.limitations
    result = parse('<a href="child">child</a>')
    assert result.records[0].url == 'http://target.test/app/pages/child'


@pytest.mark.parametrize('base', ['http://[invalid', 'javascript:bad', 'http://user:password@target.test/'])
def test_malformed_base_is_partial_with_document_fallback(base):
    result = parse(f'<base href="{base}"><a href="child">')
    assert result.records[0].url == 'http://target.test/app/pages/child'
    assert result.limitations


def test_forms_browser_defaults_missing_action_post_enctype_and_duplicate_controls():
    result = parse('<form><input name="q"><input name="q" required></form>'
                   '<form action="../submit" method="POST" enctype="multipart/form-data">'
                   '<input name="upload" type="file"><textarea name="text"></textarea></form>')
    inputs = [row for row in result.records if row.parameter]
    assert [row.parameter for row in inputs] == ['q', 'q', 'upload', 'text']
    assert inputs[0].method == 'GET' and inputs[0].url == DOCUMENT and inputs[0].location == 'query'
    assert inputs[1].occurrence != inputs[0].occurrence and inputs[1].required
    assert inputs[2].method == 'POST' and inputs[2].location == 'form'
    assert inputs[2].content_type == 'multipart/form-data' and inputs[2].url == 'http://target.test/app/submit'
    assert not result.limitations


def test_sensitive_values_are_neither_retained_nor_fingerprinted():
    template = '<form method="post"><input name="password" type="password" value="{}">'
    template += '<input type="hidden" name="csrf_token" value="{}"></form>'
    first = parse(template.format('SECRET-ONE', 'TOKEN-ONE'))
    second = parse(template.format('SECRET-TWO', 'TOKEN-TWO'))
    assert first.records == second.records and first.content_identity == second.content_identity
    assert 'SECRET' not in str(first) and 'TOKEN-' not in str(first)
    assert {row.parameter for row in first.records if row.parameter} == {'password', 'csrf_token'}


@pytest.mark.parametrize('html', ['<a href="https://external.test/a">', '<base href="https://external.test/"><a href="a">',
    '<a href="/app/#route">', '<a href="javascript:alert(1)">', '<a href="/login?token=secret-canary">',
    '<a href="/login?%74oken=secret-canary">', '<a href="/login?refresh_token=secret-canary">'])
def test_external_fragment_secret_urls_excluded_without_fetch(html):
    result = parse(html)
    assert not result.records and result.limitations
    assert 'secret-canary' not in str(result)


@pytest.mark.parametrize('html', ['<form><input name="q">', '<form></form></form>', '<a href="unfinished'])
def test_malformed_or_truncated_is_partial(html):
    assert parse(html).limitations


def test_uncertain_method_disabled_owner_and_override_not_invented():
    result = parse('<form method="dialog"><input name="q"></form>'
                   '<form><input name="disabled" disabled><input name="owner" form="other">'
                   '<button name="override" formaction="/elsewhere"></button></form>')
    assert any(row.method is None for row in result.records)
    assert not any(row.parameter for row in result.records)
    assert result.limitations


def test_nested_forms_do_not_borrow_controls_or_invent_get_body_media():
    nested = parse('<form action="/outer"><form action="/inner"><input name="q"></form></form>')
    assert nested.limitations and not any(row.parameter for row in nested.records)
    s, src = prepared()
    apply(s, src, parse('<form enctype="text/plain"><input name="q"></form>'))
    item = next(iter(s.attack_surface_inputs.values()))
    assert item.content_type is None
    assert any(row.input_id == item.id and row.media_type == 'text/plain' for row in s.discovery_provenance.values())


def test_byte_node_record_bounds_and_truncated_source():
    for result in [parse('<a href="/a">' * 10000), parse('<i></i>' * 3000),
                   parse('<form>' + '<input name="q">' * 300 + '</form>'), parse('<html></html>', complete=False)]:
        assert result.limitations and len(result.records) <= 255
        assert result.bounds['max_bytes'] == 65536


def prepared():
    s = state()
    src = source(document_url=DOCUMENT, retained_ref='obs-fixture', selected=True)
    ep = EndpointRecord('objective', 'http://target.test', DOCUMENT, 'GET')
    s.admit_discovery(src, (ep,), (ProvenanceRecord(src.id, ep.id),))
    return s, src


def apply(s, src, result, **changes):
    fields = dict(generation=s.generation, retained_ref=src.retained_ref, retained_hash=src.retained_hash,
                  document_url=DOCUMENT)
    return apply_extraction(s, src.id, result, **{**fields, **changes})


def test_transaction_input_dedup_provenance_occurrences_zero_input_and_repeated_read():
    s, src = prepared()
    result = parse('<form><input name="q"><input name="q"></form>')
    apply(s, src, result)
    assert len(s.attack_surface_inputs) == 1
    item = next(iter(s.attack_surface_inputs.values()))
    assert item.disposition == 'pending' and item.source_ref is None
    assert item.auth_context_ref is None and item.baseline_request_ref is None
    assert len([row for row in s.discovery_provenance.values() if row.input_id == item.id]) == 2
    assert s.discovery_sources[src.id].disposition == 'processed'
    before, revision = s.to_dict(), s.committed_revision
    apply(s, src, parse('<form><input name="q"><input name="q"></form>'))
    assert s.to_dict() == before and s.committed_revision == revision
    assert not s.candidates and not s.attempts and not s.evidence and not s.selected_sources


@pytest.mark.parametrize('changes', [dict(generation='stale'), dict(retained_ref='obs-wrong'),
    dict(retained_hash='b' * 64), dict(document_url='http://target.test/another')])
def test_wrong_source_binding_rejects_everything_atomically(changes):
    s, src = prepared()
    before = s.to_dict()
    with pytest.raises(ValueError): apply(s, src, parse('<form><input name="q"></form>'), **changes)
    assert s.to_dict() == before


def test_invalid_item_is_excluded_without_orphan_input_or_processed_claim():
    s, src = prepared()
    result = Extraction(records=[ExtractedRecord(DOCUMENT, 'GET', '', 'q', 'query')])
    apply(s, src, result)
    assert not s.attack_surface_inputs
    assert s.discovery_sources[src.id].disposition == 'partial'


def test_global_bound_failure_is_atomic(monkeypatch):
    s, src = prepared()
    monkeypatch.setattr('src.workflow.discovery.inventory.MAX_ENDPOINTS', 1)
    before = s.to_dict()
    with pytest.raises(ValueError): apply(s, src, parse('<a href="/new"><form><input name="q"></form>'))
    assert s.to_dict() == before
