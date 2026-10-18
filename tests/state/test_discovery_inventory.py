"""Endpoint/provenance admission never supplies request or validation authority."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from src.workflow.discovery import EndpointRecord, SourceRecord, ProvenanceRecord, observation_handoff, scanner_handoff
from src.workflow.state import WorkflowObjective, WorkflowState, AttackSurfaceInput

ORIGIN = 'http://target.test'


def state():
    return WorkflowState(objective=WorkflowObjective('objective', 'whole_target', ORIGIN))


def source(**changes: Any):
    fields: dict[str, Any] = dict(objective_id='objective', target_origin=ORIGIN, kind='http',
                                  locator='obs-fixture', retained_hash='a' * 64)
    return SourceRecord(**{**fields, **changes})


def endpoint(url='/a', method=None):
    return EndpointRecord('objective', ORIGIN, url, method)


def test_cross_source_aggregation_separates_operations_and_execution():
    s = state()
    rows = [source(), replace(source(), kind='capture', locator='capture-1', id='')]
    ep = endpoint()
    for row in rows:
        s.admit_discovery(row, (ep,), (ProvenanceRecord(row.id, ep.id),))
    assert len(s.endpoints) == 1 and len(s.discovery_provenance) == 2
    assert len({endpoint(method=m).id for m in (None, 'GET', 'POST')}) == 3
    inputs = [AttackSurfaceInput('objective', ORIGIN, method='GET', endpoint='/a', parameter='q', location='query',
                                auth_context_ref=auth, baseline_request_ref=baseline)
              for auth, baseline in [('actor-a', 'baseline-a'), ('actor-b', 'baseline-a'), ('actor-a', 'baseline-b')]]
    for item in inputs:
        s.add_attack_surface_input(item)
    assert len(s.attack_surface_inputs) == 3
    assert not s.candidates and not s.attempts and not s.evidence and not s.selected_sources


@pytest.mark.parametrize('url', ['/A', '/a/', '/a?a=1&b=2', '/a?b=2&a=1', '/a?q=1&q=2',
                                     '/a?q=2&q=1', '/a?q=%2f', '/a?q=%2F', '/a?'])
def test_raw_operation_geometry(url):
    assert endpoint(url).id != endpoint().id
    assert endpoint(url).url.endswith(url)


def test_authority_normalization():
    assert endpoint('http://TARGET.test:80/a') == endpoint('/a')


@pytest.mark.parametrize('change', [dict(objective_id='foreign'), dict(target_origin='http://other.test'),
                                   dict(retained_hash='bad'), dict(id='ds_' + '0' * 64)])
def test_invalid_source_rejection_is_atomic(change):
    s = state()
    before = s.to_dict()
    with pytest.raises(ValueError):
        s.admit_discovery(replace(source(), **change))
    assert s.to_dict() == before


@pytest.mark.parametrize('attack', ['source', 'endpoint', 'input', 'geometry', 'foreign'])
def test_provenance_binding_atomic(attack):
    s, src, ep = state(), source(), endpoint(method='GET')
    inp, _ = s.add_attack_surface_input(AttackSurfaceInput('objective', ORIGIN, method='POST',
        endpoint='/other', parameter='q', location='query'))
    link = ProvenanceRecord(src.id, ep.id)
    if attack == 'source': link = replace(link, source_id=replace(src, locator='other', id='').id, id='')
    if attack == 'endpoint': link = replace(link, endpoint_id=endpoint('/other').id, id='')
    if attack == 'input': link = replace(link, input_id='invalid-input', id='')
    if attack == 'geometry': link = replace(link, input_id=inp.id, id='')
    if attack == 'foreign': ep = EndpointRecord('foreign', ORIGIN, '/a')
    before = deepcopy(s.to_dict())
    with pytest.raises(ValueError): s.admit_discovery(src, (ep,), (link,))
    assert s.to_dict() == before
    assert not s.candidates and not s.evidence and not s.attempts


def test_persistence_clear_replace_and_corrupt_graph():
    s, src, ep = state(), source(), endpoint()
    s.admit_discovery(src, (ep,), (ProvenanceRecord(src.id, ep.id),))
    data = s.to_dict()
    assert WorkflowState.from_dict(data).to_dict() == data
    legacy = {k: v for k, v in data.items() if k not in {'endpoints', 'discovery_sources', 'discovery_provenance'}}
    assert not WorkflowState.from_dict(legacy).discovery_sources
    generation = s.generation
    s.clear()
    assert not s.endpoints and not s.discovery_sources and not s.discovery_provenance
    s.replace_from(WorkflowState.from_dict(data))
    assert s.generation != generation and s.to_dict() == data
    broken = deepcopy(data)
    broken['discovery_provenance'][0]['endpoint_id'] = endpoint('/wrong').id
    restored = WorkflowState.from_dict(broken)
    assert not restored.endpoints and not restored.discovery_sources and not restored.discovery_provenance


@pytest.mark.parametrize('url', ['http://other.test/a', 'http://target.test:81/a', 'https://target.test/a',
    '/a#route', '/a?token=super-secret', '/a?%74oken=super-secret', '/a?refresh_token=short-value',
    'http://user:password@target.test/a'])
def test_external_or_secret_operation_not_persisted(url):
    with pytest.raises(ValueError): endpoint(url)


def test_capture_admission_preserves_locator_without_raw_or_request_context():
    s = state()
    item = SimpleNamespace(objective_id=None, source_kind='imported-capture', source_details={'capture_id': 'burp:one'},
        retained_hash='b' * 64, id='obs_1', url=ORIGIN + '/a', method='POST', complete=True, truncated=False,
        body=b'password=secret-canary', request_headers={'Cookie': 'secret-canary'})
    src = observation_handoff(s, item)
    assert src is not None and src.locator == 'burp:one' and src.retained_ref == item.id
    assert 'secret-canary' not in str(s.to_dict())
    assert not s.attack_surface_inputs and not s.candidates and not s.selected_sources
    before = s.to_dict()
    item.url = 'http://foreign.test/a'
    with pytest.raises(ValueError): observation_handoff(s, item)
    assert s.to_dict() == before


def test_ffuf_exact_job_and_record_ids_and_nmap_no_http_inference(tmp_path):
    from tests.state.test_scanner_state import job, state as scanner_state
    s = scanner_state()
    scan = job(tmp_path)
    s.add_scanner_job(scan)
    rows = scan.dataset(tmp_path)
    src = scanner_handoff(s, scan, rows)
    assert src is not None and src.scanner_job_id == scan.job_id
    assert {p.locator for p in s.discovery_provenance.values()} == set(scan.sample_ids)
    assert not scan.dispositions and not s.attack_surface_inputs and not s.candidates
    before = s.to_dict()
    with pytest.raises(ValueError): scanner_handoff(s, replace(scan, objective_id='other'), rows)
    assert s.to_dict() == before
    with pytest.raises(ValueError): scanner_handoff(s, scan, b'corrupted')
    scan.scanner = 'nmap'
    scanner_handoff(s, scan, rows)
    assert len(s.endpoints) == 3


@pytest.mark.parametrize('attack', ['row', 'operation', 'dataset'])
def test_scanner_provenance_rejects_cross_record_binding(tmp_path, attack):
    from tests.state.test_scanner_state import job, state as scanner_state
    s = scanner_state()
    scan = job(tmp_path)
    s.add_scanner_job(scan)
    data = scan.dataset(tmp_path)
    src = SourceRecord('objective', scan.target_origin, 'ffuf', scan.job_id,
                       scan.artifacts['dataset_sha256'], scanner_job_id=scan.job_id)
    ep = EndpointRecord('objective', scan.target_origin, '/path0', 'GET')
    record_id = scan.sample_ids[1 if attack == 'operation' else 0]
    if attack == 'row': record_id = 'sr_' + 'f' * 24
    before = s.to_dict()
    with pytest.raises(ValueError):
        s.admit_discovery(src, (ep,), (ProvenanceRecord(src.id, ep.id, locator=record_id),),
                          scanner_dataset=b'wrong' if attack == 'dataset' else data)
    assert s.to_dict() == before


def test_provenance_cannot_mislabel_existing_input_media():
    s, src = state(), source()
    ep = endpoint(method='POST')
    item, _ = s.add_attack_surface_input(AttackSurfaceInput('objective', ORIGIN, method='POST',
        endpoint=ep.url, parameter='q', location='json', content_type='application/json'))
    before = s.to_dict()
    with pytest.raises(ValueError):
        s.admit_discovery(src, (ep,), (ProvenanceRecord(src.id, ep.id, item.id,
                                                      media_type='application/xml'),))
    assert s.to_dict() == before
