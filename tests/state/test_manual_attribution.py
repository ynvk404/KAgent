"""Atomic metadata linkage, not a test of document understanding or completeness."""
from copy import deepcopy
from dataclasses import replace
from typing import Any

import pytest

from src.workflow.discovery.attribution import record_attributed_input
from src.workflow.discovery.inventory import EndpointRecord, ProvenanceRecord
from src.workflow.state import AttackSurfaceInput, WorkflowState
from tests.helpers.discovery_calls import attribution
from tests.state.test_discovery_inventory import state, source

DOCUMENT = 'http://target.test/openapi.json'


def prepared():
    s = state()
    src = source(document_url=DOCUMENT, retained_ref='obs-fixture')
    ep = EndpointRecord('objective', 'http://target.test', DOCUMENT, 'GET')
    s.admit_discovery(src, (ep,), (ProvenanceRecord(src.id, ep.id),))
    return s, src


def proposal(**changes: Any):
    values: dict[str, Any] = {'objective_id': 'objective', 'target_origin': 'http://target.test',
        'method': 'POST', 'endpoint': '/orders', 'parameter': 'cid', 'location': 'json',
        'content_type': 'application/json', **changes}
    return AttackSurfaceInput(**values)


def record(s, src, item=None, **changes):
    return record_attributed_input(s, item or proposal(),
        {**attribution(src, '/components/schemas/Order/properties/cid'), **changes}, generation=s.generation)


def test_atomic_manual_linkage_dedup_no_context_or_fake_source_completion():
    s, src = prepared()
    item, created, link = record(s, src)
    assert created and item.disposition == 'pending'
    assert link.input_id == item.id and link.source_id == src.id
    assert link.locator == 'manual:/components/schemas/Order/properties/cid'
    assert s.endpoints[link.endpoint_id].url == 'http://target.test/orders'
    assert s.endpoints[link.endpoint_id].method == 'POST' and link.media_type == 'application/json'
    assert item.source_ref is item.baseline_request_ref is item.auth_context_ref is None
    assert s.discovery_sources[src.id] == src and not src.selected
    before, revision = s.to_dict(), s.committed_revision
    again, created, same_link = record(s, src)
    assert not created and again is item and same_link == link
    assert s.to_dict() == before and s.committed_revision == revision
    # Distinct document occurrences link the same canonical input.
    input_before = item.to_dict()
    record(s, src, document_location='/paths/~1orders/post/requestBody/cid')
    assert len(s.attack_surface_inputs) == 1 and item.to_dict() == input_before
    assert {p.locator for p in s.discovery_provenance.values() if p.input_id == item.id} == {
        'manual:/components/schemas/Order/properties/cid', 'manual:/paths/~1orders/post/requestBody/cid'}
    assert not s.candidates and not s.attempts and not s.evidence and not s.selected_sources


@pytest.mark.parametrize('fault', ['source', 'ref', 'hash', 'objective', 'origin', 'generation', 'id',
                                  'location', 'secret', 'traffic', 'extra', 'null', 'restore'])
def test_invalid_attribution_rejects_all_input_and_graph_changes(fault):
    s, src = prepared()
    data = attribution(src, '/components/schemas/Order/properties/cid')
    generation = s.generation
    if fault == 'source': data['discovery_source_id'] = 'ds_' + 'f' * 64
    if fault == 'ref': data['retained_ref'] = 'obs-wrong'
    if fault == 'hash': data['retained_hash'] = 'f' * 64
    if fault == 'objective':
        assert s.objective is not None
        s.objective.id = 'foreign'
    if fault == 'origin':
        foreign = replace(src, target_origin='https://target.test', document_url='https://target.test/openapi.json', id='')
        s.discovery_sources[foreign.id] = foreign
        data = attribution(foreign)
    if fault == 'generation': generation = 'stale'
    if fault == 'id': s.discovery_sources[src.id] = replace(src, retained_hash='b' * 64, id='')
    if fault == 'location': data['document_location'] = 'x' * 234
    if fault == 'secret': data['document_location'] = 'password=fixture-secret'
    if fault == 'traffic': data['document_location'] = 'POST /orders HTTP/1.1\nCookie: secret'
    if fault == 'extra': data['response_body'] = 'raw traffic'
    if fault == 'null': data = None
    if fault == 'restore': s.discovery_restore_invalid = True
    before, revision = deepcopy(s.to_dict()), s.committed_revision
    with pytest.raises((ValueError, TypeError)):
        record_attributed_input(s, proposal(), data, generation=generation)
    assert s.to_dict() == before and s.committed_revision == revision


def test_graph_bound_failure_rejects_input_and_enrichment_atomically(monkeypatch):
    s, src = prepared()
    existing, _ = s.add_attack_surface_input(proposal(content_type=None))
    before = deepcopy(s.to_dict())
    monkeypatch.setattr('src.workflow.discovery.inventory.MAX_ENDPOINTS', 1)
    with pytest.raises(ValueError, match='bound'):
        record(s, src)
    assert s.to_dict() == before and existing.content_type is None


def test_late_attributed_input_invalidates_review_without_reopening_historical_phase():
    from src.workflow.planning.goals import RequestedGoal
    from tests.helpers.workflow import record_completed_phase
    s, src = prepared()
    goal = RequestedGoal('xss')
    assert s.objective is not None
    s.objective.requested_goals = [goal]
    for phase in ('recon', 'enumeration', 'input_analysis'):
        record_completed_phase(s, phase, objective_id='objective', target_origin='http://target.test',
            artifact_ref=f'artifacts/{phase}.md', no_inputs_discovered=phase == 'input_analysis')
    s.mark_goal_no_candidate(goal.id, artifact_ref='artifacts/input_analysis.md', review_binding='old')
    historical = deepcopy(s.phase_completions)
    record(s, src)
    assert goal.status == 'pending' and goal.review_binding is None
    assert s.phase_completions == historical and s.input_inventory_review_error()


def test_restore_preserves_historical_extraction_graph_and_selected_obligations():
    s, src = prepared()
    s.update_discovery_source(src.id, generation=s.generation, selected=True,
        disposition='partial', limitations=('historical max_bytes=65536',),
        stop_reason='historical extraction limited', processing_bounds=(('max_bytes', 65536),),
        content_identity='c' * 64)
    item, _ = s.add_attack_surface_input(proposal())
    ep = EndpointRecord('objective', 'http://target.test', '/orders', 'POST')
    # Historical locator and ID format, without invoking an extractor.
    link = ProvenanceRecord(src.id, ep.id, item.id, '/paths/~1orders/post', required=True,
                            media_type='application/json')
    s.admit_discovery(src, (ep,), (link,))
    before = s.to_dict()
    restored = WorkflowState.from_dict(deepcopy(before))
    assert restored.to_dict() == before and not restored.discovery_restore_invalid
    assert restored.discovery_provenance[link.id] == link
    assert not restored.discovery_provenance[link.id].locator.startswith('manual:')
    assert restored.discovery_sources[src.id].unresolved
    assert restored.input_inventory_review_error()
    record(restored, src, proposal(parameter='orderLines'))
    assert restored.discovery_sources[src.id] == s.discovery_sources[src.id]
    assert restored.discovery_provenance[link.id] == link
    assert WorkflowState.from_dict(restored.to_dict()).to_dict() == restored.to_dict()
