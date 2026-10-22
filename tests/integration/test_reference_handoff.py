"""Request provenance and replay authority have independent resolvers."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from src.workflow.state import Candidate, WorkflowState
from src.workflow.validation.context import resolve_validation_context
from tests.integration.test_input_http_source import offline, source_runtime, record
from tests.helpers.discovery_calls import execute
from tests.helpers.burp_selection import ingest, ORIGIN


@pytest.mark.parametrize('action', ['record_input', 'record_candidate'])
@pytest.mark.parametrize('fault', ['missing', 'observation', 'path', 'method', 'identity', 'valid'])
async def test_replay_reference_uses_live_capture_binding_atomically(tmp_path, action, fault):
    rt, source = await source_runtime(tmp_path)
    row = ingest(rt, path='/other' if fault == 'path' else '/search',
        reqHeaders=[{'name': 'Host', 'value': '127.0.0.1:3000'}])
    ref = row['baseline_request_ref']
    if fault == 'missing': ref = 'baseline:stale:unavailable'
    elif fault == 'observation': ref = source.retained_ref
    elif fault == 'identity':
        # Re-ingest to produce a currently bound capture, with the wrong actor.
        row = ingest(rt, path='/search', authContextRef='other-actor',
            reqHeaders=[{'name': 'Host', 'value': '127.0.0.1:3000'}])
        ref = row['baseline_request_ref']
    args = {'action': action, 'method': 'POST' if fault == 'method' else 'GET',
        'endpoint': '/search', 'parameter': 'q', 'location': 'query', 'baseline_request_ref': ref}
    if action == 'record_candidate': args['candidate_class'] = 'sqli'
    before = deepcopy(rt.workflow.to_dict())
    result = await execute(rt, 'workflow', args, success=False)
    if fault == 'valid':
        assert json.loads(result.result)['ok']
    else:
        assert result.status == 'error' and 'baseline_request_ref' in result.result
        assert rt.workflow.to_dict() == before


@pytest.mark.parametrize('fault', ['missing', 'path', 'session', 'wrong-namespace', 'valid'])
async def test_candidate_source_ref_has_the_same_provenance_gate_as_inputs(tmp_path, fault):
    rt, source = await source_runtime(tmp_path)
    ref = source.retained_ref
    if fault == 'missing': ref = 'obs_unavailable'
    elif fault == 'wrong-namespace':
        ref = ingest(rt, reqHeaders=[{'name': 'Host', 'value': '127.0.0.1:3000'}])['baseline_request_ref']
    elif fault == 'session':
        item = rt.policy.observations._items[ref]
        rt.policy.observations._items[ref] = replace(item, source_details={'analysis_session': 'other'})
    before = rt.workflow.to_dict()
    result = await execute(rt, 'workflow', {'action': 'record_candidate', 'candidate_class': 'sqli',
        'method': 'GET', 'endpoint': '/other' if fault == 'path' else '/search', 'parameter': 'q',
        'location': 'query', 'source_ref': ref}, success=False)
    if fault == 'valid':
        assert json.loads(result.result)['candidate']['source_ref'] == ref
    else:
        assert result.status == 'error' and 'source_ref' in result.result
        assert rt.workflow.to_dict() == before


def test_stale_legacy_refs_hydrate_without_rebinding_or_replay_authority():
    candidate = Candidate(candidate_class='sqli', target=ORIGIN, method='GET', endpoint='/search',
        parameter='q', baseline_request_ref='obs_missing', source_ref='documentation-context')
    state = WorkflowState(candidates={candidate.id: candidate})
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.candidates[candidate.id].to_dict() == candidate.to_dict()
    context = resolve_validation_context(restored, candidate.id).to_dict()
    assert context['baseline']['available'] is False
    assert not restored.selected_sources and not restored.evidence and not restored.attempts


async def test_known_body_fields_keep_names_redacted_samples_and_pending_dispositions(tmp_path):
    # Geometry from the observed login request and retained Web3 JS call site.
    # No inference from endpoint spelling and no historical inventory rewrite.
    rt, _ = await source_runtime(tmp_path)
    for endpoint, field, sample in [
        ('/rest/user/login', 'email', '{"email":"fixture@example.test","password":"fixture-secret"}'),
        ('/rest/user/login', 'password', '{"email":"fixture@example.test","password":"fixture-secret"}'),
        ('/rest/web3/walletExploitAddress', 'walletAddress', '{"walletAddress":"fixture-address"}'),
    ]:
        result = await execute(rt, 'workflow', {'action': 'record_input', 'method': 'POST',
            'endpoint': endpoint, 'parameter': field, 'location': 'json', 'content_type': 'application/json',
            'sample_payload': sample, 'source_ref': 'documented-call-site'})
        assert json.loads(result.result)['input']['disposition'] == 'pending'
    restored = WorkflowState.from_dict(rt.workflow.to_dict())
    fields = {(row.endpoint, row.parameter) for row in restored.attack_surface_inputs.values()}
    assert (ORIGIN + '/rest/user/login', 'password') in fields
    assert (ORIGIN + '/rest/web3/walletExploitAddress', 'walletAddress') in fields
    assert 'fixture-secret' not in json.dumps(restored.to_dict())
