"""The 921-byte complete and 512-byte capped control metadata from lan-02."""
from pathlib import Path
from types import SimpleNamespace
import json

import httpx
import pytest

from src.workflow.assessment import source_association, usable_source
from src.workflow.evidence.errors import EvidenceSubmissionError
from tests.security.test_execution_policy import runtime, REAL_CLIENT
from tests.security.test_agent_assessment import setup


def test_mismatch_reports_actual_native_geometry_without_secret_url_components():
    candidate = SimpleNamespace(target='https://fixture.test', method='GET', endpoint='/rest/products/search')
    source = {'source_kind': 'native-http', 'producer': 'http', 'method': 'GET',
              'url': 'https://fixture.test/?token=fixture-secret#fragment-secret'}
    with pytest.raises(EvidenceSubmissionError) as caught:
        source_association(candidate, {}, source, {})
    message = caught.value.response('record_result')
    assert 'expected primary: GET /rest/products/search' in message
    assert 'actual: GET /;' in message and 'producer=http' in message
    assert 'no related request association' in message
    assert 'fixture-secret' not in message and 'fragment-secret' not in message and '?token' not in message


async def test_complete_existing_control_can_repair_proof_without_recapture_or_parent_rebind(runtime, tmp_path, monkeypatch):
    metadata = json.loads((Path(__file__).parents[1] / 'data/lan02_controls.json').read_text())
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, prompter, policy, *_ = runtime
    payload = b'{"control":"' + b'x' * (921 - len(b'{"control":""}')) + b'"}'
    assert len(payload) == 921
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, content=payload, request=req)), **kw))
    ids = []
    for cap in [2048, 512]:
        await registry.execute('http', {'url': '/fixture?q=control', 'phase': 'validation',
                                       'max_response_bytes': cap}, None, prompter)
        ids.append(next(reversed(policy.observations._items)))
    page = json.loads(await registry.execute('workflow', {'action': 'list', 'candidate_id': candidate.id}, None, prompter))
    inventory = {row['observation_id']: row for row in page['observations']}
    for oid, expected in zip(ids, metadata):
        assert {k: inventory[oid][k] for k in expected} == expected
        assert inventory[oid]['attempt_id'] == args['attempt_id']
    assert usable_source(inventory[ids[0]]) and not usable_source(inventory[ids[1]])
    proof = tmp_path / 'proof.md'
    proof.write_text('Capped control chosen for this offline metadata fixture.')
    old = json.loads(await registry.execute('workflow', {'action': 'record_evidence', 'candidate_id': candidate.id,
        'evidence_path': str(proof), 'observation_ids': [ids[1]]}, None, prompter))['evidence']
    old_bytes = (tmp_path / old['path']).read_bytes()
    rejected = await registry.execute('workflow', {**args, 'outcome': 'not-confirmed',
        'evidence_refs': [old['id']], 'observation_ids': [ids[1]]}, None, prompter)
    assert rejected.startswith('error:') and not state.validation_results
    requests_before = registry.get('http').dispatch_attempts
    proof.write_text('Existing complete control selected; capped duplicate remains in the forensic inventory.')
    new = json.loads(await registry.execute('workflow', {'action': 'record_evidence', 'candidate_id': candidate.id,
        'evidence_path': str(proof), 'observation_ids': [ids[0]]}, None, prompter))['evidence']
    assert old['id'] != new['id'] and (tmp_path / old['path']).read_bytes() == old_bytes
    accepted = await registry.execute('workflow', {**args, 'outcome': 'not-confirmed',
        'evidence_refs': [new['id']], 'observation_ids': [ids[0]]}, None, prompter)
    assert json.loads(accepted)['ok']
    assert registry.get('http').dispatch_attempts == requests_before
    assert ids[1] in policy.observations._items and not state.eligible_for_finding(candidate.id)
