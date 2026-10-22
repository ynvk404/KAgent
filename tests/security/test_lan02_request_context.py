"""Offline regressions for the lan-02 request/response media confusion."""
import json

import pytest

from src.redaction.redact import redact_payload
from src.workflow.state import Candidate, AttackSurfaceInput, WorkflowState


@pytest.mark.parametrize('template,location,media,expected', [
    ('GET /rest/products/search?q={INJECTION_POINT}', 'query', 'application/json',
     'GET /rest/products/search?q={INJECTION_POINT}'),
    ('q={INJECTION_POINT}&password=fixture-secret', 'query', 'application/json',
     'q={INJECTION_POINT}&password=[REDACTED]'),
    ('GET /search?token=fixture-secret&q={INJECTION_POINT}', None, 'application/json',
     'GET /search?token=[REDACTED]&q={INJECTION_POINT}'),
    ('{"q":"{INJECTION_POINT}","password":"fixture-secret"}', 'json', 'application/json',
     '{"q":"{INJECTION_POINT}","password":"[REDACTED]"}'),
    ('{"password":"fixture-secret",', 'json', 'application/json', '[REDACTED]'),
    ('not-json password=fixture-secret', 'json', 'application/json', '[REDACTED]'),
    ('GET /search?password=fixture-secret', 'json', 'application/json', '[REDACTED]'),
    ('password={INJECTION_POINT}&token=fixture-secret', 'body', 'application/x-www-form-urlencoded',
     'password={INJECTION_POINT}&token=[REDACTED]'),
    ('GET /search?q={INJECTION_POINT}', None, None, 'GET /search?q={INJECTION_POINT}'),
])
def test_templates_survive_state_export_sanitization_and_hydration(template, location, media, expected):
    candidate = Candidate(candidate_class='sqli', target='https://fixture.test', method='GET',
        endpoint='/search', parameter='q', location=location, content_type=media, request_template=template)
    item = AttackSurfaceInput(objective_id='objective', target_origin='https://fixture.test', method='GET',
        endpoint='/search', parameter='q', location=location or 'query', content_type=media, sample_payload=template)
    assert candidate.request_template == item.sample_payload == expected
    state = WorkflowState(candidates={candidate.id: candidate}, attack_surface_inputs={item.id: item})
    # The same mapping sanitizer is used by logging, tool results and sessions.
    exported = redact_payload(state.to_dict())
    encoded = json.dumps(exported)
    assert 'fixture-secret' not in encoded
    restored = WorkflowState.from_dict(json.loads(encoded))
    assert restored.candidates[candidate.id].request_template == expected
    assert restored.attack_surface_inputs[item.id].sample_payload == expected
    assert restored.candidates[candidate.id].id == candidate.id
    assert not restored.eligible_for_finding(candidate.id)


async def test_session_persistence_keeps_query_template_and_redacts_body_secrets(tmp_path):
    from src.session.store import Store
    candidate = Candidate(candidate_class='sqli', target='https://fixture.test', method='GET',
        endpoint='/search', parameter='q', location='query', content_type='application/json',
        request_template='GET /search?q={INJECTION_POINT}&token=fixture-secret')
    state = WorkflowState(candidates={candidate.id: candidate})
    store = Store.new_with_id(str(tmp_path / 'sessions'), 'fixture')
    await store.save([], workflow=state)
    assert 'fixture-secret' not in store.path.read_text()
    restored = store.load().workflow.candidates[candidate.id]
    assert restored.request_template == 'GET /search?q={INJECTION_POINT}&token=[REDACTED]'
