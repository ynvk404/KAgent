"""Sanitized statements from the five lan-02 records; no historical writes."""
from dataclasses import replace

import pytest

from src.intelligence.store import (IntelligenceScenario, IntelligenceStore, LearningInput,
    extract_scenarios, guidance_eligibility, format_intelligence_context)
from src.target.origin import HTTPOrigin

ORIGIN = HTTPOrigin.from_url('http://fixture.test:8081')
STATEMENTS = [
    ('lesson-learned', 'Error detail redacted on later reads (`read_http_observation` blocked/offset-exceeded); 500 page itself omits query text.'),
    ('finding-pattern', 'No confirmed SQLi. Evidence of parser-level injection sensitivity only: 500 `SQLITE_ERROR: incomplete input` and `near "UNION": syntax error` on crafted input vs 200 baseline.'),
    ('technical-observation', 'Validate or disprove the SQL-injection candidate `cand_fixture` on `GET /rest/products/search?q=` of the instance, then close out the assessment report. Current state: attempt `attempt_fixture` was recorded as `insufficient-evidence` (deferred, max_steps) — NOT a negative.'),
    ('lesson-learned', 'Authenticated surface work blocked pending operator-supplied test credentials.'),
    ('technical-observation', 'SQLi attempt run to max_steps; attempt state + result recorded (deferred, `mutation_performed: false`, `cleanup_state: not-required`).'),
]


@pytest.mark.parametrize('category,lesson', STATEMENTS)
async def test_model_history_is_available_for_audit_but_not_automatic_guidance(tmp_path, category, lesson):
    store = IntelligenceStore(cwd=tmp_path / 'project', home=tmp_path / 'home')
    row = IntelligenceScenario(id='lan02-fixture', title='Historical observation', category=category,
        lesson=lesson, source='derived-untrusted-summary', source_role='summary', provenance='derived',
        confidence=.4, applicability='target', target_origin=ORIGIN.to_dict())
    store.append_batch([row])
    assert guidance_eligibility(row, ORIGIN) != 'eligible'
    assert guidance_eligibility(replace(row, confidence=1), ORIGIN) != 'eligible'
    history = store.search(lesson, 25, target_origin=ORIGIN, include_history=True)
    assert any(r['scenario'].id == row.id for r in history)
    assert all(r['scenario'].id != row.id for r in store.search(lesson, 25,
        target_origin=ORIGIN, include_history=False))
    assert any(r['scenario'].lesson == lesson for r in history if r['scenario'].id == row.id)
    assert '"sourceRole": "summary"' in format_intelligence_context(history, historical=True)
    assert lesson not in format_intelligence_context(history)
    # Recompaction/re-extraction cannot turn historical wording into authority.
    learned = await store.learn_from_inputs((LearningInput('## Findings and evidence\n- ' + lesson, 'summary'),),
                                           'fixture-session', target_origin=ORIGIN)
    assert all(guidance_eligibility(r, ORIGIN) != 'eligible' for r in learned)


@pytest.mark.parametrize('heading', ['Current objective', 'Plan', 'Completed tasks', 'Open TODOs'])
def test_session_sections_do_not_extract_reusable_technical_knowledge(heading):
    text = '## ' + heading + '\n- SQLi attempt reached max_steps and credentials remain pending for the current objective.'
    assert not extract_scenarios(text, source_role='summary', target_origin=ORIGIN)


def test_primary_tool_observation_retains_existing_eligibility():
    rows = extract_scenarios('## Task outcome\n- Anonymous control requests returned a stable JSON response.',
                            source_role='tool', target_origin=ORIGIN)
    assert rows and all(guidance_eligibility(r, ORIGIN) == 'eligible' for r in rows)
