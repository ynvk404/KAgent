"""Final presentation uses the read-only Runtime obligation projection."""
from copy import deepcopy

import pytest

from src.agent.events import DoneEvent
from src.ui.core.outcomes import runtime_facts
from src.ui.core.state import AgentEventAction, SetBusy, initial_state, reducer
from src.ui.widgets.banner import BannerData
from src.workflow.state import ValidationResult, ValidationOutcome
from tests.agent.test_retry_disposition import DECLINE, call, inconclusive
from tests.agent.test_validation_continuation import candidate_for, offline
from tests.helpers.workflow import adopt_fixture_assessment
from tests.tools.test_finding import _linked_proof


def terminal_fixture(rt, candidate, outcome: ValidationOutcome = 'confirmed'):
    proof = _linked_proof(rt.workflow, candidate, rt.workflow_tool.evidence_root)
    result = adopt_fixture_assessment(rt.workflow, ValidationResult(
        candidate.id, 'sql-injection', outcome, evidence_refs=[proof],
        session_id=rt.workflow_tool.session_id, mutation_performed=False, cleanup_state='not-required'),
        policy=rt.policy)
    rt.workflow.add_validation_result(result)
    return result


def finish(facts, reason):
    state = initial_state('', BannerData('fixture', 'fixture', '.'))
    # A resumed Finding already in the turn baseline must still count as saved.
    state = reducer(state, SetBusy(True, facts=facts))
    return reducer(state, AgentEventAction(DoneEvent(stop_reason=reason), facts=facts))


async def test_multiple_obligations_include_unknown_and_not_attempted_and_saved_finding(offline, monkeypatch):
    rt, sent = offline
    first = await inconclusive(rt, DECLINE)
    second = await candidate_for(rt, 'xss')
    await call(rt, 'start_validation', candidate_id=second)
    await call(rt, 'record_result', candidate_id=second, skill_name='cross-site-scripting',
               outcome='insufficient-evidence', retry_decision=DECLINE)
    rt.workflow.latest_result(first).cleanup_state = 'unknown'
    rt.workflow.latest_result(second).cleanup_state = 'not-attempted'
    rt.workflow.objective.add_requested_goal('sqli')
    # Independent, synthetically accepted and persisted result fixture.
    from src.workflow.state import Candidate
    saved, _ = rt.workflow.add_candidate(Candidate(candidate_class='sqli', target=rt.target.base_url(),
        endpoint='/saved', method='GET', parameter='q', location='query', objective_id=rt.workflow.objective.id))
    terminal_fixture(rt, saved)
    rt.workflow.mark_finding_persisted(saved.id)
    status, actions, blockers = rt.agent._whole_target_state()
    assert status == 'blocked' and not actions
    assert len(blockers) == 5  # Two validation, two cleanup and one requested-goal obligation.
    before = deepcopy(rt.workflow.to_dict())
    revision = rt.workflow.committed_revision

    def forbidden(*args, **kwargs):
        raise AssertionError('Presentation must not reconcile or run the scheduling evaluator')

    monkeypatch.setattr(rt.agent, '_whole_target_state', forbidden)
    monkeypatch.setattr(rt.agent, '_reconcile_requested_goals', forbidden)
    monkeypatch.setattr(type(rt.workflow), 'mark_committed', forbidden)
    facts = runtime_facts(rt.agent, DoneEvent(stop_reason='workflow_blocked'), ())
    assert facts.unresolved_obligations == len(actions) + len(blockers)
    assert facts.saved_findings == 1
    assert any('unknown' in item for item in facts.blockers)
    assert any('not-attempted' in item for item in facts.blockers)
    state = finish(facts, 'workflow_blocked')
    assert state.transcript[-1].text == 'Assessment incomplete · 1 finding saved · 5 unresolved obligations'
    assert first not in state.transcript[-1].text and '/fixture' not in state.transcript[-1].text
    assert state.latest_turn_details is not None and state.latest_turn_details.saved_findings == 1
    assert first in '\n'.join(state.latest_turn_details.remaining)
    from src.ui.widgets.turn_details_modal import TurnDetailsModal
    detail_text = TurnDetailsModal(state.latest_turn_details, lambda: None).render().plain
    assert first in detail_text and 'unknown' in detail_text and 'not-attempted' in detail_text
    assert first in '\n'.join(facts.blockers)
    assert rt.workflow.to_dict() == before and rt.workflow.committed_revision == revision and not sent


@pytest.mark.parametrize('outcome', ['confirmed', 'not-confirmed'])
async def test_completed_assessment_is_short_and_uses_total_persisted_findings(offline, outcome):
    rt, sent = offline
    cid = await candidate_for(rt)
    terminal_fixture(rt, rt.workflow.candidates[cid], outcome)
    if outcome == 'confirmed':
        rt.workflow.mark_finding_persisted(cid)
    assert rt.agent._whole_target_state() == ('completed', (), ())
    before = deepcopy(rt.workflow.to_dict())
    facts = runtime_facts(rt.agent, DoneEvent(stop_reason='workflow_completed'), ())
    assert facts.completion_supported and not facts.unresolved_obligations
    text = finish(facts, 'workflow_completed').transcript[-1].text
    assert text == ('Assessment completed · 1 finding saved' if outcome == 'confirmed'
                    else 'Assessment completed · 0 findings saved')
    assert rt.workflow.to_dict() == before and not sent


async def test_pending_action_and_blocker_use_the_same_obligation_count(offline):
    rt, _ = offline
    first = await inconclusive(rt, DECLINE)
    rt.workflow.latest_result(first).cleanup_state = 'pending'
    status, actions, blockers = rt.agent._whole_target_state()
    assert status == 'actionable' and len(actions) == len(blockers) == 1
    facts = runtime_facts(rt.agent, None, ())
    assert facts.unresolved_obligations == 2 and not facts.completion_supported
    text = finish(facts, 'workflow_completed').transcript[-1].text
    assert text == 'Assessment incomplete · 0 findings saved · 2 unresolved obligations'


async def test_summary_failure_does_not_reopen_completed_assessment(offline):
    rt, _ = offline
    cid = await candidate_for(rt)
    terminal_fixture(rt, rt.workflow.candidates[cid], 'not-confirmed')
    assert rt.agent._whole_target_state() == ('completed', (), ())
    facts = runtime_facts(rt.agent, None, ())
    assert finish(facts, 'client_error').transcript[-1].text == (
        'Assessment completed · 0 findings saved · provider failure')
