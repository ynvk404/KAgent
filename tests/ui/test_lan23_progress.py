"""Canonical compact progress remains independent of loaded Skill metadata."""
from copy import deepcopy

from src.agent.events import SkillActiveEvent
from src.ui.core.outcomes import runtime_facts
from src.workflow.state import AttackSurfaceInput, Candidate
from tests.ui.test_progress_milestones import runtime, dispatch, ORIGIN, accepted_fixture, complete_phase_fixtures


def test_excluded_inputs_and_accepted_negative_are_not_progress_successes(tmp_path):
    app, state, tool = runtime(tmp_path, whole=True)
    item, _ = state.add_attack_surface_input(AttackSurfaceInput('fixture-objective', ORIGIN,
        method='GET', endpoint='/search', parameter='q', location='query'))
    state.set_input_disposition(item.id, 'analyzed')
    candidate, _ = state.add_candidate(Candidate(candidate_class='sqli', target=ORIGIN,
        method='GET', endpoint='/search', parameter='q', objective_id='fixture-objective'), input_id=item.id)
    state.add_validation_result(accepted_fixture(tmp_path, state, candidate, outcome='not-confirmed'))
    excluded, _ = state.add_attack_surface_input(AttackSurfaceInput('fixture-objective', ORIGIN,
        method='POST', endpoint='/session', parameter='email', location='json'))
    state.set_input_disposition(excluded.id, 'dropped', reason='Operator explicitly excluded; untested.')
    complete_phase_fixtures(state, tool, tmp_path)
    before = deepcopy(state.to_dict())
    facts = runtime_facts(app.agent, None, ())
    assert facts.overview == 'Workflow · Validation · 0 findings'
    assert facts.validations == 1
    assert state.to_dict() == before


def test_loaded_skill_does_not_complete_input_analysis_or_start_validation(tmp_path):
    app, state, _ = runtime(tmp_path, whole=True)
    dispatch(app, SkillActiveEvent(name='sql-injection'))
    assert app.state.active_skill == 'sql-injection'
    assert not state.completed_phases() and not state.attempts
    assert 'Recon' in runtime_facts(app.agent, None, ()).overview
