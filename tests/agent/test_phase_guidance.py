"""Phase advice supplements readiness without creating workflow artifacts."""
from dataclasses import replace

import pytest

from src.agent.action_guidance import render_action_guidance
from src.agent.decision_planner import PlannerCandidate, PlannerContext, build_whole_target_plan
from src.skills.registry import Registry
from src.tools.workflow.action_view import ActionView


def guidance(context):
    return render_action_guidance(ActionView.for_objective(context.objective_mode), context)


@pytest.mark.parametrize('completed', [frozenset(), frozenset({'recon'})])
def test_discovery_does_not_recommend_candidates_even_with_early_candidate(completed):
    context = PlannerContext(objective_mode='whole_target', completed_phases=completed)
    for candidates in ((), (PlannerCandidate('can_existing', 'sql-injection', 'new'),)):
        advice = guidance(replace(context, candidates=candidates))
        assert 'Recommended: record_candidate' not in advice
        assert 'start_validation' not in advice
        assert 'coverage' in advice
        assert 'complete_skill' in advice and 'ready' in advice


def test_input_analysis_has_conditional_candidate_path_and_bounded_reads():
    advice = guidance(PlannerContext(objective_mode='whole_target',
        completed_phases=frozenset({'recon', 'enumeration'}), pending_input_count=4))
    assert 'record_candidate' in advice and 'controllability' in advice
    assert 'disposition' in advice and 'cursor' in advice
    assert 'source' in advice and 'limitations' in advice
    assert len(advice) < 2600


def test_artifact_repair_phase_overrides_historical_completion():
    registry = Registry()
    registry.load_dir('skills')
    context = PlannerContext(objective_mode='whole_target',
        completed_phases=frozenset({'recon', 'enumeration', 'input_analysis'}),
        phase_completion_readiness={'phase': 'enumeration', 'skill_name': 'web-enumeration',
                                    'ready': False, 'error': 'artifact missing'})
    plan = build_whole_target_plan(registry.list_enabled(), context)
    assert plan is not None and plan.recommended_skill == 'web-enumeration'
    assert 'action="complete_skill"' not in plan.guidance
    assert 'Recommended: record_candidate' not in guidance(context)


def test_direct_hypothesis_still_has_candidate_path():
    assert 'record_candidate' in guidance(PlannerContext(objective_mode='direct'))


@pytest.mark.parametrize('mode', ['whole_target', 'direct'])
@pytest.mark.parametrize('status', ['validating', 'deferred', 'validated'])
def test_candidate_and_repair_labels_do_not_grant_active_ownership(mode, status):
    advice = guidance(PlannerContext(objective_mode=mode,
        candidates=(PlannerCandidate('can_repair', 'sql-injection', status),),
        repair_candidate_ids=('can_repair',)))
    assert 'no owned active attempt' in advice
    assert 'record_attempt_state' not in advice and 'record_result for the active attempt' not in advice
    assert 'permitted evidence repair' in advice and 'Preserve terminal results' in advice


@pytest.mark.parametrize('status', ['completed', 'blocked'])
def test_terminal_work_does_not_start_new_hypothesis(status):
    advice = guidance(PlannerContext(objective_mode='whole_target', workflow_status=status,
        completed_phases=frozenset({'recon', 'enumeration', 'input_analysis'})))
    assert 'record_candidate' not in advice and 'start_validation' not in advice


@pytest.mark.parametrize('status', ['pending', 'partial', 'blocked'])
def test_source_counts_stay_bounded_without_copying_source_bodies(status):
    from tests.state.test_discovery_inventory import state, source
    from src.agent.system_prompt import render_workflow
    workflow = state()
    for index in range(20):
        workflow.admit_discovery(source(locator=f'obs-{index}', selected=True, disposition=status,
            stop_reason='explicit limitation' if status != 'pending' else None))
    before = workflow.to_dict()
    text = render_workflow(workflow)
    assert f'{status}=20' in text and 'unresolved=20' in text
    assert 'view=sources|endpoints|provenance' in text and 'next_input_cursor' in text
    assert len(text) <= 6000 and 'obs-19' not in text
    assert workflow.to_dict() == before and not workflow.candidates and not workflow.evidence


@pytest.mark.parametrize('completed', [frozenset(), frozenset({'recon', 'enumeration', 'input_analysis'})])
@pytest.mark.parametrize('startable', [False, True])
def test_unavailable_artifact_repair_does_not_suppress_owned_generic_work(completed, startable):
    from src.workflow.validation.route import ValidationRoute
    context = PlannerContext(objective_mode='whole_target', completed_phases=completed,
        phase_completion_readiness={'phase': 'recon', 'skill_name': 'recon', 'ready': False},
        candidates=(PlannerCandidate('can_owned', 'unsupported-class', 'deferred', generic_startable=startable),),
        validation_routes={'can_owned': ValidationRoute('generic', 'generic-bounded-validation')})
    plan = build_whole_target_plan([], context)
    if completed and startable:
        assert plan is not None and plan.candidate_id == 'can_owned'
        assert 'complete_skill' not in plan.guidance
    else:
        assert plan is None
