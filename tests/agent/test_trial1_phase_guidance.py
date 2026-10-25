"""Advice respects owned work and the bounded per-input admission contract."""
from dataclasses import replace
import re

import pytest

from src.agent.decision_planner import PlannerContext, PlannerCandidate, build_whole_target_plan
from src.skills.registry import Registry


def skills():
    registry = Registry()
    registry.load_dir('skills')
    return registry.list_enabled()


def frontier(**fields):
    return PlannerContext(objective_mode='whole_target', workflow_status='actionable',
        pending_source_count=7, next_source_id='ds_fixture', **fields)


@pytest.mark.parametrize('obligation', ['coverage', 'finding', 'active', 'repair'])
def test_frontier_and_incomplete_phases_cannot_hide_current_obligations(obligation):
    context = frontier()
    if obligation == 'coverage': context = replace(context, coverage_sync_candidate_ids=('cand_owned',))
    if obligation == 'finding': context = replace(context, pending_finding_candidate_ids=('cand_owned',))
    if obligation == 'active': context = replace(context, candidates=(PlannerCandidate('cand_owned', 'xss', 'validating'),))
    if obligation == 'repair': context = replace(context, repair_candidate_ids=('cand_owned',))
    plan = build_whole_target_plan(skills(), context)
    assert plan is not None and plan.candidate_id == 'cand_owned'
    assert 'ds_fixture' not in plan.guidance and 'select_source' not in plan.guidance


@pytest.mark.parametrize('selected', [False, True])
def test_only_selected_frontier_obligations_guide_review_with_phase_requirements(selected):
    context = frontier(completed_phases=frozenset({'recon'}), next_source_selected=selected,
        phase_completion_readiness={'phase': 'enumeration', 'ready': False,
            'artifact_ref': 'artifacts/web-enumeration/target/inventory.md', 'artifact_valid': False,
            'required_coverage': {'html_navigation': None}, 'reason': 'canonical artifact missing'})
    plan = build_whole_target_plan(skills(), context)
    assert plan is not None and plan.recommended_skill == 'web-enumeration'
    assert ('ds_fixture' in plan.guidance) == selected
    assert 'select_source' not in plan.guidance and 'process_source' not in plan.guidance
    if selected:
        assert 'record_input' in plan.guidance and 'get_source only for missing metadata' in plan.guidance
    assert 'load_skill' in plan.guidance and 'html_navigation' in plan.guidance
    assert 'canonical artifact missing' in plan.guidance


def test_ready_completion_precedes_unselected_frontier():
    context = frontier(phase_completion_readiness={'phase': 'recon', 'skill_name': 'recon',
        'ready': True, 'artifact_ref': 'artifacts/recon/target/summary.md'})
    plan = build_whole_target_plan(skills(), context)
    assert plan is not None and 'complete_skill' in plan.guidance
    assert 'ds_fixture' not in plan.guidance


def test_analyzed_candidate_cannot_precede_input_analysis_completion():
    context = frontier(completed_phases=frozenset({'recon', 'enumeration'}), pending_input_count=8,
        candidates=(PlannerCandidate('cand_ready', 'cross-site-scripting', 'new', validation_ready=False),))
    plan = build_whole_target_plan(skills(), context)
    assert plan is not None and plan.candidate_id is None
    assert plan.recommended_skill == 'web-input-analysis'
    assert 'before opening a new validation attempt' in plan.guidance


def test_validation_result_does_not_suppress_remaining_discovery():
    context = frontier(completed_phases=frozenset({'recon'}),
        candidates=(PlannerCandidate('cand_done', 'cross-site-scripting', 'dismissed', latest_outcome='not-confirmed'),))
    plan = build_whole_target_plan(skills(), context)
    assert plan is not None and plan.recommended_skill == 'web-enumeration'
    assert 'ds_fixture' not in plan.guidance


@pytest.mark.parametrize('ready', [True, False, None])
@pytest.mark.parametrize('selected', [False, True])
def test_completed_discovery_prioritizes_only_ready_validation_over_unselected_frontier(ready, selected):
    context = frontier(completed_phases=frozenset({'recon', 'enumeration', 'input_analysis'}),
        selected_pending_source_count=int(selected), next_source_selected=selected,
        candidates=(PlannerCandidate('cand_ready', 'sql-injection', 'queued', validation_ready=ready),))
    before = replace(context)
    plan = build_whole_target_plan(skills(), context)
    assert context == before  # Planning cannot disposition any source or certify completion.
    assert plan is not None
    if ready is True and not selected:
        assert plan.candidate_id == 'cand_ready' and plan.recommended_skill == 'sql-injection'
        assert 'start_validation' in plan.guidance and 'remain open' in plan.guidance
    elif selected:
        assert plan.candidate_id is None and 'ds_fixture' in plan.guidance
    else:
        assert 'ds_fixture' not in plan.guidance and 'select_source' not in plan.guidance


@pytest.mark.parametrize('phase', ['recon', 'enumeration', 'input_analysis'])
def test_ready_candidate_cannot_hide_required_artifact_repair(phase):
    context = frontier(completed_phases=frozenset({'recon', 'enumeration', 'input_analysis'}),
        candidates=(PlannerCandidate('cand_ready', 'sql-injection', 'queued', validation_ready=True),),
        phase_completion_readiness={'phase': phase, 'historically_completed': True,
                                    'artifact_valid': False, 'reason': 'canonical artifact missing'})
    plan = build_whole_target_plan(skills(), context)
    assert plan is not None and plan.candidate_id is None
    assert plan.recommended_skill == {'recon': 'recon', 'enumeration': 'web-enumeration',
                                      'input_analysis': 'web-input-analysis'}[phase]


@pytest.mark.parametrize('branch', ['ready', 'actionable', 'goal', 'revalidation', 'direct'])
def test_every_new_expert_route_prepares_skill_and_associations_before_start(branch):
    from src.agent.decision_planner import PlannerGoal, build_decision_plan
    from src.target.target import Target
    from src.workflow.validation.route import ValidationRoute
    candidate = PlannerCandidate('cand_xss', 'cross-site-scripting', 'queued',
        validation_ready=True if branch == 'ready' else None, validation_action='start_validation')
    context = PlannerContext(objective_mode='direct' if branch == 'direct' else 'whole_target',
        workflow_status='actionable', completed_phases=frozenset({'recon', 'enumeration', 'input_analysis'}),
        candidates=(candidate,), validation_routes={candidate.id: ValidationRoute('expert', 'cross-site-scripting')},
        revalidation_candidate_ids=(candidate.id,) if branch == 'revalidation' else (),
        requested_goals=(PlannerGoal('goal_xss', 'cross-site-scripting', 'in_progress', (candidate.id,)),)
                        if branch in {'goal', 'direct'} else ())
    plan = build_decision_plan('continue', skills(), Target('https://target.test'), context)
    assert plan is not None and plan.candidate_id == candidate.id
    text = ' '.join(plan.guidance.split())
    assert text.index('load_skill') < text.index('Then call workflow(action="start_validation"')
    for contract in ('prepare the primary request', 'existing Candidate, inventory and context',
                     'candidate_id alone', 'no supplementary associations', 'consistent role',
                     'Different methods', 'payload variations are observations', 'Do not guess endpoints',
                     'no execution permission'):
        assert contract in text
    # Preserve both obligations in the owned-attempt instruction while allowing
    # a qualifier such as "recovery" before "budget".
    assert re.search(r'owned active attempts?[^.]*\bimmutable declaration\b[^.]*\bbudget\b', text, re.IGNORECASE)
