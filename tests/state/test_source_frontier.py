"""Selected-source obligations, bounded stops, restore and semantic novelty."""
from dataclasses import replace

import pytest

from src.agent.agent import WholeTargetStallTracker
from src.agent.system_prompt import render_workflow
from src.workflow.discovery import discovery_page
from tests.state.test_discovery_inventory import state, source, endpoint
from tests.helpers.workflow import record_completed_phase


def setup():
    s, src = state(), source(document_url='http://target.test/docs')
    s.admit_discovery(src)
    s.update_discovery_source(src.id, generation=s.generation, selected=True)
    return s, src


def update(s, src, **changes):
    return s.update_discovery_source(src.id, generation=s.generation, **changes)


def verdict(s):
    return s.whole_target_status(target_origin='http://target.test', available_phases=frozenset(),
        validator_classes=frozenset(), coverage_sync_available=True)


@pytest.mark.parametrize('disposition', ['pending', 'processed', 'partial', 'blocked', 'not_applicable'])
def test_zero_input_dispositions_and_completion(disposition):
    s, src = setup()
    for phase in ('recon', 'enumeration', 'input_analysis'):
        record_completed_phase(s, phase, objective_id='objective', target_origin='http://target.test',
                               artifact_ref=f'artifacts/{phase}.md', no_inputs_discovered=phase == 'input_analysis')
    update(s, src, disposition=disposition, stop_reason='Explicit source outcome')
    current = s.discovery_sources[src.id]
    assert current.unresolved == (disposition in {'pending', 'partial', 'blocked'})
    status, actions, blockers = verdict(s)
    if disposition == 'pending': assert 'source:' + src.id in actions
    if disposition in {'partial', 'blocked'}: assert any('source:' in row for row in blockers)
    if disposition in {'processed', 'not_applicable'}: assert status == 'completed'
    assert not s.attack_surface_inputs and not s.candidates and not s.evidence and not s.phase_coverage


def test_budget_stop_requires_explicit_ack_bounds_and_reason():
    s, src = setup()
    before = s.to_dict()
    with pytest.raises(ValueError):
        update(s, src, disposition='partial', bounded_stop=True, stop_reason='budget', limitations=('record bound',))
    assert s.to_dict() == before
    result = update(s, src, disposition='partial', bounded_stop=True, stop_reason='bounded document review stopped',
                    limitations=('max_records=32',), processing_bounds=(('max_records', 32),))
    assert not result.unresolved
    assert result.disposition == 'partial'
    before = s.to_dict()
    with pytest.raises(ValueError): update(s, src, disposition='processed', bounded_stop=False, limitations=())
    assert s.to_dict() == before


@pytest.mark.parametrize('attack', ['id', 'ref', 'generation', 'objective', 'unselect', 'immutable'])
def test_invalid_update_is_atomic(attack):
    s, src = setup()
    key, generation, expected = src.id, s.generation, None
    changes = {'disposition': 'processed'}
    if attack == 'id': key = 'ds_' + 'f' * 64
    if attack == 'ref': expected = 'obs-other'
    if attack == 'generation': generation = 'stale'
    if attack == 'objective':
        assert s.objective is not None
        s.objective.id = 'foreign'
    if attack == 'unselect': changes = {'selected': False}
    if attack == 'immutable': changes = {'locator': 'another-source'}
    before = s.to_dict()
    with pytest.raises(ValueError):
        s.update_discovery_source(key, generation=generation, retained_ref=expected, **changes)
    assert s.to_dict() == before
    assert not s.attempts and not s.selected_sources and not s.evidence_sources


def test_late_source_invalidates_review_and_historical_completion_remains():
    from src.workflow.goals import RequestedGoal
    s = state()
    goal = RequestedGoal('xss')
    assert s.objective is not None
    s.objective.requested_goals = [goal]
    for phase in ('recon', 'enumeration', 'input_analysis'):
        record_completed_phase(s, phase, objective_id='objective', target_origin='http://target.test',
                               artifact_ref=f'artifacts/{phase}.md', no_inputs_discovered=phase == 'input_analysis')
    s.mark_goal_no_candidate(goal.id, artifact_ref='artifacts/input_analysis.md', review_binding='old')
    src = source()
    s.admit_discovery(src)
    assert goal.status == 'pending' and goal.review_binding is None
    update(s, src, selected=True)
    assert 'input_analysis' in s.completed_phases()
    assert s.input_inventory_review_error() == f'selected source {src.id} remains pending'
    prompt = render_workflow(s)
    assert 'sources=1' in prompt and 'unresolved=1' in prompt


def test_duplicate_content_fresh_refs_reason_changes_and_finite_progress():
    s, src = setup()
    tracker = WholeTargetStallTracker()
    for disposition, result in [('pending', 'structured_progress'), ('processed', 'structured_progress'),
                                ('processed', 'no_progress'), ('pending', 'no_progress')]:
        update(s, src, disposition=disposition, stop_reason='bounded outcome')
        assert tracker.record_iteration(new_facts=s.progress_facts(), activity_fingerprints=[]) == result
    before = s.progress_facts()
    for index in range(20):
        fresh = replace(src, locator=f'obs-random-{index}', retained_hash=f'{index:064x}', id='')
        s.admit_discovery(fresh)
        update(s, fresh, stop_reason=f'Rewording {index}', selected=True)
        assert s.progress_facts() == before
        assert tracker.record_iteration(new_facts=s.progress_facts(), activity_fingerprints=[]) == 'no_progress'
    assert tracker.consecutive_no_progress == 22


def test_frontier_paging_restore_stale_cursor_and_read_only():
    from src.workflow.state import WorkflowState
    s, src = setup()
    for index in range(12): s.admit_discovery(replace(src, locator=f'obs-{index}', id=''))
    before = s.to_dict()
    first = discovery_page(s, {'view': 'sources', 'limit': 3})
    assert first['returned'] == 3 and not first['complete']
    assert s.to_dict() == before
    cursor = first['next_discovery_cursor']
    restored = WorkflowState.from_dict(before)
    assert restored.to_dict() == before
    assert restored.discovery_sources[src.id].unresolved
    with pytest.raises(ValueError, match='cursor'):
        discovery_page(restored, {'view': 'sources', 'discovery_cursor': cursor})
    update(s, src, disposition='blocked', stop_reason='auth unavailable; no automatic context change')
    with pytest.raises(ValueError, match='cursor'):
        discovery_page(s, {'view': 'sources', 'discovery_cursor': cursor})
    assert not s.attempts and not s.attack_surface_inputs


def test_corrupt_selected_source_never_restores_as_completed_empty_inventory():
    from src.workflow.state import WorkflowState
    s = state()
    for phase in ('recon', 'enumeration', 'input_analysis'):
        record_completed_phase(s, phase, objective_id='objective', target_origin='http://target.test',
                               artifact_ref=f'artifacts/{phase}.md', no_inputs_discovered=phase == 'input_analysis')
    src = source(selected=True)
    s.admit_discovery(src)
    data = s.to_dict()
    data['discovery_sources'][0]['retained_hash'] = 'not-a-hash'
    restored = WorkflowState.from_dict(data)
    status, _, blockers = verdict(restored)
    assert status == 'blocked' and any('restore failed' in row for row in blockers)
    assert not restored.discovery_sources and restored.discovery_restore_invalid
    assert restored.input_inventory_review_error() == restored.source_completion_error()
    assert 'restore_invalid=True' in render_workflow(restored)
    saved_again = WorkflowState.from_dict(restored.to_dict())
    assert saved_again.discovery_restore_invalid and verdict(saved_again)[0] == 'blocked'
    generation = saved_again.generation
    saved_again.replace_from(restored)
    assert saved_again.discovery_restore_invalid and saved_again.generation != generation
    saved_again.clear()
    assert not saved_again.discovery_restore_invalid
