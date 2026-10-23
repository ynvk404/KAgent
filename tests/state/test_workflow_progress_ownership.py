from src.agent.agent import WholeTargetStallTracker
from src.workflow.state import WorkflowObjective, WorkflowState


def test_twenty_reason_variants_and_repeated_status_are_not_progress():
    state = WorkflowState(objective=WorkflowObjective('scope', 'whole_target', 'https://fixture.test'))
    tracker = WholeTargetStallTracker()
    assert state.objective is not None
    tracker.set_scope(state.generation, state.objective.id)
    results = []
    for index in range(20):
        before = state.progress_facts()
        state.record_phase_coverage('recon', 'service_discovery', 'observed',
            objective_id='scope', target_origin='https://fixture.test', reason=f'Wording {index}')
        results.append(tracker.record_iteration(new_facts=state.progress_facts() - before, activity_fingerprints=[]))
    assert results == ['structured_progress'] + ['no_progress'] * 19
    assert tracker.consecutive_no_progress == 19
    before = state.progress_facts()
    state.record_phase_coverage('recon', 'service_discovery', 'performed',
        objective_id='scope', target_origin='https://fixture.test')
    assert tracker.record_iteration(new_facts=state.progress_facts() - before, activity_fingerprints=[]) == 'structured_progress'


def test_novelty_ledger_saturation_cannot_recredit_forgotten_facts():
    tracker = WholeTargetStallTracker()
    tracker.MAX_NOVELTY_FACTS = 4
    assert tracker.record_iteration(new_facts=frozenset(map(str, range(20))), activity_fingerprints=[]) == 'structured_progress'
    assert len(tracker.seen_facts) == 4
    assert tracker.record_iteration(new_facts=frozenset({'novel after cap'}), activity_fingerprints=[]) == 'no_progress'
    assert tracker.record_iteration(new_facts=frozenset({'0'}), activity_fingerprints=[]) == 'no_progress'


def test_coverage_source_ledger_is_bounded_preserved_by_prose_and_restored():
    state = WorkflowState(objective=WorkflowObjective('scope', 'whole_target', 'https://fixture.test'))
    for index in range(150):
        state.record_phase_coverage('recon', 'reachability', 'performed',
            objective_id='scope', target_origin='https://fixture.test', source_fingerprint=f'{index:064x}')
    row = state.phase_coverage_record('recon', 'reachability')
    assert row is not None and len(row.source_fingerprints) == 128
    facts = state.progress_facts()
    state.record_phase_coverage('recon', 'reachability', 'performed',
        objective_id='scope', target_origin='https://fixture.test', reason='new explanation')
    assert state.progress_facts() == facts
    assert WorkflowState.from_dict(state.to_dict()).progress_facts() == facts
