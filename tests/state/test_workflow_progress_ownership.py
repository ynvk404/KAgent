from src.workflow.state import WorkflowObjective, WorkflowState


def test_reworded_coverage_keeps_status_and_can_be_retried():
    state = WorkflowState(objective=WorkflowObjective('scope', 'whole_target', 'https://fixture.test'))
    assert state.objective is not None
    for index in range(20):
        state.record_phase_coverage('recon', 'service_discovery', 'observed',
            objective_id='scope', target_origin='https://fixture.test', reason=f'Wording {index}')
        row = state.phase_coverage_record('recon', 'service_discovery')
        assert row is not None and row.status == 'observed' and not row.source_fingerprints
        assert not state.needs_phase_coverage('recon', 'service_discovery')
    state.record_phase_coverage('recon', 'service_discovery', 'performed',
        objective_id='scope', target_origin='https://fixture.test')
    row = state.phase_coverage_record('recon', 'service_discovery')
    assert row is not None and row.status == 'performed'
    assert not state.needs_phase_coverage('recon', 'service_discovery')




def test_coverage_source_ledger_is_bounded_preserved_by_prose_and_restored():
    state = WorkflowState(objective=WorkflowObjective('scope', 'whole_target', 'https://fixture.test'))
    for index in range(150):
        state.record_phase_coverage('recon', 'reachability', 'performed',
            objective_id='scope', target_origin='https://fixture.test', source_fingerprint=f'{index:064x}')
    row = state.phase_coverage_record('recon', 'reachability')
    assert row is not None and len(row.source_fingerprints) == 128
    sources = row.source_fingerprints
    state.record_phase_coverage('recon', 'reachability', 'performed',
        objective_id='scope', target_origin='https://fixture.test', reason='new explanation')
    assert row.source_fingerprints == sources
    restored = WorkflowState.from_dict(state.to_dict()).phase_coverage_record('recon', 'reachability')
    assert restored is not None and restored.source_fingerprints == sources
