"""Missing scanner artifacts may retire selected work, never establish analysis."""
from copy import deepcopy
import json

import pytest

from src.permission.permission import AlwaysAllow
from src.permission.runtime.execution import ExecutionBlocked
from src.target.target import Target
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.scanner import ScannerJob
from tests.state.test_scanner_state import job, state


@pytest.mark.parametrize('missing', ['normalized', 'manifest'])
@pytest.mark.parametrize('disposition', ['deferred', 'dropped'])
async def test_missing_artifact_can_retire_selected_without_claiming_analysis(tmp_path, missing, disposition):
    workflow, row = state(), job(tmp_path)
    selected = row.sample_ids[:1]
    row.triage(tmp_path, selected, 'selected', 'Need request context')
    workflow.add_scanner_job(row)
    before = deepcopy((row.execution, row.parse, row.counts))
    (tmp_path / row.artifacts[missing]).unlink()
    tool = WorkflowTool(workflow, Target(row.target_origin), evidence_root=tmp_path)
    result = await tool.run({'action': 'triage_scanner_results', 'job_id': row.job_id,
        'record_ids': selected, 'scanner_disposition': disposition,
        'scanner_reason': 'Evidence unavailable; observation has not been analyzed'}, None, AlwaysAllow())
    response = json.loads(result)
    assert response['ok'] is True
    projection = response['scanner_job']
    assert projection['unresolved_selected'] == 0
    assert projection['retrieval'] == 'unavailable'
    assert projection['retrieval_error'] == 'missing_artifact'
    assert row.dispositions[selected[0]]['disposition'] == disposition
    assert (row.execution, row.parse, row.counts) == before
    assert not workflow.candidates and not workflow.validation_results
    _, _, blockers = workflow.whole_target_status(target_origin=row.target_origin,
        available_phases=frozenset(), validator_classes=frozenset(), coverage_sync_available=True)
    assert not any('selected scanner observations unresolved' in value for value in blockers)
    restored = ScannerJob.from_dict(row.to_dict())
    assert restored is not None and restored.projection()['retrieval_error'] == 'missing_artifact'
    assert restored.dispositions == row.dispositions
    with pytest.raises(FileNotFoundError):
        row.dataset(tmp_path)


@pytest.mark.parametrize('disposition,which,remaining', [
    ('handled', 'selected', False), ('selected', 'selected', False),
    ('deferred', 'new', False), ('dropped', 'mixed', False), ('deferred', 'none', True),
])
def test_missing_artifact_cannot_mint_membership_or_handled_state(tmp_path, disposition, which, remaining):
    row = job(tmp_path)
    row.triage(tmp_path, row.sample_ids[:1], 'selected', 'Needs context')
    before = deepcopy(row.to_dict())
    (tmp_path / row.artifacts['normalized']).unlink()
    ids = {'selected': row.sample_ids[:1], 'new': row.sample_ids[1:2],
           'mixed': row.sample_ids[:2], 'none': []}[which]
    with pytest.raises(FileNotFoundError):
        row.triage(tmp_path, ids, disposition, 'Unavailable evidence', remaining=remaining)
    assert row.to_dict() == before


@pytest.mark.parametrize('damage', ['normalized', 'manifest', 'symlink', 'permissions',
    'normalized_missing_manifest_corrupt', 'manifest_missing_normalized_corrupt'])
def test_integrity_failures_remain_errors_and_do_not_retire_selected(tmp_path, damage):
    row = job(tmp_path)
    row.triage(tmp_path, row.sample_ids[:1], 'selected', 'Needs context')
    before = deepcopy(row.to_dict())
    path = tmp_path / row.artifacts['manifest' if damage == 'manifest' else 'normalized']
    if damage.endswith('_corrupt'):
        missing, corrupt = (('normalized', 'manifest') if damage.startswith('normalized_')
                            else ('manifest', 'normalized'))
        (tmp_path / row.artifacts[missing]).unlink()
        (tmp_path / row.artifacts[corrupt]).write_text('corrupt')
    elif damage == 'symlink':
        original = path.with_suffix('.original')
        path.rename(original)
        path.symlink_to(original)
    elif damage == 'permissions':
        path.chmod(0o644)
    else:
        path.write_text('corrupt')
    with pytest.raises((ValueError, OSError, ExecutionBlocked)):
        row.triage(tmp_path, row.sample_ids[:1], 'deferred', 'Evidence unavailable')
    assert row.to_dict() == before and row.unresolved_selected == 1
