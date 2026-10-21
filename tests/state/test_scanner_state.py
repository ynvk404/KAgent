from __future__ import annotations

from dataclasses import replace
import hashlib
import json

import pytest

from src.tools.discovery.scanner_results import ParsedScan, encode, clean
from src.tools.execution.scanner_files import PrivateJob
from src.permission.runtime.execution import ExecutionBlocked
from src.workflow.discovery.scanner import ScannerJob, project_jobs
from src.workflow.state import WorkflowState, WorkflowObjective


def job(tmp_path, index=0, *, count=3):
    records = [{'id': 'sr_' + hashlib.sha256(str(i).encode()).hexdigest()[:24],
                'url': 'http://127.0.0.1:43210/path' + str(i), 'status': 200} for i in range(count)]
    data = b''.join(encode(row) + b'\n' for row in records)
    job_id = 'scan_' + f'{index:032x}'
    private = PrivateJob(tmp_path, ('.kagent', 'scanners', 'session', job_id))
    private.write('normalized.jsonl', data)
    private.write('manifest.json', b'{}')
    relative = str(private.path.relative_to(tmp_path))
    private.close(remove=False)
    return ScannerJob(job_id, 'a' * 64, 'http://127.0.0.1:43210', 'objective', 'ffuf',
        {'status': 'completed', 'exit_code': 0, 'duration_ms': 10, 'reason': 'process_exit'},
        {'status': 'valid', 'partial': False, 'coverage_complete': None},
        {'unique_records': count, 'returned_records': min(10, count), 'rejected_records': 0},
        {'manifest': relative + '/manifest.json', 'normalized': relative + '/normalized.jsonl',
         'dataset_sha256': hashlib.sha256(data).hexdigest(), 'result_refs': [], 'retrieval': 'unavailable'},
        hashlib.sha256(b'{}').hexdigest(), {'id': 'fixture', 'sha256': 'b' * 64}, '',
        [row['id'] for row in records[:10]])


def state():
    return WorkflowState(objective=WorkflowObjective('objective', 'whole_target', 'http://127.0.0.1:43210'))


def test_bounded_jobs_projection_and_selected_records_are_not_evicted(tmp_path):
    workflow = state()
    assert workflow.objective is not None
    for index in range(32):
        row = job(tmp_path, index)
        row.triage(tmp_path, row.sample_ids[:1], 'selected', 'Needs selected context')
        assert workflow.add_scanner_job(row)
    assert len(workflow.scanner_jobs) == 32
    assert not workflow.add_scanner_job(job(tmp_path, 32))
    projected = project_jobs(workflow.scanner_jobs, workflow.objective.target_origin, 'objective')
    assert len(projected) <= 4096 and len(json.loads(projected)) <= 5
    assert all(row['unresolved_selected'] == 1 for row in json.loads(projected))
    assert len(workflow.to_dict()['scanner_jobs']) == 32


def test_triage_validates_dataset_ids_and_requires_reason_without_fake_analysis(tmp_path):
    row = job(tmp_path, count=130)
    row.triage(tmp_path, row.sample_ids[:1], 'selected', 'Selected context gap')
    with pytest.raises(ValueError):
        row.triage(tmp_path, ['sr_' + '0' * 24], 'handled', 'Cannot fabricate record membership')
    with pytest.raises(ValueError):
        row.triage(tmp_path, row.sample_ids[:1], 'analyzed', 'Wrong contract')
    with pytest.raises(ValueError):
        row.triage(tmp_path, [], 'handled', 'Cannot bulk claim analysis', remaining=True)
    with pytest.raises(ValueError):
        row.triage(tmp_path, [], 'deferred', '', remaining=True)
    row.triage(tmp_path, [], 'deferred', 'Remaining paths do not address the current gap', remaining=True)
    assert row.unresolved_selected == 1 and row.projection()['untriaged'] == 0
    row.triage(tmp_path, row.sample_ids[:1], 'handled', 'Context recorded separately')
    assert row.unresolved_selected == 0


def test_state_hydration_interrupts_running_jobs_and_drops_authority_fields(tmp_path):
    workflow = state()
    row = job(tmp_path)
    row.execution.update(status='running', receipt='MUST_NOT_RESTORE', pid=123, epoch='MUST_NOT_RESTORE')
    workflow.add_scanner_job(row)
    restored = WorkflowState.from_dict(workflow.to_dict())
    history = next(iter(restored.scanner_jobs.values()))
    assert history.execution['status'] == 'interrupted'
    assert history.parse['coverage_complete'] is False
    assert 'MUST_NOT_RESTORE' not in json.dumps(history.to_dict())
    assert not WorkflowState.from_dict({}).scanner_jobs
    workflow.clear()
    assert not workflow.scanner_jobs


def test_semantic_progress_ignores_random_ids_order_empty_and_failed_retries(tmp_path):
    workflow = state()
    assert workflow.objective is not None
    row = job(tmp_path)
    workflow.add_scanner_job(row)
    first = workflow.progress_facts()
    workflow.add_scanner_job(replace(row, job_id='scan_' + '1' * 32))
    assert workflow.progress_facts() == first
    empty = job(tmp_path, 2, count=0)
    empty.execution['status'] = 'failed'
    workflow.add_scanner_job(empty)
    assert workflow.progress_facts() == first
    row.triage(tmp_path, row.sample_ids[:1], 'selected', 'Context gap')
    assert workflow.progress_facts() != first
    status, _, blockers = workflow.whole_target_status(target_origin=workflow.objective.target_origin,
        available_phases=frozenset(), validator_classes=frozenset(), coverage_sync_available=True)
    assert status == 'blocked' and any('scanner observations unresolved' in value for value in blockers)


@pytest.mark.parametrize('attack', ['dataset', 'manifest', 'symlink'])
def test_artifact_integrity_and_no_follow(tmp_path, attack):
    row = job(tmp_path)
    target = tmp_path / row.artifacts['manifest' if attack == 'manifest' else 'normalized']
    if attack == 'symlink':
        original = target.with_suffix('.original')
        target.rename(original)
        target.symlink_to(original)
    else:
        target.write_text('tamper')
    with pytest.raises((ValueError, OSError)):
        row.dataset(tmp_path)


def test_private_scratch_never_adopts_or_removes_foreign_job(tmp_path):
    row = job(tmp_path)
    path = tmp_path / row.artifacts['normalized']
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        PrivateJob(tmp_path, ('.kagent', 'scanners', 'session', row.job_id))
    assert path.read_bytes() == before


def test_parser_record_byte_limit_dedupe_and_secret_controls(monkeypatch):
    monkeypatch.setattr('src.tools.discovery.scanner_results.MAX_DATASET', 200)
    result = ParsedScan()
    for i in range(100):
        result.add({'url': 'http://127.0.0.1/' + 'a' * 64, 'status': 200}, i)
    assert len(result.dataset()) <= 200 and result.dataset_truncated and result.validity == 'partial'
    assert clean('\x1b[31mAuthorization: Bearer ' + 'A' * 50 + '\x1b[0m') != 'Authorization: Bearer ' + 'A' * 50
    assert 'secret-canary' not in clean('path/secret-canary', secrets=('secret-canary',))


def test_private_ancestor_permission_mutation_is_detected_before_output_use(tmp_path):
    private = PrivateJob(tmp_path, ('.kagent', 'tmp', 'scanners', 'owned-job'))
    private.write('scan.xml', b'')
    try:
        (tmp_path / '.kagent').chmod(0o777)
        with pytest.raises(ExecutionBlocked):
            private.validate()
    finally:
        (tmp_path / '.kagent').chmod(0o700)
        private.close(remove=True)
