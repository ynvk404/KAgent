"""Retired scanner metadata survives sessions without execution or workflow credit."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from src.agent.system_prompt import render_workflow
from src.tools.workflow.workflow_tool import WorkflowTool
from src.permission.permission import AlwaysAllow
from src.tools.common.outcome import ToolOutput
from src.workflow.state import WorkflowState, WorkflowObjective


def legacy_snapshot():
    state = WorkflowState(objective=WorkflowObjective('objective', 'whole_target', 'http://fixture.test'))
    snapshot = state.to_dict()
    snapshot['scanner_jobs'] = [{'job_id': 'scan_' + 'a' * 32, 'scanner': 'ffuf',
        'objective_id': 'objective', 'target_origin': 'http://fixture.test',
        'execution': {'status': 'running'}, 'artifacts': {'normalized': '/must/not/open'},
        'dispositions': {'sr_' + 'b' * 24: {'disposition': 'selected', 'reason': 'old work'}}}]
    snapshot['scanner_observations'] = {'c' * 64: 'd' * 64}
    return snapshot


def test_legacy_metadata_round_trip_never_reads_artifacts_or_creates_progress(monkeypatch):
    snapshot = legacy_snapshot()
    def forbidden(*args, **kwargs):
        raise AssertionError('retired artifacts must never be opened')
    monkeypatch.setattr(Path, 'open', forbidden)
    restored = WorkflowState.from_dict(deepcopy(snapshot))
    for _ in range(2):
        saved = json.loads(json.dumps(restored.to_dict()))
        assert saved['scanner_jobs'] == snapshot['scanner_jobs']
        assert saved['scanner_observations'] == snapshot['scanner_observations']
        restored = WorkflowState.from_dict(saved)
    empty = WorkflowState(objective=deepcopy(restored.objective))
    assert restored.progress_facts() == empty.progress_facts()
    assert not restored.attack_surface_inputs and not restored.candidates and not restored.phase_completions
    assert 'scan_' not in render_workflow(restored)
    assert not hasattr(restored, 'add_scanner_job')


async def test_retired_actions_are_not_advertised_or_accepted(tmp_path):
    tool = WorkflowTool(WorkflowState(), evidence_root=tmp_path)
    schema = tool.schema()
    assert 'triage_scanner_results' not in schema['properties']['action']['enum']
    for key in ('scanner_offset', 'job_id', 'scanner_disposition', 'record_ids'):
        assert key not in schema['properties']
    result = await tool.run({'action': 'triage_scanner_results', 'job_id': 'scan_' + 'a' * 32}, None, AlwaysAllow())
    assert isinstance(result, ToolOutput)
    assert result.status == 'error' and result.error_kind == 'invalid_args'


def test_opaque_history_has_bounds_and_is_not_executed():
    snapshot = legacy_snapshot()
    snapshot['scanner_jobs'] *= 40
    state = WorkflowState.from_dict(snapshot)
    assert len(state.scanner_jobs) <= 32
    snapshot['scanner_jobs'] = [dict(snapshot['scanner_jobs'][0], extra='x' * (48 * 1024))]
    assert not WorkflowState.from_dict(snapshot).scanner_jobs
