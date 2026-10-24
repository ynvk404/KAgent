"""Exercise existing reference namespaces and rejection/repair without external I/O."""
import json

import pytest

from src.tools.workflow.action_view import ActionView
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowObjective, WorkflowState
from tests.helpers.burp_selection import make_runtime
from tests.helpers.discovery_calls import execute
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime  # noqa: F401


def test_projected_workflow_schema_explains_source_and_replay_namespaces():
    spec = {'type': 'function', 'function': {'name': 'workflow', 'parameters': WorkflowTool(WorkflowState()).schema()}}
    projected = ActionView.for_objective('whole_target').project_tools([spec])
    assert projected is not None
    fields = projected[0]['function']['parameters']['properties']
    baseline = fields['baseline_request_ref']['description']
    source = fields['source_ref']['description']
    assert 'capture-store' in baseline and 'obs_' in baseline and 'not' in baseline
    assert 'method' in source and 'origin' in source and 'path' in source


async def test_invented_discovery_id_rejected_with_actual_recovery_path(tmp_path):
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('discovery', 'whole_target', rt.target.base_url())
    reader = rt.agent.tools.get('read_discovery_source')
    assert reader is not None
    assert 'list' in reader.description() and 'sources' in reader.description()
    before = rt.workflow.to_dict()
    rejected = await execute(rt, 'read_discovery_source', {
        'discovery_source_id': 'ds_' + '1' * 32, 'start_char': 0, 'max_chars': 2000}, success=False)
    assert rejected.status == 'error' and rejected.error_kind == 'invalid_args'
    assert 'list' in rejected.result and 'sources' in rejected.result and 'obs_' in rejected.result
    assert rt.workflow.to_dict() == before and not rt.policy.observations._items


async def test_wrong_evidence_ids_repair_preserves_ownership_and_immutable_snapshots(runtime, tmp_path):
    state, candidate, _, args, oid = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, prompter, policy, _, sent, *_ = runtime
    bad_id = 'obs_' + 'f' * 32
    assert bad_id not in policy.observations._items
    path = tmp_path / 'candidate-proof.md'
    bad_content = f'# Candidate\n\n- candidate_id: {candidate.id}\n\n| observation_id |\n|---|\n| {bad_id} |\n'
    path.write_text(bad_content)
    parents_before = dict(state.evidence_sources)
    register = {'action': 'record_evidence', 'candidate_id': candidate.id,
                'evidence_path': path.name, 'observation_ids': [bad_id]}
    rejected = await registry.execute('workflow', register, None, prompter)
    assert json.loads(rejected.split('\n', 1)[1])['error']['code'] == 'PRIMARY_REFERENCE_UNAVAILABLE'
    assert state.evidence_sources == parents_before and not state.validation_results
    snapshots = {p: p.read_bytes() for p in (tmp_path / '.kagent/evidence').rglob('*.proof')}
    # Repair the local source and its parents, using the real owned ledger.
    path.write_text(bad_content.replace(bad_id, oid))
    accepted = json.loads(await registry.execute('workflow', {**register, 'observation_ids': [oid]}, None, prompter))
    assert accepted['ok'] and accepted['primary_parents'] == [oid]
    evidence = accepted['evidence']
    assert bad_id not in (tmp_path / evidence['path']).read_text()
    assert state.evidence_sources[evidence['id']] == [oid]
    assert all(p.read_bytes() == content for p, content in snapshots.items())
    assert policy.observations._items[oid].attempt_id == args['attempt_id']
    assert len(sent) == 1 and not state.eligible_for_finding(candidate.id)
