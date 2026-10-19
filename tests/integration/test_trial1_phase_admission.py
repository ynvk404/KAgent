"""Whole-target prerequisites through real workflow actions, no lab/model calls."""
import json
from pathlib import Path

from src.skills.registry import Registry as Skills
from src.target.target import Target
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowObjective, WorkflowState, WorkflowMode
from src.permission.permission import AlwaysAllow
from tests.helpers.workflow import record_phase_coverage_for_test

ORIGIN = 'https://target.test'


def runtime(root, mode: WorkflowMode='whole_target'):
    skills = Skills()
    skills.load_dir('skills')
    state = WorkflowState(objective=WorkflowObjective('phase-admission', mode, ORIGIN))
    return WorkflowTool(state, Target(ORIGIN), skills=skills, evidence_root=root)


async def action(tool, action, **fields):
    return await tool.run({'action': action, **fields}, None, AlwaysAllow())


async def phases(tool):
    # Explicit bounded skip dispositions are valid production coverage, not performed claims.
    for phase, skill in [('recon', 'recon'), ('enumeration', 'web-enumeration')]:
        await record_phase_coverage_for_test(tool, phase)
        readiness = tool.phase_completion_readiness(skill)
        path = tool.evidence_root / readiness['artifact_ref']
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Bounded offline discovery fixture; coverage limitations explicitly recorded.')
        assert json.loads(await action(tool, 'complete_skill', skill_name=skill))['ok']


async def linked(tool, *, analyze=True, endpoint='/fixture'):
    item = json.loads(await action(tool, 'record_input', method='GET', endpoint=endpoint,
        parameter='q', location='query'))['input']
    candidate = json.loads(await action(tool, 'record_candidate', candidate_class='xss', input_id=item['id']))['candidate']
    if analyze:
        assert json.loads(await action(tool, 'set_input_disposition', input_id=item['id'], disposition='analyzed'))['ok']
    return item, candidate


async def test_production_prerequisites_are_reachable_without_finishing_all_inputs(tmp_path):
    tool = runtime(tmp_path)
    await phases(tool)
    item, candidate = await linked(tool)
    pending, _ = await linked(tool, analyze=False, endpoint='/later')
    assert tool.state.validate_input_candidate(item['id'], tool.state.candidates[candidate['id']]).disposition == 'analyzed'
    started = json.loads(await action(tool, 'start_validation', candidate_id=candidate['id']))
    assert started['ok'] and tool.state.attack_surface_inputs[pending['id']].disposition == 'pending'
    assert tool.state.completed_phases() == frozenset({'recon', 'enumeration'})


import pytest


@pytest.mark.parametrize('mode', ['whole_target', 'direct'])
async def test_early_candidate_is_retained_but_only_whole_target_new_attempt_is_gated(tmp_path, mode):
    tool = runtime(tmp_path, mode)
    candidate = json.loads(await action(tool, 'record_candidate', candidate_class='xss',
        method='GET', endpoint='/fixture', parameter='q', location='query',
        source_skill='web-input-analysis', current_phase='validation'))['candidate']
    before = tool.state.to_dict()
    response = await action(tool, 'start_validation', candidate_id=candidate['id'])
    if mode == 'direct':
        assert json.loads(response)['ok'] and not tool.state.completed_phases()
    else:
        assert 'WHOLE_TARGET_VALIDATION_PREREQUISITE' in response
        assert tool.state.to_dict() == before and candidate['id'] in tool.state.candidates
        assert not tool.state.attempts


@pytest.mark.parametrize('fault', ['no-link', 'pending', 'dropped', 'foreign-objective', 'foreign-target', 'mismatch'])
async def test_input_gate_uses_canonical_analyzed_linkage(tmp_path, fault):
    tool = runtime(tmp_path)
    await phases(tool)
    item, candidate = await linked(tool, analyze=fault != 'pending')
    record = tool.state.attack_surface_inputs[item['id']]
    if fault == 'no-link': record.candidate_ids.clear()
    if fault == 'dropped': record.disposition = 'dropped'
    if fault == 'foreign-objective': record.objective_id = 'other'
    if fault == 'foreign-target': record.target_origin = 'https://other.test'
    if fault == 'mismatch': record.parameter = 'different'
    result = await action(tool, 'start_validation', candidate_id=candidate['id'])
    assert 'WHOLE_TARGET_VALIDATION_PREREQUISITE' in result and not tool.state.attempts


@pytest.mark.parametrize('name', ['recon', 'web-enumeration'])
async def test_missing_artifact_blocks_new_but_does_not_block_owned_active_recovery(tmp_path, name):
    tool = runtime(tmp_path)
    await phases(tool)
    _, candidate = await linked(tool)
    relative = tool.phase_completion_readiness(name)['artifact_ref']
    path = tmp_path / relative
    original = path.read_text()
    path.unlink()
    assert 'WHOLE_TARGET_VALIDATION_PREREQUISITE' in await action(tool, 'start_validation', candidate_id=candidate['id'])
    path.write_text(original)
    first = json.loads(await action(tool, 'start_validation', candidate_id=candidate['id']))
    path.unlink()
    second = json.loads(await action(tool, 'start_validation', candidate_id=candidate['id']))
    assert second['validation_context']['attempt_id'] == first['validation_context']['attempt_id']
    assert len(tool.state.attempts) == 1
    # A forged validating status alone cannot resume an attempt under a new session.
    tool.session_id = 'different-session'
    assert 'WHOLE_TARGET_VALIDATION_PREREQUISITE' in await action(tool, 'start_validation', candidate_id=candidate['id'])


async def test_selected_late_source_does_not_force_exhaustive_discovery_before_validation(tmp_path):
    from tests.state.test_discovery_inventory import source
    tool = runtime(tmp_path)
    await phases(tool)
    _, candidate = await linked(tool)
    assert tool.state.objective is not None
    src = source(objective_id=tool.state.objective.id, target_origin=ORIGIN,
        document_url=ORIGIN + '/late', selected=True)
    tool.state.admit_discovery(src)
    assert tool.state.source_completion_error()
    assert json.loads(await action(tool, 'start_validation', candidate_id=candidate['id']))['ok']
    assert tool.state.discovery_sources[src.id].unresolved


async def test_exact_english_review_prompt_uses_unchanged_stage3_parser():
    from src.workflow.goals import extract_requested_classes
    prompt = ('Perform a whole-target assessment of the authorized target. '
              'Discover endpoints and inputs, analyze them, then validate SQL Injection and XSS. '
              'Stay within the declared origin and existing permissions and budgets. '
              'Use minimal non-sensitive proof; do not extract credentials or bulk data.')
    assert extract_requested_classes(prompt) == ['sql-injection', 'cross-site-scripting']
