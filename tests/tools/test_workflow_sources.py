import asyncio
import json
from pathlib import Path
from typing import cast

import pytest

from src.permission.permission import AlwaysAllow
from src.target.target import Target
from src.tools.workflow.workflow_tool import WorkflowTool
from tests.state.test_source_frontier import setup


async def call(tool, action, **args):
    return await tool.run({'action': action, **args}, None, AlwaysAllow())


async def test_source_frontier_api_exact_refs_and_zero_input():
    s, source = setup()
    tool = WorkflowTool(s, Target('http://target.test'))
    first = json.loads(await call(tool, 'list', view='sources'))
    assert first['sources'][0]['id'] == source.id and first['sources'][0]['unresolved']
    read = json.loads(await call(tool, 'get_source', discovery_source_id=source.id))
    assert read['discovery_source']['retained_hash'] == source.retained_hash
    before = s.to_dict()
    assert str(await call(tool, 'select_source', discovery_source_id=source.id, retained_ref='wrong')).startswith('error:')
    assert s.to_dict() == before
    closed = json.loads(await call(tool, 'set_source_disposition', discovery_source_id=source.id,
        source_disposition='processed', source_reason='Document inspected; zero input syntax'))
    assert not closed['unresolved'] and not s.attack_surface_inputs and not s.candidates


@pytest.mark.parametrize('length', [240, 241, 345])
async def test_source_reason_schema_runtime_length_and_atomic_rejection(length):
    from src.workflow.discovery.inventory import MAX_SOURCE_REASON_LENGTH
    s, source = setup()
    tool = WorkflowTool(s, Target('http://target.test'))
    assert tool.schema()['properties']['source_reason']['maxLength'] == MAX_SOURCE_REASON_LENGTH == 240
    before = s.to_dict()
    result = await call(tool, 'set_source_disposition', discovery_source_id=source.id,
        source_disposition='processed', source_reason='x' * length)
    if length == 240:
        assert json.loads(result)['discovery_source']['stop_reason'] == 'x' * length
    else:
        assert 'source_reason' in result and str(length) in result and '240' in result
        assert 'x' * length not in result and s.to_dict() == before


@pytest.mark.parametrize('reason', ['password=fixture-secret', 'line\nbreak', 'tab\tvalue', 'delete\x7f'])
async def test_source_reason_preserves_non_secret_exact_text_guard(reason):
    s, source = setup()
    before = s.to_dict()
    result = await call(WorkflowTool(s, Target('http://target.test')), 'set_source_disposition',
        discovery_source_id=source.id, source_disposition='processed', source_reason=reason)
    assert result.startswith('error:') and reason not in result
    assert s.to_dict() == before


async def test_source_update_queued_across_reset_never_guesses_replacement():
    s, source = setup()
    tool = WorkflowTool(s, Target('http://target.test'))
    await s.mutation_lock.acquire()
    task = asyncio.create_task(call(tool, 'select_source', discovery_source_id=source.id))
    await asyncio.sleep(0)
    s.clear()
    before = s.to_dict()
    s.mutation_lock.release()
    result = await task
    assert result.startswith('error:') and 'generation' in result
    assert s.to_dict() == before


async def test_cancel_queued_source_update_does_not_publish():
    s, source = setup()
    tool = WorkflowTool(s, Target('http://target.test'))
    await s.mutation_lock.acquire()
    task = asyncio.create_task(call(tool, 'set_source_disposition', discovery_source_id=source.id,
        source_disposition='processed', source_reason='zero inputs'))
    await asyncio.sleep(0)
    before = s.to_dict()
    task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    s.mutation_lock.release()
    assert s.to_dict() == before


@pytest.mark.parametrize('changes', [dict(source_limitations='bogus'), dict(source_bounds={'unknown': 3}),
                                    dict(acknowledge_bounded_stop=True), dict(source_disposition='invalid')])
async def test_invalid_disposition_arguments_are_atomic(changes):
    s, source = setup()
    tool = WorkflowTool(s, Target('http://target.test'))
    before = s.to_dict()
    result = await call(tool, 'set_source_disposition', **dict(
        {'discovery_source_id': source.id, 'source_disposition': 'partial', 'source_reason': 'bounds'}, **changes))
    assert result.startswith('error:')
    assert s.to_dict() == before


def test_late_source_blocks_current_readiness_without_rewriting_history(tmp_path):
    from src.skills.registry import Registry
    from src.skills.artifacts import completion_artifact_path
    from tests.state.test_discovery_inventory import state, source
    from tests.helpers.workflow import record_completed_phase
    from src.workflow.state import WorkflowPhase
    s = state()
    skills = Registry()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    tool = WorkflowTool(s, Target('http://target.test'), skills=skills, evidence_root=tmp_path)
    for phase, name in [('recon', 'recon'), ('enumeration', 'web-enumeration'), ('input_analysis', 'web-input-analysis')]:
        skill = skills.get(name)
        assert skill is not None and skill.completion_artifact is not None
        relative = completion_artifact_path(skill.completion_artifact, 'http://target.test')
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Bounded source review')
        record_completed_phase(s, cast(WorkflowPhase, phase), objective_id='objective', target_origin='http://target.test',
                               artifact_ref=relative, no_inputs_discovered=phase == 'input_analysis')
    before = tool.phase_completion_readiness('web-input-analysis')
    assert before['historically_completed'] and before['prerequisites_valid']
    markers = dict(s.phase_completions)
    src = source()
    s.admit_discovery(src)
    s.update_discovery_source(src.id, generation=s.generation, selected=True)
    after = tool.phase_completion_readiness('web-input-analysis')
    assert after['historically_completed'] and not after['prerequisites_valid']
    assert s.phase_completions == markers
    s.update_discovery_source(src.id, generation=s.generation, disposition='not_applicable',
                              stop_reason='Selected document has no request syntax relevant to this objective')
    assert tool.phase_completion_readiness('web-input-analysis')['prerequisites_valid']
