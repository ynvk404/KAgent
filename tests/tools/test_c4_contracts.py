import json

import pytest

from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry, Skill
from src.tools.common.outcome import ToolOutput
from src.tools.skills.paths import MAX_BYTES, MAX_PREVIEW_BYTES
from src.tools.skills.payloads import ReadPayloadsTool
from src.tools.skills.skill_file import ReadSkillFileTool
from src.tools.workflow.workflow_tool import WorkflowTool, ACTION_REQUIRED
from src.tools.workflow.coverage import CoverageTool
from src.coverage.store import CoverageStore
from src.workflow.state import WorkflowState


@pytest.mark.parametrize('factory,key', [(ReadSkillFileTool, 'path'), (ReadPayloadsTool, 'file')])
async def test_auxiliary_pages_are_byte_bounded_and_source_bound(tmp_path, factory, key):
    registry = Registry()
    registry.add(Skill('demo', 'fixture', [], False, str(tmp_path / 'SKILL.md'), ''))
    source = tmp_path / 'payloads.txt'
    text = ('雨🙂đ' * 9000) + '\nTAIL-CANARY\n'
    source.write_text(text, encoding='utf-8')
    tool = factory(registry)
    args = {'skill': 'demo', key: 'payloads.txt', 'limit': 5000}
    offset, ref, contents = 0, None, []
    while True:
        output = await tool.run({**args, 'start_char': offset, **({'source_ref': ref} if ref else {})}, None, AlwaysAllow())
        rendered, metadata = output.rsplit('\nContinuation: ', 1)
        page = json.loads(metadata)
        end = page['end_char']
        body = rendered.split('\n', 1)[1].split('\n...<truncated', 1)[0]
        assert body == text[offset:end]
        assert len(body.encode('utf-8')) <= MAX_PREVIEW_BYTES
        assert page['offset_unit'] == 'unicode_characters' and end > offset
        contents.append(body)
        ref = page['source_ref']
        if page['next_start_char'] is None:
            assert not output.truncated
            break
        assert output.truncated
        offset = end
    assert ''.join(contents) == text
    cross_reader = await factory(registry).run({**args, 'source_ref': ref, 'start_char': 1}, None, AlwaysAllow())
    assert cross_reader.error_kind == 'reference_unavailable'
    source.write_text('changed fixture', encoding='utf-8')
    changed = await tool.run({**args, 'source_ref': ref, 'start_char': 1}, None, AlwaysAllow())
    assert changed.error_kind == 'reference_unavailable' and 'source changed' in changed
    guessed = await tool.run({**args, 'start_char': 1}, None, AlwaysAllow())
    assert guessed.error_kind == 'invalid_args'
    source.write_bytes(b'x' * (MAX_BYTES + 1))
    oversized = await tool.run(args, None, AlwaysAllow())
    assert oversized.status == 'error' and 'source limit' in oversized


@pytest.mark.parametrize('action,required', list(ACTION_REQUIRED.items()))
async def test_action_only_calls_explain_missing_fields_without_state_mutation(action, required):
    state = WorkflowState()
    tool = WorkflowTool(state)
    before = state.to_dict()
    output = await tool.run({'action': action}, None, AlwaysAllow())
    assert isinstance(output, ToolOutput) and output.error_kind == 'invalid_args'
    assert all(field in output for field in required) and state.to_dict() == before
    assert all(field in tool.schema()['properties']['action']['description'] for field in required)


async def test_coverage_errors_carry_metadata_and_remain_json_strings(tmp_path):
    tool = CoverageTool(CoverageStore(str(tmp_path / 'coverage.json')))
    output = await tool.run({'action': 'mark'}, None, AlwaysAllow())
    assert isinstance(output, str) and isinstance(output, ToolOutput)
    assert output.status == 'error' and output.error_kind == 'invalid_args'
    assert json.loads(output)['ok'] is False


async def test_payload_directory_symlink_cannot_read_outside_skill(tmp_path):
    skill = tmp_path / 'skill'
    outside = tmp_path / 'outside'
    skill.mkdir()
    outside.mkdir()
    (outside / 'secret.txt').write_text('OUTSIDE-CANARY')
    (skill / 'payloads').symlink_to(outside, target_is_directory=True)
    registry = Registry()
    registry.add(Skill('demo', 'fixture', [], False, str(skill / 'SKILL.md'), ''))
    output = await ReadPayloadsTool(registry).run({'skill': 'demo', 'file': 'secret.txt'}, None, AlwaysAllow())
    assert output.startswith('error:') and 'OUTSIDE-CANARY' not in output


@pytest.mark.parametrize('factory,key', [(ReadSkillFileTool, 'path'), (ReadPayloadsTool, 'file')])
async def test_auxiliary_paging_publishes_executable_next_call_and_recovery(tmp_path, factory, key):
    registry = Registry()
    registry.add(Skill('demo', 'fixture', [], False, str(tmp_path / 'SKILL.md'), ''))
    source = tmp_path / 'payloads.txt'
    source.write_text('first\nsecond\nthird\n', encoding='utf-8')
    tool = factory(registry)
    args = {'skill': 'demo', key: 'payloads.txt', 'limit': 1}
    first = await tool.run(args, None, AlwaysAllow())
    page = json.loads(first.rsplit('\nContinuation: ', 1)[1])
    from src.agent.agent import safe_tool_text
    from src.agent.output_bounds import bound_distributed_content

    visible = safe_tool_text(first, 'unavailable')
    next_call = json.loads(visible.split('Next page: ', 1)[1].split('\n', 1)[0])
    assert next_call['tool'] == tool.name()
    # A large body must not bury the actionable instruction in its footer.
    source.write_text('first\n' + 'x' * 20000, encoding='utf-8')
    large = await tool.run({**args, 'limit': 5000}, None, AlwaysAllow())
    bounded = bound_distributed_content(safe_tool_text(large, 'unavailable'), 2000,
                                       minimum_retained_length=2000, elision_prefix='[omitted')
    bounded_call = json.loads(bounded.split('Next page: ', 1)[1].split('\n', 1)[0])
    resumed = await tool.run(bounded_call['arguments'], None, AlwaysAllow())
    assert resumed.status == 'success' and not resumed.truncated
    source.write_text('first\nsecond\nthird\n', encoding='utf-8')
    assert next_call['arguments'] == {**args, 'source_ref': page['source_ref'],
                                     'start_char': page['next_start_char']}
    second = await tool.run(next_call['arguments'], None, AlwaysAllow())
    assert 'second\n' in second and second.status == 'success'
    repeated = await tool.run(args, None, AlwaysAllow())
    assert json.loads(repeated.rsplit('\nContinuation: ', 1)[1])['source_ref'] == page['source_ref']
    for bad in ({'start_char': 6}, {'start_char': 6, 'source_ref': 'demo:payloads.txt'}):
        error = await tool.run({**args, **bad}, None, AlwaysAllow())
        assert error.status == 'error'
        recovery = json.loads(error.split('Recovery: ', 1)[1].split('\n', 1)[0])
        assert recovery == {'tool': tool.name(), 'arguments': {**args, 'start_char': 0}}
        recovered = await tool.run(recovery['arguments'], None, AlwaysAllow())
        assert recovered.status == 'success' and 'first\n' in recovered
    source.write_text('changed\ncontent\n', encoding='utf-8')
    stale = await tool.run(next_call['arguments'], None, AlwaysAllow())
    assert stale.error_kind == 'reference_unavailable'
    fresh = await tool.run(args, None, AlwaysAllow())
    assert json.loads(fresh.rsplit('\nContinuation: ', 1)[1])['source_ref'] != page['source_ref']
