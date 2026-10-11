import json

from src.agent.agent import ParsedToolCall
from src.llm.core.types import ToolCall, FunctionCall
from src.tools.execution.file import READ_BYTE_CAP
from tests.agent.test_tool_result_offloading import make, reference
from tests.helpers.agent_fakes import FakeSignal


async def test_real_file_clipping_is_truthful_through_event_retention_and_reread(make, tmp_path):
    agent = make(threshold=3000)
    path = tmp_path / 'large-source.txt'
    path.write_text('x' * (READ_BYTE_CAP + 1000), encoding='utf-8')
    args = {'path': str(path)}
    call = ToolCall('clipped', FunctionCall('file_read', json.dumps(args)))
    parsed = ParsedToolCall(args, json.dumps(args))
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    assert result.truncated and len(result.result) < path.stat().st_size
    events, working = [], []
    agent.record_tool_result(call, parsed, result, events.append, working)
    assert events[0]['truncated'] is True
    ref = reference(agent)
    assert ref.truncated is True
    reread = await agent.tools.execute('read_tool_result', {
        'result_ref': ref.result_ref, 'start_char': 0, 'max_chars': 50}, FakeSignal(), agent.prompter)
    assert json.loads(reread)['adapter_truncated'] is True
