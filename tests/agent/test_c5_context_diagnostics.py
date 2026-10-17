import json
import pytest

from src.agent.agent import ParsedToolCall
from src.agent.context_estimate import estimate_request
from src.llm.core.types import ChatRequest, Message, ToolCall, FunctionCall
from src.llm.runtime.context_budget import ContextCapacityError
from tests.agent.test_token_accounting_independent_verify import make_agent
from tests.agent.test_tool_result_offloading import make
from tests.helpers.agent_fakes import FakeSignal


async def test_soft_pressure_reports_estimates_once_but_every_request_is_admitted():
    agent = make_agent()
    agent.set_auto_compact_threshold(100)
    setattr(agent.client, 'input_token_limit', 1000)
    request = ChatRequest(model=agent.client.model(), messages=[Message('system', 's' * 800)])
    events = []
    for _ in range(3):
        await agent._admit_request(request, events.append)
    assert len(events) == 1
    diagnostic = events[0]['context_diagnostics']
    assert diagnostic['estimated_total'] == estimate_request(request, agent.client.name()).estimated_total
    assert diagnostic['hard_input_limit'] == 1000 and diagnostic['soft_threshold'] == 100
    assert diagnostic['fixed_floor'] == diagnostic['estimated_total']
    assert diagnostic['reducible_tokens'] == diagnostic['reduction_achieved'] == 0
    assert diagnostic['reason'] == 'below_hard_input_limit'
    assert diagnostic['estimate_only'] and diagnostic['provider_usage'] is None
    assert 'fits the hard input budget' in events[0]['summary']
    setattr(agent.client, 'input_token_limit', 150)
    with pytest.raises(ContextCapacityError):
        await agent._admit_request(request, events.append)
    assert len(events) == 2 and events[-1]['context_diagnostics']['reason'] == 'hard_input_limit_exceeded'


async def test_reduction_amount_is_measured_and_provider_unknown_is_explicit():
    agent = make_agent()
    agent.set_auto_compact_threshold(1000)
    request = ChatRequest(model=agent.client.model(), messages=[
        Message('system', 'fixed'), Message('tool', '雨' * 10000, name='auxiliary')])
    before = estimate_request(request, agent.client.name()).estimated_total
    events = []
    agent.guard_working_context(request.messages, events.append, request=request)
    diagnostic = events[-1]['context_diagnostics']
    after = estimate_request(request, agent.client.name()).estimated_total
    assert diagnostic['reduction_achieved'] == before - after and before > after
    assert diagnostic['hard_input_limit'] is None and diagnostic['provider_usage'] is None
    assert diagnostic['reason'] == 'hard_input_limit_unknown'


async def test_retention_reduction_reports_actual_characters_at_admission(make, tmp_path):
    agent = make(threshold=3000)
    path = tmp_path / 'source.txt'
    path.write_text('雨' * 20000, encoding='utf-8')
    args = {'path': str(path)}
    call = ToolCall('read', FunctionCall('file_read', json.dumps(args)))
    parsed = ParsedToolCall(args, json.dumps(args))
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    working = []
    agent.record_tool_result(call, parsed, result, lambda _: None, working, defer_admission=True)
    before_chars = sum(len(message.content) for message in working)
    events = []
    request = ChatRequest(model=agent.client.model(), messages=working)
    agent.guard_working_context(working, events.append, request=request)
    diagnostic_event = next(event for event in events if 'context_diagnostics' in event)
    after_chars = sum(len(message.content) for message in working)
    assert before_chars > after_chars and agent.result_retention.references
    assert f'reduced {before_chars - after_chars} characters' in diagnostic_event['summary']
    assert diagnostic_event['context_diagnostics']['reduction_achieved'] > 0
