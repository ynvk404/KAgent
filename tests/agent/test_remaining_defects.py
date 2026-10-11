"""Offline reproductions for the final bounded defect audit."""
from src.agent.agent import MaxStepsError
from src.llm.core.types import ChatResponse, Message
from src.permission.permission import AlwaysAllow
from tests.agent.test_agent import PermissionTool, refusal_agent, tool_batch, tool_call
from tests.helpers.agent_fakes import FakeSignal, collect


async def test_budget_synthesis_does_not_report_successful_completion():
    agent, client = refusal_agent([
        tool_batch(tool_call('last', 'fixture', {})),
        ChatResponse(Message(role='assistant', content='Evidence collected; work remains.'), 'stop'),
    ], [PermissionTool('fixture')], AlwaysAllow(), max_steps=1)
    events = collect()
    await agent.run('go', FakeSignal(), events['sink'])
    assert len(client.requests) == 2 and client.requests[-1].tools is None
    assert events['events'][-1].stop_reason == 'max_steps'
    assert any(isinstance(e.err, MaxStepsError) for e in events['events'] if e.type == 'error')
    assert agent.history[-1].content == 'Evidence collected; work remains.'


async def test_natural_final_response_at_budget_boundary_remains_final_response():
    agent, _ = refusal_agent([
        ChatResponse(Message(role='assistant', content='Answered.'), 'stop'),
    ], [], AlwaysAllow(), max_steps=1)
    events = collect()
    await agent.run('go', FakeSignal(), events['sink'])
    assert events['events'][-1].stop_reason == 'final_response'
