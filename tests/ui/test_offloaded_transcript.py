"""Hidden presentation leaves selective retention and diagnostic events intact."""
import copy
import pytest
from textual import events

from src.agent.agent import _to_agent_event
from src.ui.core.state import reducer, AgentEventAction
from tests.agent.test_tool_result_offloading import make, record
from tests.agent.test_output_pipeline import source, SECRET
from tests.ui.test_app import make_app


@pytest.mark.asyncio
async def test_full_offloaded_event_remains_intact_without_ui_traffic_cache(make):
    agent = make()
    full = source(40000) + "\nAuthorization: Bearer " + SECRET
    msg, _, emitted, _ = record(agent, full)
    assert msg.tool_result_refs
    event = _to_agent_event(emitted[0])
    original = copy.deepcopy(event)
    app = make_app()
    app.state = reducer(app.state, AgentEventAction(event))
    assert not app.state.transcript
    assert event == original and "TAIL-CANARY" in event.result and SECRET not in event.result
    assert len(event.result) > len(msg.content)
    refs = copy.deepcopy(msg.tool_result_refs)
    for key in ("ctrl+k", "ctrl+o", "ctrl+f"):
        await app._process_key(events.Key(key, None))
    assert not app.state.transcript and msg.tool_result_refs == refs
