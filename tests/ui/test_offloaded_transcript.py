"""Offloaded history leaves existing live transcript controls and full output intact."""
import pytest
from textual import events

from src.agent.agent import _to_agent_event
from src.ui.core.state import reducer, AgentEventAction
from tests.agent.test_tool_result_offloading import make, record
from tests.agent.test_output_pipeline import source, SECRET
from tests.ui.test_app import make_app


@pytest.mark.asyncio
async def test_full_offloaded_event_remains_expandable_and_filterable(make):
    agent = make()
    full = source(40000) + '\nAuthorization: Bearer ' + SECRET
    msg, _, emitted, _ = record(agent, full)
    assert msg.tool_result_refs
    app = make_app()
    app.state = reducer(app.state, AgentEventAction(_to_agent_event(emitted[0])))
    entry = app.state.transcript[-1]
    assert entry.collapsible and len(entry.full_text or '') > len(msg.content)
    assert 'TAIL-CANARY' in (entry.full_text or '') and SECRET not in (entry.full_text or '')
    await app._process_key(events.Key('ctrl+k', None))
    assert app.state.transcript[-1].expanded
    await app._process_key(events.Key('ctrl+o', None))
    assert app.state.transcript[-1].expanded
    await app._process_key(events.Key('ctrl+o', None))
    assert not app.state.transcript[-1].expanded
    previous = app.state.transcript_filter
    await app._process_key(events.Key('ctrl+f', None))
    assert app.state.transcript_filter != previous
    assert app.state.transcript[-1].full_text == entry.full_text
