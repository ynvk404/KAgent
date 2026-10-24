"""Diagnostic events are serialized but have no presentation/workflow effects."""
from dataclasses import asdict
import json

from src.agent.events import WorkflowProgressEvent, AssistantDeltaEvent
from src.cli.headless import EventSink
from src.cli.runtime import emit
from src.logger.session_debug import SessionDebugOptions, create_session_debug_log
from src.ui.core.state import initial_state, reducer, AgentEventAction, SetBusy
from src.ui.widgets.banner import BannerData


def test_tui_accepts_telemetry_without_flushing_stream_or_changing_state():
    state = initial_state('', BannerData('offline', 'fixture', '/tmp'))
    state = reducer(state, SetBusy(True))
    state = reducer(state, AgentEventAction(AssistantDeltaEvent(text='partial')))
    after = reducer(state, AgentEventAction(WorkflowProgressEvent(stage='iteration_evaluated', metrics={'outer_iterations': 2})))
    assert after is state and after.stream_chunks == ('partial',)


async def test_cli_headless_and_session_serialize_additive_telemetry(tmp_path, capsys):
    event = WorkflowProgressEvent(stage='iteration_evaluated', metrics={
        'outer_iterations': 3, 'workflow_status': 'actionable', 'required_phase': 'enumeration'})
    emit(asdict(event))
    assert capsys.readouterr().out == ''  # Legacy CLI has no extra user-facing noise.
    sink = EventSink(tmp_path / 'headless')
    sink.write({'event': 'agent', 'data': asdict(event)})
    sink.close()
    debug = create_session_debug_log(SessionDebugOptions(enabled=True, session_id="offline-fixture", path=str(tmp_path / 'session.jsonl')))
    debug.agent_event(asdict(event))
    await debug.aclose()
    row = json.loads((tmp_path / 'headless/events.jsonl').read_text())
    assert row['data']['metrics'] == event.metrics
    session = json.loads((tmp_path / 'session.jsonl').read_text())
    assert session['type'] == 'workflow-progress' and session['metrics'] == event.metrics
