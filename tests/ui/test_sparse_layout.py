"""Mounted acceptance for the original layout under long routine activity."""
import pytest

from src.agent.events import AssistantTextEvent, DoneEvent, ToolCallEvent, ToolResultEvent
from src.ui.core.app import KAgent
from src.ui.core.state import AgentEventAction, Append, SetBusy, TranscriptEntry
from tests.ui.test_overview import _make_app, _get_panel, _render_obj


@pytest.mark.parametrize("size", [(100, 30), (40, 24)])
@pytest.mark.parametrize("count", [1, 10, 100])
async def test_original_layout_stays_sparse_during_tool_activity(monkeypatch, size, count):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = _make_app()
    async with app.run_test(size=size) as pilot:
        app.dispatch(Append(TranscriptEntry(kind="user", text="Inspect the authorized lab")))
        app.dispatch(SetBusy(True))
        for i in range(count):
            app.dispatch(AgentEventAction(ToolCallEvent(id=str(i), name="http")))
            app.dispatch(AgentEventAction(ToolResultEvent(id=str(i), name="http", status="observation",
                                                       result="HTTP/1.1 200 OK\n\nHIDDEN_TRAFFIC")))
        app.dispatch(AgentEventAction(ToolCallEvent(id="active", name="http")))
        await pilot.pause()
        assert len(app.state.transcript) == 1
        assert app.input_static.display and app.status_bar.display
        assert app.transcript_log.region.height > 0
        assert not app.live_entry_static.display
        assert "Welcome to KAgent" in _render_obj(_get_panel(app), size[0])
        assert "HIDDEN_TRAFFIC" not in app.export_screenshot()
        assert app.status_bar.render().plain.startswith("⠋ http")
        assert app.input_static.region.bottom <= size[1]
        app.dispatch(AgentEventAction(AssistantTextEvent(text="Validation remains incomplete because evidence is unavailable.")))
        app.dispatch(AgentEventAction(DoneEvent(stop_reason="workflow_blocked")))
        await pilot.pause()
        assert len(app.state.transcript) == 3 and not app.state.busy
        rendered = "\n".join(line.text for line in app.transcript_log.lines)
        assert "evidence is unavailable" in rendered and "Blocked" in rendered
        assert "ready · idle" in app.status_bar.render().plain
