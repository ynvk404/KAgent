"""Admission replaces filters: retained answers stay intact; operation errors are not rendered."""
from src.agent.events import AssistantTextEvent, ToolResultEvent
from src.ui.core.state import AgentEventAction, reducer
from src.ui.widgets.transcript import entry_view
from tests.ui.test_state import seed


def test_retained_answers_and_actionable_errors_are_rendered_without_filters():
    state = reducer(seed(), AgentEventAction(AssistantTextEvent(text="Confirmed Finding is a tool name; evidence remains unavailable.")))
    state = reducer(state, AgentEventAction(ToolResultEvent(name="unknown", status="error", error_kind="scope_denied")))
    rendered = "\n".join(line.text for entry in state.transcript for line in entry_view(entry))
    assert "evidence remains unavailable" in rendered and "! unknown: scope_denied" not in rendered
    assert all(entry.kind != "finding" for entry in state.transcript)
