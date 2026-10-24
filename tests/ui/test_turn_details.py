import copy
from dataclasses import replace

import pytest

from src.agent.events import DoneEvent, ToolCallEvent, ToolResultEvent
from src.ui.core.outcomes import OutcomeFacts, ProgressRecord
from src.ui.core.state import AgentEventAction, Clear, SetBusy, initial_state, reducer
from src.ui.widgets.banner import BannerData


def state_for_turn():
    return reducer(initial_state("", BannerData("offline", "fixture", ".")),
                   SetBusy(True, facts=OutcomeFacts(scope="fixture")))


def finish(state, facts=None, reason="final_response"):
    return reducer(state, AgentEventAction(DoneEvent(stop_reason=reason), facts=facts))


def test_short_summary_and_details_share_source_counts_independent_of_transcript():
    state = state_for_turn()
    for call_id, name in [("a", "browser_capture_get"), ("b", "permissions_status"), ("c", "file_write"), ("d", "file_write")]:
        state = reducer(state, AgentEventAction(ToolCallEvent(id=call_id, name=name)))
        state = reducer(state, AgentEventAction(ToolResultEvent(id=call_id, name=name, result="ok")))
    # Visibility is not the source of counters.
    state = replace(state, transcript=())
    facts = OutcomeFacts(scope="fixture", records=(ProgressRecord("finding", "saved", "Fixture finding"),))
    state = finish(state, facts)
    assert state.transcript[-1].text == "Turn completed; 1 finding saved."
    details = state.latest_turn_details
    assert details is not None and details.turn_number == 1 and details.saved_findings == 1
    assert details.completed_operations == (("browser_capture_get", 1), ("permissions_status", 1), ("file_write", 2))
    assert "Operations completed" not in state.transcript[-1].text
    assert finish(state, facts).latest_turn_details is details


@pytest.mark.parametrize("reason,label", [
    ("final_response", "Turn completed"), ("runtime_error", "Runtime failure"),
    ("cancelled", "Turn cancelled"), ("max_steps", "Stopped at max steps"),
    ("workflow_blocked", "Blocked"),
    ("plan_only_blocked", "Plan-only tool request blocked"),
    ("future", "Turn ended (future)"),
])
def test_outcome_labels_and_diagnostics_keep_real_reason(reason, label):
    state = finish(state_for_turn(), reason=reason)
    assert state.transcript[-1].text.startswith(label)
    assert state.latest_turn_details is not None
    assert state.latest_turn_details.stop_reason == reason


def test_partial_work_permissions_exports_and_unsaved_findings_remain_visible():
    state = state_for_turn()
    for call_id, kind in [("denied", "permission_denied"), ("pending", "permission_pending")]:
        state = reducer(state, AgentEventAction(ToolCallEvent(id=call_id, name="fixture")))
        state = reducer(state, AgentEventAction(ToolResultEvent(id=call_id, name="fixture", status="error",
            error_kind=kind, err="permission denied" if kind == "permission_denied" else "pending review")))
    facts = OutcomeFacts(scope="fixture", incomplete=1, goals=2,
        pending=("cleanup requires-user-action", "coverage synchronization pending", "deferred requested work"),
        records=(ProgressRecord("unsaved", "accepted", "Fixture accepted assessment"),))
    state = finish(state, facts)
    text = state.transcript[-1].text
    assert text.startswith("Turn ended · work remains")
    for phrase in ("1 accepted-but-unsaved validation", "1 incomplete validation", "2 incomplete goals",
                   *facts.pending):
        assert phrase in text
    details = state.latest_turn_details
    assert details is not None
    assert details.saved_findings == 0 and details.unsaved_validations == 1
    assert "unresolved" not in text
    assert details.incomplete_validations == 1 and details.incomplete_goals == 2


def test_latest_snapshot_keeps_its_turn_and_reset_resume_do_not_invent_history():
    state = finish(state_for_turn(), OutcomeFacts(scope="fixture", records=(ProgressRecord("operation", "a", "first"),)))
    first = state.latest_turn_details
    assert first is not None
    state = reducer(state, SetBusy(True, facts=OutcomeFacts(scope="fixture")))
    assert state.latest_turn_details is first
    state = finish(state, OutcomeFacts(scope="fixture", records=(ProgressRecord("operation", "b", "second"),)))
    assert state.latest_turn_details is not None
    assert state.latest_turn_details.turn_number == 2
    assert state.latest_turn_details.completed_operations == (("second", 1),)
    assert first.completed_operations == (("first", 1),)
    assert reducer(state, Clear(message="conversation reset")).latest_turn_details is None
    assert initial_state("", BannerData("offline", "fixture", ".")).latest_turn_details is None


@pytest.mark.parametrize("mode", ["direct", "whole_target", "candidate_validation", "requested-goals", "no-objective"])
def test_real_runtime_modes_preserve_authoritative_state_and_residual_work(tmp_path, mode):
    from src.permission.permission import AlwaysAllow
    from src.target.target import Target
    from src.tools.workflow.workflow_tool import WorkflowTool
    from src.ui.core.outcomes import runtime_facts
    from src.workflow.state import Candidate, WorkflowObjective, WorkflowState
    from types import SimpleNamespace
    origin = "https://fixture.test"
    workflow = WorkflowState()
    candidate, _ = workflow.add_candidate(Candidate(candidate_class="xss", target=origin, endpoint="/search", parameter="q"))
    if mode != "no-objective":
        workflow.objective = WorkflowObjective("fixture", "direct" if mode == "requested-goals" else mode,
                                              origin, candidate_id=candidate.id if mode == "candidate_validation" else None)
        if mode == "requested-goals":
            workflow.objective.add_requested_goal("xss")
    agent = SimpleNamespace(workflow=workflow, target=Target(origin), prompter=AlwaysAllow(),
        tools={"workflow": WorkflowTool(workflow, target=Target(origin), evidence_root=tmp_path)})
    before = copy.deepcopy(workflow.to_dict())
    facts = runtime_facts(agent, None, ())
    state = reducer(initial_state("", BannerData("offline", "fixture", ".")), SetBusy(True, facts=facts))
    reason = "workflow_blocked" if mode == "whole_target" else "final_response"
    state = finish(state, facts, reason)
    assert workflow.to_dict() == before
    assert state.latest_turn_details is not None
    assert state.latest_turn_details.incomplete_validations == facts.incomplete
    assert state.latest_turn_details.incomplete_goals == facts.goals
    for value in facts.pending:
        assert value in state.transcript[-1].text
    assert not any(entry.kind in {"finding", "validation"} for entry in state.transcript)


@pytest.mark.parametrize("proposes_tool", [False, True])
async def test_real_plan_only_run_has_no_execution_and_truthful_summary(proposes_tool):
    from src.agent.agent import Agent, AgentOptions, AgentRunOptions
    from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
    from src.permission.permission import AlwaysAllow
    from src.skills.registry import Registry as Skills
    from src.target.target import Target
    from src.tools.common.registry import Registry
    from src.ui.core.app import RunAgentOptions
    from tests.helpers.agent_fakes import FakeClient
    from tests.ui.test_app import timer_app
    from tests.ui.test_presentation_equivalence import ObservationTool
    tools = Registry()
    observation = ObservationTool()
    tools.register(observation)
    text = "Plan: inspect the declared target; no validation has been performed."
    calls = [ToolCall("proposed", FunctionCall(observation.name(), '{"operation":"fixture"}'))] if proposes_tool else None
    client = FakeClient([ChatResponse(Message("assistant", text, tool_calls=calls), "tool_calls" if calls else "stop")])
    agent = Agent(AgentOptions(client, tools, Skills(), AlwaysAllow(), None,
                              Target("https://fixture.test"), streaming_enabled=False))
    app, _, _ = timer_app()
    app.agent = agent
    await app.run_agent_turn("Plan the test", RunAgentOptions(run_options=AgentRunOptions(tools=False)))
    assert observation.calls == [] and all(not request.tools for request in client.requests)
    assert any(entry.kind == "assistant" and entry.text == text for entry in app.state.transcript)
    details = app.state.latest_turn_details
    assert details is not None and details.completed_operations == () and details.saved_findings == 0
    assert details.stop_reason == ("plan_only_blocked" if proposes_tool else "final_response")
    assert not any(entry.kind in {"finding", "validation"} for entry in app.state.transcript)


@pytest.mark.parametrize("size", [(100, 40), (40, 18)])
async def test_mounted_turn_details_scroll_copy_escape_and_snapshot_ownership(monkeypatch, size):
    from textual.geometry import Offset
    from textual.selection import Selection
    from src.ui.commands.slash_handler import handle_slash
    from src.ui.core.app import AbortEvent, KAgent
    from src.ui.widgets.turn_details_modal import TurnDetailsModal
    from tests.ui.test_app import make_app
    from tests.ui.test_permission_review import _content_text
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    facts = OutcomeFacts(scope="fixture", records=tuple(ProgressRecord("operation", str(i), f"operation_{i}") for i in range(40)))
    app.state = finish(state_for_turn(), facts)
    snapshot = app.state.latest_turn_details
    async with app.run_test(size=size) as pilot:
        assert handle_slash(app, "/turn-details")
        await pilot.pause()
        assert app.overlay_static.border_title == "Turn Details"
        assert "operation_39 (1)" in _content_text(app)
        assert "total tool calls" not in _content_text(app)
        assert app.overlay_content_static.max_scroll_x == 0
        assert app.overlay_static.region.bottom <= size[1]
        await pilot.press("end")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y == app.overlay_content_static.max_scroll_y
        await pilot.press("home")
        await pilot.pause()
        app.screen.selections = {app.overlay_text_static: Selection(Offset(0, 0), Offset(6, 0))}
        assert app.screen.get_selected_text() == "Latest"
        app.screen.action_copy_text()
        assert app.clipboard == "Latest"
        # A view holds its original immutable turn, even if another turn starts.
        app.state = reducer(app.state, SetBusy(True, facts=facts))
        app.run_abort_event = AbortEvent()
        assert isinstance(app._local_modal, TurnDetailsModal)
        assert app._local_modal.details is snapshot
        await pilot.press("escape")
        assert app._local_modal is None and not app.run_abort_event.aborted
        assert app.state.latest_turn_details is snapshot


def test_pending_review_and_export_counters_are_not_hidden_by_final_response():
    from src.ui.core.state import SetPerm
    from tests.ui.test_permission_modal import make_req
    state = state_for_turn()
    state = reducer(state, AgentEventAction(ToolResultEvent(name="confirm_finding",
        result="Finding persisted; compact report export failed.", presentation_impact="persistence")))
    state = reducer(state, SetPerm(make_req()))
    state = finish(state)
    assert any("export failed" in row.text for row in state.transcript)
    assert "permission review pending" in state.transcript[-1].text
    assert state.latest_turn_details is not None
    assert "unresolved" not in state.latest_turn_details.outcome
    assert state.transcript[-1].kind == "warning"
