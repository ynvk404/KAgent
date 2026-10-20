"""Pending permission and user requests own the displayed TUI phase."""
from __future__ import annotations

import asyncio

import pytest

from src.agent.events import (
    AssistantDeltaEvent,
    DoneEvent,
    Invocation,
    ToolCallEvent,
    ToolStartedEvent,
)
from src.permission.permission import (
    Decision,
    PermissionReviewCancelled,
)
from src.tools.common.ask import Option, Question
from src.ui.bridges.ask_bridge import AskRequest, BridgedAskPrompter
from src.ui.bridges.perm_bridge import BridgedPermissionRequest, BridgedPrompter
from src.ui.core.app import AbortEvent
from src.ui.core.state import (
    AgentEventAction,
    FinalizeDeferredOutcome,
    SetAsk,
    SetBusy,
    SetPerm,
    initial_state,
    reducer,
)
from src.ui.widgets.banner import BannerData
from src.ui.widgets.ask_modal import AskModal
from src.ui.widgets.permission_modal import PermissionModal
from src.ui.widgets.status_bar import phase_label
from tests.ui.test_app import make_app


def seed():
    return initial_state("", BannerData("fixture", "fixture", "."))


def scanner_call() -> ToolCallEvent:
    return ToolCallEvent(
        id="scanner",
        name="shell",
        invocation=Invocation("invocation", ""),
        args={"scanner": "ffuf", "url": "http://fixture.test/FUZZ", "wordlist_id": "fixture"},
    )


def scanner_started(call: ToolCallEvent | None = None) -> ToolStartedEvent:
    call = call or scanner_call()
    return ToolStartedEvent(
        id=call.id,
        name=call.name,
        invocation=call.invocation,
        scanner="ffuf",
        job_id="fixture-job",
        started_monotonic=1.0,
    )


def pending_permission() -> BridgedPermissionRequest:
    return BridgedPermissionRequest(
        tool="shell",
        summary="Run command",
        detail="bounded fixture",
        resolve=lambda _decision: None,
        reject=lambda _error: None,
    )


def pending_ask() -> AskRequest:
    return AskRequest(
        question=Question(question="Fixture question", options=[Option("A")]),
        resolve=lambda _answer: None,
        reject=lambda _error: None,
    )


def test_pending_permission_survives_streaming_delta():
    state = reducer(seed(), SetBusy(True))
    state = reducer(state, SetPerm(pending_permission()))

    state = reducer(state, AgentEventAction(AssistantDeltaEvent(text="still working")))

    assert state.phase == "waiting-approval"
    assert state.pending_perm is not None
    assert state.transcript[-1].streaming


def test_pending_permission_survives_tool_started_event():
    call = scanner_call()
    state = reducer(seed(), SetBusy(True))
    state = reducer(state, SetPerm(pending_permission()))
    state = reducer(state, AgentEventAction(call))

    state = reducer(state, AgentEventAction(scanner_started(call)))

    assert state.phase == "waiting-approval"
    assert state.pending_perm is not None
    assert state.call_history[-1].started_monotonic == 1.0


def test_pending_permission_survives_busy_false():
    state = reducer(seed(), SetBusy(True))
    state = reducer(state, SetPerm(pending_permission()))

    state = reducer(state, SetBusy(False))

    assert state.busy is False
    assert state.phase == "waiting-approval"
    assert phase_label(state.phase) == "waiting approval"
    assert state.pending_perm is not None


def test_pending_user_request_survives_stream_and_tool_activity():
    call = scanner_call()
    state = reducer(seed(), SetBusy(True))
    state = reducer(state, SetAsk(pending_ask()))
    state = reducer(state, AgentEventAction(AssistantDeltaEvent(text="partial")))
    assert state.phase == "waiting-user"

    state = reducer(state, AgentEventAction(call))
    state = reducer(state, AgentEventAction(scanner_started(call)))
    state = reducer(state, SetBusy(False))

    assert state.phase == "waiting-user"
    assert phase_label(state.phase) == "waiting input"
    assert state.busy is False
    assert state.pending_ask is not None


def test_overlapping_requests_follow_active_ask_then_permission_ownership():
    state = reducer(seed(), SetBusy(True))
    state = reducer(state, SetPerm(pending_permission()))
    state = reducer(state, SetAsk(pending_ask()))
    assert state.phase == "waiting-user"

    state = reducer(state, SetAsk(None))
    assert state.phase == "waiting-approval"

    # Duplicate clearing of the already-ended ask cannot clear the permission wait.
    state = reducer(state, SetAsk(None))
    assert state.phase == "waiting-approval"
    assert state.pending_perm is not None

    state = reducer(state, SetPerm(None))
    assert state.phase == "running-tool"
    assert state.pending_perm is None


def test_stale_tool_started_event_does_not_replace_pending_permission_phase():
    call = scanner_call()
    state = reducer(seed(), SetBusy(True))
    state = reducer(state, SetPerm(pending_permission()))
    state = reducer(state, AgentEventAction(call))
    stale = scanner_started(call)
    stale.invocation = Invocation("stale-invocation", "")

    state = reducer(state, AgentEventAction(stale))

    assert state.phase == "waiting-approval"
    assert state.call_history[-1].started_monotonic is None


def test_request_resolution_returns_to_normal_busy_or_idle_phase():
    busy = reducer(reducer(seed(), SetBusy(True)), SetAsk(pending_ask()))
    answered = reducer(busy, SetAsk(None))
    assert answered.phase == "answering"

    idle = reducer(reducer(seed(), SetAsk(pending_ask())), SetAsk(None))
    assert idle.phase == "idle"

    permission = reducer(reducer(seed(), SetBusy(True)), SetPerm(pending_permission()))
    approved_or_denied = reducer(permission, SetPerm(None))
    assert approved_or_denied.phase == "running-tool"


@pytest.mark.parametrize(
    ("reason", "label"),
    [
        ("max_steps", "Stopped at max steps"),
        ("cancelled", "Turn cancelled"),
        ("runtime_error", "Runtime failure"),
    ],
)
def test_terminal_outcomes_remain_visible_without_pending_requests(reason: str, label: str):
    state = reducer(seed(), SetBusy(True))

    state = reducer(state, AgentEventAction(DoneEvent(stop_reason=reason)))

    assert state.phase == "idle"
    assert state.latest_turn_details is not None
    assert state.latest_turn_details.stop_reason == reason
    assert state.transcript[-1].text.startswith(label)


def test_max_steps_ask_stays_actionable_then_shows_terminal_outcome():
    state = reducer(reducer(seed(), SetBusy(True)), SetAsk(pending_ask()))
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason="max_steps")))
    assert state.phase == "waiting-user"
    assert state.deferred_outcome == "max_steps"
    assert not state.outcome_written

    state = reducer(state, SetAsk(None))
    state = reducer(state, FinalizeDeferredOutcome())
    assert state.phase == "idle"
    assert state.transcript[-1].text.startswith("Stopped at max steps")


def test_pending_permission_keeps_wait_label_without_hiding_terminal_message():
    state = reducer(reducer(seed(), SetBusy(True)), SetPerm(pending_permission()))

    state = reducer(state, AgentEventAction(DoneEvent(stop_reason="cancelled")))

    assert state.phase == "waiting-approval"
    assert state.transcript[-1].text.startswith("Turn cancelled")
    assert "permission review pending" in state.transcript[-1].text


@pytest.mark.parametrize("decision", [Decision.ALLOW_ONCE, Decision.DENY])
async def test_permission_modal_and_decision_survive_streaming_delta(decision: Decision):
    app = make_app()
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(True))
    bridge = BridgedPrompter(lambda req: app.dispatch(SetPerm(req=req)))
    task = asyncio.create_task(
        bridge.ask(pending_permission(), app.run_abort_event)
    )
    await asyncio.sleep(0)

    request = app.state.pending_perm
    assert request is not None
    modal = app._get_active_modal()
    assert isinstance(modal, PermissionModal)
    app.dispatch(AgentEventAction(AssistantDeltaEvent(text="progress")))

    assert app.state.phase == "waiting-approval"
    assert phase_label(app.state.phase) == "waiting approval"
    assert app._get_active_modal() is modal
    assert modal.req is request

    request.resolve(decision)
    assert await task == decision
    assert app.state.pending_perm is None
    assert app.state.phase == "running-tool"
    assert app._get_active_modal() is None
    assert not bridge._session_allowed


async def test_user_answer_clears_wait_phase_and_preserves_answer():
    app = make_app()
    app.dispatch(SetBusy(True))
    bridge = BridgedAskPrompter(lambda req: app.dispatch(SetAsk(req=req)))
    question = Question(question="Choose a fixture", options=[Option("A"), Option("B")])
    task = asyncio.create_task(bridge.ask(question))
    await asyncio.sleep(0)

    request = app.state.pending_ask
    assert request is not None
    modal = app._get_active_modal()
    assert isinstance(modal, AskModal)
    app.dispatch(AgentEventAction(AssistantDeltaEvent(text="background chunk")))

    assert app.state.phase == "waiting-user"
    assert phase_label(app.state.phase) == "waiting input"
    assert app._get_active_modal() is modal
    assert modal.req is request

    request.resolve("A")
    assert await task == "A"
    assert app.state.pending_ask is None
    assert app.state.phase == "answering"
    assert app._get_active_modal() is None


async def test_permission_cancellation_clears_waiting_display_without_aborting_turn():
    app = make_app()
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(True))
    bridge = BridgedPrompter(lambda req: app.dispatch(SetPerm(req=req)))
    task = asyncio.create_task(bridge.ask(pending_permission(), app.run_abort_event))
    await asyncio.sleep(0)

    request = app.state.pending_perm
    assert request is not None
    request.reject(PermissionReviewCancelled("operator closed the permission prompt"))

    with pytest.raises(PermissionReviewCancelled):
        await task
    assert app.state.pending_perm is None
    assert app.state.phase == "running-tool"
    assert not app.run_abort_event.is_set()
    assert not bridge._session_allowed


async def test_overlapping_bridge_requests_keep_visible_modal_and_wait_phase_in_sync():
    app = make_app()
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(True))
    permission_bridge = BridgedPrompter(lambda req: app.dispatch(SetPerm(req=req)))
    ask_bridge = BridgedAskPrompter(lambda req: app.dispatch(SetAsk(req=req)))
    permission_task = asyncio.create_task(
        permission_bridge.ask(pending_permission(), app.run_abort_event)
    )
    ask_task = asyncio.create_task(
        ask_bridge.ask(Question(question="Continue?", options=[Option("Yes")]))
    )
    for _ in range(4):
        await asyncio.sleep(0)
        if app.state.pending_perm is not None and app.state.pending_ask is not None:
            break

    permission_request = app.state.pending_perm
    ask_request = app.state.pending_ask
    assert permission_request is not None and ask_request is not None
    assert app.state.phase == "waiting-user"
    assert phase_label(app.state.phase) == "waiting input"
    modal = app._get_active_modal()
    assert isinstance(modal, AskModal)
    assert modal.req is ask_request

    ask_request.resolve("Yes")
    assert await ask_task == "Yes"
    assert app.state.pending_ask is None
    assert app.state.pending_perm is permission_request
    assert app.state.phase == "waiting-approval"
    assert phase_label(app.state.phase) == "waiting approval"
    modal = app._get_active_modal()
    assert isinstance(modal, PermissionModal)
    assert modal.req is permission_request

    # A duplicate clear for the resolved ask cannot hide the active permission.
    app.dispatch(SetAsk(None))
    assert app.state.phase == "waiting-approval"
    modal = app._get_active_modal()
    assert isinstance(modal, PermissionModal)
    assert modal.req is permission_request

    permission_request.resolve(Decision.ALLOW_ONCE)
    assert await permission_task == Decision.ALLOW_ONCE
    assert app.state.pending_perm is None
    assert app.state.phase == "running-tool"
    assert app._get_active_modal() is None


def test_no_pending_request_keeps_existing_answering_running_and_idle_phases():
    state = reducer(seed(), SetBusy(True))
    state = reducer(state, AgentEventAction(AssistantDeltaEvent(text="answer")))
    assert state.phase == "answering"

    call = scanner_call()
    state = reducer(state, AgentEventAction(call))
    state = reducer(state, AgentEventAction(scanner_started(call)))
    assert state.phase == "running-tool"

    state = reducer(state, SetBusy(False))
    assert state.phase == "idle"
