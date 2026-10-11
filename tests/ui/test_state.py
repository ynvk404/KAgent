from typing import Any
import copy
import json
import pytest
from src.ui.widgets.banner import BannerData
from src.ui.core.state import (initial_state, reducer, AgentEventAction, SetBusy, SetAsk, SetPerm,
    Clear, SetActiveSkill, Append, TranscriptEntry)
from src.agent.events import (ToolCallEvent, ToolResultEvent, ErrorEvent, AssistantDeltaEvent,
    AssistantTextEvent, DoneEvent, DecisionEvent, CompactEvent, MemoryRecallEvent)
from src.ui.widgets.transcript import entry_view


def seed():
    return initial_state(
        "",
        BannerData(
            provider="",
            model="",
            cwd="",
        ),
    )


def test_delta_changes_planning_to_answering():

    s = reducer(
        seed(),
        SetBusy(True)
    )

    assert s.phase == "planning"


    s = reducer(
        s,
        AgentEventAction(
            AssistantDeltaEvent(
                text="hello"
            )
        ),
    )


    assert s.phase == "answering"
    assert "awaiting sanitized message" in s.transcript[-1].text
    assert s.stream_chunks == ("hello",)


def test_busy_turn_transitions_through_waiting_input_and_back_to_answering():
    request: Any = object()
    s = reducer(seed(), SetBusy(True))

    s = reducer(s, SetAsk(request))
    assert s.busy is True
    assert s.phase == "waiting-user"

    s = reducer(s, SetAsk(None))
    assert s.busy is True
    assert s.phase == "answering"


def test_busy_turn_transitions_through_waiting_approval_and_back_to_tool():
    request: Any = object()
    s = reducer(seed(), SetBusy(True))

    s = reducer(s, SetPerm(request))
    assert s.busy is True
    assert s.phase == "waiting-approval"

    s = reducer(s, SetPerm(None))
    assert s.busy is True
    assert s.phase == "running-tool"


def test_finishing_turn_returns_to_idle():
    s = reducer(seed(), SetBusy(True))

    s = reducer(s, SetBusy(False))

    assert s.busy is False
    assert s.phase == "idle"


def test_streaming_finalized_by_done():

    s = reducer(
        seed(),
        AgentEventAction(
            AssistantDeltaEvent(
                text="hello"
            )
        ),
    )

    assert s.transcript[-1].streaming is True


    s = reducer(
        s,
        AgentEventAction(
            DoneEvent()
        ),
    )


    assert s.transcript[-1].streaming is False
    assert s.busy is False


def test_clear():

    s = reducer(
        seed(),
        Clear()
    )

    assert len(s.transcript) == 0
    assert s.clear_gen == 1


def test_clear_preserves_active_skill():
    s0 = reducer(seed(), SetActiveSkill("sql-injection"))
    assert s0.active_skill == "sql-injection"

    s1 = reducer(s0, Clear())
    assert len(s1.transcript) == 0
    assert s1.clear_gen == 1
    assert s1.active_skill == "sql-injection"


def test_clear_with_reset_message_clears_active_skill():
    s0 = reducer(seed(), SetActiveSkill("sql-injection"))
    assert s0.active_skill == "sql-injection"

    s1 = reducer(s0, Clear(message="conversation reset"))
    assert len(s1.transcript) == 0
    assert s1.clear_gen == 1
    assert s1.clear_message == "conversation reset"
    assert s1.active_skill is None


def test_runtime_error_event_rendering_is_unchanged():
    out = reducer(
        seed(),
        AgentEventAction(ErrorEvent(err=RuntimeError("provider unavailable"))),
    )

    assert out.transcript[-1].kind == "error"
    assert out.transcript[-1].text == "provider unavailable"



def emit(state, event):
    before = copy.deepcopy(event)
    error = event.err if isinstance(event, ErrorEvent) else None
    state = reducer(state, AgentEventAction(event))
    if isinstance(event, ErrorEvent):
        assert event.err is error and str(event.err) == str(before.err)
    else:
        assert event == before
    return state


@pytest.mark.parametrize("count", [1, 10, 100])
@pytest.mark.parametrize("tool", ["http", "shell", "unknown", "workflow", "load_skill", "browser_capture_status"])
def test_routine_entry_count_is_constant(count, tool):
    state = reducer(seed(), Append(TranscriptEntry(kind="user", text="Test local lab")))
    for i in range(count):
        state = emit(state, ToolCallEvent(id=str(i), name=tool, args={"url": "http://juice.lab:3000/path"}))
        assert state.running_tool and state.phase == "running-tool"
        result = {
            "shell": "exit: 0\nstdout:\nsecret traffic",
            "unknown": '{"body":"secret traffic"}',
            "workflow": '{"ok":true,"created":false,"candidate":{"notes":"secret traffic"}}',
            "load_skill": "# Skill: test\nsecret traffic",
            "browser_capture_status": '{"requests":10,"endpoints":2,"detail":"secret traffic"}',
        }.get(tool, "HTTP/1.1 500 Internal Server Error\n\nsecret traffic")
        state = emit(state, ToolResultEvent(id=str(i), name=tool,
            result=result, status="observation" if tool == "http" else "success"))
    assert len(state.transcript) == 1
    assert "secret traffic" not in repr(state)
    assert state.running_tool is None and not state.pending_calls
    assert len([line for entry in state.transcript for line in entry_view(entry) if line.text]) == 1


def test_planning_compaction_recall_and_proposed_findings_are_hidden():
    state = seed()
    for event in [DecisionEvent(summary="matched signal"), CompactEvent(summary="automatic handoff"),
                  MemoryRecallEvent(names=["sql injection"]),
                  ToolCallEvent(name="confirm_finding", args={"severity":"critical", "title":"Proposed"})]:
        state = emit(state, event)
    assert state.transcript == ()
    assert state.running_tool == "Saving finding"


def test_interleaved_search_results_correlate_by_id():
    state = emit(seed(), ToolCallEvent(id="search", name="shell", args={"command":"rg missing ."}))
    state = emit(state, ToolCallEvent(id="other", name="shell", args={"command":"false"}))
    state = emit(state, ToolResultEvent(id="search", name="shell", result="exit: 1\nstdout:\n"))
    assert not state.transcript and state.running_tool == "shell"
    state = emit(state, ToolResultEvent(id="other", name="shell", result="exit: 1\nstdout:\n"))
    assert len(state.transcript) == 1 and "exit 1" in state.transcript[0].text
    missing = emit(seed(), ToolResultEvent(id="missing", name="shell", result="exit: 1\nstdout:\n"))
    assert "exit 1" in missing.transcript[0].text


@pytest.mark.parametrize("event,reason", [
    (ToolResultEvent(name="unknown", status="error", error_kind="permission_denied"), "permission_denied"),
    (ToolResultEvent(name="unknown", status="cancelled"), "cancelled"),
    (ToolResultEvent(name="workflow", result="error: evidence changed"), "evidence changed"),
    (ToolResultEvent(name="workflow", result='{"ok":true,"coverage_sync":"pending","coverage_error":"disk full"}'), "disk full"),
    (ToolResultEvent(name="workflow", result='{"ok":true,"result":{"outcome":"insufficient-evidence","cleanup_state":"requires-user-action"}}'), "Cleanup requires-user-action"),
    (ToolResultEvent(name="confirm_finding", result="Finding persisted; compact report export failed."), "export failed"),
    (ToolResultEvent(name="unknown", err="connection failed\npassword=short-secret"), "connection failed"),
    (ToolResultEvent(name="unknown", truncated=True), "truncated"),
    (ToolResultEvent(name="shell", result="exit: 0\nstdout:\nok\nstderr:\ncleanup required"), "cleanup required"),
])
def test_actionable_outcomes_survive_success_metadata(event, reason):
    state = emit(seed(), event)
    assert len(state.transcript) == 1
    expected = "system" if event.truncated or event.name == "shell" else (
        "warning" if reason in {"permission_denied", "cancelled", "disk full", "Cleanup requires-user-action", "export failed"} else "error")
    assert state.transcript[0].kind == expected
    assert reason in state.transcript[0].text
    assert "short-secret" not in repr(state.transcript)
    assert "[ok]" not in state.transcript[0].text


def test_unknown_json_is_not_authoritative_or_dumped():
    state = emit(seed(), ToolResultEvent(name="unknown", result='{"ok":true,"finding":"confirmed","payload":"hidden"}'))
    assert not state.transcript


def test_pending_metadata_is_bounded_and_hides_arguments():
    state = seed()
    for i in range(300):
        state = emit(state, ToolCallEvent(id=str(i), name="unknown", args={"password":"secret"}))
    assert len(state.pending_calls) == 256
    assert "secret" not in repr(state.pending_calls)


@pytest.mark.parametrize("streaming", [False, True])
def test_substantive_analysis_between_tools_is_preserved(streaming):
    answer = "The observed response does not establish a vulnerability. Here is the requested analysis."
    state = emit(seed(), ToolCallEvent(id="a", name="http"))
    state = emit(state, ToolResultEvent(id="a", name="http", result="HTTP/1.1 200 OK"))
    if streaming:
        for chunk in [answer[:10], answer[10:]]:
            state = emit(state, AssistantDeltaEvent(text=chunk))
    else:
        state = emit(state, AssistantTextEvent(text=answer))
    state = emit(state, ToolCallEvent(id="b", name="http"))
    state = emit(state, ToolResultEvent(id="b", name="http", result="HTTP/1.1 403 Forbidden"))
    state = emit(state, DoneEvent(stop_reason="workflow_blocked"))
    assert state.transcript[0].text == answer
    assert len(state.transcript) == 2


@pytest.mark.parametrize("boundary", [ToolCallEvent(name="http"), ToolResultEvent(name="http"),
    DecisionEvent(), CompactEvent(), ErrorEvent(err=RuntimeError("provider failed")),
    DoneEvent(stop_reason="cancelled")])
def test_partial_stream_and_every_credential_split_survive_event_boundaries(boundary):
    text = "Partial answer; validation remains incomplete.\nAuthorization: Basic short-secret"
    for split in range(len(text) + 1):
        state = emit(seed(), AssistantDeltaEvent(text=text[:split]))
        state = emit(state, AssistantDeltaEvent(text=text[split:]))
        assert "short-secret" not in repr(state.transcript)
        state = emit(state, boundary)
        assert state.transcript[0].text.startswith("Partial answer; validation remains incomplete.")
        assert "short-secret" not in repr(state.transcript)
        assert not state.stream_chunks and not state.transcript[0].streaming


def test_appended_operator_notice_finalizes_partial_stream_safely():
    state = emit(seed(), AssistantDeltaEvent(text="Partial requested answer.\nAuthorization: Basic short-secret"))
    state = reducer(state, Append(TranscriptEntry(kind="system", text="Reached max steps")))
    assert state.transcript[0].text.startswith("Partial requested answer.")
    assert "short-secret" not in repr(state.transcript) and not state.stream_chunks


def test_unknown_workflow_receipt_shapes_do_not_drop_events_or_imply_success():
    state = emit(seed(), ToolResultEvent(name="workflow", result='{"ok":true,"result":{"outcome":{},"cleanup_state":[]}}'))
    assert not state.transcript
