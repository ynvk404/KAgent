from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, Mock

import pytest

from src.agent.agent import AgentRunOptions
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import Decision, PermissionReviewCancelled, UserControlledRefusal
from src.tools.common.registry import Registry
from src.tools.execution.shell import ShellTool
from src.ui.bridges.perm_bridge import BridgedPermissionRequest, BridgedPrompter
from src.ui.core.app import AbortEvent, KAgent
from src.ui.core.state import SetBusy, SetPerm
from tests.agent.test_tool_outcomes import make_agent
from tests.helpers.agent_fakes import FakeClient
from tests.ui.test_app import make_app


@pytest.mark.parametrize("size", [(100, 40), (40, 18)])
@pytest.mark.parametrize("tool,summary,head,warning", [
    ("shell", "Review command", "echo start", "Sensitive operation"),
    ("file_edit", "edit file: report.txt", "path: report.txt", "Sensitive-path review required"),
    ("http", "Approve exact HTTP request", "POST http://juice.lab:3000/login", "Captured credentials require review"),
    ("mcp_plugin_action", "mcp: fixture-server action", "Arguments:", "Unsupported adapter limitations"),
    ("http_lab_grant", "Activate broad lab grant for http://juice.lab:3000", "Expires in 60s; 10 calls; 2/s", "WARNING: unknown server effects"),
    ("browser_grant", "Review bounded Browser grant", "Origin: http://juice.lab:3000", "Click/type may submit forms; expires in 60s; at most 10 calls"),
])
async def test_complete_permission_tails_are_directly_scrollable(monkeypatch, size, tool, summary, head, warning):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    request = BridgedPermissionRequest(tool=tool, summary=summary,
        detail=head + "\n" + warning + "\n" + "x" * 9500 + "\nFINAL_ARGUMENT --token=fake-secret",
        no_session_cache=True, force_operator=True, risk_tier="high-impact",
        resolve=Mock(), reject=Mock())
    async with app.run_test(size=size) as pilot:
        app.dispatch(SetPerm(request))
        app._sync_overlay()
        await pilot.pause()
        full = _content_text(app)
        assert "FINAL_ARGUMENT" in full and "fake-secret" not in full
        assert warning in " ".join(full.split())
        assert "truncated" not in full and "v full detail" not in full
        assert app.transcript_log.region.height > 0
        assert app.overlay_content_static.max_scroll_x == 0
        assert app.overlay_static.region.bottom <= size[1]
        await pilot.press("end")
        await pilot.pause()
        visible = _content_text(app, visible_only=True)
        for _ in range(8):
            if "FINAL_ARGUMENT" in visible:
                break
            await pilot.press("up")
            await pilot.pause()
            visible = _content_text(app, visible_only=True)
        assert "FINAL_ARGUMENT" in visible
        request.resolve.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 40), (40, 18)])
async def test_full_approval_detail_can_be_reviewed_with_keyboard_scroll(monkeypatch, size):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    # The shared fixture stubs repaint methods for non-mounted unit tests.
    # This integration check needs the real repaint/keyboard path.
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    resolve = Mock()
    request = BridgedPermissionRequest(
        tool="shell", summary="Review command",
        detail="\n".join(f"line {i}: " + "x" * 100 for i in range(100))
        + "\nLAST_OPERATION --token=fake-secret",
        risk_tier="high-impact", no_session_cache=True,
        resolve=resolve, reject=Mock(),
    )
    async with app.run_test(size=size) as pilot:
        app.dispatch(SetPerm(request))
        app._sync_overlay()
        await pilot.pause()
        assert app._perm_modal is not None
        assert app.overlay_static.border_title == "Permission"
        assert app.overlay_static.region.right <= size[0]
        assert app.overlay_static.region.bottom <= size[1]
        assert app.overlay_content_static.max_scroll_x == 0
        preview = _content_text(app)
        assert "Allow once:" in preview
        assert "LAST_OPERATION" in preview
        assert "truncated" not in preview
        await pilot.press("v")
        await pilot.pause()
        assert app._perm_modal is not None
        full = _content_text(app)
        assert "LAST_OPERATION" in full
        assert "fake-secret" not in full
        assert "truncated" not in full
        assert full.count("y allow once") == 1
        assert full.count("n deny") == 1
        await pilot.press("pagedown")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y > 0
        await pilot.press("end")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y > 0
        assert app.overlay_content_static.scroll_y == app.overlay_content_static.max_scroll_y
        visible = _content_text(app, visible_only=True)
        assert "y allow once" in visible and "scroll to review" not in visible
        await pilot.press("home")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y == 0
        assert "Shell command" in _content_text(app, visible_only=True)
        resolve.assert_not_called()


def _content_text(app: KAgent, *, visible_only: bool = False) -> str:
    widget = app.overlay_text_static
    first = int(app.overlay_content_static.scroll_y) if visible_only else 0
    last = widget.virtual_size.height
    if visible_only:
        last = min(first + app.overlay_content_static.size.height, last)
    details = "\n".join(widget.render_line(y).text for y in range(first, last))
    # Instructions are fixed beside the scrollable detail viewport.
    hints = app.permission_hints_static
    if hints.display:
        details += "\n" + "\n".join(hints.render_line(y).text for y in range(hints.size.height))
    return details


@pytest.mark.asyncio
async def test_escape_cancels_permission_proposal_without_interrupting_parallel_turn(monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    agent = make_agent()
    app.agent = agent
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(True))
    signal = app.run_abort_event
    visible, started, release, proposal_completed = (asyncio.Event() for _ in range(4))
    shown, events, sibling_calls = [], [], []

    def publish(request):
        app.dispatch(SetPerm(request))
        if request is not None:
            shown.append(request)
            visible.set()

    def emit(event):
        events.append(event)
        if event.type == "tool-result" and event.id == "proposal":
            proposal_completed.set()

    async def sibling(args, current_signal, prompter):
        sibling_calls.append(args)
        started.set()
        await release.wait()
        assert not current_signal.aborted
        return "sibling completed"

    bridge = BridgedPrompter(publish)
    agent.prompter = bridge
    agent.tools.register(ShellTool())
    sibling_tool = agent.tools.get("case")
    assert sibling_tool is not None
    monkeypatch.setattr(sibling_tool, "run", sibling)
    run_capture = AsyncMock(return_value="must not execute")
    monkeypatch.setattr("src.tools.execution.shell.run_with_capture", run_capture)
    client = FakeClient([
        ChatResponse(Message(role="assistant", content="", tool_calls=[
            ToolCall(id="proposal", function=FunctionCall(name="shell", arguments=json.dumps({"command": "pwd"}))),
            ToolCall(id="sibling", function=FunctionCall(name="case", arguments=json.dumps({"case": "success"}))),
        ]), "tool_calls"),
        ChatResponse(Message(role="assistant", content="Turn completed."), "stop"),
    ])
    agent.client = client

    async with app.run_test(size=(64, 30)) as pilot:
        turn = asyncio.create_task(agent.run("Run the offline fixture operations", signal, emit,
                                            AgentRunOptions(max_steps=2)))
        try:
            await asyncio.wait_for(visible.wait(), 2)
            await asyncio.wait_for(started.wait(), 2)
            await pilot.pause()
            assert app.state.pending_perm is shown[0]
            assert agent.is_running() and not turn.done()
            run_capture.assert_not_called()

            await pilot.press("escape")
            assert app.run_abort_event is signal and not signal.aborted
            await asyncio.wait_for(proposal_completed.wait(), 2)
            assert app.state.pending_perm is None
            assert app.state.busy and agent.is_running() and not turn.done()
            assert len(client.requests) == 1
            assert [(event.status, event.error_kind) for event in events
                    if event.type == "tool-result" and event.id == "proposal"] == [("cancelled", "cancelled")]
            # A late approval cannot revive the cancelled proposal or cache authority.
            shown[0].resolve(Decision.ALLOW_ONCE)
            release.set()
            await asyncio.wait_for(turn, 2)

            assert not signal.aborted and not agent.is_running()
            assert len(client.requests) == 2 and len(shown) == 1 and len(sibling_calls) == 1
            results = {message.tool_call_id: message for message in agent.history if message.role == "tool"}
            assert len(results) == 2
            assert (results["proposal"].tool_status, results["proposal"].tool_error_kind) == ("cancelled", "cancelled")
            assert results["sibling"].tool_status == "success" and results["sibling"].content == "sibling completed"
            assert [event.stop_reason for event in events if event.type == "done"] == ["final_response"]
            assert not bridge._session_allowed and not bridge._busy and not bridge._waiters
            run_capture.assert_not_called()
        finally:
            release.set()
            if not turn.done():
                turn.cancel()
            await asyncio.gather(turn, return_exceptions=True)


@pytest.mark.asyncio
async def test_escape_without_permission_modal_aborts_busy_turn_through_keyboard(monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(True))
    signal = app.run_abort_event

    async with app.run_test(size=(64, 30)) as pilot:
        assert app._get_active_modal() is None
        await pilot.press("escape")
        await asyncio.wait_for(signal.wait(), 2)
        assert app.run_abort_event is signal and signal.aborted


@pytest.mark.asyncio
async def test_short_high_impact_shell_preview_needs_no_scroll_at_normal_size(monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    req = BridgedPermissionRequest(
        tool="shell", summary="shell: pwd; python3 --version", detail="pwd; python3 --version",
        risk_tier="high-impact", no_session_cache=True, resolve=Mock(), reject=Mock(),
    )
    async with app.run_test(size=(64, 40)) as pilot:
        app.dispatch(SetPerm(req))
        KAgent._sync_overlay(app)
        await pilot.pause()
        assert app.overlay_static.border_title == "Permission"
        assert app.overlay_content_static.max_scroll_y == 0
        text = _content_text(app, visible_only=True)
        assert "Shell command" in text
        assert "current invocation only" in text
        assert "pwd; python3 --version" in text
        assert "y allow once · n deny · Esc cancel" in text


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["y", "n", "escape"])
async def test_shell_operator_decision_reaches_registry_without_changing_execution(monkeypatch, key):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(True))
    bridge = BridgedPrompter(lambda req: app.dispatch(SetPerm(req)))
    run_capture = AsyncMock(return_value="fixture output")
    monkeypatch.setattr("src.tools.execution.shell.run_with_capture", run_capture)
    registry = Registry()
    registry.register(ShellTool())
    command = "pwd; python3 --version"

    async with app.run_test(size=(64, 30)) as pilot:
        pending = asyncio.create_task(
            registry.execute("shell", {"command": command}, app.run_abort_event, bridge)
        )
        try:
            await pilot.pause()
            assert app.state.pending_perm is not None
            assert app.state.pending_perm.risk_tier == "high-impact"
            assert app.state.pending_perm.no_session_cache is True
            run_capture.assert_not_called()
            await pilot.press("a")
            await pilot.pause()
            assert not pending.done()
            run_capture.assert_not_called()
            await pilot.press(key)
            if key == "y":
                assert await asyncio.wait_for(pending, 2) == "fixture output"
                run_capture.assert_awaited_once()
                assert run_capture.call_args.args[1][-1] == command
            elif key == "n":
                with pytest.raises(UserControlledRefusal):
                    await asyncio.wait_for(pending, 2)
                run_capture.assert_not_called()
            else:
                with pytest.raises(PermissionReviewCancelled):
                    await asyncio.wait_for(pending, 2)
                assert not app.run_abort_event.is_set()
                run_capture.assert_not_called()
            assert app.state.pending_perm is None
            assert not bridge._session_allowed
        finally:
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
