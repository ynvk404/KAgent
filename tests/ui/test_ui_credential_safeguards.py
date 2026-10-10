"""Credential safeguards retained when restoring the original TUI."""
import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.agent.events import AssistantDeltaEvent, AssistantTextEvent, DoneEvent, ToolCallEvent, ToolResultEvent
from src.ui.commands.slash_handler import handle_slash
from src.ui.core.app import KAgent
from src.ui.core.state import AgentEventAction, Append, TranscriptEntry
from src.ui.widgets.transcript import entry_view
from tests.ui.test_app import make_app
from tests.ui.test_overview import _make_app
from tests.ui.test_state import seed


def emit(state, event):
    from src.ui.core.state import reducer
    return reducer(state, AgentEventAction(event))


@pytest.mark.parametrize("text,secret", [
    ("Authorization: Basic short-secret\n", "short-secret"),
    ('{"password":"short-secret"}', "short-secret"),
    ("curl --token short-secret", "short-secret"),
    ("-----BEGIN PRIVATE KEY-----\nshort-secret", "short-secret"),
])
@pytest.mark.parametrize("terminal", ["done", "message"])
def test_every_stream_split_hides_credentials_until_sanitized_boundary(text, secret, terminal):
    for boundary in range(len(text) + 1):
        state = emit(seed(), AssistantDeltaEvent(text=text[:boundary]))
        state = emit(state, AssistantDeltaEvent(text=text[boundary:]))
        assert secret not in repr(state.transcript)
        event = DoneEvent() if terminal == "done" else AssistantTextEvent(text=text)
        state = emit(state, event)
        assert secret not in repr(state.transcript)
        assert not state.stream_chunks and not state.transcript[-1].streaming


def test_stream_buffer_preserves_ordinary_text_at_message_and_tool_boundaries():
    state = emit(emit(seed(), AssistantDeltaEvent(text="first ")), AssistantDeltaEvent(text="second"))
    finalized = emit(state, AssistantTextEvent(text="first second"))
    assert finalized.transcript[-1].text == "first second"
    finalized = emit(state, ToolCallEvent(name="http", args_json='{"url":"/"}'))
    assert finalized.transcript[-2].text == "first second"
    assert not finalized.stream_chunks


def test_tool_arguments_and_full_results_are_redacted_without_mutating_events():
    secret = "short-credential"
    raw_args = json.dumps({"password": secret, "command": "echo " + "x" * 200})
    call = ToolCallEvent(name="http", args_json=raw_args)
    raw_result = f"HTTP/1.1 200 OK\nAuthorization: Basic {secret}\ncontent-type: text/plain\n\n" + "\n".join(
        f"evidence line {i}" for i in range(40)
    )
    result = ToolResultEvent(name="http", result=raw_result)
    state = emit(emit(seed(), call), result)
    assert secret not in repr(state.transcript)
    assert state.transcript[-1].full_text is not None
    assert "evidence line 39" in state.transcript[-1].full_text
    for expanded in (False, True):
        assert secret not in "\n".join(row.text for row in entry_view(replace(state.transcript[-1], expanded=expanded)))
    assert call.args_json == raw_args and result.result == raw_result


def test_append_and_right_click_copy_sanitize_secrets():
    app = make_app()
    app.dispatch(Append(TranscriptEntry(kind="system", text="password=short-secret", full_text="token=short-secret")))
    assert "short-secret" not in repr(app.state.transcript)
    copied = []
    app.copy_to_clipboard = copied.append
    app._last_selected_text = "Authorization: Basic short-secret"
    click = SimpleNamespace(button=3, stop=Mock())
    app.on_mouse_down(click)
    assert copied and "short-secret" not in copied[0]
    click.stop.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("command,status", [
    ("/burp status", "running"),
    ("/burp", "started"),
    ("/burp 9876", "restarted"),
    ("/burp", "already_running"),
])
async def test_bridge_commands_hide_token_and_offer_explicit_access(command, status):
    app = make_app()
    bridge = SimpleNamespace(url="http://localhost:9876", port=9876, token="local-bridge-credential")
    result = SimpleNamespace(status=status, state=bridge, old_port=9875)
    app.start_burp_bridge = AsyncMock(return_value=result)
    app.close_burp_bridge = AsyncMock()
    app.burp_bridge_status = AsyncMock(return_value=result)
    assert handle_slash(app, command)
    await asyncio.sleep(0)
    text = "\n".join(entry.text for entry in app.state.transcript)
    assert bridge.token not in text and "/burp credentials" in text


def test_startup_notice_hides_bridge_token():
    app = make_app()
    app._publish_notice("Burp bridge listening at http://localhost:9876\nToken: local-bridge-credential")
    assert "local-bridge-credential" not in repr(app.state.transcript)
    assert "/burp credentials" in app.state.transcript[-1].text


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 30), (40, 18)])
async def test_explicit_bridge_reveal_copy_stays_outside_original_transcript(size, monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = _make_app()
    copied = []
    app.copy_to_clipboard = copied.append
    bridge = SimpleNamespace(url="http://localhost:9876", port=9876, token="local-bridge-credential")
    app.start_burp_bridge = AsyncMock()
    app.close_burp_bridge = AsyncMock()
    app.burp_bridge_status = AsyncMock(return_value=SimpleNamespace(status="running", state=bridge))
    async with app.run_test(size=size) as pilot:
        assert handle_slash(app, "/burp credentials")
        await pilot.pause()
        assert app.transcript_panel.border_title == "Transcript"
        assert bridge.token not in app._get_active_modal().render().plain
        await pilot.press("v")
        assert bridge.token in app._get_active_modal().render().plain
        await pilot.press("c")
        assert copied == [bridge.token]
        await pilot.press("escape")
        assert app._get_active_modal() is None
        assert bridge.token not in repr(app.state.transcript)
        assert bridge.token not in "\n".join(line.text for line in app.transcript_log.lines)
