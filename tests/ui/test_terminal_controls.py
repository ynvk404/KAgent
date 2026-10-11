"""Presentation controls are inert; operation and evidence content is intact."""
from copy import deepcopy
from io import StringIO
import re
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest
from rich.console import Console
from textual import events

from src.agent.events import AssistantDeltaEvent, AssistantTextEvent
from src.cli import runtime
from src.permission.permission import Decision
from src.tools.common.registry import Registry
from src.tools.execution.file import FileWriteTool
from src.ui.bridges.perm_bridge import BridgedPermissionRequest
from src.ui.core.state import AgentEventAction, TranscriptEntry, reducer
from src.ui.render.sanitize import sanitize_text
from src.ui.widgets.permission_modal import PermissionModal
from src.ui.widgets.transcript import BannerData, Transcript, entry_view
from tests.ui.test_app import make_app
from tests.ui.test_state import seed

CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
PAYLOADS = [
    "start\x1b[2J\x1b[Hend", "start\x1b[31mred\x1b[0mend",
    "start\x1b]52;c;ZmFrZQ==\x07end", "start\x1b]0;title\x1b\\end",
    "start\x9b2Jend", "start\x9d52;c;ZmFrZQ==\x9cend",
    "start\x1b", "start\x1b[", "start\x1b]52;c;unfinished",
    "start\x00\x08\x0b\x0c\x0e\x1f\x7fend", "start\rhidden",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_presentation_boundary_escapes_controls_and_keeps_unicode(payload):
    raw = "Tiếng Việt ☃\n\t" + payload + "\npassword=synthetic-secret"
    rendered = sanitize_text(raw)
    assert not CONTROLS.search(rendered)
    assert "Tiếng Việt ☃\n\t" in rendered
    assert "synthetic-secret" not in rendered
    assert sanitize_text(rendered) == rendered
    assert sanitize_text("normal\r\nline") == "normal\nline"


@pytest.mark.parametrize("payload", PAYLOADS)
def test_transcript_cli_and_tui_rows_never_receive_untrusted_controls(payload, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    entry = TranscriptEntry(kind="assistant", text="Unicode ☃\n" + payload)
    before = entry.text
    rows = entry_view(entry)
    assert not CONTROLS.search("\n".join(row.text for row in rows))
    output = StringIO()
    Transcript(out=output).flush([entry], BannerData("fake", "fixture", "/tmp"), 0)
    assert not CONTROLS.search(output.getvalue())
    assert entry.text == before


@pytest.mark.parametrize("payload", PAYLOADS)
def test_every_stream_split_is_safe_in_reducer_and_cli(payload, monkeypatch):
    monkeypatch.setattr(runtime, "_c", lambda _code, text: text)
    for split in range(len(payload) + 1):
        chunks = (payload[:split], payload[split:])
        state = seed()
        output = StringIO()
        monkeypatch.setattr(runtime.sys, "stdout", output)
        for chunk in chunks:
            state = reducer(state, AgentEventAction(AssistantDeltaEvent(text=chunk)))
            runtime.emit({"type": "assistant-delta", "text": chunk})
            assert not CONTROLS.search(output.getvalue())
        state = reducer(state, AgentEventAction(AssistantTextEvent(text=payload)))
        assert not CONTROLS.search(state.transcript[-1].text)
        assert "start" in state.transcript[-1].text


@pytest.mark.parametrize("event_type,field", [
    ("assistant-text", "text"), ("tool-call", "name"), ("tool-call", "id"),
    ("tool-result", "result"), ("tool-result", "err"), ("tool-result", "duration_ms"),
    ("decision", "summary"), ("skill-active", "name"), ("error", "err"),
])
def test_cli_event_fields_are_sanitized_before_application_styles(event_type, field, monkeypatch):
    monkeypatch.setattr(runtime, "_c", lambda _code, text: text)
    raw = "ordinary ☃\x1b]52;c;ZmFrZQ==\x07\npassword=synthetic-secret"
    event = {"type": event_type, field: raw}
    original = deepcopy(event)
    output = StringIO()
    monkeypatch.setattr(runtime.sys, "stdout", output)
    runtime.emit(event)
    assert event == original
    assert not CONTROLS.search(output.getvalue())
    assert "synthetic-secret" not in output.getvalue()


def test_cli_none_error_still_displays_success(monkeypatch):
    monkeypatch.setattr(runtime, "_c", lambda _code, text: text)
    output = StringIO()
    monkeypatch.setattr(runtime.sys, "stdout", output)
    runtime.emit({"type": "tool-result", "result": "ok", "err": None})
    assert "✔ RESULT" in output.getvalue() and "✖ FAILED" not in output.getvalue()


def test_copy_and_permission_preview_are_inert_but_request_is_unchanged():
    raw = "printf '☃\x1b]52;c;ZmFrZQ==\x07'"
    app = make_app()
    copied = []
    def copy_to_clipboard(text: str) -> None:
        copied.append(text)
    app.copy_to_clipboard = copy_to_clipboard
    app._last_selected_text = raw
    click = SimpleNamespace(button=3, stop=Mock())
    app.on_mouse_down(cast(events.MouseDown, click))
    assert copied == [sanitize_text(raw)]
    request = BridgedPermissionRequest(tool="shell", summary="shell command", detail=raw,
                                       resolve=Mock(), reject=Mock())
    output = StringIO()
    Console(file=output, width=100, color_system=None).print(PermissionModal(request).render())
    assert not CONTROLS.search(output.getvalue())
    assert request.detail == raw


async def test_display_sanitization_never_changes_file_content(tmp_path):
    raw = "Tiếng Việt\r\n\x1b[31mproof\x1b]52;c;ZmFrZQ==\x07"
    path = tmp_path / "proof.txt"
    tool = FileWriteTool()
    registry = Registry()
    registry.register(tool)
    args = {"path": str(path), "content": raw}
    original = deepcopy(args)

    class Approve:
        async def ask(self, request, signal=None):
            preview = sanitize_text(request.detail)
            assert not CONTROLS.search(preview)
            assert "proof" in preview
            return Decision.ALLOW_ONCE

    await registry.execute(tool.name(), args, None, Approve())
    assert args == original and path.read_bytes() == raw.encode("utf-8")
