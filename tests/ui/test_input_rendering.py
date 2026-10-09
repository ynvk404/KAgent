"""Exercise real Textual dispatch/rendering without a provider or network."""
from __future__ import annotations

import asyncio
import io
import sys
from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from rich.cells import cell_len
from textual import events
from textual.app import ComposeResult
from textual.drivers.headless_driver import HeadlessDriver
from textual.geometry import Offset
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from src.agent.agent import Agent
from src.ui.core.app import AppProps, KAgent
from src.ui.core.state import Append, TranscriptEntry
from src.ui.widgets.banner import BannerData
from src.ui.widgets.input_box import DEFAULT_PROMPT
from src.ui.widgets.text_input_modal import TextInputRequest
from tests.helpers.ui_fakes import make_test_config_snapshot


class RecordingDriver(HeadlessDriver):
    """Use Textual's output/capture lifecycle, with an in-memory terminal sink."""

    @property
    def is_headless(self) -> bool:
        return False

    def write(self, data: str) -> None:
        self.output.append(data)

    def start_application_mode(self) -> None:
        self.output: list[str] = []
        super().start_application_mode()


@pytest.fixture
def app() -> KAgent:
    agent = MagicMock()
    agent.skills.list_enabled.return_value = []
    agent.skills.list.return_value = []
    agent.target.empty.return_value = True
    agent.target.base_url.return_value = None
    agent.target.name.return_value = "target"
    agent.get_memory_stats.return_value.items = 0
    agent.get_memory_stats.return_value.compactions = 0
    agent.approx_tokens.return_value = 0
    agent.idle_request_estimate.return_value.estimated_total = 0
    agent.get_auto_compact_threshold.return_value = 0
    agent.get_max_steps.return_value = 10
    agent.thinking_is_enabled.return_value = False
    agent.is_running.return_value = False
    agent.save_context_snapshot = AsyncMock(return_value=None)
    # No pinger: on_mount runs normally but cannot call an external provider.
    agent.client = object()
    app = KAgent(AppProps(
        agent=cast(Agent, agent),
        banner_data=BannerData(provider="offline", model="test", cwd="."),
        parent_signal=asyncio.Event(),
        read_config=lambda: make_test_config_snapshot(model="test"),
        apply_provider=AsyncMock(),
    ))
    app.run_agent_turn = AsyncMock()
    return app


def visible_caret(app: KAgent, widget: Static) -> Offset:
    """Find the drawn caret independently of terminal cursor bookkeeping."""
    region = widget.region
    for y, strip in enumerate(app.screen._compositor.render_strips()):
        if region.y <= y < region.bottom:
            index = strip.text.find("▌")
            if index >= 0:
                return Offset(cell_len(strip.text[:index]), y)
    raise AssertionError("The editable widget has no visible caret")


@pytest.mark.asyncio
async def test_terminal_cursor_starts_at_drawn_input_caret(app: KAgent) -> None:
    async with app.run_test(size=(100, 30)):
        assert app.cursor_position == visible_caret(app, app.input_static)
        assert app.input_static.region.contains(app.cursor_position.x, app.cursor_position.y)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["/scope", "/scope show", "/help", "ssssssss", "hello", "tiếng Việt"])
async def test_typing_does_not_leak_into_transcript(app: KAgent, value: str) -> None:
    async with app.run_test(size=(100, 30)) as pilot:
        before = app.state.transcript
        title_row = app.screen._compositor.render_strips()[0].text
        await pilot.press(*value)
        assert app.input.value == value
        assert app.input.cursor == len(value)
        assert app.input_static.value == value
        assert app.state.transcript == before
        assert app.transcript_log.lines == []
        assert app.transcript_panel.border_title == "Transcript"
        assert app.screen._compositor.render_strips()[0].text == title_row
        assert app.cursor_position == visible_caret(app, app.input_static)
        cast(AsyncMock, app.run_agent_turn).assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["/scope", "/scope show", "/help"])
async def test_slash_dispatches_once_and_typing_continues(
    app: KAgent, command: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.ui.core import app as app_module

    handler = Mock(wraps=app_module.handle_slash)
    monkeypatch.setattr(app_module, "handle_slash", handler)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press(*command, "enter")
        handler.assert_called_once_with(app, command)
        assert len(app.state.transcript) == 1
        assert app.state.transcript[0].kind == "system"
        assert app.input.value == ""
        await pilot.press("a", "b", "c")
        assert app.input.value == "abc"
        assert app.cursor_position == visible_caret(app, app.input_static)
        handler.assert_called_once()
        cast(AsyncMock, app.run_agent_turn).assert_not_called()


@pytest.mark.asyncio
async def test_cursor_tracks_editing_focus_and_completion(app: KAgent) -> None:
    async with app.run_test(size=(100, 30)) as pilot:
        app.set_focus(app.transcript_log)
        await pilot.press("a", "界", "b", "left")
        assert app.input.value == "a界b"
        assert app.input.cursor == 2
        assert app.cursor_position == app.input_static.content_region.offset + Offset(
            cell_len(DEFAULT_PROMPT + "a界"), 0,
        )
        app.set_focus(None)
        await pilot.press("x", "backspace", "ctrl+a", "ctrl+e")
        assert app.input.value == "a界b"
        assert app.input.cursor == 3
        assert app.cursor_position == visible_caret(app, app.input_static)
        await pilot.press("escape", "/", "s", "c", "tab")
        assert app.input.value == "/scope "
        assert app.cursor_position == visible_caret(app, app.input_static)
        await pilot.press("tab")
        assert len(app.state.transcript) == 1
        assert app.input.value == ""
        await pilot.press("ctrl+f")
        assert app.state.transcript_filter != "all"
        assert app.cursor_position == visible_caret(app, app.input_static)


@pytest.mark.asyncio
async def test_cursor_follows_wrap_multiline_resize_and_background_layout(app: KAgent) -> None:
    async with app.run_test(size=(40, 24)) as pilot:
        await pilot.press(*("界" * 20), "ctrl+n", "e")
        # Pilot's Unicode-name lookup cannot synthesize a combining mark;
        # deliver the character-bearing event the terminal parser produces.
        assert app._driver is not None
        app._driver.send_message(events.Key("combining_acute_accent", "\u0301"))
        await pilot.press(*"abc")
        assert app.input.value == "界" * 20 + "\ne\u0301abc"
        assert app.cursor_position == visible_caret(app, app.input_static)
        await pilot.resize_terminal(70, 30)
        assert app.cursor_position == visible_caret(app, app.input_static)
        app.dispatch(Append(entry=TranscriptEntry(kind="system", text="background notice")))
        await pilot.pause()
        assert app.cursor_position == visible_caret(app, app.input_static)


@pytest.mark.asyncio
@pytest.mark.parametrize("masked", [False, True])
async def test_text_modal_uses_its_own_caret_then_restores_prompt(
    app: KAgent, masked: bool,
) -> None:
    async with app.run_test(size=(60, 30)) as pilot:
        pending = asyncio.create_task(app.prompt_text(TextInputRequest(
            header="Offline input", question="Enter text", placeholder=None,
            masked=masked, resolve=lambda _: None, reject=lambda _: None,
        )))
        try:
            await pilot.pause()
            assert not app.input_static.display
            assert app.cursor_position == visible_caret(app, app.overlay_text_static)
            await pilot.press(*"abc", "left")
            assert app.cursor_position == visible_caret(app, app.overlay_text_static)
            await pilot.press("enter")
            assert await pending == "abc"
            assert app.input_static.display
            assert app.cursor_position == visible_caret(app, app.input_static)
        finally:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.asyncio
async def test_background_screen_cannot_move_native_input_caret(app: KAgent) -> None:
    class NativeInputScreen(ModalScreen):
        def compose(self) -> ComposeResult:
            yield Input()

    async with app.run_test(size=(80, 30)) as pilot:
        background = app.screen
        await app.push_screen(NativeInputScreen())
        await pilot.press("a")
        native_input = app.screen.query_one(Input)
        position = native_input.cursor_screen_offset
        assert app.cursor_position == position
        # A screen-stack render may revisit the prompt underneath a native
        # Textual modal (e.g. the command palette). Only the top owns the caret.
        app.input_static.refresh()
        background._compositor.render_strips()
        assert app.cursor_position == position
        app.pop_screen()
        await pilot.pause()
        assert app.cursor_position == visible_caret(app, app.input_static)


@pytest.mark.asyncio
async def test_driver_emits_caret_position_and_captures_background_output(
    app: KAgent, monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "__stdout__", stdout)
    monkeypatch.setattr(sys, "__stderr__", stderr)
    app.driver_class = RecordingDriver
    async with app.run_test(headless=False, size=(80, 30)) as pilot:
        await pilot.press(*"abc")
        position = visible_caret(app, app.input_static)
        driver = cast(RecordingDriver, app._driver)
        assert driver.output[-1].endswith(f"\x1b[{position.y + 1};{position.x + 1}H")

        async def background_output() -> None:
            print("offline worker stdout")
            sys.stderr.write("offline worker stderr\n")
            app.dispatch(Append(entry=TranscriptEntry(kind="system", text="worker notice")))

        await asyncio.create_task(background_output())
        await pilot.pause()
        assert stdout.getvalue() == stderr.getvalue() == ""
        output = "".join(driver.output)
        assert "offline worker stdout" not in output
        assert "offline worker stderr" not in output
        assert "worker notice" in output
        assert app.state.transcript[-1].text == "worker notice"
        assert app.cursor_position == visible_caret(app, app.input_static)
    assert app.ping_task is not None and app.ping_task._task is None
    assert app.snapshot_task is not None and app.snapshot_task.done()
