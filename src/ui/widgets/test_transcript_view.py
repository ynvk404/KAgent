from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.geometry import Offset
from textual.selection import Selection

from src.ui.widgets.transcript_view import TranscriptView


class _TranscriptHarness(App):
    CSS = """
    Screen > .screen--selection {
        background: #38BDF8 30%;
        color: transparent;
    }
    """

    def compose(self) -> ComposeResult:
        self.transcript = TranscriptView()
        yield self.transcript

    def on_mount(self) -> None:
        self.transcript.write("alpha beta")


class _ScrolledTranscriptHarness(App):
    CSS = _TranscriptHarness.CSS

    def compose(self) -> ComposeResult:
        self.transcript = TranscriptView()
        yield self.transcript

    def on_mount(self) -> None:
        for index in range(16):
            self.transcript.write(f"row-{index:02d} selected text")


@pytest.mark.asyncio
async def test_transcript_lines_expose_offsets_for_mouse_selection() -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(40, 8)) as pilot:
        widget, offset = app.screen.get_widget_and_offset_at(3, 0)

        assert widget is app.transcript
        assert offset is not None
        assert (offset.x, offset.y) == (3, 0)

        await pilot.mouse_down(app.transcript, offset=(1, 0))
        await pilot.hover(app.transcript, offset=(5, 0))
        await pilot.mouse_up(app.transcript, offset=(5, 0))

        assert app.screen.get_selected_text() == "lpha "
        selected_line = app.transcript.render_line(0)
        assert any(
            segment.style is not None
            and segment.style.bgcolor == app.transcript.selection_style.bgcolor
            and segment.style.color is not None
            for segment in selected_line
            if segment.text == "lpha "
        )
        app.screen.action_copy_text()
        assert app.clipboard == "lpha "


@pytest.mark.asyncio
async def test_selection_style_uses_richlog_virtual_line_coordinates() -> None:
    app = _ScrolledTranscriptHarness()
    async with app.run_test(size=(40, 8)) as pilot:
        await pilot.pause()
        app.transcript.auto_scroll = False
        app.transcript.scroll_y = 4
        app.screen.selections = {
            app.transcript: Selection(Offset(7, 4), Offset(15, 4))
        }

        selected_line = app.transcript.render_line(0)
        assert any(
            segment.text == "selected"
            and segment.style is not None
            and segment.style.bgcolor == app.transcript.selection_style.bgcolor
            and segment.style.color is not None
            for segment in selected_line
        )
