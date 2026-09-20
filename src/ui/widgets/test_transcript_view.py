from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.geometry import Offset
from textual.selection import Selection

from src.ui.core.state import TranscriptEntry
from src.ui.widgets.transcript import EntryKind, ROLE_STYLES, entry_view
from src.ui.widgets.transcript_view import TranscriptView


_FOUR_COLUMN_TABLE = """| Technique | Target | Evidence | Mitigation |
| --- | --- | --- | --- |
| Error-based injection | `/api/report` | Database error reveals detailed schema information | Parameterize queries and validate every untrusted value before execution |"""


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


@pytest.mark.asyncio
async def test_four_column_table_is_laid_out_at_transcript_content_width() -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(60, 12)) as pilot:
        app.transcript.clear()
        app.transcript._write_entry(
            TranscriptEntry(kind="assistant", text=_FOUR_COLUMN_TABLE)
        )
        await pilot.pause()

        width = app.transcript.transcript_content_width
        table_lines = [line.text for line in app.transcript.lines if line.text]
        body_lines = [line for line in table_lines if "│" in line]

        assert width == 59
        assert max(map(len, table_lines)) <= width
        assert all(line.startswith("  ") for line in table_lines)
        assert all(line.endswith(("╮", "│", "┤", "╯")) for line in table_lines)
        assert len({tuple(i for i, char in enumerate(line) if char == "│") for line in body_lines}) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "content", "expected"),
    [
        ("tool-result", "[ok] http", "↳ [ok] http"),
        ("user", "message", "› message"),
        ("assistant", "response", "  response"),
        ("system", "compacted", "· compacted"),
        ("error", "error text", "! error text"),
        ("finding", "finding text", "★ finding text"),
        ("decision", "decision text", "· decision text"),
    ],
)
async def test_transcript_role_prefixes_preserve_their_configured_separator(
    kind: EntryKind,
    content: str,
    expected: str,
) -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(80, 8)) as pilot:
        app.transcript.clear()
        app.transcript._write_entry(TranscriptEntry(kind=kind, text=content))
        await pilot.pause()

        assert app.transcript.lines[0].text == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("Ask User", "⚙  Ask User"),
        ("http GET https://example.test", "⚙  http GET https://example.test"),
    ],
)
async def test_tool_call_uses_extra_visual_separator(
    content: str,
    expected: str,
) -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(80, 8)) as pilot:
        app.transcript.clear()
        app.transcript._write_entry(TranscriptEntry(kind="tool-call", text=content))
        await pilot.pause()

        assert app.transcript.lines[0].text == expected


@pytest.mark.parametrize("kind", ROLE_STYLES)
def test_entry_view_preserves_each_configured_prefix(kind: EntryKind) -> None:
    entry = TranscriptEntry(kind=kind, text="content")

    assert entry_view(entry)[0].text == f"{ROLE_STYLES[kind].prefix}content"


@pytest.mark.asyncio
async def test_two_column_table_still_fits_without_secondary_wrapping() -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(40, 10)) as pilot:
        app.transcript.clear()
        app.transcript._write_entry(
            TranscriptEntry(
                kind="assistant",
                text="| Name | Value |\n| --- | --- |\n| alpha | beta |",
            )
        )
        await pilot.pause()

        table_lines = [line.text for line in app.transcript.lines if line.text]

        assert max(map(len, table_lines)) <= app.transcript.transcript_content_width
        assert all(line.startswith("  ") for line in table_lines)
        assert table_lines[0].endswith("╮")
        assert table_lines[-1].endswith("╯")


@pytest.mark.asyncio
async def test_new_table_uses_content_width_after_terminal_resize() -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(80, 12)) as pilot:
        assert app.transcript.transcript_content_width == 79
        await pilot.resize_terminal(50, 12)
        app.transcript.clear()
        app.transcript._write_entry(
            TranscriptEntry(kind="assistant", text=_FOUR_COLUMN_TABLE)
        )
        await pilot.pause()

        width = app.transcript.transcript_content_width
        table_lines = [line.text for line in app.transcript.lines if line.text]

        assert width == 49
        assert max(map(len, table_lines)) <= width
        assert all(line.startswith("  ") for line in table_lines)


@pytest.mark.asyncio
async def test_scrollbar_stays_narrow_to_preserve_stable_table_width() -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(40, 8)) as pilot:
        await pilot.pause()

        assert app.transcript.show_vertical_scrollbar is True
        assert app.transcript.scrollbar_size_vertical == 1
        assert app.transcript.transcript_content_width == 39
        assert app.transcript.styles.scrollbar_color.hex == "#7E8A9A"


@pytest.mark.asyncio
async def test_get_selection_preserves_valid_single_and_multiline_text() -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(40, 8)):
        app.transcript.write("gamma delta")

        assert app.transcript.get_selection(
            Selection(Offset(1, 0), Offset(5, 0))
        ) == ("lpha", "\n")
        assert app.transcript.get_selection(
            Selection(Offset(6, 0), Offset(5, 1))
        ) == ("beta\ngamma", "\n")


@pytest.mark.asyncio
@pytest.mark.parametrize("start_line", [1, 2, 219])
async def test_get_selection_rejects_start_at_or_beyond_end(
    start_line: int,
) -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(40, 8)):
        assert app.transcript.get_selection(
            Selection(Offset(60, start_line), Offset(63, start_line))
        ) is None


@pytest.mark.asyncio
async def test_get_selection_handles_last_blank_transcript_line() -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(80, 8)):
        for index in range(218):
            app.transcript.write(f"row-{index}")
        app.transcript.write("")

        assert len(app.transcript.lines) == 220
        assert app.transcript.get_selection(
            Selection(Offset(60, 219), Offset(63, 219))
        ) == ("", "\n")


@pytest.mark.asyncio
async def test_get_selection_clamps_end_beyond_current_content() -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(40, 8)):
        app.transcript.write("gamma")

        assert app.transcript.get_selection(
            Selection(Offset(6, 0), Offset(99, 219))
        ) == ("beta\ngamma", "\n")


@pytest.mark.asyncio
async def test_get_selection_handles_empty_transcript() -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(40, 8)):
        app.transcript.clear()

        assert app.transcript.get_selection(
            Selection(Offset(0, 0), Offset(1, 0))
        ) is None


@pytest.mark.asyncio
async def test_get_selection_handles_stale_selection_after_content_shrinks() -> None:
    app = _ScrolledTranscriptHarness()
    async with app.run_test(size=(40, 8)):
        stale_selection = Selection(Offset(7, 15), Offset(15, 15))
        app.transcript.clear()
        app.transcript.write("replacement")

        assert app.transcript.get_selection(stale_selection) is None


@pytest.mark.asyncio
async def test_get_selection_clamps_negative_offsets_without_negative_indexing() -> None:
    app = _TranscriptHarness()
    async with app.run_test(size=(40, 8)):
        assert app.transcript.get_selection(
            Selection(Offset(-4, -1), Offset(5, 0))
        ) == ("alpha", "\n")
        assert app.transcript.get_selection(
            Selection(None, Offset(1, -1))
        ) is None
