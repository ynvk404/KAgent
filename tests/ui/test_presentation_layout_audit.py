"""Reproduced layout failures, checked against complete cells and compositor output."""
from __future__ import annotations

import pytest
from rich.cells import cell_len
from rich.text import Text
from textual.geometry import Offset
from unittest.mock import Mock

from src.ui.core.app import KAgent
from src.ui.commands.slash_items import SLASH_ITEMS
from src.ui.core.state import Append, TranscriptEntry, SetAsk
from src.tools.common.ask import Option, Question
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.render.markdown import render_markdown
from src.ui.widgets.status_bar import idle_line
from src.ui.widgets.ask_modal import AskModal
from tests.ui.test_input_rendering import app  # Full offline TUI fixture.
from tests.ui.test_status_bar import props


VIEWPORTS = [(160, 40), (100, 30), (48, 20)]
HEADERS = ["ID", "Method", "Endpoint", "Parameter", "Class", "Outcome", "Evidence", "Coverage"]
VALUES = ["candidate-1", "POST", "/api/report", "selected_input", "injection", "pending", "artifact.txt", "incomplete"]
TABLE = "\n".join((
    "| " + " | ".join(HEADERS) + " |",
    "| " + " | ".join("---" for _ in HEADERS) + " |",
    "| " + " | ".join(VALUES) + " |",
))


def assert_complete_table(lines: list[str]) -> None:
    separator = next(i for i, line in enumerate(lines) if "├" in line)
    for part, expected in ((lines[:separator], HEADERS), (lines[separator + 1:], VALUES)):
        rows = [line.split("│")[1:-1] for line in part if "│" in line]
        assert rows and all(len(row) == len(expected) for row in rows)
        for column, value in enumerate(expected):
            assert "".join(row[column].strip() for row in rows) == value
    assert "…" not in "\n".join(lines)


@pytest.mark.parametrize("width", [154, 94, 42])
def test_markdown_table_wraps_every_cell_without_losing_identifiers(width: int) -> None:
    lines = Text.from_ansi(render_markdown(TABLE, width=width)).plain.splitlines()
    assert max(map(cell_len, lines)) <= width - 2
    assert_complete_table(lines)


@pytest.mark.parametrize("size", VIEWPORTS)
async def test_markdown_table_remains_complete_in_the_actual_transcript(app: KAgent, size) -> None:
    async with app.run_test(size=size) as pilot:
        app.dispatch(Append(TranscriptEntry("assistant", TABLE)))
        await pilot.pause()
        lines = [line.text for line in app.transcript_log.lines if line.text]
        assert max(map(cell_len, lines)) <= app.transcript_log.transcript_content_width
        assert app.transcript_log.max_scroll_x == 0
        assert_complete_table(lines)
        app.transcript_log.scroll_end(animate=False, immediate=True, x_axis=False)
        await pilot.pause()
        assert app.transcript_log.is_vertical_scroll_end


async def test_existing_markdown_table_reflows_without_cell_loss(app: KAgent) -> None:
    async with app.run_test(size=VIEWPORTS[0]) as pilot:
        app.dispatch(Append(TranscriptEntry("assistant", TABLE)))
        await pilot.pause()
        for width, height in [*VIEWPORTS[1:], VIEWPORTS[0]]:
            await pilot.resize_terminal(width, height)
            await pilot.pause()
            lines = [line.text for line in app.transcript_log.lines if line.text]
            assert max(map(cell_len, lines)) <= app.transcript_log.transcript_content_width
            assert app.transcript_log.max_scroll_x == 0
            assert_complete_table(lines)


def wide_table() -> str:
    headers = [f"Header{i:02d}" for i in range(16)]
    return "\n".join((
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
        "| " + " | ".join(f"VALUE{i:02d}" for i in range(16)) + " |",
        "| " + " | ".join(f"SECOND{i:02d}" for i in range(16)) + " |",
    ))


async def test_wide_table_switches_to_readable_fields_and_back_on_resize(app: KAgent) -> None:
    async with app.run_test(size=VIEWPORTS[0]) as pilot:
        app.dispatch(Append(TranscriptEntry("assistant", wide_table())))
        await pilot.pause()
        for width, height in [*VIEWPORTS[1:], VIEWPORTS[0]]:
            await pilot.resize_terminal(width, height)
            await pilot.pause()
            lines = [line.text for line in app.transcript_log.lines if line.text]
            assert max(map(cell_len, lines)) <= app.transcript_log.transcript_content_width
            text = "\n".join(lines)
            if "│" in text:
                separator = next(i for i, line in enumerate(lines) if "├" in line)
                header = [line.split("│")[1:-1] for line in lines[:separator] if "│" in line]
                body = [line.split("│")[1:-1] for line in lines[separator + 1:] if "│" in line]
                for column in range(16):
                    assert "".join(row[column].strip() for row in header) == f"Header{column:02d}"
                    assert "".join(row[column].strip() for row in body) == f"VALUE{column:02d}SECOND{column:02d}"
            else:
                for column in range(16):
                    for label in (f"Header{column:02d}", f"VALUE{column:02d}", f"SECOND{column:02d}"):
                        assert label in text
            assert app.transcript_log.max_scroll_x == 0
            assert ("│" in text) == (width != 48)


def test_idle_status_shortens_model_before_hiding_context_and_elapsed_time() -> None:
    status = idle_line(props(
        model="organization/research-model-with-a-long-name-and-version-2026",
        tool_support="yes", ctx_tokens=2300, request_tokens=5300,
        compact_threshold=6000, elapsed_seconds=18,
    ), width=86)
    assert status.cell_len <= 86
    assert "…" in status.plain
    assert "h~2.3k · r~5.3k/6k soft 88%" in status.plain
    assert "time 00:18" in status.plain


@pytest.mark.parametrize("busy", [False, True])
@pytest.mark.parametrize("size", VIEWPORTS)
async def test_status_badge_stays_visible_with_long_runtime_metadata(
    app: KAgent, size, busy: bool,
) -> None:
    async with app.run_test(size=size) as pilot:
        status = app.status_bar
        status.apply(props(
            busy=busy, yolo=True, phase="running-tool" if busy else "idle",
            model="organization/research-model-with-a-long-name-and-version-2026",
            running_tool="ffuf preparing/reviewing · scanner job",
            tool_support="yes", ctx_tokens=2300, request_tokens=5300,
            compact_threshold=6000, elapsed_seconds=18,
        ))
        await pilot.pause()
        line = status.render()
        assert line.cell_len <= status.content_size.width
        assert line.plain.endswith("AutoApprove")
        screen_line = app.screen._compositor.render_strips()[status.region.y].text
        assert "AutoApprove" in screen_line
        assert status.region.bottom <= size[1]


def prepare_completion(app: KAgent) -> None:
    app.input.set_value("/")
    app._recompute_menus()
    app.slash_idx = 8
    app._sync_overlay()
    app._render_input()


def completion_rows(app: KAgent, index: int) -> list[int]:
    widget = app.overlay_text_static
    return [y for y in range(widget.size.height) if any(
        segment.style and segment.style.meta.get("completion_item") == index
        for segment in widget.render_line(y)
    )]


def assert_completion_layout(app: KAgent) -> None:
    assert app.transcript_log.size.height >= 2
    assert app.input_static.region.bottom <= app.size.height
    assert app.status_bar.region.bottom <= app.size.height
    assert app.overlay_content_static.max_scroll_x == 0
    rows = completion_rows(app, app.slash_idx)
    scroll = app.overlay_content_static
    assert rows
    assert int(scroll.scroll_y) <= rows[0] < int(scroll.scroll_y) + scroll.scrollable_content_region.height
    frame = "\n".join(strip.text for strip in app.screen._compositor.render_strips())
    assert "Input" in frame and "ready" in frame


@pytest.mark.parametrize("size", VIEWPORTS)
async def test_completion_menu_bounds_navigation_and_resize(
    app: KAgent, size,
) -> None:
    async with app.run_test(size=size) as pilot:
        prepare_completion(app)
        await pilot.pause()
        assert_completion_layout(app)
        original_input = app.input.value
        await pilot.press("down", "down")
        await pilot.pause()
        assert_completion_layout(app)
        selection = app.slash_idx
        for width, height in VIEWPORTS:
            await pilot.resize_terminal(width, height)
            await pilot.pause()
            assert_completion_layout(app)
            assert app.slash_idx == selection
        assert app.input.value == original_input
        assert not app.state.transcript


@pytest.mark.parametrize("size", [(100, 30), (48, 20)])
async def test_click_on_wrapped_slash_continuation_selects_its_actual_item(
    app: KAgent, size,
) -> None:
    async with app.run_test(size=size) as pilot:
        prepare_completion(app)
        await pilot.pause()
        index = next(i for i, item in enumerate(SLASH_ITEMS) if item.name == "/scope")
        rows = completion_rows(app, index)
        assert len(rows) > 1
        target = rows[1]
        app.overlay_content_static.scroll_to(y=target, animate=False, immediate=True)
        await pilot.pause()
        offset_y = app.overlay_text_static.region.y + target - app.overlay_content_static.region.y
        await pilot.click("#overlay-content", offset=(3, offset_y))
        await pilot.pause()
        assert app.slash_idx == index
        assert app.input.value == "/"
        assert not app.state.transcript


@pytest.mark.parametrize("size", VIEWPORTS)
async def test_long_prompt_scrolls_its_caret_without_covering_transcript_or_status(
    app: KAgent, size,
) -> None:
    value = "Review this authorized fixture. " + "界 e\u0301 observed evidence and next steps. " * 60
    async with app.run_test(size=size) as pilot:
        app.input.set_value(value)
        app._render_input()
        await pilot.pause()
        assert app.input_panel.max_scroll_y > 0
        for keys in [("ctrl+a",), ("right",), ("ctrl+e",)]:
            await pilot.press(*keys)
            await pilot.pause()
            assert app.input.value == value
            assert app.input_panel.region.bottom <= app.size.height
            assert app.status_bar.region.bottom <= app.size.height
            assert app.transcript_panel.region.bottom <= app.input_panel.region.y
            assert app.transcript_log.size.height >= 2
            assert app.cursor_position == visible_input_caret(app)
        for width, height in VIEWPORTS:
            await pilot.resize_terminal(width, height)
            await pilot.pause()
            assert app.input.value == value
            assert app.status_bar.region.bottom <= height
            assert app.transcript_panel.region.bottom <= app.input_panel.region.y
            assert app.cursor_position == visible_input_caret(app)


def visible_input_caret(app: KAgent) -> Offset:
    for y, strip in enumerate(app.screen._compositor.render_strips()):
        x = 0
        for segment in strip:
            if segment.style and segment.style.meta.get("kagent_caret"):
                assert app.input_panel.scrollable_content_region.contains(x, y)
                return Offset(x, y)
            x += segment.cell_length
    raise AssertionError("Input caret is outside the visible viewport")


async def test_picker_reveals_selection_after_child_layout_width_settles(app: KAgent) -> None:
    async with app.run_test(size=(100, 30)) as pilot:
        app.dispatch(SetAsk(AskRequest(
            Question(header="model", question="Select an offline fixture model", options=[
                Option(label=f"model-{i}", description="full description " * 35) for i in range(8)
            ]), resolve=Mock(), reject=Mock(),
        )))
        await pilot.pause()
        await pilot.press("down", "down", "down", "down")
        await pilot.pause()
        # Parent/scrollbar layout may settle after the app's Resize handler.
        # Exercise the child width changing without another app Resize event.
        app.overlay_text_static.styles.width = "50%"
        await pilot.pause()
        widget = app.overlay_text_static
        rows = [y for y in range(widget.size.height) if any(
            segment.style and segment.style.meta.get("modal_item") == 4
            for segment in widget.render_line(y)
        )]
        scroll = app.overlay_content_static
        assert rows
        assert int(scroll.scroll_y) <= rows[0] < int(scroll.scroll_y) + scroll.scrollable_content_region.height
        modal = app._get_active_modal()
        assert isinstance(modal, AskModal) and modal.idx == 4
