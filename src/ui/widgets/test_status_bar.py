"""Tests for status_bar.py.
"""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult

from .status_bar import StatusBar, StatusProps, busy_line, format_elapsed


def props(**overrides) -> StatusProps:
    base: dict = dict(
        busy=False,
        api_ready=True,
        active_skill=None,
        yolo=False,
        ctx_tokens=0,
        compact_threshold=0,
        memory_items=0,
        phase="idle",
        transcript_filter="all",
        expand_hint=False,
    )
    base.update(overrides)
    return StatusProps(**base)


class _HarnessApp(App):
    """Minimal host app so StatusBar can be mounted and measured, the way
    ink-testing-library's `render()` mounts a component into a virtual
    terminal."""

    def __init__(self, status_props: StatusProps) -> None:
        super().__init__()
        self._status_props = status_props

    def compose(self) -> ComposeResult:
        yield StatusBar()

    def on_mount(self) -> None:
        self.query_one(StatusBar).apply(self._status_props)


async def render_frame(status_props: StatusProps, size: tuple[int, int] = (100, 3)) -> str:
    """Equivalent of `render(<StatusBar {...props} />).lastFrame()`."""
    app = _HarnessApp(status_props)
    async with app.run_test(size=size):
        return app.query_one(StatusBar).render().plain


class TestFormatElapsed:
    def test_formats_seconds_as_mmss(self) -> None:
        assert format_elapsed(0) == "0:00"
        assert format_elapsed(42) == "0:42"
        assert format_elapsed(125) == "2:05"
        assert format_elapsed(3700) == "61:40"


class TestStatusBarBusyLine:
    def test_names_running_tool_and_shows_elapsed_clock(self) -> None:
        frame = busy_line(
            props(
                busy=True,
                phase="running-tool",
                running_tool="Shell · HTTP request",
                elapsed_seconds=42,
            )
        ).plain
        assert "Shell · HTTP request" in frame
        assert "0:42" in frame
        assert "Esc to cancel" in frame

    def test_falls_back_to_phase_word_when_no_tool_is_running(self) -> None:
        frame = busy_line(
            props(busy=True, phase="planning", elapsed_seconds=3)
        ).plain
        assert "planning" in frame
        assert "0:03" in frame


@pytest.mark.asyncio
class TestStatusBarAutoApproveBadge:
    async def test_shows_supermode_on_the_same_line_as_status_pinned_right(self) -> None:
        frame = await render_frame(props(yolo=True, api_ready=True))
        assert "AutoApprove" in frame
        # It shares the status row - the line with "ready" also carries it.
        ready_line = next((line for line in frame.split("\n") if "ready" in line), "")
        assert "AutoApprove" in ready_line
        # ...and it's pushed to the right of the status text (space-between).
        assert ready_line.index("AutoApprove") > ready_line.index("ready")

    async def test_shows_supermode_while_busy_too(self) -> None:
        frame = await render_frame(props(yolo=True, busy=True))
        assert "AutoApprove" in frame
        assert "Esc to cancel" in frame

    async def test_hides_supermode_when_yolo_is_off(self) -> None:
        frame = await render_frame(props(yolo=False))
        assert "AutoApprove" not in frame