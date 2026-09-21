
from __future__ import annotations

import pytest
from textual.app import App, ComposeResult

from src.ui.widgets.status_bar import (
    SPINNER_FRAMES,
    WAITING_MARKER,
    StatusBar,
    StatusProps,
    busy_line,
    format_elapsed,
)
from src.ui.theme import ACCENT, BOLD_SUCCESS, WARNING


def props(**overrides) -> StatusProps:
    base: dict = dict(
        busy=False,
        api_ready=True,
        active_skill=None,
        yolo=False,
        ctx_tokens=0,
        request_tokens=0,
        compact_threshold=0,
        memory_items=0,
        phase="idle",
        transcript_filter="all",
        expand_hint=False,
    )
    base.update(overrides)
    return StatusProps(**base)


class _HarnessApp(App):
    def __init__(self, status_props: StatusProps) -> None:
        super().__init__()
        self._status_props = status_props

    def compose(self) -> ComposeResult:
        yield StatusBar()

    def on_mount(self) -> None:
        self.query_one(StatusBar).apply(self._status_props)


async def render_frame(status_props: StatusProps, size: tuple[int, int] = (100, 3)) -> str:
    app = _HarnessApp(status_props)
    async with app.run_test(size=size):
        return app.query_one(StatusBar).render().plain


class TestFormatElapsed:
    def test_formats_seconds_as_mmss(self) -> None:
        assert format_elapsed(0) == "00:00"
        assert format_elapsed(42) == "00:42"
        assert format_elapsed(125) == "02:05"
        assert format_elapsed(3807) == "1:03:27"


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
        assert "time 00:42" in frame
        assert "turn 00:42" not in frame
        assert "Esc to cancel" in frame

    def test_tool_skill_precedes_final_cancel_hint(self) -> None:
        frame = busy_line(
            props(
                busy=True,
                phase="running-tool",
                running_tool="Shell · Print text",
                elapsed_seconds=30,
                active_skill="recon",
            )
        ).plain

        assert frame.endswith("skill: recon · Esc to cancel")
        assert "Esc to cancel · skill: recon" not in frame

    def test_tool_without_skill_keeps_cancel_hint_last(self) -> None:
        frame = busy_line(
            props(
                busy=True,
                phase="running-tool",
                running_tool="HTTP · GET /health",
                elapsed_seconds=4,
            )
        ).plain

        assert frame.endswith("Esc to cancel")
        assert frame.count("Esc to cancel") == 1

    def test_prompt_processing_skill_precedes_final_cancel_hint(self) -> None:
        frame = busy_line(
            props(
                busy=True,
                phase="planning",
                elapsed_seconds=8,
                active_skill="recon",
            )
        ).plain

        assert frame.endswith("skill: recon · Esc to cancel")

    def test_repeated_busy_refresh_does_not_duplicate_cancel_hint(self) -> None:
        status = StatusBar()
        status.apply(
            props(
                busy=True,
                phase="running-tool",
                running_tool="HTTP · GET /",
                active_skill="recon",
            )
        )
        first = status.render().plain
        status.elapsed_seconds = 1
        second = status.render().plain

        assert first.count("Esc to cancel") == 1
        assert second.count("Esc to cancel") == 1
        assert second.endswith("skill: recon · Esc to cancel")

    def test_falls_back_to_phase_word_when_no_tool_is_running(self) -> None:
        frame = busy_line(
            props(busy=True, phase="planning", elapsed_seconds=3)
        ).plain
        assert "planning" in frame
        assert "time 00:03" in frame

    def test_uses_accent_for_running_state(self) -> None:
        line = busy_line(props(busy=True, phase="planning"))
        assert line.spans[0].style == ACCENT

    @pytest.mark.parametrize("phase", ["planning", "answering", "running-tool"])
    def test_animates_active_processing_phases(self, phase: str) -> None:
        first = busy_line(
            props(busy=True, phase=phase, elapsed_seconds=0)
        ).plain
        second = busy_line(
            props(busy=True, phase=phase, elapsed_seconds=1)
        ).plain

        assert first.startswith(SPINNER_FRAMES[0])
        assert second.startswith(SPINNER_FRAMES[1])
        assert first[0] != second[0]

    @pytest.mark.parametrize(
        ("phase", "label"),
        [("waiting-user", "waiting input"), ("waiting-approval", "waiting approval")],
    )
    def test_waiting_phases_use_a_stable_marker(self, phase: str, label: str) -> None:
        first = busy_line(
            props(busy=True, phase=phase, elapsed_seconds=0)
        ).plain
        later = busy_line(
            props(busy=True, phase=phase, elapsed_seconds=9)
        ).plain

        assert first.startswith(f"{WAITING_MARKER} {label}")
        assert later.startswith(f"{WAITING_MARKER} {label}")
        assert "Esc to cancel" not in first
        assert "Esc to cancel" not in later

    def test_idle_state_does_not_render_the_busy_indicator(self) -> None:
        from src.ui.widgets.status_bar import idle_line

        line = idle_line(props(busy=False, phase="idle")).plain

        assert line.startswith("ready · idle")
        assert not line.startswith((*SPINNER_FRAMES, WAITING_MARKER))

    def test_idle_state_retains_final_turn_time_after_context(self) -> None:
        from src.ui.widgets.status_bar import idle_line

        line = idle_line(
            props(
                busy=False,
                phase="idle",
                ctx_tokens=2300,
                request_tokens=7300,
                compact_threshold=6000,
                elapsed_seconds=18,
            )
        ).plain

        assert "hist ~2.3k · req ~7.3k/6k 122% · time 00:18" in line

    @pytest.mark.asyncio
    async def test_wide_idle_status_orders_hints_metrics_then_expand_last(self) -> None:
        frame = await render_frame(
            props(
                model="openai/gpt-oss-20b",
                tool_support="yes",
                ctx_tokens=2400,
                request_tokens=5400,
                compact_threshold=6000,
                elapsed_seconds=1,
                expand_hint=True,
            ),
            size=(140, 3),
        )
        line = next(line for line in frame.splitlines() if "ready" in line)

        fields = [
            "ready · idle",
            "openai/gpt-oss-20b [tools ✓]",
            "Enter send",
            "/ commands",
            "hist ~2.4k · req ~5.4k/6k 90%",
            "time 00:01",
            "Ctrl-O expand output",
        ]
        positions = [line.index(field) for field in fields]
        assert positions == sorted(positions)
        assert line.endswith("Ctrl-O expand output")
        assert "turn 00:01" not in line

    @pytest.mark.asyncio
    async def test_medium_width_drops_only_expand_before_hints_and_metrics(self) -> None:
        frame = await render_frame(
            props(
                model="openai/gpt-oss-20b",
                tool_support="yes",
                ctx_tokens=2400,
                request_tokens=5400,
                compact_threshold=6000,
                elapsed_seconds=1,
                expand_hint=True,
            ),
            size=(120, 3),
        )

        assert "Enter send · / commands" in frame
        assert "hist ~2.4k · req ~5.4k/6k 90%" in frame
        assert "time 00:01" in frame
        assert "Ctrl-O expand output" not in frame

    @pytest.mark.asyncio
    async def test_narrow_status_preserves_context_and_time_before_expand_hint(self) -> None:
        frame = await render_frame(
            props(
                model="gpt-oss-20b",
                tool_support="yes",
                ctx_tokens=2300,
                request_tokens=5300,
                compact_threshold=6000,
                elapsed_seconds=18,
                expand_hint=True,
            ),
            size=(72, 3),
        )

        assert "h~2.3k · r~5.3k/6k 88%" in frame
        assert "time 00:18" in frame
        assert "Ctrl-O expand output" not in frame

    def test_keeps_success_and_warning_semantics_distinct(self) -> None:
        from src.ui.widgets.status_bar import idle_line

        ready = idle_line(props(api_ready=True))
        pressure = idle_line(
            props(ctx_tokens=90, request_tokens=90, compact_threshold=100)
        )

        assert ready.spans[0].style == BOLD_SUCCESS
        assert any(span.style == WARNING for span in pressure.spans)


@pytest.mark.asyncio
class TestStatusBarAutoApproveBadge:
    async def test_shows_supermode_on_the_same_line_as_status_pinned_right(self) -> None:
        frame = await render_frame(props(yolo=True, api_ready=True))
        assert "AutoApprove" in frame
        ready_line = next((line for line in frame.split("\n") if "ready" in line), "")
        assert "AutoApprove" in ready_line
        assert ready_line.index("AutoApprove") > ready_line.index("ready")

    async def test_shows_supermode_while_busy_too(self) -> None:
        frame = await render_frame(props(yolo=True, busy=True))
        assert "AutoApprove" in frame
        assert "Esc to cancel" in frame

    async def test_hides_supermode_when_yolo_is_off(self) -> None:
        frame = await render_frame(props(yolo=False))
        assert "AutoApprove" not in frame
