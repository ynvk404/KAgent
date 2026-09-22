from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.text import Text
from textual.reactive import reactive
from textual.widget import Widget

from src.ui.theme import ACCENT, BOLD_ACCENT, BOLD_ERROR, MUTED, SUCCESS

StartupPhase = Literal[
    "identity",
    "workspace",
    "skills",
    "provider",
    "ready",
    "failed",
]

_READINESS_PHASES: frozenset[StartupPhase] = frozenset(
    {"workspace", "skills", "provider", "ready"}
)

PHASE_CONFIG: dict[StartupPhase, tuple[int, str]] = {
    "workspace": (25, "Workspace"),
    "skills": (50, "Skills & tools"),
    "provider": (75, "Provider"),
    "ready": (100, "Ready"),
}

_ROWS: list[tuple[StartupPhase, str]] = [
    ("workspace", "Workspace"),
    ("skills", "Skills & tools"),
    ("provider", "Provider"),
]

_BORDER_TITLES: dict[StartupPhase, str] = {
    "identity": "Startup",
    "workspace": "Initializing",
    "skills": "Initializing",
    "provider": "Initializing",
    "ready": "Ready",
    "failed": "Failed",
}

_FOOTER_STATUS: dict[StartupPhase, str] = {
    "identity": "Starting runtime environment…",
    "workspace": "Preparing interactive workspace…",
    "skills": "Loading environment and runtime tools…",
    "provider": "Verifying provider connection and session…",
    "ready": "Ready to begin testing",
    "failed": "Initialization encountered an error",
}

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧"

WORD = "KAGENT"
SHINE_INTERVAL = 0.12

_PANEL_MAX = 68
_PANEL_MIN = 44

_BAR_MAX = 38
_BAR_MIN = 18

BAR_WIDTH = _BAR_MAX


def _phase_order(phase: StartupPhase) -> int:
    order = {
        "identity": -1,
        "workspace": 0,
        "skills": 1,
        "provider": 2,
        "ready": 3,
        "failed": 99,
    }
    return order.get(phase, -1)


def render_kagent_word(shine_idx: int = 0, shine_done: bool = False) -> Text:
    """Render 'KAGENT' with a moving shine sweep across already-visible letters."""
    heading = Text(justify="center", no_wrap=True)
    for i, ch in enumerate(WORD):
        if not shine_done and i == shine_idx:
            heading.append(ch, style=BOLD_ACCENT)
        else:
            heading.append(ch, style=ACCENT)
    return heading


def render_progress_bar(pct: int, width: int = BAR_WIDTH) -> Text:
    """Deterministic progress bar: [████░░░░░░]  75%  — always uses ACCENT."""
    filled = max(0, min(width, round((pct / 100) * width)))
    empty = width - filled
    bar = Text()
    bar.append("  ", style=MUTED)
    bar.append("█" * filled, style=ACCENT)
    bar.append("░" * empty, style=MUTED)
    bar.append(f"  {pct}%", style=ACCENT)
    return bar


@dataclass(slots=True)
class SplashProps:
    provider: str | None = None
    model: str | None = None
    skill_count: int | None = None
    tool_count: int | None = None
    resumed: bool = False
    resume_summary: str | None = None
    error: str | None = None


class StartupSplash(Widget):
    """Two-phase startup card: identity -> readiness.

    Phase A (identity): KAGENT shine sweep + spinner — shown immediately.
    Phase B (readiness): readiness rows + metadata + progress bar.
    Phase B (readiness): readiness rows + 2-row metadata + progress bar + footer.
    """

    DEFAULT_CSS = """
    StartupSplash {
        width: 100%;
        height: 1fr;
        content-align: center middle;
        align: center middle;
    }
    """

    phase: reactive[StartupPhase] = reactive("identity")
    error: reactive[str | None] = reactive(None)
    _spinner_idx: reactive[int] = reactive(0)
    shine_idx: reactive[int] = reactive(0)
    shine_done: reactive[bool] = reactive(False)

    def __init__(
        self,
        props: SplashProps | None = None,
        *,
        id: str | None = "startup-splash",
    ) -> None:
        super().__init__(id=id)
        self.props = props or SplashProps()
        if self.props.error:
            self.phase = "failed"
            self.error = self.props.error
        self._spinner_timer = None
        self._shine_timer = None

    def on_mount(self) -> None:
        self._spinner_timer = self.set_interval(0.1, self._tick_spinner)
        self._shine_timer = self.set_interval(SHINE_INTERVAL, self._tick_shine)

    def on_unmount(self) -> None:
        self._stop_timers()

    def _stop_timers(self) -> None:
        if self._shine_timer is not None:
            self._shine_timer.stop()
            self._shine_timer = None
        if self._spinner_timer is not None:
            self._spinner_timer.stop()
            self._spinner_timer = None

    def _tick_spinner(self) -> None:
        self._spinner_idx = (self._spinner_idx + 1) % len(_SPINNER)

    def _tick_shine(self) -> None:
        if self.shine_done:
            return
        next_idx = self.shine_idx + 1
        if next_idx >= len(WORD):
            self.shine_idx = len(WORD)
            self.shine_done = True
            if self._shine_timer is not None:
                self._shine_timer.stop()
                self._shine_timer = None
        else:
            self.shine_idx = next_idx

    def set_phase(self, phase: StartupPhase, error: str | None = None) -> None:
        self.phase = phase
        if error:
            self.error = error

    def _panel_width(self) -> int:
        """Preferred panel content width, clamped to terminal size."""
        term_w = self.size.width if self.size.width > 0 else 80
        available = max(_PANEL_MIN, term_w - 8)
        return min(_PANEL_MAX, available)

    def _bar_width(self, panel_w: int) -> int:
        raw = panel_w - 10
        return max(_BAR_MIN, min(_BAR_MAX, raw))

    def render(self) -> RenderableType:
        panel_w = self._panel_width()
        spinner_char = _SPINNER[self._spinner_idx % len(_SPINNER)]

        parts: list[RenderableType] = []

        # Identity block (always present)
        # 1. Main center heading + subtitle (always present)
        parts.append(Text(""))
        heading = render_kagent_word(self.shine_idx, self.shine_done)
        parts.append(heading)
        subtitle = Text("AI-assisted Web Pentest Agent", style=MUTED, justify="center", no_wrap=True)
        parts.append(subtitle)
        parts.append(Text(""))

        if self.phase == "identity":
            spinner_line = Text(f"{spinner_char}  Starting…", style=ACCENT, justify="center")
            parts.append(spinner_line)
            parts.append(Text(""))

        elif self.phase == "failed":
            err_text = Text(
                f"✗  Initialization failed: {self.error or 'unknown error'}",
                style=BOLD_ERROR,
            )
            parts.append(err_text)
            parts.append(Text(""))

        elif self.phase in _READINESS_PHASES:
            current_order = _phase_order(self.phase)

            # Readiness rows
            # 2. Phase list
            for row_phase, row_label in _ROWS:
                row_order = _phase_order(row_phase)
                if row_order < current_order:
                    row = Text()
                    row.append("  ✓  ", style=f"bold {SUCCESS}")
                    row.append(row_label, style=MUTED)
                elif row_order == current_order:
                    row = Text()
                    row.append(f"  {spinner_char}  ", style=ACCENT)
                    row.append(row_label, style=BOLD_ACCENT)
                else:
                    row = Text()
                    row.append("  ·  ", style=MUTED)
                    row.append(row_label, style=MUTED)
                parts.append(row)

            parts.append(Text(""))

            # Compact metadata line
            meta_parts: list[str] = []
            # 3. Compact 2-row metadata area
            p = self.props
            r1 = Text(justify="center")
            if p.provider and p.model:
                meta_parts.append(f"{p.provider} · {p.model}")
                r1.append(f"{p.provider} · {p.model}", style=MUTED)
            elif p.provider:
                meta_parts.append(p.provider)
                r1.append(p.provider, style=MUTED)
            elif p.model:
                meta_parts.append(p.model)
                r1.append(p.model, style=MUTED)

            r2 = Text(justify="center")
            counts: list[str] = []
            if p.skill_count is not None:
                counts.append(f"{p.skill_count} skills")
            if p.tool_count is not None:
                counts.append(f"{p.tool_count} tools")
            if p.resumed:
                summary = f" ({p.resume_summary})" if p.resume_summary else ""
                counts.append(f"Resumed{summary}")
            if counts:
                meta_parts.append("  ·  ".join(counts))
                r2.append("  ·  ".join(counts), style=MUTED)

            if p.resumed:
                summary = f" · {p.resume_summary}" if p.resume_summary else ""
                meta_parts.append(f"Session  Resumed{summary}")

            if meta_parts:
                meta_line = Text("  ", style=MUTED)
                meta_line.append("  ·  ".join(meta_parts), style=MUTED)
                parts.append(meta_line)
            if r1.plain or r2.plain:
                if r1.plain:
                    parts.append(r1)
                if r2.plain:
                    parts.append(r2)
                parts.append(Text(""))

            # Progress bar
            # 4. Progress bar
            pct, _ = PHASE_CONFIG.get(self.phase, (0, ""))
            bar_w = self._bar_width(panel_w)
            parts.append(render_progress_bar(pct, width=bar_w))
            parts.append(Text(""))

            # Ready label
            # 5. Ready label
            if self.phase == "ready":
                parts.append(Text("  ✓  Ready", style=BOLD_ACCENT, justify="center"))
                parts.append(Text(""))

        # 6. Subtle footer status line
        footer_text = _FOOTER_STATUS.get(self.phase, "")
        if footer_text:
            parts.append(Text(footer_text, style=MUTED, justify="center"))
            parts.append(Text(""))

        inner_padding = max(2, (panel_w - 32) // 2)
        inner_padding = min(inner_padding, 8)

        content = Group(*parts)
        border_title = _BORDER_TITLES.get(self.phase, "Initializing")
        return Panel(
            content,
            title=f"[bold {ACCENT}]{border_title}[/]",
            border_style=MUTED,
            box=box.ROUNDED,
            padding=(0, inner_padding),
            expand=False,
        )
