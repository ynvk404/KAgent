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
    "session",
    "target",
    "skills",
    "provider",
    "integrations",
    "ready",
    "failed",
]

_READINESS_PHASES: frozenset[StartupPhase] = frozenset(
    {"workspace", "session", "target", "skills", "provider", "integrations", "ready"}
)

_DEFAULT_ROWS: list[tuple[StartupPhase, str]] = [
    ("workspace", "Workspace"),
    ("skills", "Skills & tools"),
    ("provider", "Provider"),
]

_BORDER_TITLES: dict[StartupPhase, str] = {
    "identity": "Startup",
    "workspace": "Initializing",
    "session": "Initializing",
    "target": "Initializing",
    "skills": "Initializing",
    "provider": "Initializing",
    "integrations": "Initializing",
    "ready": "Initializing",
    "failed": "Failed",
}

_FOOTER_STATUS: dict[StartupPhase, str] = {
    "identity": "Starting runtime environment…",
    "workspace": "Preparing interactive workspace…",
    "session": "Restoring session…",
    "target": "Restoring target and scope…",
    "skills": "Loading environment and runtime tools…",
    "provider": "Verifying provider connection and session…",
    "integrations": "Preparing configured integrations…",
    "ready": "Ready to begin testing",
    "failed": "Initialization encountered an error",
}

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧"

WORD = "KAGENT"
SHINE_INTERVAL = 0.12

_PANEL_MAX = 68
_PANEL_MIN = 28

_BAR_MAX = 38
_BAR_MIN = 12

BAR_WIDTH = _BAR_MAX


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
    has_target: bool = False
    has_integrations: bool = False
    error: str | None = None


class StartupSplash(Widget):
    """Presentation of the runtime state already initialized by the CLI."""

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

    def readiness_rows(self) -> list[tuple[StartupPhase, str]]:
        rows = list(_DEFAULT_ROWS)
        if self.props.resumed:
            rows.insert(1, ("session", "Session"))
        if self.props.has_target:
            rows.insert(2 if self.props.resumed else 1, ("target", "Target & scope"))
        if self.props.has_integrations:
            rows.append(("integrations", "Integrations"))
        return rows

    def progress_percent(self) -> int:
        if self.phase == "ready":
            return 100
        phases = [phase for phase, _ in self.readiness_rows()]
        if self.phase not in phases:
            return 0
        return round(100 * (phases.index(self.phase) + 1) / (len(phases) + 1))

    def _panel_width(self) -> int:
        """Preferred panel content width, clamped to terminal size."""
        term_w = self.size.width if self.size.width > 0 else 80
        available = max(_PANEL_MIN, term_w - 4)
        return min(_PANEL_MAX, available)

    def _bar_width(self, panel_w: int) -> int:
        raw = panel_w - 14
        return max(_BAR_MIN, min(_BAR_MAX, raw))

    def render(self) -> RenderableType:
        panel_w = self._panel_width()
        spinner_char = _SPINNER[self._spinner_idx % len(_SPINNER)]

        parts: list[RenderableType] = []

        # Identity block (always present)
        # 1. Main center heading + subtitle (always present)
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
            rows = self.readiness_rows()
            row_phases = [phase for phase, _ in rows]
            current_order = len(rows) if self.phase == "ready" else row_phases.index(self.phase)

            # Readiness rows
            # 2. Phase list
            for row_order, (row_phase, row_label) in enumerate(rows):
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

            # Provider and counts each appear once, on their own centered row.
            p = self.props
            r1 = Text(justify="center")
            if p.provider and p.model:
                r1.append(f"{p.provider} · {p.model}", style=MUTED)
            elif p.provider:
                r1.append(p.provider, style=MUTED)
            elif p.model:
                r1.append(p.model, style=MUTED)

            r2 = Text(justify="center")
            counts: list[str] = []
            if p.skill_count is not None:
                counts.append(f"{p.skill_count} skills")
            if p.tool_count is not None:
                counts.append(f"{p.tool_count} tools")
            if counts:
                r2.append("  ·  ".join(counts), style=MUTED)
            if r1.plain or r2.plain:
                if r1.plain:
                    parts.append(r1)
                if r2.plain:
                    parts.append(r2)
                parts.append(Text(""))

            # Progress bar
            # 4. Progress bar
            pct = self.progress_percent()
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
