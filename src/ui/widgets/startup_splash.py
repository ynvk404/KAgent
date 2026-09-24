from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from rich import box
from rich.align import Align
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
    "model",
    "integrations",
    "ready",
    "failed",
]

_READINESS_PHASES: frozenset[StartupPhase] = frozenset(
    {"workspace", "session", "target", "skills", "provider", "model", "integrations", "ready"}
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
    "model": "Initializing",
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
    "model": "Using the selected model…",
    "integrations": "Preparing configured integrations…",
    "ready": "Ready to begin testing",
    "failed": "Initialization encountered an error",
}

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧"

WORD = "KAGENT"
SHINE_INTERVAL = 0.12

_PANEL_MAX = 68
_PANEL_MIN = 28

def render_kagent_word(shine_idx: int = 0, shine_done: bool = False) -> Text:
    """Render 'KAGENT' with a moving shine sweep across already-visible letters."""
    heading = Text(justify="center", no_wrap=True)
    for i, ch in enumerate(WORD):
        if not shine_done and i == shine_idx:
            heading.append(ch, style=BOLD_ACCENT)
        else:
            heading.append(ch, style=ACCENT)
    return heading


@dataclass(slots=True)
class SplashProps:
    provider: str | None = None
    model: str | None = None
    skill_count: int | None = None
    tool_count: int | None = None
    resumed: bool = False
    resume_summary: str | None = None
    has_target: bool = False
    has_model_override: bool = False
    has_integrations: bool = False
    error: str | None = None


class StartupSplash(Widget):
    """Presentation of the runtime state already initialized by the CLI."""

    DEFAULT_CSS = """
    StartupSplash {
        width: 100%;
        height: auto;
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
        self.refresh(layout=True)

    def readiness_rows(self) -> list[tuple[StartupPhase, str]]:
        rows = list(_DEFAULT_ROWS)
        if self.props.resumed:
            rows.insert(1, ("session", "Session"))
        if self.props.has_target:
            rows.insert(2 if self.props.resumed else 1, ("target", "Target & scope"))
        if self.props.has_model_override:
            rows.append(("model", "Model override"))
        if self.props.has_integrations:
            rows.append(("integrations", "Integrations"))
        return rows

    def _panel_width(self) -> int:
        """Preferred panel content width, clamped to terminal size."""
        term_w = self.size.width if self.size.width > 0 else 80
        available = max(_PANEL_MIN, term_w - 4)
        return min(_PANEL_MAX, available)

    def render(self) -> RenderableType:
        panel_w = self._panel_width()
        inner_padding = min(max(2, (panel_w - 32) // 2), 8)
        spinner_char = _SPINNER[self._spinner_idx % len(_SPINNER)]

        parts: list[RenderableType] = []

        # Identity block (always present)
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
            readiness_lines: list[Text] = []
            for row_order, (row_phase, row_label) in enumerate(rows):
                if row_order < current_order:
                    row = Text()
                    row.append("✓  ", style=f"bold {SUCCESS}")
                    row.append(row_label, style=MUTED)
                elif row_order == current_order:
                    row = Text()
                    row.append(f"{spinner_char}  ", style=ACCENT)
                    row.append(row_label, style=BOLD_ACCENT)
                else:
                    row = Text()
                    row.append("·  ", style=MUTED)
                    row.append(row_label, style=MUTED)
                readiness_lines.append(row)

            parts.append(Align.center(Group(*readiness_lines)))

            parts.append(Text(""))
            if self.phase == "ready":
                # Center the label itself; the check sits just to its left.
                label = "Complete"
                content_w = panel_w - 2 - 2 * inner_padding
                label_start = (content_w - len(label)) // 2
                completion_line = Text(no_wrap=True)
                completion_line.append(" " * max(0, label_start - 3))
                completion_line.append("✓  ", style=f"bold {SUCCESS}")
                completion_line.append(label, style=BOLD_ACCENT)
                parts.append(completion_line)
                parts.append(Text(""))

        # Subtle footer status line
        footer_text = _FOOTER_STATUS.get(self.phase, "")
        if footer_text:
            parts.append(Text(footer_text, style=MUTED, justify="center"))

        content = Group(*parts)
        border_title = _BORDER_TITLES.get(self.phase, "Initializing")
        return Panel(
            content,
            title=f"[bold {ACCENT}]{border_title}[/]",
            border_style=MUTED,
            box=box.ROUNDED,
            padding=(1, inner_padding),
            expand=True,
            width=panel_w,
        )
