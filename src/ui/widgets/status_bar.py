from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Literal

from rich.text import Text
from textual.reactive import reactive
from textual.widget import Widget
from src.ui.widgets.banner import ToolSupportPill
from src.ui.core.state import TranscriptFilter
from src.ui.theme import ACCENT, BOLD_DANGER, BOLD_ERROR, BOLD_SUCCESS, MUTED, SUCCESS, WARNING

UiPhase = Literal[
    "planning",
    "running-tool",
    "answering",
    "waiting-approval",
    "waiting-user",
    "skills",
    "idle",
]

SUPERMODE_COLOR = BOLD_DANGER
SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
PROCESSING_PHASES: frozenset[UiPhase] = frozenset(
    {"planning", "running-tool", "answering"}
)
WAITING_PHASES: frozenset[UiPhase] = frozenset(
    {"waiting-approval", "waiting-user"}
)
WAITING_MARKER = "○"

def format_elapsed(total_seconds: float) -> str:
    """mm:ss elapsed clock. 42 -> "0:42", 125 -> "2:05", 3700 -> "61:40"."""
    s = max(0, int(total_seconds // 1))
    mins, secs = divmod(s, 60)
    return f"{mins}:{secs:02d}"


def tool_pill(t: ToolSupportPill | None) -> tuple[str, str] | None:
    """Returns (text, color) for the tool-support pill, or None."""
    return {
        "yes": ("tools ✓", SUCCESS),
        "no": ("NO TOOLS", BOLD_ERROR),
        "probing": ("probing…", WARNING),
    }.get(t) if t else None


def phase_label(phase: UiPhase) -> str:
    return {
        "planning": "planning",
        "running-tool": "running tool",
        "answering": "answering",
        "waiting-approval": "waiting approval",
        "waiting-user": "waiting input",
        "skills": "skills",
        "idle": "idle",
    }[phase]


def compact_target(target: str) -> str:
    target = target.removeprefix("https://").removeprefix("http://")
    return target.removesuffix("/")

@dataclass(slots=True)
class StatusProps:
    busy: bool
    api_ready: bool
    active_skill: str | None
    yolo: bool
    ctx_tokens: int
    compact_threshold: int
    memory_items: int
    phase: UiPhase
    transcript_filter: TranscriptFilter
    model: str | None = None
    tool_support: ToolSupportPill | None = None
    target: str | None = None
    expand_hint: bool = False
    running_tool: str | None = None
    elapsed_seconds: float | None = None


def busy_line(p: StatusProps) -> Text:
    phase_text = phase_label(p.phase)
    label = (
        p.running_tool
        if p.phase == "running-tool" and p.running_tool
        else phase_text
    )
    clock = (
        f" · {format_elapsed(p.elapsed_seconds)}"
        if p.elapsed_seconds is not None
        else ""
    )

    indicator = (
        SPINNER_FRAMES[int(p.elapsed_seconds or 0) % len(SPINNER_FRAMES)]
        if p.phase in PROCESSING_PHASES
        else WAITING_MARKER
    )

    line = Text()
    line.append(f"{indicator} ", style=ACCENT)
    cancel_hint = "" if p.phase in WAITING_PHASES else " · Esc to cancel"
    line.append(f"{label}{clock}{cancel_hint}", style=MUTED)
    if p.active_skill:
        line.append(f" · skill: {p.active_skill}", style=MUTED)
    return line


def idle_line(p: StatusProps) -> Text:
    phase_text = phase_label(p.phase)

    if p.ctx_tokens >= 1000:
        ctx_hint = f"  ·  ctx: ~{p.ctx_tokens / 1000:.1f}k"
    elif p.ctx_tokens > 0:
        ctx_hint = f"  ·  ctx: ~{p.ctx_tokens}"
    else:
        ctx_hint = ""

    ctx_percent = (
        min(999, round((p.ctx_tokens / p.compact_threshold) * 100))
        if p.compact_threshold > 0 and p.ctx_tokens > 0
        else 0
    )
    pill = tool_pill(p.tool_support)

    line = Text()
    if p.api_ready:
        line.append("ready", style=BOLD_SUCCESS)
    else:
        line.append("disconnected", style=BOLD_ERROR)

    line.append(f" · {phase_text} · Enter send · / commands", style=MUTED)

    if p.model:
        line.append(f" · {p.model}", style=MUTED)
    if p.target:
        line.append(f" · target: {compact_target(p.target)}", style=MUTED)
    if pill:
        text, color = pill
        line.append(f" [{text}]", style=color)
    if p.expand_hint:
        line.append(" · Ctrl-O expand output", style=ACCENT)
    if p.transcript_filter != "all":
        line.append(f" · filter: {p.transcript_filter}", style=ACCENT)
    if p.active_skill:
        line.append(f" · skill: {p.active_skill}", style=MUTED)
    if ctx_hint:
        style = WARNING if ctx_percent >= 90 else MUTED
        suffix = (
            f"/{round(p.compact_threshold / 1000)}k {ctx_percent}%"
            if ctx_percent
            else ""
        )
        line.append(f"{ctx_hint}{suffix}", style=style)
    if p.memory_items > 0:
        line.append(f" · mem: {p.memory_items}", style=MUTED)

    return line

class StatusBar(Widget):
    """Right-aligned AutoApprove badge + left-aligned status content."""

    DEFAULT_CSS = """
    StatusBar {
        width: 100%;
        height: 1;
    }
    """

    busy: reactive[bool] = reactive(False)
    api_ready: reactive[bool] = reactive(True)
    active_skill: reactive[str | None] = reactive(None)
    yolo: reactive[bool] = reactive(False)
    ctx_tokens: reactive[int] = reactive(0)
    compact_threshold: reactive[int] = reactive(0)
    memory_items: reactive[int] = reactive(0)
    model: reactive[str | None] = reactive(None)
    tool_support: reactive[ToolSupportPill | None] = reactive(None)
    phase: reactive[UiPhase] = reactive("idle")
    transcript_filter: reactive[TranscriptFilter] = reactive("all")
    target: reactive[str | None] = reactive(None)
    expand_hint: reactive[bool] = reactive(False)
    running_tool: reactive[str | None] = reactive(None)
    elapsed_seconds: reactive[float | None] = reactive(None)

    def apply(self, props: StatusProps) -> None:
        """Bulk-update from a StatusProps bag."""
        for f in fields(props):
            setattr(self, f.name, getattr(props, f.name))

    def _to_props(self) -> StatusProps:
        return StatusProps(
            busy=self.busy,
            api_ready=self.api_ready,
            active_skill=self.active_skill,
            yolo=self.yolo,
            ctx_tokens=self.ctx_tokens,
            compact_threshold=self.compact_threshold,
            memory_items=self.memory_items,
            phase=self.phase,
            transcript_filter=self.transcript_filter,
            model=self.model,
            tool_support=self.tool_support,
            target=self.target,
            expand_hint=self.expand_hint,
            running_tool=self.running_tool,
            elapsed_seconds=self.elapsed_seconds,
        )

    def render(self) -> Text:
        props = self._to_props()
        content = busy_line(props) if props.busy else idle_line(props)

        if not props.yolo:
            return content

        badge = Text("AutoApprove", style=SUPERMODE_COLOR)
        width = self.size.width or 80
        pad = max(1, width - content.cell_len - badge.cell_len)
        line = content.copy()
        line.append(" " * pad)
        line.append(badge)
        return line
