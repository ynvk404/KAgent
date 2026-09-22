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
    """Stable turn duration: mm:ss below one hour, then h:mm:ss."""
    s = max(0, int(total_seconds // 1))
    hours, remainder = divmod(s, 3600)
    mins, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}:{mins:02d}:{secs:02d}"
    return f"{mins:02d}:{secs:02d}"


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
    request_tokens: int
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
        f" · time {format_elapsed(p.elapsed_seconds)}"
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
    line.append(f"{label}{clock}", style=MUTED)
    if p.active_skill:
        line.append(f" · skill: {p.active_skill}", style=MUTED)
    if p.phase not in WAITING_PHASES:
        line.append(" · Esc to cancel", style=MUTED)
    return line


def idle_line(p: StatusProps, width: int | None = None) -> Text:
    phase_text = phase_label(p.phase)

    if p.ctx_tokens >= 1000:
        history_hint = f"~{p.ctx_tokens / 1000:.1f}k"
    elif p.ctx_tokens > 0:
        history_hint = f"~{p.ctx_tokens}"
    else:
        history_hint = ""

    if p.request_tokens >= 1000:
        request_hint = f"~{p.request_tokens / 1000:.1f}k"
    elif p.request_tokens > 0:
        request_hint = f"~{p.request_tokens}"
    else:
        request_hint = ""

    ctx_percent = (
        min(999, round((p.request_tokens / p.compact_threshold) * 100))
        if p.compact_threshold > 0 and p.request_tokens > 0
        else 0
    )
    pill = tool_pill(p.tool_support)

    # The status bar is idle here, so no submitted input exists to estimate.
    # ``request_tokens`` is therefore history plus the current tool registry.
    # Use a shorter spelling on narrow terminals before dropping telemetry.
    compact_context = width is not None and width < 90
    if history_hint and request_hint:
        context_hint = (
            f" · h{history_hint} · r{request_hint}"
            if compact_context
            else f" · hist {history_hint} · req {request_hint}"
        )
    elif request_hint:
        context_hint = f" · req {request_hint}"
    else:
        context_hint = ""

    context_suffix = (
        f"/{round(p.compact_threshold / 1000)}k {ctx_percent}%"
        if ctx_percent
        else ""
    )

    def build(
        *,
        include_input_hints: bool,
        include_extras: bool,
        include_expand: bool,
    ) -> Text:
        line = Text()
        if p.api_ready:
            line.append("ready", style=BOLD_SUCCESS)
        else:
            line.append("disconnected", style=BOLD_ERROR)

        line.append(f" · {phase_text}", style=MUTED)
        if p.model:
            line.append(f" · {p.model}", style=MUTED)
        if pill:
            text, color = pill
            line.append(f" [{text}]", style=color)
        if p.target and include_extras:
            line.append(f" · target: {compact_target(p.target)}", style=MUTED)

        if include_input_hints:
            line.append(" · Enter send · / commands", style=MUTED)

        if context_hint:
            style = WARNING if ctx_percent >= 90 else MUTED
            line.append(f"{context_hint}{context_suffix}", style=style)
        if p.elapsed_seconds is not None:
            line.append(f" · time {format_elapsed(p.elapsed_seconds)}", style=MUTED)

        if include_extras and p.transcript_filter != "all":
            line.append(f" · filter: {p.transcript_filter}", style=ACCENT)
        if include_extras and p.active_skill:
            line.append(f" · skill: {p.active_skill}", style=MUTED)
        if include_extras and p.memory_items > 0:
            line.append(f" · mem: {p.memory_items}", style=MUTED)
        if include_expand and p.expand_hint:
            line.append(" · Ctrl-O expand output", style=ACCENT)
        return line

    full = build(
        include_input_hints=True,
        include_extras=True,
        include_expand=True,
    )
    if width is None or full.cell_len <= width:
        return full

    without_expand = build(
        include_input_hints=True,
        include_extras=True,
        include_expand=False,
    )
    if without_expand.cell_len <= width:
        return without_expand

    without_input_hints = build(
        include_input_hints=False,
        include_extras=True,
        include_expand=False,
    )
    if without_input_hints.cell_len <= width:
        return without_input_hints

    without_extras = build(
        include_input_hints=True,
        include_extras=False,
        include_expand=False,
    )
    if without_extras.cell_len <= width:
        return without_extras

    return build(
        include_input_hints=False,
        include_extras=False,
        include_expand=False,
    )

class StatusBar(Widget):
    """Right-aligned AutoApprove badge + left-aligned status content."""

    DEFAULT_CSS = """
    StatusBar {
        width: 100%;
        height: 1;
        padding: 0 1;
        background: #7E8A9A 12%;
    }
    """

    busy: reactive[bool] = reactive(False)
    api_ready: reactive[bool] = reactive(True)
    active_skill: reactive[str | None] = reactive(None)
    yolo: reactive[bool] = reactive(False)
    ctx_tokens: reactive[int] = reactive(0)
    request_tokens: reactive[int] = reactive(0)
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
            request_tokens=self.request_tokens,
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
        width = self.size.width or 80
        content = busy_line(props) if props.busy else idle_line(props, width=width)

        if not props.yolo:
            return content

        badge = Text("AutoApprove", style=SUPERMODE_COLOR)
        pad = max(1, width - content.cell_len - badge.cell_len)
        line = content.copy()
        line.append(" " * pad)
        line.append(badge)
        return line
