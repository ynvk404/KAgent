from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Literal

from rich.text import Text
from textual.reactive import reactive
from textual.widget import Widget
from src.ui.widgets.banner import ToolSupportPill
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
    model: str | None = None
    tool_support: ToolSupportPill | None = None
    target: str | None = None
    running_tool: str | None = None
    elapsed_seconds: float | None = None


def busy_line(p: StatusProps, width: int | None = None) -> Text:
    phase_text = phase_label(p.phase)
    label = (
        p.running_tool
        if p.phase == "running-tool" and p.running_tool
        else phase_text
    )
    if p.phase in WAITING_PHASES and p.running_tool:
        label += " · " + p.running_tool
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
    if width is not None and line.cell_len > width:
        # Preserve the request's method/input before secondary skill metadata.
        clock = f" · {format_elapsed(p.elapsed_seconds)}" if p.elapsed_seconds is not None else ""
        cancel = " · Esc" if p.phase not in WAITING_PHASES else ""
        budget = max(0, width - 2 - len(clock) - len(cancel))
        for verbose, concise in (("workflow: start validation · ", "start: "),
                                 ("workflow: record result · ", "record: "),
                                 ("Saving finding: ", "Saving · ")):
            label = label.replace(verbose, concise)
        head, separator, parameter = label.rpartition(" · input ")
        if separator:
            tail = Text(" · " + parameter, style=MUTED)
            tail.truncate(max(0, budget // 2), overflow="ellipsis")
            activity = Text(head, style=MUTED)
            activity.truncate(max(0, budget - tail.cell_len), overflow="ellipsis")
            activity.append_text(tail)
        else:
            activity = Text(label, style=MUTED)
            activity.truncate(budget, overflow="ellipsis")
        line = Text(f"{indicator} ", style=ACCENT)
        line.append_text(activity)
        line.append(clock + cancel, style=MUTED)
        line.truncate(width, overflow="ellipsis")
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
    # ``request_tokens`` includes carried observations/catalog/workflow and
    # actual default tool schemas, without pending input or recall/search.
    # Use a shorter spelling on narrow terminals before dropping telemetry.
    compact_context = width is not None and width < 90
    if history_hint and request_hint:
        context_hint = (
            f" · h{history_hint} · r{request_hint}"
            if compact_context
            else f" · history {history_hint} · request {request_hint}"
        )
    elif request_hint:
        context_hint = f" · request {request_hint}"
    else:
        context_hint = ""

    context_suffix = (
        f"/{round(p.compact_threshold / 1000)}k soft {ctx_percent}%"
        if ctx_percent
        else ""
    )

    def build(
        *,
        include_extras: bool = True,
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
        if include_extras and p.active_skill:
            line.append(f" · skill: {p.active_skill}", style=MUTED)
        if p.target and include_extras:
            line.append(f" · target: {compact_target(p.target)}", style=MUTED)

        if context_hint:
            style = WARNING if ctx_percent >= 90 else MUTED
            line.append(f"{context_hint}{context_suffix}", style=style)
        if p.elapsed_seconds is not None:
            line.append(f" · time {format_elapsed(p.elapsed_seconds)}", style=MUTED)

        return line

    full = build(
        include_extras=True,
    )
    if width is None or full.cell_len <= width:
        return full

    return build(
        include_extras=False,
    )

class StatusBar(Widget):
    """Right-aligned AutoApprove badge + left-aligned status content."""

    DEFAULT_CSS = f"""
    StatusBar {{
        width: 100%;
        height: 1;
        padding: 0 1;
        background: {MUTED} 12%;
    }}
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
    target: reactive[str | None] = reactive(None)
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
            model=self.model,
            tool_support=self.tool_support,
            target=self.target,
            running_tool=self.running_tool,
            elapsed_seconds=self.elapsed_seconds,
        )

    def render(self) -> Text:
        props = self._to_props()
        width = self.content_size.width or self.size.width or 80
        badge_width = len("AutoApprove") + 1 if props.yolo else 0
        content_width = max(1, width - badge_width)
        content = busy_line(props, width=content_width) if props.busy else idle_line(props, width=content_width)

        if not props.yolo:
            return content

        badge = Text("AutoApprove", style=SUPERMODE_COLOR)
        pad = max(1, width - content.cell_len - badge.cell_len)
        line = content.copy()
        line.append(" " * pad)
        line.append(badge)
        return line
