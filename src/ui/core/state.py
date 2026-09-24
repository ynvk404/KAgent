from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Literal, Union

from src.agent.events import (
    AgentEvent,
    AssistantTextEvent,
    AssistantDeltaEvent,
    ToolCallEvent,
    ToolResultEvent,
    ErrorEvent,
    CompactEvent,
    DecisionEvent,
    SkillActiveEvent,
    MemoryRecallEvent,
    DoneEvent,
)

if TYPE_CHECKING:
    from src.ui.bridges.ask_bridge import AskRequest
    from src.ui.bridges.perm_bridge import BridgedPermissionRequest
    from src.ui.widgets.banner import BannerData
else:
    AskRequest = Any
    BridgedPermissionRequest = Any
    BannerData = Any

try:
    from src.tools.tool_display import display_tool_name, format_tool_result, primary_tool_arg
except ImportError:

    def display_tool_name(name: str) -> str:
        return name

    def format_tool_result(name: str, result: str) -> str | None:
        return None

    def primary_tool_arg(name: str, args: dict[str, Any]) -> str | None:
        return None


from src.ui.render.tool_result_format import build_tool_result_view, shell_result_exit_status
from src.ui.theme import ACCENT, DANGER, ERROR, MUTED, WARNING


TranscriptKind = Literal[
    "user",
    "assistant",
    "tool-call",
    "tool-result",
    "system",
    "error",
    "finding",
    "decision",
]

UiPhase = Literal[
    "idle",
    "planning",
    "running-tool",
    "answering",
    "waiting-approval",
    "waiting-user",
    "skills",
]

TranscriptFilter = Literal["all", "compact", "findings", "errors", "current"]

TRANSCRIPT_FILTERS: list[TranscriptFilter] = ["all", "compact", "findings", "errors", "current"]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class TranscriptEntry:
    kind: TranscriptKind
    text: str
    streaming: bool = False
    collapsible: bool = False
    full_text: str | None = None
    expanded: bool = False
    prefix: str | None = None
    color: str | None = None


@dataclass(frozen=True, slots=True)
class AppState:
    banner: str
    banner_data: BannerData
    transcript: tuple[TranscriptEntry, ...] = field(default_factory=tuple)
    busy: bool = False
    clear_gen: int = 0
    clear_message: str | None = None
    api_ready: bool = True
    active_skill: str | None = None
    pending_perm: BridgedPermissionRequest  | None = None
    pending_ask: AskRequest | None = None
    pending_skills: bool = False
    yolo: bool = False
    phase: UiPhase = "idle"
    transcript_filter: TranscriptFilter = "all"
    running_tool: str | None = None


def initial_state(banner: str, banner_data: BannerData) -> AppState:
    return AppState(banner=banner, banner_data=banner_data)


@dataclass(frozen=True, slots=True)
class SetBanner:
    banner: str


@dataclass(frozen=True, slots=True)
class MergeBannerData:
    patch: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Append:
    entry: TranscriptEntry


@dataclass(frozen=True, slots=True)
class AppendDelta:
    text: str


@dataclass(frozen=True, slots=True)
class SetBusy:
    busy: bool


@dataclass(frozen=True, slots=True)
class SetApiReady:
    ready: bool


@dataclass(frozen=True, slots=True)
class SetActiveSkill:
    name: str | None


@dataclass(frozen=True, slots=True)
class SetYolo:
    on: bool


@dataclass(frozen=True, slots=True)
class SetPerm:
    req: BridgedPermissionRequest  | None


@dataclass(frozen=True, slots=True)
class SetAsk:
    req: AskRequest | None


@dataclass(frozen=True, slots=True)
class SetSkillsPicker:
    open: bool


@dataclass(frozen=True, slots=True)
class CycleTranscriptFilter:
    pass


@dataclass(frozen=True, slots=True)
class ExpandToolOutput:
    pass


@dataclass(frozen=True, slots=True)
class Clear:
    message: str | None = None


@dataclass(frozen=True, slots=True)
class AgentEventAction:
    event: AgentEvent


Action = Union[
    SetBanner,
    MergeBannerData,
    Append,
    AppendDelta,
    SetBusy,
    SetApiReady,
    SetActiveSkill,
    SetYolo,
    SetPerm,
    SetAsk,
    SetSkillsPicker,
    CycleTranscriptFilter,
    ExpandToolOutput,
    Clear,
    AgentEventAction,
]


def reducer(state: AppState, action: Action) -> AppState:
    match action:
        case SetBanner(banner=banner):
            return replace(state, banner=banner)

        case MergeBannerData(patch=patch):
            merged = replace(
                state.banner_data,
                **patch,
            )
            return replace(state, banner_data=merged)

        case Append(entry=entry):
            return replace(state, transcript=(*state.transcript, entry))

        case AppendDelta(text=text):
            phase: UiPhase = "answering" if state.busy else state.phase
            last = state.transcript[-1] if state.transcript else None
            if last is not None and last.kind == "assistant" and last.streaming:
                updated = replace(last, text=last.text + text)
                return replace(state, phase=phase, transcript=(*state.transcript[:-1], updated))
            return replace(
                state,
                phase=phase,
                transcript=(*state.transcript, TranscriptEntry(kind="assistant", text=text, streaming=True)),
            )

        case SetBusy(busy=busy):
            return replace(state, busy=busy, phase="planning" if busy else "idle")

        case SetApiReady(ready=ready):
            return replace(state, api_ready=ready)

        case SetActiveSkill(name=name):
            return replace(state, active_skill=name)

        case SetYolo(on=on):
            return replace(state, yolo=on)

        case SetPerm(req=req):
            return replace(
                state,
                pending_perm=req,
                phase="waiting-approval" if req else ("running-tool" if state.busy else "idle"),
            )

        case SetAsk(req=req):
            return replace(
                state,
                pending_ask=req,
                phase="waiting-user" if req else ("answering" if state.busy else "idle"),
            )

        case SetSkillsPicker(open=open_):
            return replace(state, pending_skills=open_, phase="skills" if open_ else "idle")

        case CycleTranscriptFilter():
            return replace(state, transcript_filter=_next_transcript_filter(state.transcript_filter))

        case ExpandToolOutput():
            idx = -1
            for i in range(len(state.transcript) - 1, -1, -1):
                e = state.transcript[i]
                if e.collapsible and not e.expanded:
                    idx = i
                    break
            if idx == -1:
                return state
            entry = state.transcript[idx]
            transcript = list(state.transcript)
            transcript[idx] = replace(entry, expanded=True)
            transcript.append(TranscriptEntry(kind="tool-result", text=entry.full_text or entry.text))
            return replace(state, transcript=tuple(transcript))

        case Clear(message=message):
            return replace(
                state,
                transcript=(),
                clear_gen=state.clear_gen + 1,
                clear_message=message,
                active_skill=(
                    None
                    if message == "conversation reset"
                    else state.active_skill
                ),
            )

        case AgentEventAction(event=event):
            return _apply_agent_event(state, event)

        case _:
            raise AssertionError(f"Unhandled action: {action!r}")


def _next_transcript_filter(current: TranscriptFilter) -> TranscriptFilter:
    idx = TRANSCRIPT_FILTERS.index(current)
    return TRANSCRIPT_FILTERS[(idx + 1) % len(TRANSCRIPT_FILTERS)]


TOOL_CALL_PREVIEW_CAP = 120
SHELL_TITLE_CAP = 72
SHELL_BLOCK_COMMAND_THRESHOLD = 88


def _preview_args(raw: str) -> str:
    one_line = re.sub(r"\\[nrt]", " ", raw)
    one_line = re.sub(r"[\r\n\t]+", " ", one_line)
    one_line = re.sub(r"\s+", " ", one_line).strip()
    if len(one_line) <= TOOL_CALL_PREVIEW_CAP:
        return one_line
    return f"{one_line[:TOOL_CALL_PREVIEW_CAP]}…"


def _preview_tool_args(name: str, raw: str) -> str:
    try:
        import json

        parsed = json.loads(raw)

        if isinstance(parsed, dict):

            # shell command
            if _is_shell_tool(name):
                command = parsed.get("command")
                if isinstance(command, str):
                    return _preview_args(command)

            primary = primary_tool_arg(name, parsed)
            if primary is not None:
                return _preview_args(primary)

    except Exception:
        pass

    return _preview_args(raw)


def _is_shell_tool(name: str) -> bool:
    return name in ("shell", "bash", "BashTool")


def _tool_call_color(name: str) -> str | None:
    return DANGER if name == "confirm_finding" else None


def _severity_color(severity: str) -> str:
    return {
        "critical": DANGER,
        "high": ERROR,
        "medium": WARNING,
        "low": ACCENT,
        "info": MUTED,
    }.get(severity, WARNING)


def _format_finding_card(args_json: str) -> dict[str, str] | None:
    import json

    try:
        a = json.loads(args_json)
    except Exception:
        return None
    if not isinstance(a, dict):
        return None

    def s(key: str) -> str:
        v = a.get(key)
        return v if isinstance(v, str) else ""

    title = s("title")
    if not title:
        return None
    severity = s("severity").lower()
    method = s("method")
    url = s("url")
    parameter = s("parameter")
    impact = s("impact")

    lines = [f"{severity.upper() if severity else 'FINDING'} · {title}"]
    if url:
        loc = f"{method + ' ' if method else ''}{url}{f'  (param: {parameter})' if parameter else ''}"
        lines.append(f"  {loc}")
    if impact:
        lines.append(f"  impact: {impact}")
    return {"text": "\n".join(lines), "color": _severity_color(severity)}


def _shell_display_name(name: str) -> str:
    return "Shell" if name == "shell" else "Bash"


def _cap_text(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return f"{s[:max_len]}…"


def _shell_command_from_args(args_json: str) -> str | None:
    import json

    try:
        parsed = json.loads(args_json)
    except Exception:
        return None
    command = parsed.get("command") if isinstance(parsed, dict) else None
    return command if isinstance(command, str) and command else None


def _clean_shell_comment(line: str) -> str:
    line = re.sub(r"^#\s*", "", line)
    line = re.sub(r"\s+-\s+.+$", "", line)
    return line.strip()


def _is_shell_assignment(line: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", line))


def _shell_action_from_command(command: str) -> dict[str, str] | None:
    lines = [line.strip() for line in command.replace("\r\n", "\n").split("\n") if line.strip()]
    comment_idx = next((i for i, line in enumerate(lines) if line.startswith("#")), -1)
    if comment_idx == -1:
        return None
    if comment_idx > 0 and any(not _is_shell_assignment(line) for line in lines[:comment_idx]):
        return None

    comment = lines[comment_idx] if comment_idx < len(lines) else ""
    runnable = [line for line in lines if not line.startswith("#")]

    if len(lines) > 1:
        return {
            "title": _cap_text(_clean_shell_comment(comment), SHELL_TITLE_CAP),
            "command": _preview_args(" && ".join(runnable)),
        }

    curl_idx = comment.find(" curl ")
    if curl_idx != -1:
        return {
            "title": _cap_text(_clean_shell_comment(comment[:curl_idx]), SHELL_TITLE_CAP),
            "command": _preview_args(comment[curl_idx + 1 :]),
        }

    return {
        "title": _cap_text(_clean_shell_comment(comment), SHELL_TITLE_CAP),
        "command": _preview_args(command),
    }


def _shell_long_command_block(command: str) -> dict[str, str] | None:
    preview = _preview_args(command)
    is_structured = any(tok in command for tok in ("\n", " && ", " || ", ";"))
    if len(preview) < SHELL_BLOCK_COMMAND_THRESHOLD and not preview.endswith("…") and not is_structured:
        return None
    return {"title": _shell_title_from_preview(preview), "command": preview}


_SHELL_TITLE_BY_WORD = {
    "curl": "HTTP request",
    "http": "HTTP request",
    "wget": "HTTP request",
    "for": "Run loop",
    "while": "Run loop",
    "until": "Run loop",
    "mkdir": "Create directory",
    "grep": "Search files",
    "rg": "Search files",
    "find": "Find files",
    "cat": "Read output",
    "head": "Read output",
    "tail": "Read output",
    "awk": "Process text",
    "jq": "Process text",
    "sed": "Process text",
    "python": "Run script",
    "python3": "Run script",
    "node": "Run script",
    "tsx": "Run script",
    "npm": "Run package task",
    "pnpm": "Run package task",
    "yarn": "Run package task",
    "bun": "Run package task",
    "git": "Git command",
    "openssl": "OpenSSL",
    "echo": "Print text",
    "printf": "Print text",
}


def _shell_title_from_preview(preview: str) -> str:
    first_word = _first_shell_word(preview)
    return _SHELL_TITLE_BY_WORD.get(first_word, f"Run {first_word}")


def _first_shell_word(preview: str) -> str:
    without_assignments = re.sub(
        r"^(?:[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|\S+)\s+)+", "", preview
    )
    m = re.match(r"^[A-Za-z0-9_.:/-]+", without_assignments)
    return m.group(0) if m else "command"


def _format_tool_call_text(name: str, args_json: str) -> str:
    args_preview = _preview_tool_args(name, args_json)
    if _is_shell_tool(name):
        shell_name = _shell_display_name(name)
        command = _shell_command_from_args(args_json)
        action = None
        if command:
            action = _shell_action_from_command(command) or _shell_long_command_block(command)
        if action:
            return f"{shell_name} · {action['title']}\n$ {action['command']}"
        return f"{shell_name} · {args_preview}"
    if name == "ask_user":
        return f"{display_tool_name(name)} · {args_preview}"
    return f"{display_tool_name(name)} {args_preview}"


def _running_tool_label(name: str, args_json: str) -> str:
    if _is_shell_tool(name):
        command = _shell_command_from_args(args_json)
        action = None
        if command:
            action = _shell_action_from_command(command) or _shell_long_command_block(command)
        if action and action.get("title"):
            return f"{_shell_display_name(name)} · {action['title']}"
        return _shell_display_name(name)
    return display_tool_name(name)


def _is_successful_empty_shell_result(result: str) -> bool:
    plain = result.replace("\r\n", "\n").rstrip("\n")
    return plain == "exit: 0\nstdout:"


def _is_empty_shell_exit(result: str, exit_code: str) -> bool:
    plain = result.replace("\r\n", "\n").rstrip("\n")
    return plain == f"exit: {exit_code}\nstdout:"


def _previous_shell_call_was_search(transcript: tuple[TranscriptEntry, ...]) -> bool:
    prev = transcript[-1] if transcript else None
    if prev is None or prev.kind != "tool-call":
        return False
    return bool(re.search(r"(^|\s|\||\$ )(grep|rg)(\s|$)", prev.text))


def _tool_result_prefix(
    name: str,
    err: str,
    result: str,
    duration_ms: float,
    transcript: tuple[TranscriptEntry, ...],
) -> str:
    if err:
        return f"[error] {display_tool_name(name)}: {err}"
    if _is_shell_tool(name):
        exit_code = shell_result_exit_status(result)
        if exit_code and exit_code != "0":
            if (
                exit_code == "1"
                and _is_empty_shell_exit(result, exit_code)
                and _previous_shell_call_was_search(transcript)
            ):
                return f"[no match] {display_tool_name(name)} ({duration_ms}ms)"
            label = "timeout" if exit_code.startswith("timeout") else f"exit {exit_code}"
            return f"[{label}] {display_tool_name(name)} ({duration_ms}ms)"
    return f"[ok] {display_tool_name(name)} ({duration_ms}ms)"


def _format_compact_event(ev: Any) -> str:
    meta: list[str] = []
    tokens_before = getattr(ev, "tokens_before", None)
    tokens_after = getattr(ev, "tokens_after", None)
    if isinstance(tokens_before, int) and isinstance(tokens_after, int):
        meta.append(f"~{tokens_before} → ~{tokens_after} tokens")
    memory_items = getattr(ev, "memory_items", None)
    if isinstance(memory_items, int):
        meta.append(f"{memory_items} memory items")
    if meta:
        return f"compacted: {ev.summary}\n{' · '.join(meta)}"
    return f"compacted: {ev.summary}"


def _apply_agent_event(state: AppState, ev: AgentEvent) -> AppState:
    match ev:
        case AssistantTextEvent(text=text):
            last = state.transcript[-1] if state.transcript else None
            if last is not None and last.kind == "assistant" and last.streaming:
                finalized = replace(last, streaming=False)
                return replace(state, phase="answering", transcript=(*state.transcript[:-1], finalized))
            return replace(
                state,
                phase="answering",
                transcript=(*state.transcript, TranscriptEntry(kind="assistant", text=text)),
            )

        case AssistantDeltaEvent(text=text):
            return reducer(state, AppendDelta(text=text))

        case ToolCallEvent(name=name, args_json=args_json):
            if name == "confirm_finding":
                card = _format_finding_card(args_json)
                if card is not None:
                    return replace(
                        state,
                        transcript=(
                            *state.transcript,
                            TranscriptEntry(
                                kind="finding", text=card["text"], color=card["color"], prefix="★ "
                            ),
                        ),
                        phase="running-tool",
                        running_tool=_running_tool_label(name, args_json),
                    )
            return replace(
                state,
                transcript=(
                    *state.transcript,
                    TranscriptEntry(
                        kind="tool-call",
                        text=_format_tool_call_text(name, args_json),
                        prefix="⏺  " if _is_shell_tool(name) else None,
                        color=_tool_call_color(name),
                    ),
                ),
                phase="running-tool",
                running_tool=_running_tool_label(name, args_json),
            )

        case ToolResultEvent(name=name, result=result, err=err, duration_ms=duration_ms):
            if not err and name == "confirm_finding":
                return replace(
                    state,
                    phase="answering",
                    transcript=(*state.transcript, TranscriptEntry(kind="tool-result", text=result)),
                )

            if not err and _is_shell_tool(name) and _is_successful_empty_shell_result(result):
                return replace(
                    state,
                    phase="answering",
                    transcript=(
                        *state.transcript,
                        TranscriptEntry(kind="tool-result", text="Done", prefix="  ⎿ "),
                    ),
                )

            prefix = _tool_result_prefix(name, err, result, duration_ms, state.transcript)

            if err and result == f"ERROR: {err}":
                return replace(
                    state,
                    phase="answering",
                    transcript=(
                        *state.transcript,
                        TranscriptEntry(kind="tool-result", text=prefix),
                    ),
                )

            if (
                not err
                and _is_shell_tool(name)
                and shell_result_exit_status(result) == "1"
                and _is_empty_shell_exit(result, "1")
                and _previous_shell_call_was_search(state.transcript)
            ):
                return replace(
                    state,
                    phase="answering",
                    transcript=(
                        *state.transcript,
                        TranscriptEntry(kind="tool-result", text=f"{prefix}\n(no matches)"),
                    ),
                )

            if not err:
                friendly = format_tool_result(name, result)
                if friendly is not None:
                    return replace(
                        state,
                        phase="answering",
                        transcript=(
                            *state.transcript,
                            TranscriptEntry(kind="tool-result", text=f"{prefix}\n{friendly}"),
                        ),
                    )

            view = build_tool_result_view(result)
            collapsed_text = f"{prefix}\n{view.preview}"
            if not view.collapsible:
                return replace(
                    state,
                    phase="answering",
                    transcript=(*state.transcript, TranscriptEntry(kind="tool-result", text=collapsed_text)),
                )
            return replace(
                state,
                phase="answering",
                transcript=(
                    *state.transcript,
                    TranscriptEntry(
                        kind="tool-result",
                        text=collapsed_text,
                        collapsible=True,
                        full_text=f"{prefix}\n{view.full}",
                    ),
                ),
            )

        case ErrorEvent(err=agent_err):
            return replace(
                state,
                phase="answering" if state.busy else state.phase,
                transcript=(*state.transcript, TranscriptEntry(kind="error", text=str(agent_err))),
            )

        case CompactEvent():
            return replace(
                state,
                phase="planning",
                transcript=(*state.transcript, TranscriptEntry(kind="system", text=_format_compact_event(ev))),
            )

        case DecisionEvent(summary=summary):
            return replace(
                state,
                phase="planning",
                transcript=(*state.transcript, TranscriptEntry(kind="decision", text=summary)),
            )

        case SkillActiveEvent(name=name):
            return replace(state, active_skill=name)

        case MemoryRecallEvent(names=names):
            return replace(
                state,
                transcript=(
                    *state.transcript,
                    TranscriptEntry(kind="system", text=f"recalled memory: {', '.join(names)}"),
                ),
            )

        case DoneEvent():
            last = state.transcript[-1] if state.transcript else None
            if last is not None and last.kind == "assistant" and last.streaming:
                finalized = replace(last, streaming=False)
                return replace(
                    state,
                    busy=False,
                    phase="idle",
                    running_tool=None,
                    transcript=(*state.transcript[:-1], finalized),
                )
            return replace(state, busy=False, phase="idle", running_tool=None)

        case _:
            raise AssertionError(f"Unhandled AgentEvent: {ev!r}")
