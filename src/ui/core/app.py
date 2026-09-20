from __future__ import annotations

plastic_imports = None 
import dataclasses
import traceback
import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from pathlib import Path
import sys
from typing import Any, TypedDict, cast, IO

from rich.text import Text
from textual.app import App, ComposeResult
from textual import events
from textual.selection import Selection
from textual.widgets import RichLog, Static

from src.agent.agent import Agent, AgentRunOptions
from src.agent.events import AgentEvent, MaxStepsError
from src.agent.agent import AddMemoryInput
from src.agent.mentions import (
    find_active_mention,
    list_mention_dir,
    parse_mention_path,
)
from src.ask.ask import Option, Question
from src.config.config import ToolingProfile, Backend
from src.llm.models import list_models
from src.llm.providers import (
    ANTHROPIC_DEFAULT_BASE_URL,
    ANTHROPIC_RECOMMENDED_MODELS,
    DEEPSEEK_DEFAULT_BASE_URL,
    DEEPSEEK_MODELS,
    GEMINI_CHEAP_MODELS,
    GEMINI_DEFAULT_BASE_URL,
    GEMINI_RECOMMENDED_MODELS,
    GROQ_DEFAULT_BASE_URL,
    GROQ_MODELS,
    KIMI_DEFAULT_BASE_URL,
    KIMI_MODELS,
    OPENROUTER_DEFAULT_BASE_URL,
    OPENROUTER_RECOMMENDED_MODELS,
)
from src.browser.server import BurpBridgeResult, BurpBridgeState
from src.logger.session_debug import SessionDebugLog
from src.skills.template import render_skill_template
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.bridges.perm_bridge import BridgedPermissionRequest 
from src.ui.commands.slash_items import SLASH_ITEMS, SlashItem, filter_slash
from src.ui.commands.slash_handler import (
    handle_slash,
    build_help_text,
    build_plan_prompt,
    build_coverage_next_prompt,
    suggest_closest,
)
from src.ui.core.state import (
    Action,
    AgentEventAction,
    Append,
    Clear,
    CycleTranscriptFilter,
    ExpandToolOutput,
    MergeBannerData,
    SetApiReady,
    SetAsk,
    SetBusy,
    SetPerm,
    SetSkillsPicker,
    SetYolo,
    TranscriptEntry,
    TranscriptFilter,
    initial_state,
    reducer,
)
from src.ui.render.color_level import color_level
from src.ui.utils.ping import PingTask
from src.ui.utils.text_field import (
    TextField,
    cursor_is_on_first_line,
    cursor_is_on_last_line,
    expand_pasted_text_markers,
    looks_like_paste,
    normalize_pasted_text,
    pasted_text_marker,
    should_collapse_paste,
    strip_paste_markers,
)
from src.ui.widgets.ask_modal import AskModal
from src.ui.widgets.banner import BannerData
from src.ui.widgets.input_box import DEFAULT_PROMPT, InputBox
from src.ui.widgets.mention_menu import MentionMenu
from src.ui.widgets.permission_modal import PermissionModal
from src.ui.widgets.skills_modal import SkillsModal
from src.ui.widgets.text_input_modal import TextInputModal, TextInputRequest
from src.ui.widgets.slash_menu import SlashMenu
from src.ui.widgets.status_bar import StatusBar, StatusProps
from src.ui.widgets.transcript import Transcript, entry_view
from src.ui.widgets.transcript_view import TranscriptView
from src.ui.theme import ACCENT, MUTED, PRIMARY


MENTION_LIMIT = 12
CLEAR_SCREEN = "\x1b[2J\x1b[3J\x1b[H"
CONTEXT_SNAPSHOT_INTERVAL = 5 * 60


class AbortEvent(asyncio.Event):

    @property
    def aborted(self) -> bool:
        return self.is_set()

    def abort(self) -> None:
        self.set()

    def throw_if_aborted(self) -> None:
        if self.is_set():
            raise Exception("aborted")
        
@dataclass(slots=True)
class ProviderChange:
    backend: Backend
    model: str
    base_url: str | None = None
    api_key: str | None = None


ApplyProvider = Callable[[ProviderChange], Awaitable[None]]
PersistDisabledSkills = Callable[[list[str]], Awaitable[None]]
UpdateProviderApiKey = Callable[[str, str], Awaitable[None]]
TestConnection = Callable[[], Awaitable[None]]


class ConfigSnapshot(TypedDict):
    backend: Backend
    base_url: str
    api_key: str
    api_keys: dict[str, str]
    model: str

@dataclass(slots=True)
class AppProps:
    agent: Agent
    banner_data: BannerData
    parent_signal: asyncio.Event
    read_config: Callable[[], ConfigSnapshot]
    apply_provider: ApplyProvider
    update_provider_api_key: UpdateProviderApiKey | None = None
    test_connection: TestConnection | None = None

    bind_perm_publisher: (
        Callable[[Callable[[BridgedPermissionRequest  | None], None]], None] | None
    ) = None
    bind_ask_publisher: (
        Callable[[Callable[[AskRequest | None], None]], None] | None
    ) = None
    yolo_initial: bool | None = None
    set_yolo: Callable[[bool], None] | None = None
    bind_banner_publisher: (
        Callable[[Callable[[dict], None]], None] | None
    ) = None
    persist_disabled_skills: PersistDisabledSkills | None = None
    session_debug: SessionDebugLog | None = None
    on_skill_created: Callable[[str], None] | None = None
    bind_notice_publisher: Callable[[Callable[[str], None]], None] | None = None
    start_burp_bridge: (
        Callable[[int | None], Awaitable[BurpBridgeResult]] | None
    ) = None
    close_burp_bridge: (
        Callable[[], Awaitable[BurpBridgeResult]] | None
    ) = None
    burp_bridge_status: (
        Callable[[], Awaitable[BurpBridgeResult]] | None
    ) = None
    resume_summary: str | None = None   

@dataclass(slots=True)
class RunAgentOptions:
    transcript_user_text: str | None = None
    system_text: str | None = None
    run_options: AgentRunOptions | None = None


class _RichLogWriter:

    def __init__(self, log: RichLog) -> None:
        self._log = log

    def content_width(self) -> int:
        if isinstance(self._log, TranscriptView):
            return self._log.transcript_content_width
        return max(1, self._log.scrollable_content_region.width)

    def write(self, s: str) -> int:
        self._log.write(
            Text.from_ansi(s.rstrip("\n")),
            width=self.content_width(),
        )
        return len(s)

_INPUT_STYLE_MAP: dict[str, str] = {
    "gray": MUTED,
    "prompt": f"bold {ACCENT}",
    "text": PRIMARY,
    "cursor": f"bold {PRIMARY}",
    "cursor_char": "reverse",
}


def _input_style(name: str | None) -> str:
    return _INPUT_STYLE_MAP.get(name or "text", name or "")


def _modal_text(modal) -> Text:
    text = Text()
    for i, line in enumerate(modal.render()):
        if i > 0:
            text.append("\n")
        if isinstance(modal, TextInputModal) and line.startswith(DEFAULT_PROMPT):
            text.append(DEFAULT_PROMPT, style=_input_style("prompt"))
            value = line[len(DEFAULT_PROMPT):]
            if value.endswith("▌"):
                text.append(value[:-1], style=_input_style("text"))
                text.append("▌", style=_input_style("cursor"))
            else:
                text.append(value, style=_input_style("text"))
        else:
            text.append(line)
    return text


def _input_selection_text(value: str, selection: Selection) -> str:
    lines = value.split("\n")

    def offset(position, *, end: bool) -> int:
        if position is None:
            return len(value) if end else 0
        if position.y <= 1:
            return 0
        if position.y >= len(lines) + 1:
            return len(value)
        line_index = position.y - 1
        line_start = sum(len(line) + 1 for line in lines[:line_index])
        prefix_len = 2
        return line_start + min(
            len(lines[line_index]),
            max(0, position.x - prefix_len),
        )

    start = offset(selection.start, end=False)
    end = offset(selection.end, end=True)
    return value[min(start, end) : max(start, end)]


class _InputStatic(Static):
    def __init__(self) -> None:
        super().__init__(id="input-box")
        self.value = ""

    def get_selection(self, selection: Selection) -> tuple[str, str] | None:
        return _input_selection_text(self.value, selection), "\n"


def filter_transcript(
    entries: list[TranscriptEntry], f: TranscriptFilter
) -> list[TranscriptEntry]:
    if f == "all":
        return entries
    if f == "errors":
        return [e for e in entries if e.kind == "error"]
    if f == "findings":
        return [e for e in entries if e.kind == "finding"]
    if f == "compact":
        return [e for e in entries if e.kind not in ("tool-call", "tool-result")]
    if f == "current":
        start = 0
        for i in range(len(entries) - 1, -1, -1):
            if entries[i].kind == "user":
                start = i
                break
        return entries[start:]
    return entries


def transcript_entry_matches_filter(
    entry: TranscriptEntry, f: TranscriptFilter
) -> bool:
    if f == "all":
        return True
    if f == "errors":
        return entry.kind == "error"
    if f == "findings":
        return entry.kind == "finding"
    if f == "compact":
        return entry.kind not in ("tool-call", "tool-result")
    return True  


class KAgent(App):

    CSS = f"""
    Screen > .screen--selection {{
        background: #38BDF8 30%;
        color: transparent;
    }}

    #overlay.modal-panel {{
        border-top: solid {MUTED};
        border-bottom: solid {MUTED};
        padding: 0 1;
    }}
    """

    def __init__(self, props: AppProps):
        super().__init__()
        self.agent = props.agent
        self.banner_data = props.banner_data
        self.parent_signal = props.parent_signal

        self.bind_perm_publisher = props.bind_perm_publisher
        self.bind_ask_publisher = props.bind_ask_publisher

        self.read_config = props.read_config
        self.apply_provider = props.apply_provider
        self.update_provider_api_key = props.update_provider_api_key
        self.test_connection = props.test_connection

        self.set_yolo = props.set_yolo
        self.bind_banner_publisher = props.bind_banner_publisher

        self.persist_disabled_skills = props.persist_disabled_skills
        self.session_debug = props.session_debug

        self.on_skill_created = props.on_skill_created
        self.bind_notice_publisher = props.bind_notice_publisher

        self.start_burp_bridge = props.start_burp_bridge
        self.close_burp_bridge = props.close_burp_bridge
        self.burp_bridge_status = props.burp_bridge_status
        self.resume_summary = props.resume_summary
        self.state = initial_state(
            "",
            self.banner_data,
        )

        if props.yolo_initial:
            self.state = replace(
                self.state,
                yolo=True,
            )

        self.input = TextField("")
        self.slash_idx = 0
        self.mention_idx = 0
        self.text_input = None
        self.slash_matches: list[SlashItem] = []
        self.mention_matches: list = []
        self.mention_ctx: dict | None = None
        self._prev_slash_match_count: int | None = None
        self._prev_mention_match_count: int | None = None
        self.run_task: asyncio.Task | None = None
        self.run_abort_event: AbortEvent | None = None
        self.snapshot_task: asyncio.Task | None = None
        self.cols: int = 80
        self.banner_snapshot: BannerData = replace(
            self.banner_data,
            tool_support=None,
            context_window=None,
        )

        self.ping_task: PingTask | None = None
        self.parent_abort_task: asyncio.Task | None = None

        self.snapshot_saving = False
        self.resume_summary_shown = False

        self.history: list[str] = []
        self.history_draft = ""
        self.history_idx: int | None = None
        self.HISTORY_CAP = 500

        self.pasted_text: dict[int, str] = {}
        self.pasted_text_seq = 0
        self._last_selected_text = ""

        self.text_input_future: asyncio.Future[str] | None = None

        self._text_input_modal: TextInputModal | None = None
        self._ask_text_input_for: AskRequest | None = None
        self._ask_text_input_modal: TextInputModal | None = None
        self._ask_modal: AskModal | None = None
        self._perm_modal: PermissionModal | None = None
        self._skills_modal: SkillsModal | None = None

        self._status_cache_key: tuple | None = None
        self._status_info: dict = {}

        self._elapsed_busy = False
        self._elapsed_timer = None
        self._elapsed_start: float = 0.0


    def compose(self) -> ComposeResult:

        self.transcript_log = TranscriptView(auto_scroll=True)
        yield self.transcript_log
        rich_log_writer = _RichLogWriter(self.transcript_log)
        self.transcript_writer = Transcript(
            out=cast(IO[str], rich_log_writer),
            width=rich_log_writer.content_width,
            clear=self.transcript_log.clear,
        )

        self.live_entry_static = Static(id="live-entry")
        yield self.live_entry_static

        self.overlay_static = Static(id="overlay")
        yield self.overlay_static

        self.input_static = _InputStatic()
        yield self.input_static

        self.status_bar = StatusBar()
        yield self.status_bar

        self._render_input()


    def dispatch(
        self,
        action: Action,
    ) -> None:
        self.state = reducer(
            self.state,
            cast(Any, action),
        )

        self._recompute_view()
        self._sync_elapsed_timer(self.state.busy)

        self.refresh()


    def is_max_steps_error(
        self,
        err: Exception,
    ) -> bool:
        return isinstance(
            err,
            MaxStepsError,
        )

    def apply_yolo(self, on: bool) -> None:

        if self.set_yolo is not None:
            self.set_yolo(on)

        self.dispatch(SetYolo(on=on))

    def clear_screen(self) -> None:
        self.dispatch(Clear())


    async def prompt_text(
        self,
        input_req: TextInputRequest,
    ) -> str:
        loop = asyncio.get_running_loop()

        self.text_input_future = loop.create_future()

        self.text_input = TextInputRequest(
            header=input_req.header,
            question=input_req.question,
            placeholder=input_req.placeholder,
            masked=input_req.masked,
            resolve=lambda value: self.resolve_text_input(value),
            reject=lambda err: self.reject_text_input(err),
        )

        self.refresh()

        return await self.text_input_future

    def resolve_text_input(
        self,
        value: str,
    ) -> None:
        if self.text_input_future and not self.text_input_future.done():
            self.text_input_future.set_result(value)

        self.text_input_future = None
        self.text_input = None

        self.refresh()

    def reject_text_input(
        self,
        err: Exception,
    ) -> None:
        if self.text_input_future and not self.text_input_future.done():
            self.text_input_future.set_exception(err)

        self.text_input_future = None
        self.text_input = None

        self.refresh()


    def _recompute_menus(self) -> None:

        value = self.input.value

        skill_slash_items: list[SlashItem] = (
            [
                SlashItem(
                    name=f"/{s.name}",
                    description=(
                        f"[skill] {s.description[:70]}"
                        f"{'…' if len(s.description) > 70 else ''}"
                    ),
                )
                for s in self.agent.skills.list_enabled()
            ]
            if value.startswith("/")
            else []
        )

        slash_matches = filter_slash(value, skill_slash_items)

        mention_ctx = find_active_mention(value)
        mention_dir_base = (
            parse_mention_path(mention_ctx["partial"]) if mention_ctx else None
        )
        mention_matches = (
            list_mention_dir(
                mention_dir_base[0], mention_dir_base[1], MENTION_LIMIT
            )
            if mention_dir_base
            else []
        )

        self.slash_matches = slash_matches
        self.mention_matches = mention_matches
        self.mention_ctx = mention_ctx

        if len(slash_matches) != self._prev_slash_match_count:
            if len(slash_matches) > 0:
                self.slash_idx = 0
        self._prev_slash_match_count = len(slash_matches)

        if len(mention_matches) != self._prev_mention_match_count:
            if len(mention_matches) > 0:
                self.mention_idx = 0
        self._prev_mention_match_count = len(mention_matches)

    async def on_key(self, event: events.Key) -> None:

        prev_value = self.input.value

        await self._process_key(event)

        if self.input.value != prev_value:
            self._recompute_menus()

        self._sync_overlay()
        self._render_input()

    def _insert_pasted_text(self, raw_input: str) -> None:
        pasted = normalize_pasted_text(strip_paste_markers(raw_input))
        if should_collapse_paste(pasted):
            self.pasted_text_seq += 1
            id = self.pasted_text_seq
            self.pasted_text[id] = pasted
            self.input.insert_text(pasted_text_marker(id, pasted))
            return
        self.input.insert_text(pasted)

    async def on_paste(self, event: events.Paste) -> None:
        modal = self._get_active_modal()
        if isinstance(modal, TextInputModal):
            modal.handle_key("", event.text)
        elif modal is None and not self.state.busy:
            previous_value = self.input.value
            self._insert_pasted_text(event.text)
            if self.input.value != previous_value:
                self._recompute_menus()
        else:
            return

        event.stop()
        self._sync_overlay()
        self._render_input()

    def on_text_selected(self, event: events.TextSelected) -> None:
        selected = self.screen.get_selected_text()
        if selected:
            self._last_selected_text = selected

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button == 3 and self._last_selected_text:
            self.copy_to_clipboard(self._last_selected_text)
            event.stop()

    async def _process_key(self, event: events.Key) -> None:
        raw_input = event.character or ""
        key = event.key  
        if key == "ctrl+c":
            if self.run_abort_event is not None:
                self.run_abort_event.set()
            self.exit()
            return

        if key == "escape" and self.state.busy:
            if self.run_abort_event is not None:
                self.run_abort_event.set()
            return

        if await self._handle_modal_key(key, raw_input):
            return

        if key == "ctrl+o":
            self.dispatch(ExpandToolOutput())
            return
        if key == "ctrl+f":
            self.dispatch(CycleTranscriptFilter())
            return
        if len(self.mention_matches) > 0:
            if key == "up":
                self.mention_idx = (self.mention_idx - 1 + len(self.mention_matches)) % len(self.mention_matches)
                return
            if key == "down":
                self.mention_idx = (self.mention_idx + 1) % len(self.mention_matches)
                return
            if key == "tab" or key == "enter":
                picked = self.mention_matches[self.mention_idx] if self.mention_idx < len(self.mention_matches) else None
                if picked and self.mention_ctx:
                    head = self.input.value[: self.mention_ctx["at"]]
                    suffix = "" if picked.is_dir else " "
                    self.input.set_value(f"{head}@{picked.insert}{suffix}")
                return
            if key == "escape":
                if self.mention_ctx:
                    self.input.set_value(self.input.value[: self.mention_ctx["at"]])
                return

        if len(self.slash_matches) > 0:
            if key == "up":
                self.slash_idx = (self.slash_idx - 1 + len(self.slash_matches)) % len(self.slash_matches)
                return
            if key == "down":
                self.slash_idx = (self.slash_idx + 1) % len(self.slash_matches)
                return
            if key == "tab":
                picked = self.slash_matches[self.slash_idx] if self.slash_idx < len(self.slash_matches) else None
                if picked:
                    self.input.set_value(f"{picked.name} " if picked.args else picked.name)
                return
            if key == "enter":
                picked = self.slash_matches[self.slash_idx] if self.slash_idx < len(self.slash_matches) else None
                typed = self.input.value.strip()
                if picked and typed == picked.name:
                    self.input.clear()
                    self.submit(typed)
                    return
                if picked:
                    self.input.set_value(f"{picked.name} " if picked.args else picked.name)
                    return
            if key == "escape":
                self.input.clear()
                return

        if self.state.busy:
            return

        if key == "escape":
            if len(self.input.value) > 0:
                self.input.clear()
            if self.history_idx is not None:
                self.history_idx = None
                self.history_draft = ""
            return

        if looks_like_paste(raw_input, key == "enter"):
            self._insert_pasted_text(raw_input)
            return

        if key in ("ctrl+n", "ctrl+j"):  
            self.input.insert_text("\n")
            return

        if key == "enter":
            v = self.input.value.strip()
            if len(v) == 0:
                return
            self.input.clear()
            self.submit(v)
            return

        if key == "left":
            self.input.move_left()
            return
        if key == "right":
            self.input.move_right()
            return
        if key == "up":
            if "\n" not in self.input.value and cursor_is_on_first_line(self.input.value, self.input.cursor):
                h = self.history
                if len(h) == 0:
                    return
                if self.history_idx is None:
                    self.history_draft = self.input.value
                    next = len(h) - 1
                    self.history_idx = next
                    self.input.set_value(h[next] if next < len(h) else "")
                elif self.history_idx > 0:
                    next = self.history_idx - 1
                    self.history_idx = next
                    self.input.set_value(h[next] if next < len(h) else "")
                return
            self.input.move_up()
            return
        if key == "down":
            if "\n" not in self.input.value and cursor_is_on_last_line(self.input.value, self.input.cursor):
                if self.history_idx is None:
                    return  
                h = self.history
                next = self.history_idx + 1
                if next >= len(h):
                    self.history_idx = None
                    self.input.set_value(self.history_draft)
                    self.history_draft = ""
                else:
                    self.history_idx = next
                    self.input.set_value(h[next])
                return
            self.input.move_down()
            return
        if key == "ctrl+a":
            self.input.move_line_start()
            return
        if key == "ctrl+e":
            self.input.move_line_end()
            return

        if key in ("backspace", "delete"):
            self.input.backspace()
            return

        if key.startswith("ctrl+") or key.startswith("meta+"):  
            return

        if raw_input and key != "escape":
            self.input.insert_text(raw_input)

    def _get_active_modal(self):

        if self.text_input:
            if self._text_input_modal is None or self._text_input_modal.req is not self.text_input:
                self._text_input_modal = TextInputModal(self.text_input)
            return self._text_input_modal
        self._text_input_modal = None

        if self.state.pending_ask:
            if not self.state.pending_ask.question.options:
                if self._ask_text_input_for is not self.state.pending_ask:
                    question = self.state.pending_ask.question
                    self._ask_text_input_for = self.state.pending_ask
                    self._ask_text_input_modal = TextInputModal(
                        TextInputRequest(
                            header=question.header or "Question",
                            question=question.question,
                            placeholder=None,
                            resolve=self.state.pending_ask.resolve,
                            reject=self.state.pending_ask.reject,
                        )
                    )
                return self._ask_text_input_modal
            self._ask_text_input_for = None
            self._ask_text_input_modal = None
            if self._ask_modal is None or self._ask_modal.req is not self.state.pending_ask:
                self._ask_modal = AskModal(self.state.pending_ask)
            return self._ask_modal
        self._ask_text_input_for = None
        self._ask_text_input_modal = None
        self._ask_modal = None

        if self.state.pending_perm:
            if self._perm_modal is None or self._perm_modal.req is not self.state.pending_perm:
                self._perm_modal = PermissionModal(self.state.pending_perm)
            return self._perm_modal
        self._perm_modal = None

        if self.state.pending_skills:
            if self._skills_modal is None:
                self._skills_modal = SkillsModal(
                    agent=self.agent,
                    on_close=lambda: self.dispatch(SetSkillsPicker(open=False)),
                    persist_disabled_skills=self.persist_disabled_skills,
                )
            return self._skills_modal
        self._skills_modal = None

        return None

    async def _handle_modal_key(
        self,
        key: str,
        raw_input: str = "",
    ) -> bool:

        modal = self._get_active_modal()
        if modal is None:
            return False

        if isinstance(modal, TextInputModal):
            result = modal.handle_key(key, raw_input)
        else:
            result = modal.handle_key(key)
        if asyncio.iscoroutine(result):
            await result

        self._sync_overlay()
        return True

    def _recompute_view(self) -> None:

        transcript = self.state.transcript
        tfilter = self.state.transcript_filter

        last = transcript[-1] if transcript else None
        live = last if (last and last.kind == "assistant" and last.streaming) else None
        committed = transcript[:-1] if live else transcript

        filtered_committed = filter_transcript(list(committed), tfilter)
        generation = f"{self.state.clear_gen}:{tfilter}"
        self.transcript_writer.flush(
            filtered_committed,
            self.state.banner_data,
            generation,
            clear_message=self.state.clear_message,
        )

        show_live = transcript_entry_matches_filter(live, tfilter) if live else False
        if live and show_live:
            self._render_live_entry(live)
        else:
            self.live_entry_static.update("")

        expand_hint = any(e.collapsible and not e.expanded for e in transcript)

        self._sync_overlay()
        self._sync_status_bar(expand_hint=expand_hint)

    def _render_live_entry(self, live: TranscriptEntry) -> None:
        text = Text()
        for i, ln in enumerate(entry_view(live, streaming=True)):
            if i > 0:
                text.append("\n")
            text.append(ln.text, style=ln.color)
        self.live_entry_static.update(text)

    def _render_input(self) -> None:
        box = InputBox(
            value=self.input.value,
            cursor=self.input.cursor,
            disabled=self.state.busy,
        )
        text = Text()
        for i, line in enumerate(box.render()):
            if i > 0:
                text.append("\n")
            for seg in line.segments:
                text.append(seg.text, style=_input_style(seg.style))
        self.input_static.value = self.input.value
        self.input_static.update(text)

    def _sync_overlay(self) -> None:

        modal = self._get_active_modal()
        self.overlay_static.set_class(
            isinstance(modal, (TextInputModal, AskModal, PermissionModal)),
            "modal-panel",
        )

        if modal is not None:
            self.overlay_static.update(_modal_text(modal))
            self.overlay_static.display = True
        elif self.mention_matches:
            menu = MentionMenu(
                cwd=(self.mention_ctx or {}).get("dir", ""),
                candidates=self.mention_matches,
                selected=self.mention_idx,
            )
            self.overlay_static.update(self._menu_lines_to_text(menu.render()))
            self.overlay_static.display = True
        elif self.slash_matches:
            menu = SlashMenu(items=self.slash_matches, selected=self.slash_idx)
            self.overlay_static.update(self._menu_lines_to_text(menu.render()))
            self.overlay_static.display = True
        else:
            self.overlay_static.update("")
            self.overlay_static.display = False

        self.input_static.display = modal is None

    def _menu_lines_to_text(self, lines) -> Text:
        text = Text()
        for i, ln in enumerate(lines):
            if i > 0:
                text.append("\n")
            style = (
                f"bold {ACCENT}"
                if getattr(ln, "selected", False)
                else ("dim" if getattr(ln, "dim", False) else "")
            )
            text.append(ln.text, style=style)
        return text

    def _sync_status_bar(self, *, expand_hint: bool) -> None:
        cache_key = (len(self.state.transcript), self.state.busy)
        if cache_key != self._status_cache_key:
            self._status_cache_key = cache_key
            self._status_info = {
                "target": self.agent.target.base_url() or self.agent.target.name(),
                "memory_items": self.agent.get_memory_stats().items,
                "ctx_tokens": self.agent.approx_tokens(),
                "compact_threshold": self.agent.get_auto_compact_threshold(),
            }

        self.status_bar.apply(
            StatusProps(
                busy=self.state.busy,
                api_ready=self.state.api_ready,
                active_skill=self.state.active_skill,
                yolo=self.state.yolo,
                phase=self.state.phase,
                transcript_filter=self.state.transcript_filter,  
                model=self.state.banner_data.model,
                tool_support=self.state.banner_data.tool_support,
                target=self._status_info["target"],
                expand_hint=expand_hint,
                running_tool=self.state.running_tool,
                ctx_tokens=self._status_info["ctx_tokens"],
                compact_threshold=self._status_info["compact_threshold"],
                memory_items=self._status_info["memory_items"],
                elapsed_seconds=self.status_bar.elapsed_seconds,
            )
        )

    def _sync_elapsed_timer(self, busy: bool) -> None:

        if busy and not self._elapsed_busy:
            import time

            self._elapsed_start = time.monotonic()
            self._elapsed_timer = self.set_interval(1.0, self._tick_elapsed)
        elif not busy and self._elapsed_busy:
            if self._elapsed_timer is not None:
                self._elapsed_timer.stop()
            self.status_bar.elapsed_seconds = None
        self._elapsed_busy = busy

    def _tick_elapsed(self) -> None:
        import time

        self.status_bar.elapsed_seconds = time.monotonic() - self._elapsed_start


    async def run_agent_turn(
        self,
        value: str,
        opts: RunAgentOptions | None = None,
    ) -> None:
        if self.agent.is_running():
            self.dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=(
                            "a turn is already running — cancel it with Esc"
                            " first"
                        ),
                    )
                )
            )
            return

        if self.session_debug:
            self.session_debug.write(
                "turn_start",
                {
                    "prompt": value,
                    "transcript_user_text": (
                        opts.transcript_user_text if opts else None
                    ),
                    "system_text": (opts.system_text if opts else None),
                },
            )

        if opts and opts.transcript_user_text:
            self.dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="user",
                        text=opts.transcript_user_text,
                    ),
                )
            )

        if opts and opts.system_text:
            self.dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=opts.system_text,
                    ),
                )
            )

        self.dispatch(
            SetBusy(
                busy=True,
            )
        )

        abort_event = AbortEvent()
        self.run_abort_event = abort_event
        def handle_event(
            ev: AgentEvent,
        ) -> None:
            if self.session_debug is not None:
                self.session_debug.agent_event(dataclasses.asdict(ev))

            if ev.type == "error" and isinstance(ev.err, MaxStepsError):
                steps = ev.err.steps

                self.dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="system",
                            text=(
                                f"Reached max steps ({steps}) without finishing."
                            ),
                        )
                    )
                )

                async def continue_run() -> None:
                    self.dispatch(SetAsk(req=None))

                    await self.run_agent_turn(
                        "Continue from where you stopped and finish the current task.",
                        RunAgentOptions(
                            system_text="continuing after max-steps limit"
                        ),
                    )

                def handle_abort_during_ask() -> None:

                    self.dispatch(SetAsk(req=None))

                    self.dispatch(
                        Append(
                            entry=TranscriptEntry(
                                kind="system",
                                text="stopped at max steps",
                            )
                        )
                    )

                async def wait_abort_then_reject() -> None:
                    await abort_event.wait()
                    handle_abort_during_ask()

                abort_watcher = asyncio.create_task(wait_abort_then_reject())

                def resolve_max_steps(
                    label: str,
                ) -> None:
                    abort_watcher.cancel()

                    if label == "Continue":
                        asyncio.create_task(continue_run())
                    else:
                        self.dispatch(SetAsk(req=None))

                        self.dispatch(
                            Append(
                                entry=TranscriptEntry(
                                    kind="system",
                                    text="stopped at max steps",
                                )
                            )
                        )

                def reject_max_steps(_: Exception) -> None:
                    abort_watcher.cancel()
                    handle_abort_during_ask()

                self.dispatch(
                    SetAsk(
                        req=AskRequest(
                            question=Question(
                                header="Max steps",
                                question=(
                                    "The agent reached the per-turn step limit."
                                    " Continue or stop?"
                                ),
                                options=[
                                    Option(
                                        label="Continue",
                                        description=(
                                            "Start another turn and continue "
                                            "from the current session state."
                                        ),
                                    ),
                                    Option(
                                        label="Stop",
                                        description=(
                                            "Leave the session as-is so you "
                                            "can decide the next command."
                                        ),
                                    ),
                                ],
                            ),
                            resolve=resolve_max_steps,
                            reject=reject_max_steps,
                        )
                    )
                )
                return

            self.dispatch(AgentEventAction(event=ev))

        try:
            await self.agent.run(
                value,
                signal=abort_event,
                emit=handle_event,
                opts=opts.run_options if opts else None,
            )

        except Exception as err:
            if self.session_debug is not None:
                self.session_debug.write(
                    "run_error",
                    {
                        "error": str(err),
                    },
                )

            self.dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=str(err),
                    )
                )
            )

        finally:
            self.run_abort_event = None

            self.dispatch(
                SetBusy(
                    busy=False,
                )
            )


    def run_agent_compact(self) -> None:
        """Fire-and-forget compact, giống `void agent.compact(...)` trong TS."""

        if self.session_debug:
            self.session_debug.write("compact_start")

        self.dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text="Compacting conversation...",
                )
            )
        )

        self.dispatch(
            SetBusy(
                busy=True,
            )
        )

        self.run_task = asyncio.create_task(
            self._run_agent_compact(),
            name="agent-compact",
        )

    async def _run_agent_compact(self) -> None:
        abort_event = AbortEvent()
        self.run_abort_event = abort_event

        def handle_event(event: AgentEvent) -> None:
            if self.session_debug is not None:
                self.session_debug.agent_event(dataclasses.asdict(event))

            self.dispatch(AgentEventAction(event=event))

        try:
            await self.agent.compact(
                signal=abort_event,
                emit=handle_event,
            )

        except asyncio.CancelledError:
            raise

        except Exception as err:
            if self.session_debug:
                self.session_debug.write(
                    "compact_error",
                    {
                        "err": {
                            "name": type(err).__name__,
                            "message": str(err),
                        }
                    },
                )

            self.dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=f"compact: {err}",
                    )
                )
            )

        finally:
            self.run_abort_event = None
            self.run_task = None


            self.dispatch(
                SetBusy(
                    busy=False,
                )
            )


    def on_resize(self, event: events.Resize) -> None:
        self.cols = event.size.width
        self._render_input()
        self.refresh()

    def on_mount(self) -> None:

        if self.bind_perm_publisher is not None:
            self.bind_perm_publisher(
                lambda req: self.dispatch(SetPerm(req=req))
            )

        if self.bind_ask_publisher is not None:
            self.bind_ask_publisher(
                lambda req: self.dispatch(SetAsk(req=req))
            )

        if self.bind_banner_publisher is not None:
            self.bind_banner_publisher(
                lambda patch: self.dispatch(MergeBannerData(patch=patch))
            )

        if self.bind_notice_publisher is not None:
            self.bind_notice_publisher(
                lambda text: self.dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="system",
                            text=text,
                        )
                    )
                )
            )

        if not self.resume_summary_shown and self.resume_summary:
            self.resume_summary_shown = True
            self.dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=self.resume_summary,
                    )
                )
            )

        self.ping_task = PingTask(
            lambda: self.agent.client,
            lambda ok: self.dispatch(SetApiReady(ready=ok)),
        )
        self.ping_task.start()

        if self.parent_signal.is_set():
            self._on_parent_abort()
        else:
            self.parent_abort_task = asyncio.create_task(
                self._wait_parent_abort()
            )

        asyncio.create_task(self._save_snapshot())

        self.snapshot_task = asyncio.create_task(
            self._snapshot_loop()
        )

    async def on_unmount(self) -> None:
        if self.snapshot_task:
            self.snapshot_task.cancel()

        if self.parent_abort_task is not None:
            self.parent_abort_task.cancel()

        if self.ping_task is not None:
            await self.ping_task.stop()


    async def _save_snapshot(self) -> None:
        if self.agent.is_running():
            return

        if self.snapshot_saving:
            return

        self.snapshot_saving = True

        try:
            path = await self.agent.save_context_snapshot(
                "periodic 5 minute snapshot"
            )

            if path and self.session_debug is not None:
                self.session_debug.write(
                    "context_snapshot",
                    {
                        "path": path,
                    },
                )

        except Exception as err:
            if self.session_debug is not None:
                self.session_debug.write(
                    "context_snapshot_error",
                    {
                        "err": str(err),
                    },
                )

        finally:
            self.snapshot_saving = False

    async def _snapshot_loop(self) -> None:
        while True:
            await asyncio.sleep(CONTEXT_SNAPSHOT_INTERVAL)

            await self._save_snapshot()


    async def _wait_parent_abort(self) -> None:
        await self.parent_signal.wait()
        self._on_parent_abort()

    def _on_parent_abort(self) -> None:
        if self.run_abort_event is not None:
            self.run_abort_event.set()
        self.exit()


    def submit(self, value: str) -> None:
        agent_value = expand_pasted_text_markers(
            value,
            self.pasted_text,
        )

        recorded = value.strip()

        if recorded:
            if not self.history or self.history[-1] != recorded:
                self.history.append(recorded)

                if len(self.history) > self.HISTORY_CAP:
                    self.history.pop(0)

        self.history_idx = None
        self.history_draft = ""

        if agent_value.startswith("#"):
            personal = agent_value.startswith("#!")

            text = (
                agent_value[2:].strip()
                if personal
                else agent_value[1:].strip()
            )

            if not text:
                self.dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="system",
                            text=(
                                "usage: #<text to remember>"
                                "  (or #!<text> for personal)"
                            ),
                        )
                    )
                )
                return

            async def save_memory() -> None:
                try:
                    fact = await self.agent.add_memory(
                        AddMemoryInput(
                            text=text,
                            scope="personal" if personal else "project",
                        )
                    )

                    if fact:
                        self.dispatch(
                            Append(
                                entry=TranscriptEntry(
                                    kind="system",
                                    text=(
                                        f"remembered "
                                        f"({fact.scope}/{fact.type}): "
                                        f"{fact.name}"
                                    ),
                                )
                            )
                        )
                    else:
                        self.dispatch(
                            Append(
                                entry=TranscriptEntry(
                                    kind="error",
                                    text=(
                                        "memory not saved "
                                        "(empty after redaction or no store)"
                                    ),
                                )
                            )
                        )

                except Exception as err:
                    self.dispatch(
                        Append(
                            entry=TranscriptEntry(
                                kind="error",
                                text=f"memory save failed: {err}",
                            )
                        )
                    )

            asyncio.create_task(save_memory())
            return

        if agent_value.startswith("/"):
            handled = handle_slash(self, agent_value)
            if handled:
                return

        asyncio.create_task(
            self.run_agent_turn(
                agent_value,
                RunAgentOptions(
                    transcript_user_text=value,
                ),
            )
        )
