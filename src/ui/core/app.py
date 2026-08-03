from __future__ import annotations

plastic_imports = None  # To preserve structure space
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
from src.ui.widgets.input_box import InputBox
from src.ui.widgets.mention_menu import MentionMenu
from src.ui.widgets.permission_modal import PermissionModal
from src.ui.widgets.skills_modal import SkillsModal
from src.ui.widgets.text_input_modal import TextInputModal, TextInputRequest
from src.ui.widgets.slash_menu import SlashMenu
from src.ui.widgets.status_bar import StatusBar, StatusProps
from src.ui.widgets.transcript import Transcript, entry_view

# ==========================================================
# Constants
# ==========================================================

MENTION_LIMIT = 12
CLEAR_SCREEN = "\x1b[2J\x1b[3J\x1b[H"
CONTEXT_SNAPSHOT_INTERVAL = 5 * 60

# ==========================================================
# Types & Data Structures
# ==========================================================

class AbortEvent(asyncio.Event):
    """asyncio.Event mở rộng thêm interface AbortSignal (`.aborted`,
    `.abort()`, `.throw_if_aborted()`) mà agent.py cần, đồng thời vẫn giữ
    `.wait()` / `.set()` / `.is_set()` để dùng như asyncio.Event thông
    thường ở các chỗ khác trong app.py."""

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


class BurpBridgeInfo(TypedDict):
    url: str
    token: str
    already_running: bool


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
        Callable[[int | None], Awaitable[BurpBridgeInfo]] | None
    ) = None
    resume_summary: str | None = None


@dataclass(slots=True)
class RunAgentOptions:
    transcript_user_text: str | None = None
    system_text: str | None = None
    run_options: AgentRunOptions | None = None


# ==========================================================
# Textual view-sync adapters (port của phần render JSX bên TS)
#
# Các class dưới đây (Transcript, InputBox, entry_view, AskModal,
# PermissionModal, SkillsModal, TextInputModal, MentionMenu, SlashMenu)
# đều là PURE RENDERER — không phải Textual Widget, chỉ tính ra
# text/dataclass thuần. Phần adapter này chịu trách nhiệm nối chúng vào
# cây widget Textual thật (RichLog/Static) trong class Pentestagent.
# ==========================================================


class _RichLogWriter:
    """Cho Transcript (vốn ghi ra IO[str]) ghi vào RichLog thay vì stdout.
    Transcript tự thêm "\\n" cuối mỗi dòng khi gọi out.write(), RichLog tự
    xuống dòng mỗi lần .write() nên phải strip lại tránh dòng trống dư."""

    def __init__(self, log: RichLog) -> None:
        self._log = log

    def write(self, s: str) -> int:
        self._log.write(s.rstrip("\n"))
        return len(s)


# Style map cho InputBox.render() (InputSegment.style) -> rich style string.
# TODO: đoán theo status_bar.py ("grey62" cho text mờ) — chưa có bảng màu/
# theme chính thức để đối chiếu chính xác, xác nhận lại nếu có theme riêng.
_INPUT_STYLE_MAP: dict[str, str] = {
    "gray": "grey62",
    "prompt": "bold cyan",
    "text": "white",
    "cursor": "bold white",
    "cursor_char": "reverse",
}


def _input_style(name: str | None) -> str:
    return _INPUT_STYLE_MAP.get(name or "text", name or "")


# filter_transcript / transcript_entry_matches_filter
# TODO: KHÔNG có bản TS gốc trong ngữ cảnh — suy luận từ
# TRANSCRIPT_FILTERS = ["all","compact","findings","errors","current"]
# trong state.py. "current" không có field turn-id trong TranscriptEntry
# nên tạm coi là "kể từ entry kind='user' gần nhất". Cần xác nhận lại với
# bản TS gốc filterTranscript/transcriptEntryMatchesFilter nếu có.


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
    return True  # "current": live entry luôn thuộc lượt hiện tại


# ==========================================================
# Main Application Class
# ==========================================================


class Pentestagent(App):

    # ==========================================================
    # Init
    # ==========================================================

    def __init__(self, props: AppProps):
        super().__init__()

        # Props
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
        self.resume_summary = props.resume_summary

        # useReducer
        self.state = initial_state(
            "",
            self.banner_data,
        )

        if props.yolo_initial:
            self.state = replace(
                self.state,
                yolo=True,
            )

        # useTextField
        self.input = TextField("")

        # useState
        self.slash_idx = 0
        self.mention_idx = 0
        self.text_input = None

        # derived menu state (được _recompute_menus() cập nhật mỗi khi
        # input value đổi — tương đương phần tính slashMatches/mentionMatches
        # ở đầu component TS, chạy lại mỗi render). Được wire vào on_key
        # bên dưới (xem method _recompute_menus() + on_key()).
        self.slash_matches: list[SlashItem] = []
        self.mention_matches: list = []
        self.mention_ctx: dict | None = None
        self._prev_slash_match_count: int | None = None
        self._prev_mention_match_count: int | None = None

        # useRef
        self.run_task: asyncio.Task | None = None
        self.run_abort_event: AbortEvent | None = None
        self.snapshot_task: asyncio.Task | None = None

        # Live terminal width (tương đương useTerminalSize()); cập nhật
        # qua on_resize khi Textual gửi events.Resize.
        self.cols: int = 80

        # Banner đóng băng tại thời điểm khởi động — bỏ các field resolve
        # bất đồng bộ (tool_support, context_window) để tránh bị kẹt ở
        # placeholder mãi mãi; giá trị sống hiển thị ở StatusBar thay vì
        # banner tĩnh.
        self.banner_snapshot: BannerData = replace(
            self.banner_data,
            tool_support=None,
            context_window=None,
        )

        # Live health probe + task theo dõi abort từ tiến trình cha.
        self.ping_task: PingTask | None = None
        self.parent_abort_task: asyncio.Task | None = None

        self.snapshot_saving = False
        self.resume_summary_shown = False

        # history
        self.history: list[str] = []
        self.history_draft = ""
        self.history_idx: int | None = None
        self.HISTORY_CAP = 500

        # paste tracking
        self.pasted_text: dict[int, str] = {}
        self.pasted_text_seq = 0

        # text prompt
        self.text_input_future: asyncio.Future[str] | None = None

        # --- Textual view-sync state (port của phần render JSX) ---
        # Cache modal có state nội bộ (value gõ dở, idx đang chọn...) —
        # phải tái sử dụng instance qua nhiều lần vẽ, xem _get_active_modal().
        self._text_input_modal: TextInputModal | None = None
        self._ask_modal: AskModal | None = None
        self._perm_modal: PermissionModal | None = None
        self._skills_modal: SkillsModal | None = None

        # Cache statusInfo (target/memory/tokens/threshold) — chỉ tính lại
        # khi (len(transcript), busy) đổi, tương đương useMemo phía TS.
        self._status_cache_key: tuple | None = None
        self._status_info: dict = {}

        # Elapsed clock (tương đương ElapsedTimer bên TS).
        self._elapsed_busy = False
        self._elapsed_timer = None
        self._elapsed_start: float = 0.0

    # ==========================================================
    # Compose — dựng cây widget MỘT LẦN lúc mount. Không có nhánh
    # if/else theo state ở đây (khác JSX) — mount hết rồi ẩn/hiện hoặc
    # cập nhật nội dung động trong _recompute_view()/_sync_overlay().
    # ==========================================================

    def compose(self) -> ComposeResult:
        # Committed log -> RichLog (append-only scrollback), thay cho
        # Ink <Static>. Transcript instance ghi vào đây qua adapter.
        self.transcript_log = RichLog(wrap=True, markup=False, auto_scroll=True)
        yield self.transcript_log
        self.transcript_writer = Transcript(
            out=cast(IO[str], _RichLogWriter(self.transcript_log))
        )

        # Entry đang streaming — Static vì cần OVERWRITE mỗi delta, khác
        # RichLog chỉ append.
        self.live_entry_static = Static(id="live-entry")
        yield self.live_entry_static

        # Overlay: đúng MỘT trong {text input, ask, perm, skills, mention
        # menu, slash menu} hiện tại một thời điểm — nội dung được thay
        # trong _sync_overlay(), không mount/remove widget con vì các modal
        # không phải Widget.
        self.overlay_static = Static(id="overlay")
        yield self.overlay_static

        # Input box — InputBox chỉ tính ra list[InputLine], không tự vẽ
        # được lên Textual, nên dùng Static + _render_input().
        self.input_static = Static(id="input-box")
        yield self.input_static

        self.status_bar = StatusBar()
        yield self.status_bar

        self._render_input()

    # ==========================================================
    # Reducer
    # ==========================================================

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

    # ==========================================================
    # Error helpers
    # ==========================================================

    def is_max_steps_error(
        self,
        err: Exception,
    ) -> bool:
        return isinstance(
            err,
            MaxStepsError,
        )

    # ==========================================================
    # YOLO toggle
    # ==========================================================

    def apply_yolo(self, on: bool) -> None:
        """Bật/tắt YOLO ở một chỗ duy nhất: chỉnh gate thật (prompter) VÀ
        pill hiển thị cùng lúc để chúng không bao giờ lệch nhau."""

        if self.set_yolo is not None:
            self.set_yolo(on)

        self.dispatch(SetYolo(on=on))

    # ==========================================================
    # Clear screen
    # ==========================================================

    def clear_screen(self) -> None:
        """Xoá màn hình + scrollback cho /clear và /reset.

        Clear() action (state.py) đã xoá state.transcript + tăng
        clear_gen. RichLog là scrollback NGOÀI reducer nên tự .clear()
        riêng, và tạo lại Transcript writer để _printed_count về 0
        (Transcript cũng tự reset theo generation, nhưng clear luôn cho
        chắc — clear_gen đổi kéo theo generation đổi ngay ở lần
        _recompute_view() tiếp theo do dispatch(Clear()) gọi ra).
        """
        self.dispatch(Clear())
        self.transcript_log.clear()
        self.transcript_writer = Transcript(
            out=cast(IO[str], _RichLogWriter(self.transcript_log))
        )

    # ==========================================================
    # Text input
    # ==========================================================

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

    # ==========================================================
    # Menu derivation (slash / @mention)
    # ==========================================================

    def _recompute_menus(self) -> None:
        """Tính lại slash_matches / mention_matches từ input hiện tại.

        Được gọi trong on_key() ngay sau mỗi lần self.input.value thay đổi
        (chèn ký tự, xoá ký tự, paste, v.v.) — tương đương việc TS tính
        lại slashMatches/mentionMatches mỗi render vì inputValue là state.
        """

        value = self.input.value

        # Slash menu chỉ tính khi input là lệnh slash — filterSlash trả
        # về [] cho input thường bất kể extras, nên tính skill list mỗi
        # keystroke khi gõ văn xuôi (trường hợp phổ biến) là lãng phí.
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

        # @file picker: active word bắt đầu bằng @<partial>.
        # find_active_mention trả về dict {"at": int, "partial": str}
        # hoặc None — KHÔNG phải object có attribute.
        mention_ctx = find_active_mention(value)
        mention_dir_base = (
            parse_mention_path(mention_ctx["partial"]) if mention_ctx else None
        )
        # parse_mention_path trả về tuple[str, str] = (dir, base)
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

        # Reset menu selection when the relevant menu (re)appears —
        # effect chạy mỗi khi length ĐỔI GIÁ TRỊ (không chỉ 0 -> dương).
        if len(slash_matches) != self._prev_slash_match_count:
            if len(slash_matches) > 0:
                self.slash_idx = 0
        self._prev_slash_match_count = len(slash_matches)

        if len(mention_matches) != self._prev_mention_match_count:
            if len(mention_matches) > 0:
                self.mention_idx = 0
        self._prev_mention_match_count = len(mention_matches)

    # ==========================================================
    # Key handling (port của useInput hook TS)
    # ==========================================================

    async def on_key(self, event: events.Key) -> None:
        """Wrapper mỏng quanh _process_key(): Textual không tự re-render
        như React, nên sau khi xử lý phím xong phải tự đồng bộ lại
        menu/overlay/input box — 3 việc mà bản gốc từng để lửng
        (_recompute_menus chưa từng được gọi ở đâu cả)."""

        prev_value = self.input.value

        await self._process_key(event)

        if self.input.value != prev_value:
            self._recompute_menus()

        self._sync_overlay()
        self._render_input()

    async def _process_key(self, event: events.Key) -> None:
        raw_input = event.character or ""
        key = event.key  # TODO: xác nhận định dạng thực tế của Textual (event.key) bằng runtime — chưa verify "ctrl+c", "escape", "up", "down", "enter", "tab", "backspace", "delete", "left", "right", "ctrl+a", "ctrl+e", "ctrl+o", "ctrl+f", "ctrl+n", "ctrl+j"

        # 0. Always-on: Ctrl-C kills the app; Esc cancels an in-flight run.
        if key == "ctrl+c":
            if self.run_abort_event is not None:
                self.run_abort_event.set()
            self.exit()
            return

        if key == "escape" and self.state.busy:
            if self.run_abort_event is not None:
                self.run_abort_event.set()
            return

        # 1. Modal overlays consume keys before us.
        if await self._handle_modal_key(key, raw_input):
            return

        # 2. History scrolling is the terminal's own job now — the transcript
        #    lives in native scrollback (Ink <Static>), so the mouse wheel and
        #    scrollbar reach the full conversation. No in-app scroll keys.
        #
        #    Ctrl-O ("output") reprints the most recent truncated tool-result's
        #    full body as a new log entry — e.g. the full browser accessibility
        #    snapshot behind a "… N more lines" notice. No-op when nothing is
        #    collapsible.
        if key == "ctrl+o":
            self.dispatch(ExpandToolOutput())
            return
        if key == "ctrl+f":
            self.dispatch(CycleTranscriptFilter())
            return

        # 3. Active @file picker (takes priority over slash so /commands
        #    don't interfere when the user already engaged the @ menu).
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
                    # Directories: descend by replacing the partial with the new
                    # path and leave the picker engaged (no trailing space). The
                    # path already ends in `/`, so the next render will list it.
                    # Files: replace with `@<path> ` and close the picker.
                    head = self.input.value[: self.mention_ctx["at"]]
                    suffix = "" if picked.is_dir else " "
                    self.input.set_value(f"{head}@{picked.insert}{suffix}")
                return
            if key == "escape":
                # Strip the @<partial> back to the @ itself so the menu drops.
                if self.mention_ctx:
                    self.input.set_value(self.input.value[: self.mention_ctx["at"]])
                return

        # 4. Active slash menu.
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
                # Enter on a menu: if the typed input is already a complete
                # command, submit it; otherwise complete the highlighted one.
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

        # 5. Normal multi-line input editing.
        if self.state.busy:
            return

        # 5a. Esc clears the input when there's text to clear. The
        #     "Esc = give up on this draft" gesture — at
        #     this point in the keymap the menu / modal Esc-handlers above
        #     have already returned, so we know the user wants to abandon
        #     a half-typed prompt, not dismiss a menu.
        if key == "escape":
            if len(self.input.value) > 0:
                self.input.clear()
            # Always exit history mode on Esc — the next ↑ should walk from
            # the newest entry, not from wherever we last were.
            if self.history_idx is not None:
                self.history_idx = None
                self.history_draft = ""
            return

        # 5b. Bracketed paste / multi-character chunks. Insert wholesale
        #     so an embedded newline doesn't auto-submit the half-typed
        #     prompt (and so heredocs / payloads land in one piece).
        if looks_like_paste(raw_input, key == "enter"):
            pasted = normalize_pasted_text(strip_paste_markers(raw_input))
            if should_collapse_paste(pasted):
                self.pasted_text_seq += 1
                id = self.pasted_text_seq
                self.pasted_text[id] = pasted
                self.input.insert_text(pasted_text_marker(id, pasted))
                return
            self.input.insert_text(pasted)
            return

        # 5b. Ctrl-N (or Ctrl-J on some terminals) → insert a newline
        #     instead of submitting (the Ctrl-J convention). Ink reports Ctrl-J as key.return + key.ctrl on most
        #     terminals; some report it as key.ctrl + input === 'j'.
        if key in ("ctrl+n", "ctrl+j"):  # TODO: xác nhận runtime — nhánh TS `(key.return && rawInput === '')` chưa có tương đương rõ ràng trong Textual
            self.input.insert_text("\n")
            return

        if key == "enter":
            v = self.input.value.strip()
            if len(v) == 0:
                return
            self.input.clear()
            self.submit(v)
            return

        # 5c. Cursor movement.
        if key == "left":
            self.input.move_left()
            return
        if key == "right":
            self.input.move_right()
            return
        # ↑/↓ move between lines inside a multi-line draft. Prompt history is
        # available only for single-line input, so editing a pasted/request
        # draft never gets interrupted by an older command.
        #
        #   - Single-line ↑ on the first line → previous history entry (newer→older).
        #   - Single-line ↓ on the last line  → next history entry; past the newest,
        #     restore the draft the user had before entering history mode.
        if key == "up":
            if "\n" not in self.input.value and cursor_is_on_first_line(self.input.value, self.input.cursor):
                h = self.history
                if len(h) == 0:
                    return
                if self.history_idx is None:
                    # Entering history mode — stash the draft so Down can restore it.
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
                    return  # not in history mode, nothing below
                h = self.history
                next = self.history_idx + 1
                if next >= len(h):
                    # Past the newest entry → restore whatever draft we stashed.
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

        # 5d. Deletion. macOS keyboards label the left-delete key "delete"
        # and many terminals report it as key.delete (not key.backspace).
        # Treat both as delete-left so the key matches user expectation; a
        # true forward-delete can be added via a chord later if anyone asks.
        # The behavior also matches our original single-line input which
        # collapsed both into a single setValue((v) => v.slice(0, -1)).
        if key in ("backspace", "delete"):
            self.input.backspace()
            return

        # 5e. Other chords reserved (Ctrl-L clear-transcript is handled
        #     elsewhere; Ctrl-K kill, Ctrl-Y yank could land later).
        if key.startswith("ctrl+") or key.startswith("meta+"):  # TODO: xác nhận cách Textual biểu diễn modifier meta
            return

        # 5f. Plain printable character.
        if raw_input and key != "escape":
            self.input.insert_text(raw_input)

    # ==========================================================
    # View sync (port của phần render JSX / useMemo / ElapsedTimer bên TS)
    #
    # Textual chỉ dựng compose() MỘT LẦN — không có "re-render cả cây"
    # như React. Các method dưới đây đóng vai trò effect: tính lại phần
    # dẫn xuất từ state rồi APPLY (update/mount) vào widget đã mount sẵn.
    # Gọi từ dispatch() (sau khi reducer chạy) và từ on_key() (cho phần
    # menu/overlay/idx không đi qua reducer).
    # ==========================================================

    def _get_active_modal(self):
        """Đúng MỘT modal đang active, ưu tiên textInput > pendingAsk >
        pendingPerm > pendingSkills — khớp thứ tự gốc. Tái sử dụng
        instance cũ nếu request chưa đổi (so identity `is`, không phải
        `==`) vì các modal này giữ state nội bộ (value gõ dở, idx đang
        chọn) cần sống xuyên suốt nhiều lần vẽ."""

        if self.text_input:
            if self._text_input_modal is None or self._text_input_modal.req is not self.text_input:
                self._text_input_modal = TextInputModal(self.text_input)
            return self._text_input_modal
        self._text_input_modal = None

        if self.state.pending_ask:
            if self._ask_modal is None or self._ask_modal.req is not self.state.pending_ask:
                self._ask_modal = AskModal(self.state.pending_ask)
            return self._ask_modal
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
        """True nếu có modal active và đã xử lý phím này (caller nên
        return luôn, không rơi xuống các bước xử lý input thường).
        modal.handle_key() có thể trả về coroutine chưa await (trường
        hợp SkillsModal.toggle()/toggle_all()) nên tự await ở đây nếu cần."""

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
        """Effect chạy sau mỗi dispatch(): flush transcript committed (đã
        filter) vào RichLog, vẽ live entry đang streaming, và đồng bộ
        overlay + status bar."""

        transcript = self.state.transcript
        tfilter = self.state.transcript_filter

        last = transcript[-1] if transcript else None
        live = last if (last and last.kind == "assistant" and last.streaming) else None
        committed = transcript[:-1] if live else transcript

        filtered_committed = filter_transcript(list(committed), tfilter)
        generation = f"{self.state.clear_gen}:{tfilter}"
        self.transcript_writer.flush(filtered_committed, self.state.banner_data, generation)

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
        self.input_static.update(text)

    def _sync_overlay(self) -> None:
        """Vẽ ĐÚNG một trong {modal active, mention menu, slash menu,
        (trống)} vào overlay_static. Chỉ MODAL (không phải @/slash menu)
        mới ẩn input — khớp đúng nhánh TS gốc (Input vẫn hiển thị cùng
        SlashMenu/MentionMenu, chỉ biến mất khi có secretInput/pendingAsk/
        pendingPerm/pendingSkills)."""

        modal = self._get_active_modal()

        if modal is not None:
            self.overlay_static.update(Text("\n".join(modal.render())))
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
                "bold magenta"
                if getattr(ln, "selected", False)
                else ("dim" if getattr(ln, "dim", False) else "")
            )
            # TODO: MentionMenuLine.icon_color (icon thư mục luôn cyan kể
            # cả không selected) chưa tách riêng được vì icon đã nối chung
            # vào ln.text trong MentionMenu.render().
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
                transcript_filter=self.state.transcript_filter,  # type: ignore[arg-type]
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
        """StatusBar.elapsed_seconds là reactive nên set nó là đủ để
        Textual tự vẽ lại riêng StatusBar — không cần tách component
        ElapsedTimer riêng như bên TS (lý do tách bên đó là tránh
        re-render App, nhưng StatusBar ở đây đã tự cô lập re-render)."""

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

    # ==========================================================
    # Agent turn
    # ==========================================================

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
                    # Tương đương rejectMaxSteps() trong TS: nếu Esc (abort)
                    # được nhấn trong lúc modal Continue/Stop đang mở, tự
                    # đóng modal và ghi nhận là đã dừng ở max-steps.
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

                # Tương đương ctl.signal.addEventListener('abort', rejectMaxSteps, { once: true })
                abort_watcher = asyncio.create_task(wait_abort_then_reject())

                def resolve_max_steps(
                    label: str,
                ) -> None:
                    # Tương đương ctl.signal.removeEventListener(...)
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
                    # Tương đương removeEventListener + gọi rejectMaxSteps() trực tiếp
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

    # ==========================================================
    # Agent compact
    # ==========================================================

    def run_agent_compact(self) -> None:
        """Fire-and-forget compact, giống `void agent.compact(...)` trong TS."""

        if self.session_debug:
            self.session_debug.write("compact_start")

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

            # Safety net: bù cho trường hợp compact() raise trước khi kịp
            # emit DoneEvent (reducer chỉ tự clear busy khi thấy DoneEvent).
            # Vô hại trên happy-path vì DoneEvent đã set busy=False rồi.
            self.dispatch(
                SetBusy(
                    busy=False,
                )
            )

    # ==========================================================
    # Lifecycle
    # ==========================================================

    def on_resize(self, event: events.Resize) -> None:
        self.cols = event.size.width
        self.refresh()

    def on_mount(self) -> None:
        # Bridge publishers wired exactly once so prompts surface as modals.

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

        # Hiện resume-summary một lần duy nhất khi session được resume.
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

        # Live health probe (tương đương usePing(clientGetter, setReady)).
        self.ping_task = PingTask(
            lambda: self.agent.client,
            lambda ok: self.dispatch(SetApiReady(ready=ok)),
        )
        self.ping_task.start()

        # SIGINT (và parent abort) huỷ mọi run đang chạy rồi thoát app.
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

    # ==========================================================
    # Context snapshot
    # ==========================================================

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

    # ==========================================================
    # Parent abort (SIGINT / parent process teardown)
    # ==========================================================

    async def _wait_parent_abort(self) -> None:
        await self.parent_signal.wait()
        self._on_parent_abort()

    def _on_parent_abort(self) -> None:
        if self.run_abort_event is not None:
            self.run_abort_event.set()
        self.exit()

    # ==========================================================
    # Submit
    # ==========================================================
    # LƯU Ý: method này bị lồng sai bên trong _on_parent_abort() ở bản
    # trước — đã đưa ra thành method ngang cấp của class Pentestagent,
    # không đổi logic bên trong.

    def submit(self, value: str) -> None:
        agent_value = expand_pasted_text_markers(
            value,
            self.pasted_text,
        )

        # history
        recorded = value.strip()

        if recorded:
            if not self.history or self.history[-1] != recorded:
                self.history.append(recorded)

                if len(self.history) > self.HISTORY_CAP:
                    self.history.pop(0)

        self.history_idx = None
        self.history_draft = ""

        # memory shortcut
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

        # slash command
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
