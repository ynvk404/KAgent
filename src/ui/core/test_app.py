from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest
from rich.text import Text
from textual import events
from textual.selection import Selection
from textual.geometry import Offset

from src.ui.bridges.ask_bridge import BridgedAskPrompter
from src.ui.bridges.perm_bridge import BridgedPermissionRequest, BridgedPrompter
from src.permission.permission import PermissionRequest
from src.ask.ask import Option, Question
from src.agent.agent import Agent
from src.agent.events import DoneEvent
from src.config.config import Backend
from src.ui.core.app import (
    AbortEvent,
    AppProps,
    ConfigSnapshot,
    KAgent,
    ProviderChange,
    _PermissionStatic,
    _RichLogWriter,
    _clean_permission_selection,
    _input_selection_text,
    _modal_text,
)
from src.ui.core.state import AgentEventAction, SetAsk, SetBusy, SetPerm
from src.ui.widgets.banner import BannerData
from src.ui.widgets.text_input_modal import TextInputRequest
from src.ui.widgets.text_input_modal import TextInputModal


def make_app() -> KAgent:
    async def apply_provider(_: ProviderChange) -> None:
        pass

    def read_config() -> ConfigSnapshot:
        return {
            "backend": cast(Backend, "openai"),
            "base_url": "",
            "api_key": "",
            "api_keys": {},
            "model": "test",
        }

    app = KAgent(
        AppProps(
            agent=cast(
                Agent,
                SimpleNamespace(skills=SimpleNamespace(list_enabled=lambda: [])),
            ),
            banner_data=BannerData(provider="test", model="test", cwd="."),
            parent_signal=asyncio.Event(),
            read_config=read_config,
            apply_provider=apply_provider,
        )
    )
    app._recompute_view = lambda: None
    app._sync_overlay = lambda: None
    app._render_input = lambda: None
    return app


class FakeInterval:
    def __init__(self) -> None:
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def timer_app() -> tuple[KAgent, FakeClock, list[FakeInterval]]:
    app = make_app()
    clock = FakeClock()
    intervals: list[FakeInterval] = []
    app._monotonic = clock
    app.status_bar = cast(Any, SimpleNamespace(elapsed_seconds=None))

    def set_interval(*_args, **_kwargs):
        interval = FakeInterval()
        intervals.append(interval)
        return interval

    app.set_interval = cast(Any, set_interval)
    return app, clock, intervals


def test_turn_timer_resets_ticks_and_retains_final_idle_value() -> None:
    app, clock, intervals = timer_app()

    app._start_turn_timer()
    assert app.status_bar.elapsed_seconds == 0
    clock.advance(18)
    app._tick_elapsed()
    assert app.status_bar.elapsed_seconds == 18

    app._stop_turn_timer()
    assert intervals[-1].stopped is True
    clock.advance(40)
    app._tick_elapsed()
    assert app.status_bar.elapsed_seconds == 18

    app._start_turn_timer()
    assert app.status_bar.elapsed_seconds == 0


def test_turn_timer_continues_while_waiting_for_permission_or_user() -> None:
    app, clock, _ = timer_app()
    app._start_turn_timer()
    app.dispatch(SetBusy(busy=True))

    app.dispatch(SetPerm(req=cast(Any, object())))
    clock.advance(4)
    app._tick_elapsed()
    assert app.state.phase == "waiting-approval"
    assert app.status_bar.elapsed_seconds == 4

    app.dispatch(SetPerm(req=None))
    app.dispatch(SetAsk(req=cast(Any, object())))
    clock.advance(5)
    app._tick_elapsed()
    assert app.state.phase == "waiting-user"
    assert app.status_bar.elapsed_seconds == 9


def test_status_telemetry_separates_history_from_next_request_pressure() -> None:
    app = make_app()
    received = []
    app.agent = cast(
        Agent,
        SimpleNamespace(
            target=SimpleNamespace(base_url=lambda: "", name=lambda: "target"),
            get_memory_stats=lambda: SimpleNamespace(items=0),
            approx_tokens=lambda: 9_002,
            tools_token_estimate=lambda: 5_019,
            get_auto_compact_threshold=lambda: 16_000,
        ),
    )
    app.status_bar = cast(
        Any,
        SimpleNamespace(
            apply=received.append,
            elapsed_seconds=None,
        ),
    )
    app._status_cache_key = None

    app._sync_status_bar(expand_hint=False)

    props = received[-1]
    assert props.ctx_tokens == 9_002
    assert props.request_tokens == 14_021
    assert props.compact_threshold == 16_000


def test_done_event_stops_timer_for_normal_refusal_and_abort_completion() -> None:
    app, clock, intervals = timer_app()

    for elapsed in (3, 7, 11):
        app._start_turn_timer()
        app.dispatch(SetBusy(busy=True))
        clock.advance(elapsed)
        app.dispatch(AgentEventAction(event=DoneEvent()))
        final = app.status_bar.elapsed_seconds
        clock.advance(20)
        app._tick_elapsed()
        assert app.state.busy is False
        assert app.status_bar.elapsed_seconds == final == elapsed
        assert intervals[-1].stopped is True


@pytest.mark.asyncio
async def test_turn_timer_stops_when_agent_turn_aborts() -> None:
    app, clock, intervals = timer_app()
    requests: list[str] = []

    async def aborting_run(*_args, **_kwargs) -> None:
        clock.advance(7)
        raise Exception("aborted")

    app.agent = cast(
        Any,
        SimpleNamespace(
            is_running=lambda: False,
            run=aborting_run,
            requests=requests,
        ),
    )

    await app.run_agent_turn("go")

    assert app.status_bar.elapsed_seconds == 7
    assert intervals[-1].stopped is True
    assert app._elapsed_active is False
    assert requests == []


def test_turn_timer_is_local_and_does_not_mutate_agent_history() -> None:
    app, clock, _ = timer_app()
    history = ["unchanged"]
    app.agent = cast(Any, SimpleNamespace(history=history))

    app._start_turn_timer()
    clock.advance(5)
    app._tick_elapsed()
    app._stop_turn_timer()

    assert app.agent.history == ["unchanged"]


@pytest.mark.asyncio
async def test_bracketed_paste_reaches_custom_input() -> None:
    app = make_app()

    await app.on_paste(events.Paste("alpha\nbeta"))

    assert app.input.value == "[Pasted text #1 +2 lines, 10 chars]"
    assert app.pasted_text == {1: "alpha\nbeta"}


@pytest.mark.asyncio
async def test_slash_tab_completes_then_executes_on_second_tab() -> None:
    app = make_app()
    submitted: list[str] = []

    def submit(value: str) -> None:
        submitted.append(value)

    app.submit = submit
    app.input.set_value("/pro")
    app._recompute_menus()

    await app.on_key(events.Key("tab", None))

    assert app.input.value == "/provider"
    assert submitted == []

    await app.on_key(events.Key("tab", None))
    await app.on_key(events.Key("tab", None))

    assert submitted == ["/provider"]


@pytest.mark.asyncio
async def test_slash_tab_completion_resets_after_edit_or_selection_change() -> None:
    app = make_app()
    submitted: list[str] = []

    def submit(value: str) -> None:
        submitted.append(value)

    app.submit = submit
    app.input.set_value("/pro")
    app._recompute_menus()

    await app.on_key(events.Key("tab", None))
    await app.on_key(events.Key("x", "x"))
    await app.on_key(events.Key("tab", None))

    assert submitted == []

    app.input.set_value("/")
    app._recompute_menus()
    app._slash_tab_completion = "/help"
    await app._process_key(events.Key("down", None))

    assert app._slash_tab_completion is None


@pytest.mark.asyncio
async def test_slash_enter_executes_completed_command_normally() -> None:
    app = make_app()
    submitted: list[str] = []

    def submit(value: str) -> None:
        submitted.append(value)

    app.submit = submit
    app.input.set_value("/provider")
    app._recompute_menus()

    await app.on_key(events.Key("enter", None))

    assert submitted == ["/provider"]


@pytest.mark.asyncio
async def test_paste_reaches_active_text_input_modal() -> None:
    app = make_app()
    app.text_input = TextInputRequest(
        header="test",
        question="question",
        placeholder=None,
        resolve=lambda _: None,
        reject=lambda _: None,
    )

    await app.on_paste(events.Paste("alpha\nbeta"))

    assert app._text_input_modal is not None
    assert app._text_input_modal.value == "alphabeta"


@pytest.mark.asyncio
async def test_escape_aborts_an_active_tui_ask_modal_and_clears_it() -> None:
    app = make_app()
    bridge = BridgedAskPrompter(lambda req: app.dispatch(SetAsk(req=req)))
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(busy=True))
    question = Question(
        question="What should be reset?",
        options=[Option("Browser capture data"), Option("Coverage state")],
    )
    pending = asyncio.create_task(bridge.ask(question, app.run_abort_event))

    await asyncio.sleep(0)
    assert app.state.pending_ask is not None
    assert app._get_active_modal() is not None

    await app._process_key(events.Key("escape", None))

    with pytest.raises(Exception, match="aborted"):
        await pending
    assert app.run_abort_event.is_set()
    assert app.state.pending_ask is None


@pytest.mark.asyncio
async def test_escape_aborts_active_tui_permission_instead_of_denying() -> None:
    app = make_app()
    bridge = BridgedPrompter(lambda req: app.dispatch(SetPerm(req=req)))
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(busy=True))

    pending = asyncio.create_task(
        bridge.ask(
            PermissionRequest(tool="shell", summary="Run command", detail="echo ok"),
            app.run_abort_event,
        )
    )
    await asyncio.sleep(0)

    assert app.state.pending_perm is not None
    await app._process_key(events.Key("escape", None))

    with pytest.raises(Exception, match="aborted"):
        await pending
    assert app.run_abort_event.is_set()
    assert app.state.pending_perm is None


@pytest.mark.asyncio
async def test_escape_keeps_aborting_an_active_processing_turn() -> None:
    app = make_app()
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(busy=True))

    await app._process_key(events.Key("escape", None))

    assert app.run_abort_event.is_set()


@pytest.mark.asyncio
async def test_input_editor_remains_visible_while_a_turn_is_active() -> None:
    app = make_app()
    app.overlay_static = cast(
        Any,
        SimpleNamespace(
            display=False,
            set_class=lambda *_: None,
        ),
    )
    app.overlay_content_static = cast(Any, SimpleNamespace(set_class=lambda *_: None))
    app.overlay_text_static = cast(Any, SimpleNamespace(update=lambda _: None))
    app.input_static = cast(Any, SimpleNamespace(display=True))
    app.status_bar = cast(Any, SimpleNamespace(elapsed_seconds=None))

    app.dispatch(SetBusy(busy=True))
    KAgent._sync_overlay(app)
    assert app.input_static.display is True

    app.dispatch(SetBusy(busy=False))
    KAgent._sync_overlay(app)
    assert app.input_static.display is True


def test_prompt_panels_receive_shared_modal_frame_class() -> None:
    app = make_app()
    class_changes: list[tuple[bool, str]] = []
    app.overlay_static = cast(
        Any,
        SimpleNamespace(
            display=False,
            set_class=lambda on, name: class_changes.append((on, name)),
        ),
    )
    app.overlay_content_static = cast(Any, SimpleNamespace(set_class=lambda *_: None))
    app.overlay_text_static = cast(Any, SimpleNamespace(update=lambda _: None))
    app.input_static = cast(Any, SimpleNamespace(display=True))
    app.text_input = TextInputRequest(
        header="Question",
        question="What should be reset?",
        placeholder=None,
        resolve=lambda _: None,
        reject=lambda _: None,
    )

    KAgent._sync_overlay(app)

    assert (True, "modal-panel") in class_changes
    assert app.overlay_static.display is True

    app.text_input = None
    app.dispatch(
        SetPerm(
            BridgedPermissionRequest(
                tool="shell",
                summary="Run command",
                detail="echo ok",
                resolve=lambda _: None,
                reject=lambda _: None,
            )
        )
    )
    KAgent._sync_overlay(app)

    assert (True, "modal-panel") in class_changes
    assert class_changes[-1] == (True, "permission-panel")


@pytest.mark.asyncio
async def test_long_permission_panel_is_capped_and_scrolls_without_hiding_transcript(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    request = BridgedPermissionRequest(
        tool="shell",
        summary="Run command",
        detail="\n".join(f"argument line {line}" for line in range(80)),
        resolve=lambda _: None,
        reject=lambda _: None,
    )

    async with app.run_test(size=(64, 40)) as pilot:
        app.dispatch(SetPerm(request))
        KAgent._sync_overlay(app)
        await pilot.pause()

        assert app.overlay_content_static.styles.max_height is not None
        assert app.overlay_content_static.styles.overflow_y == "auto"
        assert app.overlay_content_static.styles.scrollbar_size_vertical == 1
        assert app.overlay_content_static.styles.scrollbar_color.hex == "#7E8A9A"
        assert app.overlay_static.region.height <= 15
        assert app.overlay_content_static.max_scroll_y > 0
        assert app.transcript_panel.display is True
        assert app.transcript_panel.region.height > 0


@pytest.mark.asyncio
async def test_short_permission_panel_keeps_content_driven_height(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    request = BridgedPermissionRequest(
        tool="shell",
        summary="Run command",
        detail="echo ok",
        resolve=lambda _: None,
        reject=lambda _: None,
    )

    async with app.run_test(size=(64, 40)) as pilot:
        app.dispatch(SetPerm(request))
        KAgent._sync_overlay(app)
        await pilot.pause()

        height = app.overlay_content_static.styles.height
        assert height is not None
        assert height.is_auto
        assert app.overlay_static.region.height < 15
        assert app.overlay_content_static.max_scroll_y == 0


@pytest.mark.asyncio
async def test_main_shell_regions_have_distinct_native_panels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()

    async with app.run_test(size=(64, 22)) as pilot:
        assert app.transcript_panel.border_title == "Transcript"
        assert app.input_static.border_title == "Input"
        assert app.overview_static.parent is app.transcript_panel
        assert app.transcript_log.parent is app.transcript_panel
        assert app.live_entry_static.parent is app.transcript_panel
        assert app.transcript_panel.styles.border.top[0] == "round"
        assert app.input_static.styles.border.top[0] == "round"
        assert app.status_bar.styles.background.a > 0

        await pilot.resize_terminal(32, 14)

        assert app.transcript_panel.region.width == 32
        assert app.input_static.region.width == 32


def test_resize_rerenders_composer() -> None:
    app = make_app()
    rendered: list[bool] = []
    app_any = cast(Any, app)
    app_any._render_input = lambda: rendered.append(True)
    app_any.refresh = lambda: None
    event = cast(Any, SimpleNamespace(size=SimpleNamespace(width=47)))

    KAgent.on_resize(app, event)

    assert app.cols == 47
    assert rendered == [True]


@pytest.mark.asyncio
async def test_open_ended_ask_uses_text_input_and_returns_the_typed_answer() -> None:
    app = make_app()
    bridge = BridgedAskPrompter(lambda req: app.dispatch(SetAsk(req=req)))
    pending = asyncio.create_task(bridge.ask(Question(question="What should be reset?")))

    await asyncio.sleep(0)
    modal = app._get_active_modal()
    assert isinstance(modal, TextInputModal)
    assert "Answer:\n❯ ▌" in "\n".join(modal.render())

    await app._process_key(events.Key("c", "c"))
    await app._process_key(events.Key("enter", None))

    assert await pending == "c"
    assert app.state.pending_ask is None


def test_free_text_modal_uses_composer_prompt_styles() -> None:
    modal = TextInputModal(
        TextInputRequest(
            header="Question",
            question="What should be reset?",
            placeholder=None,
            resolve=lambda _: None,
            reject=lambda _: None,
        )
    )
    modal.handle_key("x")

    rendered = _modal_text(modal)

    assert "Answer:\n❯ x▌" in rendered.plain
    assert [span.style for span in rendered.spans] == [
        "bold #38BDF8",
        "#D6DEE8",
        "bold #D6DEE8",
    ]


def test_input_selection_excludes_prompt_and_border() -> None:
    value = "alpha\nbeta"
    selected = _input_selection_text(
        value,
        Selection(Offset(2, 1), Offset(6, 2)),
    )

    assert selected == "alpha\nbeta"
    assert value == "alpha\nbeta"


def test_right_click_copies_the_last_mouse_selection() -> None:
    app = make_app()
    app._last_selected_text = "selected output"
    copied: list[str] = []
    stopped = False

    class Event:
        button = 3

        def stop(self) -> None:
            nonlocal stopped
            stopped = True

    def copy_to_clipboard(text: str) -> None:
        copied.append(text)

    app.copy_to_clipboard = copy_to_clipboard
    app.on_mouse_down(cast(events.MouseDown, Event()))

    assert copied == ["selected output"]
    assert stopped is True


def test_permission_selection_text_omits_panel_borders() -> None:
    selected = _clean_permission_selection(
        "╭─ Shell command ─╮\n│ echo hello       │\n╰──────────────────╯"
    )

    assert selected == "Shell command\necho hello"
    assert "╭" not in selected
    assert "│" not in selected


async def _drag_select_visible_text(pilot, widget, needle: str) -> None:
    lines = [widget.render_line(y).text for y in range(widget.virtual_size.height)]
    y, line = next((y, line) for y, line in enumerate(lines) if needle in line)
    x = line.index(needle)
    await pilot.mouse_down(widget, offset=(x, y))
    await pilot.hover(widget, offset=(x + len(needle) - 1, y))
    await pilot.mouse_up(widget, offset=(x + len(needle) - 1, y))
    await pilot.pause()


@pytest.mark.asyncio
async def test_permission_group_panel_selection_and_right_click_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    request = BridgedPermissionRequest(
        tool="shell",
        summary="shell: echo hello",
        detail="echo hello",
        session_scope_display="this exact shell command only",
        resolve=lambda _: None,
        reject=lambda _: None,
    )

    async with app.run_test(size=(80, 30)) as pilot:
        app.dispatch(SetPerm(request))
        KAgent._sync_overlay(app)
        await pilot.pause()

        assert isinstance(app.overlay_text_static, _PermissionStatic)
        lines = [
            app.overlay_text_static.render_line(y).text
            for y in range(app.overlay_text_static.virtual_size.height)
        ]
        title_y, _title_line = next(
            (y, line) for y, line in enumerate(lines) if "Shell command" in line
        )
        command_y, command_line = next(
            (y, line) for y, line in enumerate(lines) if "echo hello" in line
        )
        await pilot.mouse_down(app.overlay_text_static, offset=(0, title_y))
        await pilot.hover(
            app.overlay_text_static,
            offset=(len(command_line) - 1, command_y),
        )
        await pilot.mouse_up(
            app.overlay_text_static,
            offset=(len(command_line) - 1, command_y),
        )
        await pilot.pause()

        assert app.screen.selections.get(app.overlay_text_static) is not None
        assert app._last_selected_text == "Shell command\necho hello"
        assert "╭" not in app._last_selected_text
        assert "│" not in app._last_selected_text
        selected_line = app.overlay_text_static.render_line(command_y)
        assert any(
            segment.style is not None
            and segment.style.bgcolor == app.overlay_text_static.selection_style.bgcolor
            for segment in selected_line
            if "echo hello" in segment.text
        )

        copied: list[str] = []
        app.copy_to_clipboard = copied.append
        await pilot.mouse_down(
            app.overlay_text_static,
            offset=(command_line.index("echo hello"), command_y),
            button=3,
        )
        assert copied == ["Shell command\necho hello"]


@pytest.mark.asyncio
async def test_permission_selection_keeps_structured_and_explanatory_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    request = BridgedPermissionRequest(
        tool="http",
        summary="http: private/internal URL http://127.0.0.1/status",
        detail="host: 127.0.0.1\nreason: DNS resolves to loopback IPv4 (127.0.0.1)",
        no_session_cache=True,
        resolve=lambda _: None,
        reject=lambda _: None,
    )

    async with app.run_test(size=(80, 30)) as pilot:
        app.dispatch(SetPerm(request))
        KAgent._sync_overlay(app)
        await pilot.pause()

        await _drag_select_visible_text(
            pilot,
            app.overlay_text_static,
            "http://127.0.0.1/status",
        )
        assert app._last_selected_text == "http://127.0.0.1/status"

        await _drag_select_visible_text(
            pilot,
            app.overlay_text_static,
            "DNS resolves to loopback IPv4",
        )
        assert app._last_selected_text == "DNS resolves to loopback IPv4"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("permission_req", "needle"),
    [
        (
            BridgedPermissionRequest(
                tool="http",
                summary="http: GET http://juice.lab:3000/robots.txt",
                detail="GET http://juice.lab:3000/robots.txt",
                resolve=lambda _: None,
                reject=lambda _: None,
            ),
            "GET http://juice.lab:3000/robots.txt",
        ),
        (
            BridgedPermissionRequest(
                tool="file_write",
                summary="write file: report.txt",
                detail="path: report.txt\n--- content ---\nsummary",
                resolve=lambda _: None,
                reject=lambda _: None,
            ),
            "report.txt",
        ),
    ],
)
async def test_structured_permission_content_supports_real_mouse_drag(
    monkeypatch: pytest.MonkeyPatch,
    permission_req: BridgedPermissionRequest,
    needle: str,
) -> None:
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()

    async with app.run_test(size=(80, 30)) as pilot:
        app.dispatch(SetPerm(permission_req))
        KAgent._sync_overlay(app)
        await pilot.pause()

        await _drag_select_visible_text(pilot, app.overlay_text_static, needle)

        assert app.screen.selections.get(app.overlay_text_static) is not None
        assert app._last_selected_text == needle


def test_rich_log_writer_decodes_ansi_without_background_resets() -> None:
    written: list[tuple[Text, int]] = []

    def write(text: Text, *, width: int) -> None:
        written.append((text, width))

    log = cast(
        Any,
        SimpleNamespace(
            scrollable_content_region=SimpleNamespace(width=40),
            write=write,
        ),
    )

    _RichLogWriter(log).write("\x1b[36mstyled\x1b[0m plain\n")

    assert len(written) == 1
    text, width = written[0]
    assert text.plain == "styled plain"
    assert "\x1b" not in text.plain
    assert any(getattr(span.style, "color", None) is not None for span in text.spans)
    assert all(getattr(span.style, "bgcolor", None) is None for span in text.spans)
    assert width == 40


@pytest.mark.asyncio
async def test_text_selected_ignores_stale_transcript_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    async with app.run_test(size=(40, 8)):
        app.transcript_log.write("current line")
        app.screen.selections = {
            app.transcript_log: Selection(Offset(60, 219), Offset(63, 219))
        }

        app.on_text_selected(events.TextSelected())

        assert app._last_selected_text == ""
