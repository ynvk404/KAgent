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
from src.config.config import Backend
from src.ui.core.app import (
    AbortEvent,
    AppProps,
    ConfigSnapshot,
    KAgent,
    ProviderChange,
    _RichLogWriter,
    _input_selection_text,
    _modal_text,
)
from src.ui.core.state import SetAsk, SetBusy, SetPerm
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
            update=lambda _: None,
            display=False,
            set_class=lambda *_: None,
        ),
    )
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
            update=lambda _: None,
            display=False,
            set_class=lambda on, name: class_changes.append((on, name)),
        ),
    )
    app.input_static = cast(Any, SimpleNamespace(display=True))
    app.text_input = TextInputRequest(
        header="Question",
        question="What should be reset?",
        placeholder=None,
        resolve=lambda _: None,
        reject=lambda _: None,
    )

    KAgent._sync_overlay(app)

    assert class_changes[-1] == (True, "modal-panel")
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

    assert class_changes[-1] == (True, "modal-panel")


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
