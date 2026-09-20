from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest
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
            agent=cast(Agent, SimpleNamespace()),
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


def test_prompt_panels_receive_modal_separator_class() -> None:
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


def test_resize_rebuilds_width_dependent_composer_rules() -> None:
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
