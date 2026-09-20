from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import cast

import pytest
from textual import events
from textual.selection import Selection
from textual.geometry import Offset

from src.ui.bridges.ask_bridge import BridgedAskPrompter
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
)
from src.ui.core.state import SetAsk, SetBusy
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
async def test_open_ended_ask_uses_text_input_and_returns_the_typed_answer() -> None:
    app = make_app()
    bridge = BridgedAskPrompter(lambda req: app.dispatch(SetAsk(req=req)))
    pending = asyncio.create_task(bridge.ask(Question(question="What should be reset?")))

    await asyncio.sleep(0)
    modal = app._get_active_modal()
    assert isinstance(modal, TextInputModal)
    assert "Answer:\n> ▌" in "\n".join(modal.render())

    await app._process_key(events.Key("c", "c"))
    await app._process_key(events.Key("enter", None))

    assert await pending == "c"
    assert app.state.pending_ask is None


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
