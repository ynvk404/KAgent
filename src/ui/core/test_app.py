from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from textual import events
from textual.selection import Selection
from textual.geometry import Offset

from src.ui.core.app import AppProps, KAgent, _input_selection_text
from src.ui.widgets.banner import BannerData
from src.ui.widgets.text_input_modal import TextInputRequest


def make_app() -> KAgent:
    app = KAgent(
        AppProps(
            agent=SimpleNamespace(),
            banner_data=BannerData(provider="test", model="test", cwd="."),
            parent_signal=asyncio.Event(),
            read_config=lambda: {},
            apply_provider=lambda _: None,
        )
    )
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

    app.copy_to_clipboard = copied.append
    app.on_mouse_down(Event())

    assert copied == ["selected output"]
    assert stopped is True
