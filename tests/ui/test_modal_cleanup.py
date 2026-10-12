"""Offline regressions for the remaining modal presentation contracts."""
import asyncio
import threading
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock
from typing import Any, cast

import pytest
from textual import events

from src.ui.commands import model_picker
from src.ui.commands.provider_picker import _prompt_custom_model, open_provider_picker
from src.llm.transport.errors import ProviderControlError
from src.ui.core.app import AbortEvent, KAgent
from src.ui.core.state import SetAsk, SetBusy
from src.tools.common.ask import Option, Question
from src.ui.bridges.ask_bridge import AskRequest, BridgedAskPrompter
from src.ui.widgets.details_modal import BridgeCredentialsModal
from src.ui.widgets.provider_picker_modal import ProviderPickerModal, SECTION_CUSTOM
from src.ui.core.custom_provider_adapter import InMemoryCustomProviderAdapter
from src.ui.widgets.text_input_modal import TextInputModal, TextInputRequest
from src.ui.widgets.skills_modal import SkillsModal
from src.browser.server import BurpBridgeResult, BurpBridgeState
from src.ui.widgets.ask_modal import AskModal
from tests.ui.test_app import make_app
from tests.ui.test_permission_review import _content_text


def mounted_app(monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    # make_app disables transcript recomputation. Retain its production overlay
    # update so dispatches are visible without starting startup integrations.
    app._recompute_view = lambda: app._sync_overlay()
    return app


@pytest.mark.parametrize("size", [(40, 18), (80, 24)])
async def test_loading_has_no_answer_and_cancel_ignores_late_models(monkeypatch, size):
    app = mounted_app(monkeypatch)
    started, release = threading.Event(), threading.Event()
    applied = []

    def discover(*_):
        started.set()
        assert release.wait(5)
        return ["fixture-model"]

    monkeypatch.setattr(model_picker, "list_models", discover)
    async with app.run_test(size=size) as pilot:
        task = asyncio.create_task(model_picker.fetch_and_pick_model(
            "openai", "https://offline.invalid", "fixture-key", app.dispatch, applied.append,
        ))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            await pilot.pause()
            modal = app._get_active_modal()
            assert isinstance(modal, AskModal)
            assert "Fetching available models" in "\n".join(modal.render())
            for wrong_hint in ("Answer:", "▌", "Enter confirm"):
                assert wrong_hint not in "\n".join(modal.render())
            await pilot.press("enter", "a")
            assert app.state.pending_ask is modal.req and not applied
            await pilot.press("escape")
            assert app.state.pending_ask is None
        finally:
            release.set()
            await task
        await pilot.pause()
        assert app.state.pending_ask is None and not applied


def test_loading_metadata_does_not_change_free_text_ask(monkeypatch):
    from src.tools.common.ask import Question
    from src.ui.bridges.ask_bridge import AskRequest
    from src.ui.widgets.text_input_modal import TextInputModal
    app = mounted_app(monkeypatch)
    app.state = replace(app.state, pending_ask=AskRequest(
        Question(question="Fetching… is part of this real question"), lambda _: None, lambda _: None,
    ))
    assert isinstance(app._get_active_modal(), TextInputModal)


@pytest.mark.parametrize("free_text", [False, True])
@pytest.mark.parametrize("busy", [False, True])
async def test_ask_escape_hint_matches_abort_or_cancel(monkeypatch, busy, free_text):
    app = mounted_app(monkeypatch)
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(busy))
    bridge = BridgedAskPrompter(lambda req: app.dispatch(SetAsk(req)))
    async with app.run_test() as pilot:
        task = asyncio.create_task(bridge.ask(
            Question(question="Keep this exact question: Esc cancel", options=[] if free_text else [Option("Yes")]),
            app.run_abort_event if busy else None,
        ))
        await pilot.pause()
        content = _content_text(app)
        assert f"Esc {'stop turn' if busy else 'cancel'}" in " ".join(content.split())
        assert "Keep this exact question: Esc cancel" in " ".join(content.split())
        await pilot.press("escape")
        with pytest.raises(Exception, match="aborted" if busy else "cancelled"):
            await task
        assert app.run_abort_event.aborted is busy
        assert app.state.pending_ask is None


async def test_delayed_burp_command_opens_during_turn_escape_only_closes_view(monkeypatch):
    app = mounted_app(monkeypatch)
    requested, release = asyncio.Event(), asyncio.Event()
    token = "offline-bridge-token"

    async def status():
        requested.set()
        await release.wait()
        return BurpBridgeResult(status="already_running", state=BurpBridgeState(running=True, url="http://localhost:9876", token=token))

    app.start_burp_bridge = AsyncMock()
    app.close_burp_bridge = AsyncMock()
    app.burp_bridge_status = status
    app.run_abort_event = AbortEvent()
    async with app.run_test(size=(40, 18)) as pilot:
        # Production command schedules a status callback while idle. It may finish
        # after another turn starts; no live bridge is needed to exercise that path.
        app.submit("/burp credentials")
        await requested.wait()
        app.dispatch(SetBusy(True))
        release.set()
        await pilot.pause()
        assert isinstance(app._get_active_modal(), BridgeCredentialsModal)
        await pilot.press("escape")
        assert app._local_modal is None
        assert not app.run_abort_event.aborted
        assert token not in repr(app.state.transcript)
        # A subsequent ask retains ownership of Escape and aborts the turn.
        bridge = BridgedAskPrompter(lambda req: app.dispatch(SetAsk(req)))
        task = asyncio.create_task(bridge.ask(Question(question="Continue?", options=[Option("Yes")]), app.run_abort_event))
        await pilot.pause()
        await pilot.press("escape")
        with pytest.raises(Exception, match="aborted"):
            await task
        assert app.run_abort_event.aborted


def control_rows(app, name, value):
    widget = app.overlay_text_static
    return [y for y in range(widget.size.height) if any(
        segment.style and segment.style.meta.get(name) == value
        for segment in widget.render_line(y)
    )]


def assert_control_visible(app, name, value):
    rows = control_rows(app, name, value)
    first = int(app.overlay_content_static.scroll_y)
    height = app.overlay_content_static.scrollable_content_region.height
    assert rows and first <= rows[0] < first + height


@pytest.mark.parametrize("size", [(40, 18), (80, 24)])
@pytest.mark.parametrize("kind", ["ask", "skills", "provider"])
async def test_long_lists_navigation_scroll_resize_and_wrapped_click(monkeypatch, size, kind):
    app = mounted_app(monkeypatch)
    resolved = []
    toggled = []
    long_text = "full description " * 55 + "UNTRUNCATED_END"
    if kind == "skills":
        skills = [SimpleNamespace(name=f"skill_{i}", description=long_text) for i in range(20)]
        app.agent = cast(Any, SimpleNamespace(
            skills=SimpleNamespace(list=lambda: skills, is_disabled=lambda _: False),
            set_skill_enabled=AsyncMock(side_effect=lambda *args: toggled.append(args)),
        ))
        app.state = replace(app.state, pending_skills=True)
    elif kind == "provider":
        adapter = InMemoryCustomProviderAdapter()
        for i in range(20):
            adapter.add_custom_provider(f"Gateway {i} " + "long name " * 9, "https://offline.invalid")
        req = AskRequest(Question(header="provider", question="Pick", options=[Option("stub")]), resolved.append, lambda _: None)
        app.state = replace(app.state, pending_ask=req)
        app._provider_modal = ProviderPickerModal(req, adapter=adapter, initial_section=SECTION_CUSTOM)
    else:
        app.state = replace(app.state, pending_ask=AskRequest(
            Question(header="Question", question="Long question " * 70,
                     options=[Option(f"option_{i}", long_text) for i in range(20)]),
            resolved.append, lambda _: None,
        ))
    async with app.run_test(size=size) as pilot:
        app._sync_overlay()
        await pilot.pause()
        modal = app._get_active_modal()
        assert isinstance(modal, (AskModal, SkillsModal, ProviderPickerModal))
        assert app.overlay_static.region.bottom <= size[1]
        assert app.overlay_content_static.max_scroll_x == 0
        assert_control_visible(app, "modal_item", 0)
        await pilot.press("tab", "shift+tab", *(["down"] * 12))
        await pilot.pause()
        assert modal.idx == 12 and not resolved and not toggled
        assert_control_visible(app, "modal_item", 12)
        if kind != "provider":
            assert "UNTRUNCATED_END" in _content_text(app)
        await pilot.press("pagedown")
        await pilot.pause()
        manual_scroll = app.overlay_content_static.scroll_y
        app._sync_overlay()
        await pilot.pause()
        assert app.overlay_content_static.scroll_y == manual_scroll
        assert modal.idx == 12
        # Reflow restores the selected label while preserving the selection.
        other_size = (80, 24) if size == (40, 18) else (40, 18)
        await pilot.resize_terminal(*other_size)
        await pilot.pause()
        assert app.overlay_static.region.bottom <= other_size[1]
        assert_control_visible(app, "modal_item", 12)
        # Select the next row by clicking a wrapped continuation, without activation.
        rows = control_rows(app, "modal_item", 13)
        target = rows[1] if len(rows) > 1 else rows[0]
        app.overlay_content_static.scroll_to(y=target, animate=False, immediate=True)
        await pilot.pause()
        offset_y = app.overlay_text_static.region.y + target - app.overlay_static.region.y
        await pilot.click("#overlay", offset=(4, offset_y))
        await pilot.pause()
        assert modal.idx == 13 and not resolved and not toggled
        await pilot.press("escape")


@pytest.mark.parametrize("size", [(40, 18), (80, 24)])
@pytest.mark.parametrize("masked", [False, True])
async def test_long_input_keeps_caret_visible_without_losing_data(monkeypatch, size, masked):
    app = mounted_app(monkeypatch)
    initial = "長い/path/▌/" * 60
    async with app.run_test(size=size) as pilot:
        task = asyncio.create_task(app.prompt_text(TextInputRequest(
            "API key" if masked else "Long input", "Full instructions " * 100 + "QUESTION_END",
            None, lambda _: None, lambda _: None, masked=masked, initial_value=initial,
        )))
        await pilot.pause()
        modal = app._get_active_modal()
        assert isinstance(modal, TextInputModal)
        assert app.overlay_static.region.bottom <= size[1]
        assert "QUESTION_END" in _content_text(app)
        if masked:
            assert initial not in _content_text(app)
        await pilot.press("left", "x")
        await pilot.pause()
        assert_control_visible(app, "modal_cursor", True)
        expected = initial[:-1] + "x" + initial[-1:]
        assert modal.value == expected
        await pilot.press("home")
        await pilot.pause()
        assert_control_visible(app, "modal_cursor", True)
        await pilot.resize_terminal(*( (80, 24) if size == (40, 18) else (40, 18)))
        await pilot.pause()
        assert_control_visible(app, "modal_cursor", True)
        await pilot.press("enter", "enter")
        assert await task == expected
        assert app.text_input is None


async def test_old_input_callbacks_and_cancelled_task_cannot_resolve_new_input(monkeypatch):
    app = mounted_app(monkeypatch)
    req = TextInputRequest("Input", "Question", None, lambda _: None, lambda _: None)
    async with app.run_test() as pilot:
        old = asyncio.create_task(app.prompt_text(req))
        await pilot.pause()
        stale = app.text_input
        assert stale is not None
        old.cancel()
        with pytest.raises(asyncio.CancelledError):
            await old
        new = asyncio.create_task(app.prompt_text(req))
        await pilot.pause()
        stale.resolve("stale")
        stale.reject(Exception("stale"))
        assert not new.done() and app.text_input is not stale
        await pilot.press("x", "enter")
        assert await new == "x"


def test_ask_and_input_do_not_submit_twice():
    resolved = []
    modal = AskModal(AskRequest(Question(question="Pick", options=[Option("Yes")]), resolved.append, lambda _: None))
    modal.handle_key("enter")
    modal.handle_key("enter")
    modal.handle_key("escape")
    assert resolved == ["Yes"]
    input_modal = TextInputModal(TextInputRequest("Input", "Question", None, resolved.append, lambda _: None))
    input_modal.handle_key("x")
    input_modal.handle_key("enter")
    input_modal.handle_key("enter")
    assert resolved == ["Yes", "x"]


@pytest.mark.parametrize("size", [(40, 18), (80, 24)])
async def test_custom_model_preview_preserves_ids_current_value_and_manual_entry(monkeypatch, size):
    app = mounted_app(monkeypatch)
    ids = [f"model-{i}-" + "identifier" * 12 for i in range(25)]

    async def discover():
        return ids

    async with app.run_test(size=size) as pilot:
        task = asyncio.create_task(_prompt_custom_model(
            app.prompt_text, "https://offline.invalid", "", current_model="current-model",
            discover_models=discover,
        ))
        await pilot.pause()
        req = app.text_input
        assert req is not None and req.initial_value == "current-model"
        assert all(model in req.question.splitlines() for model in ids[:20])
        assert ids[20] not in req.question
        assert app.overlay_static.region.bottom <= size[1]
        await pilot.press("pagedown")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y > 0
        await pilot.press("end", "x")
        await pilot.pause()
        assert_control_visible(app, "modal_cursor", True)
        await pilot.press("enter")
        assert await task == "current-modelx"


@pytest.mark.parametrize("outcome", ["empty", "error", "retry", "auth"])
async def test_custom_model_discovery_feedback_and_retry_are_preserved(monkeypatch, outcome):
    requests = []
    calls = 0

    async def discover():
        nonlocal calls
        calls += 1
        if outcome == "auth":
            raise ProviderControlError("authentication", "Authentication failed")
        if outcome == "error":
            raise ProviderControlError("unsupported-endpoint", "No model listing")
        if outcome == "retry" and calls == 1:
            raise ProviderControlError("rate-limited", "Retry later")
        return [] if outcome == "empty" else ["fixture-model"]

    async def prompt(req):
        requests.append(req)
        return "retry" if "rate limited" in req.header else "manual-model"

    if outcome == "auth":
        with pytest.raises(ProviderControlError):
            await _prompt_custom_model(prompt, "https://offline.invalid", "", discover_models=discover)
        assert not requests
    else:
        assert await _prompt_custom_model(prompt, "https://offline.invalid", "", discover_models=discover) == "manual-model"
        assert requests[-1].scrollable
        assert "enter one manually" in requests[-1].question
        if outcome == "empty":
            assert "empty model list" in requests[-1].question
        elif outcome == "error":
            assert "No model listing" in requests[-1].question
        else:
            assert calls == 2 and len(requests) == 2


async def test_cancel_custom_model_step_saves_no_profile(monkeypatch):
    app = mounted_app(monkeypatch)
    adapter = InMemoryCustomProviderAdapter()
    monkeypatch.setattr("src.ui.commands.provider_picker.list_models", lambda *_: ["fixture-model"])
    async with app.run_test() as pilot:
        open_provider_picker(app.dispatch, app.read_config, app.apply_provider, app.prompt_text, adapter=adapter)
        req = app.state.pending_ask
        assert req is not None
        cast(Any, req).on_add_provider()
        await pilot.pause()
        for value in ("Fixture gateway", "https://offline.invalid/v1", "fixture-key"):
            assert not adapter.list_custom_providers()
            app.resolve_text_input(value)
            await pilot.pause()
        assert app.text_input is not None and "Default model" in app.text_input.header
        await pilot.press("escape")
        await pilot.pause()
        assert not adapter.list_custom_providers()
        assert isinstance(app._get_active_modal(), ProviderPickerModal)


@pytest.mark.parametrize("size", [(40, 18), (80, 24)])
@pytest.mark.parametrize("action", ["submit", "abstain", "cancel"])
async def test_cwe_metadata_remains_accessible_and_typing_reveals_answer(monkeypatch, size, action):
    app = mounted_app(monkeypatch)
    warning = "Search ranking is a lexical score, not confidence or proof."
    metadata = warning + "\nSelect a numbered candidate for mechanism review, or 0 to abstain.\n" + "\n".join(
        f"Source {i}: [bold]literal data[/bold] score={i}" for i in range(80)
    )
    async with app.run_test(size=size) as pilot:
        task = asyncio.create_task(app.prompt_text(TextInputRequest(
            "CWE classification review", metadata, "0–5", lambda _: None, lambda _: None, scrollable=True,
        )))
        await pilot.pause()
        assert app.overlay_static.border_title == "CWE classification review"
        assert warning in " ".join(_content_text(app).split())
        assert "[bold]literal data[/bold]" in _content_text(app)
        assert app.overlay_static.region.bottom <= size[1]
        await pilot.press("pagedown", "pageup")
        assert not task.done()
        if action == "cancel":
            await pilot.press("escape")
            with pytest.raises(Exception, match="cancelled"):
                await task
        else:
            await pilot.press("0" if action == "abstain" else "1")
            await pilot.pause()
            assert_control_visible(app, "modal_cursor", True)
            await pilot.resize_terminal(*( (80, 24) if size == (40, 18) else (40, 18)))
            await pilot.pause()
            assert_control_visible(app, "modal_cursor", True)
            assert "score=79" in _content_text(app)
            await pilot.press("enter")
            assert await task == ("0" if action == "abstain" else "1")
        assert app.text_input is None


async def test_mouse_wheel_scrolls_content_without_changing_selection(monkeypatch):
    app = mounted_app(monkeypatch)
    app.state = replace(app.state, pending_ask=AskRequest(
        Question(question="Choose", options=[Option(f"option-{i}", "Full description " * 80) for i in range(10)]),
        lambda _: None, lambda _: None,
    ))
    async with app.run_test(size=(40, 18)) as pilot:
        app._sync_overlay()
        await pilot.pause()
        modal = app._get_active_modal()
        assert isinstance(modal, AskModal)
        start = app.overlay_content_static.scroll_y
        await pilot._post_mouse_events([events.MouseScrollDown], offset=(4, app.overlay_content_static.region.y + 2))
        await pilot.pause()
        assert app.overlay_content_static.scroll_y > start
        assert modal.idx == 0
        await pilot._post_mouse_events([events.MouseScrollUp], offset=(4, app.overlay_content_static.region.y + 2))
        await pilot.pause()
        assert app.overlay_content_static.scroll_y == start and modal.idx == 0


async def test_rendering_preserves_content_after_active_marker(monkeypatch):
    from src.ui.core.app import _modal_text
    from rich.text import Text
    req = AskRequest(Question(question="Full question", options=[
        Option("Label", "● active · retain this full description"),
    ]), lambda _: None, lambda _: None)
    rendered = _modal_text(AskModal(req))
    assert isinstance(rendered, Text)
    assert "● active · retain this full description" in rendered.plain
