"""Exercise real Textual dispatch/rendering without a provider or network."""
from __future__ import annotations

import asyncio
import io
import sys
from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from rich.cells import cell_len
from textual import events
from textual.app import ComposeResult
from textual.drivers.headless_driver import HeadlessDriver
from textual.geometry import Offset
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from src.agent.agent import Agent
from src.ui.core.app import AppProps, KAgent
from src.ui.core.state import Append, TranscriptEntry
from src.ui.widgets.banner import BannerData
from src.ui.widgets.input_box import DEFAULT_PROMPT
from src.ui.widgets.text_input_modal import TextInputRequest
from tests.helpers.ui_fakes import make_test_config_snapshot


class RecordingDriver(HeadlessDriver):
    """Use Textual's output/capture lifecycle, with an in-memory terminal sink."""

    @property
    def is_headless(self) -> bool:
        return False

    def write(self, data: str) -> None:
        self.output.append(data)

    def start_application_mode(self) -> None:
        self.output: list[str] = []
        super().start_application_mode()


@pytest.fixture
def app() -> KAgent:
    agent = MagicMock()
    agent.skills.list_enabled.return_value = []
    agent.skills.list.return_value = []
    agent.target.empty.return_value = True
    agent.target.base_url.return_value = None
    agent.target.name.return_value = "target"
    agent.get_memory_stats.return_value.items = 0
    agent.get_memory_stats.return_value.compactions = 0
    agent.approx_tokens.return_value = 0
    agent.idle_request_estimate.return_value.estimated_total = 0
    agent.get_auto_compact_threshold.return_value = 0
    agent.get_max_steps.return_value = 10
    agent.thinking_is_enabled.return_value = False
    agent.is_running.return_value = False
    agent.save_context_snapshot = AsyncMock(return_value=None)
    # No pinger: on_mount runs normally but cannot call an external provider.
    agent.client = object()
    app = KAgent(AppProps(
        agent=cast(Agent, agent),
        banner_data=BannerData(provider="offline", model="test", cwd="."),
        parent_signal=asyncio.Event(),
        read_config=lambda: make_test_config_snapshot(model="test"),
        apply_provider=AsyncMock(),
    ))
    app.run_agent_turn = AsyncMock()
    return app


def visible_caret(app: KAgent, widget: Static) -> Offset:
    """Find the drawn caret independently of terminal cursor bookkeeping."""
    region = widget.region
    for y, strip in enumerate(app.screen._compositor.render_strips()):
        if region.y <= y < region.bottom:
            index = strip.text.find("▌")
            if index >= 0:
                return Offset(cell_len(strip.text[:index]), y)
    raise AssertionError("The editable widget has no visible caret")


@pytest.mark.asyncio
async def test_max_steps_returns_to_editable_input_and_accepts_next_prompt(app: KAgent, monkeypatch) -> None:
    from src.agent.events import AssistantTextEvent, DoneEvent, ErrorEvent, MaxStepsError
    from src.ui.core.state import SetAsk

    app.run_agent_turn = KAgent.run_agent_turn.__get__(app, KAgent)
    prompts = []
    actions = []
    original_dispatch = app.dispatch
    def record(action):
        actions.append(action)
        original_dispatch(action)
    monkeypatch.setattr(app, "dispatch", record)
    async def run(value, *, signal, emit, opts=None):
        prompts.append(value)
        emit(AssistantTextEvent(text="Partial summary." if len(prompts) == 1 else "New request answered."))
        if len(prompts) == 1:
            emit(ErrorEvent(err=MaxStepsError(10)))
            emit(DoneEvent(stop_reason="max_steps"))
        else:
            emit(DoneEvent(stop_reason="final_response"))
    monkeypatch.setattr(app.agent, "run", AsyncMock(side_effect=run))

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press(*"first", "enter")
        await pilot.pause()
        assert prompts == ["first"]
        assert app.state.latest_turn_details is not None
        assert app.state.latest_turn_details.stop_reason == "max_steps"
        assert app.state.phase == "idle" and not app.state.busy
        assert app.run_task is None and app.run_abort_event is None
        assert app.state.pending_ask is None and app._get_active_modal() is None
        assert not any(isinstance(action, SetAsk) for action in actions)
        assert app.input.value == ""
        assert not app.overlay_static.display
        assert any(entry.text == "Partial summary." for entry in app.state.transcript)
        assert app.state.transcript[-1].text == "Stopped at max steps."

        await pilot.press(*"next")
        assert app.input.value == "next" and app.input_static.value == "next"
        assert app.cursor_position == visible_caret(app, app.input_static)
        await pilot.press("enter")
        await pilot.pause()
        assert prompts == ["first", "next"]
        assert app.state.latest_turn_details.stop_reason == "final_response"
        assert app.state.latest_turn_details.turn_number == 2
        assert app.state.transcript[-1].text == "Turn completed."
        assert sum(entry.text == "Stopped at max steps." for entry in app.state.transcript) == 1
        assert app.input.value == "" and app.state.phase == "idle" and not app.state.busy


@pytest.mark.asyncio
async def test_terminal_cursor_starts_at_drawn_input_caret(app: KAgent) -> None:
    async with app.run_test(size=(100, 30)):
        assert app.cursor_position == visible_caret(app, app.input_static)
        assert app.input_static.region.contains(app.cursor_position.x, app.cursor_position.y)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["/scope", "/scope show", "/help", "ssssssss", "hello", "tiếng Việt"])
async def test_typing_does_not_leak_into_transcript(app: KAgent, value: str) -> None:
    async with app.run_test(size=(100, 30)) as pilot:
        before = app.state.transcript
        title_row = app.screen._compositor.render_strips()[0].text
        await pilot.press(*value)
        assert app.input.value == value
        assert app.input.cursor == len(value)
        assert app.input_static.value == value
        assert app.state.transcript == before
        assert app.transcript_log.lines == []
        assert app.transcript_panel.border_title == "Transcript"
        assert app.screen._compositor.render_strips()[0].text == title_row
        assert app.cursor_position == visible_caret(app, app.input_static)
        cast(AsyncMock, app.run_agent_turn).assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["/scope", "/scope show", "/help"])
async def test_slash_dispatches_once_and_typing_continues(
    app: KAgent, command: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.ui.core import app as app_module

    handler = Mock(wraps=app_module.handle_slash)
    monkeypatch.setattr(app_module, "handle_slash", handler)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press(*command, "enter")
        handler.assert_called_once_with(app, command)
        assert len(app.state.transcript) == 1
        assert app.state.transcript[0].kind == "system"
        assert app.input.value == ""
        await pilot.press("a", "b", "c")
        assert app.input.value == "abc"
        assert app.cursor_position == visible_caret(app, app.input_static)
        handler.assert_called_once()
        cast(AsyncMock, app.run_agent_turn).assert_not_called()


@pytest.mark.asyncio
async def test_cursor_tracks_editing_focus_and_completion(app: KAgent) -> None:
    async with app.run_test(size=(100, 30)) as pilot:
        app.set_focus(app.transcript_log)
        await pilot.press("a", "界", "b", "left")
        assert app.input.value == "a界b"
        assert app.input.cursor == 2
        assert app.cursor_position == app.input_static.content_region.offset + Offset(
            cell_len(DEFAULT_PROMPT + "a界"), 0,
        )
        app.set_focus(None)
        await pilot.press("x", "backspace", "ctrl+a", "ctrl+e")
        assert app.input.value == "a界b"
        assert app.input.cursor == 3
        assert app.cursor_position == visible_caret(app, app.input_static)
        await pilot.press("escape", "/", "s", "c", "tab")
        assert app.input.value == "/scope "
        assert app.cursor_position == visible_caret(app, app.input_static)
        await pilot.press("tab")
        assert len(app.state.transcript) == 1
        assert app.input.value == ""
        await pilot.press("ctrl+f")
        assert len(app.state.transcript) == 1
        assert app.cursor_position == visible_caret(app, app.input_static)


@pytest.mark.asyncio
async def test_cursor_follows_wrap_multiline_resize_and_background_layout(app: KAgent) -> None:
    async with app.run_test(size=(40, 24)) as pilot:
        await pilot.press(*("界" * 20), "ctrl+n", "e")
        # Pilot's Unicode-name lookup cannot synthesize a combining mark;
        # deliver the character-bearing event the terminal parser produces.
        assert app._driver is not None
        app._driver.send_message(events.Key("combining_acute_accent", "\u0301"))
        await pilot.press(*"abc")
        assert app.input.value == "界" * 20 + "\ne\u0301abc"
        assert app.cursor_position == visible_caret(app, app.input_static)
        await pilot.resize_terminal(70, 30)
        assert app.cursor_position == visible_caret(app, app.input_static)
        app.dispatch(Append(entry=TranscriptEntry(kind="system", text="background notice")))
        await pilot.pause()
        assert app.cursor_position == visible_caret(app, app.input_static)


@pytest.mark.asyncio
@pytest.mark.parametrize("masked", [False, True])
async def test_text_modal_uses_its_own_caret_then_restores_prompt(
    app: KAgent, masked: bool,
) -> None:
    async with app.run_test(size=(60, 30)) as pilot:
        pending = asyncio.create_task(app.prompt_text(TextInputRequest(
            header="Offline input", question="Enter text", placeholder=None,
            masked=masked, resolve=lambda _: None, reject=lambda _: None,
        )))
        try:
            await pilot.pause()
            assert not app.input_static.display
            assert app.cursor_position == visible_caret(app, app.overlay_text_static)
            await pilot.press(*"abc", "left")
            assert app.cursor_position == visible_caret(app, app.overlay_text_static)
            await pilot.press("enter")
            assert await pending == "abc"
            assert app.input_static.display
            assert app.cursor_position == visible_caret(app, app.input_static)
        finally:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.asyncio
async def test_background_screen_cannot_move_native_input_caret(app: KAgent) -> None:
    class NativeInputScreen(ModalScreen):
        def compose(self) -> ComposeResult:
            yield Input()

    async with app.run_test(size=(80, 30)) as pilot:
        background = app.screen
        await app.push_screen(NativeInputScreen())
        await pilot.press("a")
        native_input = app.screen.query_one(Input)
        position = native_input.cursor_screen_offset
        assert app.cursor_position == position
        # A screen-stack render may revisit the prompt underneath a native
        # Textual modal (e.g. the command palette). Only the top owns the caret.
        app.input_static.refresh()
        background._compositor.render_strips()
        assert app.cursor_position == position
        app.pop_screen()
        await pilot.pause()
        assert app.cursor_position == visible_caret(app, app.input_static)


@pytest.mark.asyncio
async def test_driver_emits_caret_position_and_captures_background_output(
    app: KAgent, monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "__stdout__", stdout)
    monkeypatch.setattr(sys, "__stderr__", stderr)
    app.driver_class = RecordingDriver
    async with app.run_test(headless=False, size=(80, 30)) as pilot:
        await pilot.press(*"abc")
        position = visible_caret(app, app.input_static)
        driver = cast(RecordingDriver, app._driver)
        assert driver.output[-1].endswith(f"\x1b[{position.y + 1};{position.x + 1}H")

        async def background_output() -> None:
            print("offline worker stdout")
            sys.stderr.write("offline worker stderr\n")
            app.dispatch(Append(entry=TranscriptEntry(kind="system", text="worker notice")))

        await asyncio.create_task(background_output())
        await pilot.pause()
        assert stdout.getvalue() == stderr.getvalue() == ""
        output = "".join(driver.output)
        assert "offline worker stdout" not in output
        assert "offline worker stderr" not in output
        assert "worker notice" in output
        assert app.state.transcript[-1].text == "worker notice"
        assert app.cursor_position == visible_caret(app, app.input_static)
    assert app.ping_task is not None and app.ping_task._task is None
    assert app.snapshot_task is not None and app.snapshot_task.done()


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['final_response', 'cancelled', 'context_capacity'])
async def test_dispatch_refreshes_input_and_status_without_keyboard_or_resize(app, reason):
    from src.agent.events import DoneEvent
    from src.ui.core.state import AgentEventAction, SetBusy, SetPerm
    from src.ui.bridges.perm_bridge import BridgedPermissionRequest
    async with app.run_test(size=(100, 30)) as pilot:
        app.dispatch(SetBusy(True))
        await pilot.pause()
        assert app.state.busy and app.status_bar.phase == 'planning'
        assert 'agent running' in str(app.input_static.render())
        permission = BridgedPermissionRequest(tool='shell', summary='fixture', detail='fixture',
                                             no_session_cache=True, resolve=Mock(), reject=Mock())
        app.dispatch(SetPerm(permission))
        await pilot.pause()
        assert app.status_bar.phase == 'waiting-approval'
        assert 'agent running' in str(app.input_static.render())
        app.dispatch(SetPerm(None))
        app.dispatch(AgentEventAction(DoneEvent(stop_reason=reason)))
        await pilot.pause()
        assert not app.state.busy and app.status_bar.phase == 'idle'
        assert 'agent running' not in str(app.input_static.render())


@pytest.mark.asyncio
async def test_status_tracks_effective_capture_and_native_requests_while_transport_waits(app, monkeypatch):
    import httpx
    from src.agent.events import DoneEvent, ToolCallEvent, ToolResultEvent
    from src.browser.store import CaptureStore
    from src.engagement.state import EngagementState
    from src.permission.permission import AlwaysAllow
    from src.target.target import Target
    from src.tools.common.outcome import ToolOutput
    from src.tools.common.registry import Registry
    from src.tools.http.http_tool import HTTPTool
    from src.tools.workflow.workflow_tool import WorkflowTool
    from src.ui.core.state import AgentEventAction, SetBusy
    from src.workflow.state import Candidate, WorkflowState

    origin = 'http://127.0.0.1:3000'
    target, engagement, workflow, capture = Target(origin), EngagementState(), WorkflowState(), CaptureStore()
    engagement.initialize_target(origin)
    baseline = capture.ingest({'kind':'burp', 'id':'fixture', 'method':'POST', 'url':origin+'/api/login',
        'requestHeaders':[{'name':'Content-Type','value':'application/json'}],
        'requestBody':'{"email":"fixture@example.test"}'})
    tool = HTTPTool(target, engagement, workflow, capture)
    registry = Registry()
    registry.register(tool)
    registry.register(WorkflowTool(workflow, target))
    app.agent.workflow = workflow
    app.agent.target = target
    app.agent.engagement_state = engagement
    app.agent.tools = registry
    entered, release = asyncio.Event(), asyncio.Event()
    requests = []
    async def transport(request):
        requests.append(request)
        entered.set()
        await release.wait()
        return httpx.Response(200, content=b'Offline fixture response', request=request)
    real_client = httpx.AsyncClient
    monkeypatch.setattr('src.tools.http.http_tool.httpx.AsyncClient',
        lambda **kwargs:real_client(transport=httpx.MockTransport(transport), **kwargs))
    monkeypatch.setattr('src.tools.http.http_tool.gate_private_request', AsyncMock(return_value=''))

    async def execute(event_id, args):
        app.dispatch(AgentEventAction(ToolCallEvent(id=event_id, name='http', args=args)))
        result = await registry.execute('http', args, None, AlwaysAllow())
        assert isinstance(result, ToolOutput)
        app.dispatch(AgentEventAction(ToolResultEvent(id=event_id, name='http', result=result,
            status=result.status, http_status=result.http_status)))

    async with app.run_test(size=(120, 32)) as pilot:
        app.dispatch(SetBusy(True))
        candidate, _ = workflow.add_candidate(Candidate(candidate_class='authentication', target=origin,
            method='POST', endpoint='/api/login', parameter='email', location='json',
            content_type='application/json', baseline_request_ref=baseline['baseline_request_ref']))
        cases = [({'candidate_id':candidate.id, 'mutation_value':'fixture2@example.test', 'phase':'validation'},
                  'POST /api/login · input email', 'POST', '/api/login'),
                 ({'url':origin+'/health?token=short-secret', 'method':'GET', 'phase':'recon'},
                  'GET /health', 'GET', '/health')]
        for index, (args, activity, method, path) in enumerate(cases):
            entered.clear()
            release.clear()
            task = asyncio.create_task(execute(str(index), args))
            try:
                await asyncio.wait_for(entered.wait(), 2)
                await pilot.pause()
                assert not task.done()  # Inspect the actual rendered UI during pending I/O.
                assert activity in app.status_bar.render().plain
                row = app.screen._compositor.render_strips()[app.status_bar.region.y].text
                assert activity in row and 'short-secret' not in row
                if index:
                    assert 'input email' not in row
                assert requests[-1].method == method and requests[-1].url.path == path
                assert 'agent running' in str(app.input_static.render())
                assert sum(entry.text.startswith('Selected:') for entry in app.state.transcript) == 1
                assert not any(entry.text.startswith('Validation ') for entry in app.state.transcript)
                release.set()
                await asyncio.wait_for(task, 2)
            finally:
                release.set()
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        app.dispatch(AgentEventAction(DoneEvent(stop_reason='final_response')))
        await pilot.pause()
        assert app.status_bar.phase == 'idle' and 'agent running' not in str(app.input_static.render())
        assert len(requests) == 2
