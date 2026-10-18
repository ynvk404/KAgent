"""Mounted startup themes use the same presentation data and isolated runtime."""
from __future__ import annotations

import asyncio
import copy
import io
import os
import subprocess
import sys
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from rich.text import Text
from textual.geometry import Offset
from textual.selection import Selection

from src.agent.agent import Agent, AgentOptions
from src.llm.core.types import Message
from src.permission.permission import AlwaysAllow
from src.session.store import Store
from src.skills.registry import Registry as Skills
from src.target.target import Target
from src.tools.common.registry import Registry
from src.ui.core.app import AppProps, KAgent
from src.ui.core.state import Append, SetBusy, SetPerm, TranscriptEntry
from src.ui.render.modal import _INPUT_STYLE_MAP
from src.ui.theme import DARK_UI, LIGHT_UI, ThemeChoice
from src.ui.widgets.banner import BannerData
from src.ui.widgets.status_bar import StatusProps
from src.ui.widgets.text_input_modal import TextInputRequest
from src.workflow.state import Candidate, WorkflowState
from tests.helpers.agent_fakes import FakeClient
from tests.helpers.ui_fakes import make_test_config_snapshot
from tests.ui.test_input_rendering import RecordingDriver
from tests.ui.test_permission_modal import make_req


@pytest.fixture(autouse=True)
def colored_terminal(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)


def make_app(choice: ThemeChoice = "dark") -> KAgent:
    agent = MagicMock()
    agent.skills.list_enabled.return_value = []
    agent.target.base_url.return_value = None
    agent.target.name.return_value = "fixture"
    agent.get_memory_stats.return_value.items = 0
    agent.approx_tokens.return_value = 0
    agent.idle_request_estimate.return_value.estimated_total = 0
    agent.get_auto_compact_threshold.return_value = 0
    agent.is_running.return_value = False
    agent.save_context_snapshot = AsyncMock(return_value=None)
    agent.client = object()  # No external pinger.
    return KAgent(AppProps(agent=cast(Agent, agent),
        banner_data=BannerData("offline", "fixture", "."), parent_signal=asyncio.Event(),
        read_config=lambda: make_test_config_snapshot(model="fixture"),
        apply_provider=AsyncMock(), theme=choice))


def renderable(widget):
    # Static may expose Textual Content; retain the supplied Rich Text for spans.
    return widget.content


@pytest.mark.parametrize("choice", ["dark", "light"])
@pytest.mark.parametrize("size", [(100, 38), (45, 22)])
async def test_startup_colors_layout_and_permission_selection(choice, size):
    app = make_app(choice)
    ui = LIGHT_UI if choice == "light" else DARK_UI
    assert app.theme == ("kagent-light" if choice == "light" else "textual-dark")
    assert app.ui_palette is ui
    async with app.run_test(size=size) as pilot:
        assert app.screen.styles.background.hex == ("#FAF8F2" if choice == "light" else "#121212")
        assert app.transcript_log.styles.background.hex == ("#F2F0E8" if choice == "light" else "#1E1E1E")
        assert app.transcript_log.styles.color.hex == (ui.text if choice == "light" else "#E0E0E0")
        for widget in (app.transcript_panel, app.input_panel):
            assert widget.styles.border.top[0] == "round"
            assert widget.styles.border.top[1].hex == ui.border
            assert widget.styles.border_title_color.hex == ui.accent
        assert app.transcript_log.styles.scrollbar_color.hex == ui.muted
        assert app.transcript_log.styles.scrollbar_size_vertical == 1
        assert app.transcript_log.styles.scrollbar_background.a == 0
        if choice == "light":
            assert app.status_bar.styles.background.hex == "#EEECE4"
        else:
            assert app.status_bar.styles.background.hex == "#7E8A9A1E"
        req = make_req(tool="http", detail="GET https://fixture.test/search?q=fixture")
        app.dispatch(SetPerm(req))
        await pilot.pause()
        assert app.overlay_static.region.bottom <= size[1]
        assert app.overlay_content_static.styles.scrollbar_color.hex == ui.muted
        app.screen.selections = {app.overlay_text_static: Selection(Offset(0, 0), Offset(4, 0))}
        assert app.screen.get_selected_text()
        foregrounds = [segment.style.color for strip in app.overlay_text_static.render_lines(
            app.overlay_text_static.content_region.reset_offset) for segment in strip
            if segment.style and segment.style.color]
        assert foregrounds
        req.resolve.assert_not_called()
        req.reject.assert_not_called()


async def test_light_input_free_text_streaming_and_disabled_status():
    app = make_app("light")
    async with app.run_test(size=(100, 38)) as pilot:
        app.input.set_value("ordinary text")
        app._render_input()
        text = renderable(app.input_static)
        assert isinstance(text, Text)
        assert any(str(span.style) == LIGHT_UI.text for span in text.spans)
        app._render_live_entry(TranscriptEntry("assistant", "streaming fixture", streaming=True))
        live = renderable(app.live_entry_static)
        assert isinstance(live, Text) and LIGHT_UI.text in str(live.spans)
        app.input.clear()
        app.dispatch(SetBusy(True))
        disabled = renderable(app.input_static)
        assert isinstance(disabled, Text)
        assert "agent running…" in disabled.plain
        assert all(str(span.style) == _INPUT_STYLE_MAP["gray"] for span in disabled.spans)
        app.dispatch(SetBusy(False))
        app.text_input = TextInputRequest("Input", "Fixture question", "placeholder", Mock(), Mock())
        app._sync_overlay()
        await pilot.pause()
        modal_text = renderable(app.overlay_text_static)
        assert isinstance(modal_text, Text)
        assert "placeholder" in modal_text.plain
        assert LIGHT_UI.text in str(modal_text.spans)


@pytest.mark.parametrize("phase", ["planning", "running-tool", "answering", "waiting-approval", "waiting-user", "idle"])
async def test_status_bar_styles_are_identical_between_themes(phase):
    frames = []
    for choice in ("dark", "light"):
        app = make_app(cast(ThemeChoice, choice))
        async with app.run_test(size=(120, 38)):
            app.status_bar.apply(StatusProps(busy=phase != "idle", api_ready=True,
                active_skill="sql-injection", yolo=True, ctx_tokens=10, request_tokens=99,
                compact_threshold=100, memory_items=0, phase=phase,
                model="fixture", tool_support="probing", running_tool="workflow: start validation",
                elapsed_seconds=3))
            text = app.status_bar.render()
            frames.append((text.plain, [(s.start, s.end, str(s.style)) for s in text.spans]))
    assert frames[0] == frames[1]


@pytest.mark.parametrize("capability,background,dark_background", [
    ("truecolor", "48;2;250;248;242", "48;2;18;18;18"),
    ("256", "48;5;231", "48;5;233"),
])
async def test_light_first_terminal_frame_uses_selected_theme(
        monkeypatch, capability, background, dark_background):
    import sys
    # The recording driver is a sink, not a terminal capability provider.
    # Declare each emulated terminal before Textual builds its Rich console.
    monkeypatch.setenv("TERM", "xterm-256color")
    if capability == "truecolor":
        monkeypatch.setenv("COLORTERM", "truecolor")
    else:
        monkeypatch.delenv("COLORTERM", raising=False)
    from textual import constants
    monkeypatch.setattr(constants, "COLOR_SYSTEM", "auto")
    app = make_app("light")
    assert app.console.color_system == capability
    monkeypatch.setattr(sys, "__stdout__", io.StringIO())
    monkeypatch.setattr(sys, "__stderr__", io.StringIO())
    app.driver_class = RecordingDriver
    async with app.run_test(headless=False, size=(100, 38)) as pilot:
        await pilot.pause()
        output = cast(RecordingDriver, app._driver).output
        assert output
        # Check the first paint in the terminal's actual encoding. The 256-color
        # light Screen maps to index 231; truecolor retains the exact RGB.
        paints = [chunk for chunk in output if "48;" in chunk]
        assert paints and background in paints[0]
        assert dark_background not in paints[0]


def test_cli_default_dark_overrides_textual_environment():
    # Textual captures TEXTUAL_THEME at import time, so use a fresh process.
    probe = subprocess.run([sys.executable, "-B", "-c",
        "from textual.app import App; "
        "from tests.ui.test_light_theme_app import make_app; "
        "assert App().theme == 'textual-light'; "
        "assert make_app().theme == 'textual-dark'"],
        env={**os.environ, "TEXTUAL_THEME": "textual-light"},
        capture_output=True, text=True, check=False)
    assert probe.returncode == 0, probe.stderr


@pytest.mark.parametrize("choice", ["dark", "light"])
async def test_theme_rendering_does_not_mutate_runtime_or_persistence(tmp_path: Path, monkeypatch, choice):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: self._recompute_view())
    client = FakeClient([])
    tools, skills, permission = Registry(), Skills(), AlwaysAllow()
    workflow = WorkflowState()
    workflow.add_candidate(Candidate(candidate_class="sqli", target="https://fixture.test",
        endpoint="/search", parameter="q", method="GET"))
    store = Store.new_with_id(tmp_path / "sessions", "theme-fixture")
    agent = Agent(AgentOptions(client, tools, skills, permission, store,
                              Target("https://fixture.test"), workflow=workflow))
    await store.save([Message("user", "Saved fixture")])
    finding = tmp_path / "artifacts" / "findings" / "fixture.md"
    finding.parent.mkdir(parents=True)
    finding.write_text("Synthetic offline finding fixture", encoding="utf-8")
    before_files = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    before_history = copy.deepcopy(agent.history)
    before_workflow = copy.deepcopy(workflow.to_dict())
    before_permissions = copy.deepcopy(agent.engagement_state.to_dict())
    app = KAgent(AppProps(agent, BannerData("offline", "fixture", "."), asyncio.Event(),
        lambda: make_test_config_snapshot(model="fixture"), AsyncMock(), theme=choice))
    async with app.run_test(size=(100, 38)) as pilot:
        app.dispatch(Append(TranscriptEntry("finding", "Finding saved · SQLi fixture")))
        app.dispatch(Append(TranscriptEntry("warning", "Permission denied")))
        await pilot.pause()
        await pilot.resize_terminal(70, 26)
        assert app.state.transcript[-1].text == "Permission denied"
    assert agent.history == before_history
    assert workflow.to_dict() == before_workflow
    assert agent.engagement_state.to_dict() == before_permissions
    assert {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before_files
    assert tools.names() == [] and client.requests == []
