from __future__ import annotations
from tests.helpers.ui_fakes import make_test_config_snapshot

import asyncio
from typing import Any, cast
from unittest.mock import MagicMock
from unittest.mock import AsyncMock
from types import SimpleNamespace
from dataclasses import replace

import pytest
from rich.console import Console

from src.agent.agent import Agent
from src.config.config import Backend
from src.ui.core.app import AppProps, ConfigSnapshot, KAgent
from src.ui.core.state import Clear
from src.ui.widgets.banner import BannerData
from src.agent.events import DecisionEvent, DoneEvent, ToolCallEvent, ToolResultEvent, WorkflowProgressEvent, Invocation
from src.agent.scope import runtime_scope
from src.permission.permission import AlwaysAllow
from src.target.target import Target
from src.tools.workflow.workflow_tool import WorkflowTool
from src.tools.common.registry import Registry
from src.ui.core.state import AgentEventAction, SetBusy, SetSkillsPicker
from src.ui.commands.slash_handler import handle_slash
from src.workflow.state import WorkflowState, WorkflowObjective
from tests.helpers.workflow import record_completed_phase


@pytest.fixture(autouse=True)
def offline_startup(monkeypatch):
    monkeypatch.setattr("src.ui.core.app.PingTask.start", lambda self: None)
    monkeypatch.setattr(KAgent, "_save_snapshot", AsyncMock())
    monkeypatch.setattr(KAgent, "_snapshot_loop", AsyncMock())


def _make_app(cols: int = 80, lines: int = 24) -> KAgent:
    agent = MagicMock()
    agent.skills = SimpleNamespace(list=lambda: [], list_enabled=lambda: [])
    agent.tools = []
    agent.is_running.return_value = False
    agent.approx_tokens.return_value = 0
    agent.tools_token_estimate.return_value = 0
    agent.idle_request_estimate.return_value.estimated_total = 0
    agent.get_auto_compact_threshold.return_value = 0
    agent.get_memory_stats.return_value.items = 0
    agent.target.base_url.return_value = None
    agent.target.name.return_value = "target"
    agent.model_name.return_value = "chat-model"
    agent.store = SimpleNamespace(id="offline-session")

    banner = BannerData(
        provider="deepseek",
        model="deepseek-chat",
        cwd="/workspace/kagent",
    )

    return KAgent(
        AppProps(
            agent=cast(Agent, agent),
            banner_data=banner,
            parent_signal=asyncio.Event(),
            read_config=lambda: make_test_config_snapshot(
                backend=cast(Backend, "openai"),
                model="deepseek-chat",
            ),
            apply_provider=_dummy_apply_provider,
        )
    )


async def _dummy_apply_provider(_: Any) -> None:
    pass


def _render_obj(panel: Any, width: int = 76) -> str:
    c = Console(width=width, force_terminal=False, color_system=None)
    with c.capture() as cap:
        c.print(panel)
    return cap.get()


def _get_panel(app: KAgent) -> Any:
    rendered = cast(Any, app.overview_static.render())
    return getattr(rendered, "_renderable", rendered)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(45, 24), (100, 30)])
@pytest.mark.parametrize("resume_summary", [None, "Restored saved conversation."])
async def test_startup_shows_workspace_and_accepts_first_key(
    size: tuple[int, int], resume_summary: str | None,
) -> None:
    app = _make_app()
    app.resume_summary = resume_summary

    async with app.run_test(size=size) as pilot:
        assert app.transcript_panel.display
        assert app.input_static.display
        assert app.status_bar.display
        assert "Welcome to KAgent" in _render_obj(_get_panel(app), width=size[0])
        if resume_summary:
            assert sum(
                entry.kind == "system" and entry.text == resume_summary
                for entry in app.state.transcript
            ) == 1

        await pilot.press("h")
        assert app.input.value == "h"


@pytest.mark.asyncio
async def test_initial_overview_compact_layout() -> None:
    """Initial Overview renders in compact side-by-side layout (height <= 8 lines)."""
    app = _make_app()
    async with app.run_test(size=(80, 24)):
        panel = _get_panel(app)
        text = _render_obj(panel)
        lines = [ln for ln in text.splitlines() if ln.strip()]

        # Compact layout has logo and details side-by-side (~6-8 lines total)
        # Vertical stacked fallback has > 10 lines
        assert len(lines) <= 9, f"Initial Overview should be compact (<=9 lines), got {len(lines)}"
        assert "Welcome to KAgent" in text
        assert "Provider: deepseek" in text
        assert "Model: deepseek-chat" in text
        assert "Path: /workspace/kagent" in text
        assert "Target: (not set)" in text
        assert "Session: offline-session" in text
        assert "Status:" not in text
        assert "Progress:" not in text


@pytest.mark.asyncio
async def test_transcript_background_aligns_with_overview_frame() -> None:
    app = _make_app()
    async with app.run_test(size=(100, 30)):
        overview = app.overview_static.region
        transcript = app.transcript_log.region

        # The transcript reserves its last column for the scrollbar. Inset
        # the background by one cell so it sits inside the Overview frame.
        assert transcript.x == overview.x + 1
        assert transcript.right == overview.right


@pytest.mark.asyncio
async def test_post_clear_overview_compact_layout() -> None:
    """Post-/clear Overview renders in compact side-by-side layout."""
    app = _make_app()
    async with app.run_test(size=(80, 24)) as pilot:
        app.dispatch(Clear())
        await pilot.pause()

        panel = _get_panel(app)
        text = _render_obj(panel)
        lines = [ln for ln in text.splitlines() if ln.strip()]

        assert len(lines) <= 9
        assert "Welcome to KAgent" in text
        assert "Provider: deepseek" in text


@pytest.mark.asyncio
async def test_initial_and_post_clear_overview_are_identical() -> None:
    """Initial Overview and post-/clear Overview use the identical rendering output."""
    app = _make_app()
    async with app.run_test(size=(80, 24)) as pilot:
        p1 = _render_obj(_get_panel(app))

        app.dispatch(Clear())
        await pilot.pause()

        p2 = _render_obj(_get_panel(app))

        assert p1 == p2, (
            f"Initial overview does not match post-/clear overview:\n"
            f"--- INITIAL ---\n{p1}\n"
            f"--- POST-CLEAR ---\n{p2}"
        )


@pytest.mark.asyncio
async def test_overview_updates_on_terminal_resize() -> None:
    """Terminal resize updates the overview layout cleanly."""
    app = _make_app()
    async with app.run_test(size=(80, 24)) as pilot:
        # Resize to narrow terminal
        await pilot.resize_terminal(45, 24)
        panel = _get_panel(app)
        text = _render_obj(panel, width=41)
        assert "Overview" in text
        assert "Provider: deepseek" in text


def _workflow_app(tmp_path):
    app = _make_app()
    app.agent.target = Target("https://fixture.test")
    app.agent.prompter = AlwaysAllow()
    workflow = WorkflowState(objective=WorkflowObjective("overview", "whole_target", "https://fixture.test"))
    app.agent.workflow = workflow
    tools = Registry()
    tools.register(WorkflowTool(workflow, app.agent.target, evidence_root=tmp_path))
    app.agent.tools = tools
    record_completed_phase(workflow, "recon", objective_id="overview", target_origin="https://fixture.test",
                           artifact_ref="missing.md")
    return app, workflow


async def test_overview_uses_runtime_identity_without_duplicate_status():
    app = _make_app()
    app.agent.target = Target("https://user:short-secret@EXAMPLE.test:443/path?token=short-secret#fragment")
    app.state = replace(app.state, banner_data=replace(app.state.banner_data,
        status="Session invented-id", endpoint="https://provider.test/v1?api_key=short-secret"))
    async with app.run_test(size=(120, 32)) as pilot:
        def rendered():
            return _render_obj(_get_panel(app), 116)
        text = rendered()
        assert "Target: https://example.test" in text
        assert "Session: offline-session" in text and "Status:" not in text
        assert "Endpoint:" in text
        assert "short-secret" not in text and "invented-id" not in text
        for action, phase in [(SetBusy(True), "planning"), (SetBusy(False), "idle"),
                              (SetSkillsPicker(True), "skills"), (SetSkillsPicker(False), "idle")]:
            app.dispatch(action)
            assert "Status:" not in rendered()
            assert app.status_bar.phase == phase
        app.dispatch(AgentEventAction(DoneEvent(stop_reason="runtime_error")))
        assert "Status:" not in rendered() and app.status_bar.phase == "idle"
        app.agent.target.clear()
        app._recompute_view()
        assert "Target: (not set)" in rendered()
        await pilot.pause()


async def test_wait_status_remains_in_status_bar_without_overview_duplication():
    from src.ui.core.state import SetAsk, SetPerm
    from tests.ui.test_pending_phase import pending_ask, pending_permission
    app = _make_app()
    async with app.run_test(size=(120, 32)):
        app.dispatch(SetBusy(True))
        app.dispatch(SetPerm(pending_permission()))
        assert app.status_bar.phase == "waiting-approval"
        assert "Status:" not in _render_obj(_get_panel(app), 116)
        app.dispatch(SetAsk(pending_ask()))
        assert app.status_bar.phase == "waiting-user"
        assert "Status:" not in _render_obj(_get_panel(app), 116)
        app.dispatch(SetBusy(False))
        assert app.status_bar.phase == "waiting-user"
        assert "Status:" not in _render_obj(_get_panel(app), 116)
        app.dispatch(SetAsk(None))
        assert app.status_bar.phase == "waiting-approval"
        assert "Status:" not in _render_obj(_get_panel(app), 116)
        app.dispatch(SetPerm(None))
        assert app.status_bar.phase == "idle"
        assert "Status:" not in _render_obj(_get_panel(app), 116)


@pytest.mark.parametrize("resume", [False, True])
async def test_progress_restored_once_and_clear_rebuilds_without_telemetry(tmp_path, resume):
    app, workflow = _workflow_app(tmp_path)
    if resume:
        app.resume_summary = "Restored offline conversation."
    async with app.run_test(size=(120, 32)):
        text = _render_obj(_get_panel(app), 116)
        assert text.count("Progress:") == 1
        assert "Recon repair" in text and "Blocked" in text
        assert not any(entry.text.startswith("Workflow ·") for entry in app.state.transcript)
        before = app.state
        app.dispatch(AgentEventAction(WorkflowProgressEvent(metrics={"made_up_progress": 100})))
        assert app.state is before
        app.dispatch(Clear())
        assert "Progress:" in _render_obj(_get_panel(app), 116)
        assert not app.state.transcript
        assert workflow.objective is not None
        workflow.objective.mode = "direct"
        app.refresh_assessment_progress()
        assert "Progress:" not in _render_obj(_get_panel(app), 116)


async def test_progress_preserves_all_snapshot_fields_without_assessment_conclusion(tmp_path):
    from src.workflow.state import AttackSurfaceInput, Candidate, RequestedGoal
    from tests.ui.test_progress_milestones import accepted_fixture
    app, workflow = _workflow_app(tmp_path)
    assert workflow.objective is not None
    workflow.objective.requested_goals.append(RequestedGoal("sqli"))
    for disposition in ("analyzed", "blocked"):
        item = AttackSurfaceInput("overview", "https://fixture.test", method="GET", endpoint="/" + disposition,
                                  parameter="q", location="query", disposition=disposition,
                                  disposition_reason="Offline fixture constraint" if disposition == "blocked" else None)
        workflow.attack_surface_inputs[item.id] = item
    accepted, _ = workflow.add_candidate(Candidate(candidate_class="xss", target="https://fixture.test",
        method="GET", endpoint="/accepted", parameter="q", objective_id="overview"))
    workflow.add_validation_result(accepted_fixture(tmp_path, workflow, accepted))
    active, _ = workflow.add_candidate(Candidate(candidate_class="xss", target="https://fixture.test", method="GET",
                                                endpoint="/active", parameter="q", objective_id="overview"))
    workflow.set_candidate_status(active.id, "validating")
    async with app.run_test(size=(120, 32)):
        text = " ".join(_render_obj(_get_panel(app), 116).replace("│", "").split())
        for part in ("Progress:", "Recon repair", "Blocked", "1/2 inputs reviewed",
                     "1 input blocked", "1 validation active", "1 validation accepted", "1 goal pending"):
            assert part in text
        assert not app.state.transcript
        assert "Status:" not in text


async def test_overview_sanitizes_controls_and_missing_session_without_status_parsing():
    app = _make_app()
    app.agent.store = None
    app.state = replace(app.state, banner_data=replace(app.state.banner_data, provider="offline\x1b]52;c;DATA\x07",
        model="fixture password=short-secret", status="Session invented-id"))
    async with app.run_test(size=(120, 32)):
        text = _render_obj(_get_panel(app), 116)
        assert "Session: (not set)" in text and "Target: (not set)" in text
        assert "invented-id" not in text and "short-secret" not in text
        assert "\x1b" not in text and "\x07" not in text
        assert r"\x1b" in text and r"\x07" in text


@pytest.mark.parametrize("change", ["target", "revision", "scope", "objective", "session", "generation"])
async def test_context_change_hides_old_progress_and_late_duplicate_cannot_restore_it(tmp_path, change):
    app, workflow = _workflow_app(tmp_path)
    async with app.run_test(size=(120, 32)):
        call = ToolCallEvent(id="old", name="http", args={"url":"https://fixture.test/path"},
                             invocation=Invocation("old", runtime_scope(app.agent)))
        app.dispatch(AgentEventAction(call))
        result = ToolResultEvent(id="old", name="http", http_status=200, invocation=call.invocation)
        app.dispatch(AgentEventAction(result))
        assert "Progress:" in _render_obj(_get_panel(app), 116)
        if change == "target":
            app.agent.target.set_base_url("https://other.test")
        elif change == "revision":
            app.agent.target.revision += 1
        elif change == "scope":
            app.agent.engagement_state = cast(Any, SimpleNamespace(revision=1, http_permissions=None))
        elif change == "objective":
            workflow.objective = WorkflowObjective("replacement", "direct", "https://fixture.test")
        elif change == "session":
            assert app.agent.store is not None
            app.agent.store.id = "another-session"
        else:
            workflow.retire_generation()
        app._recompute_view()
        assert "Progress:" not in _render_obj(_get_panel(app), 116)
        app.dispatch(AgentEventAction(result))
        assert "Progress:" not in _render_obj(_get_panel(app), 116)
        app.dispatch(AgentEventAction(DecisionEvent(target_origin="https://stale.test")))
        assert "Progress:" not in _render_obj(_get_panel(app), 116)


async def test_reset_hides_progress_through_await_and_keeps_actual_store_id(tmp_path):
    app, workflow = _workflow_app(tmp_path)
    entered, release = asyncio.Event(), asyncio.Event()
    async def reset():
        entered.set()
        await release.wait()
        workflow.clear()
    app.agent.reset = reset
    async with app.run_test(size=(120, 32)) as pilot:
        assert "Progress:" in _render_obj(_get_panel(app), 116)
        handle_slash(app, "/reset")
        await entered.wait()
        assert app.state.latest_facts is None
        for action in (AgentEventAction(DecisionEvent()), Clear()):
            app.dispatch(action)
            assert app.state.latest_facts is None
            assert "Progress:" not in _render_obj(_get_panel(app), 116)
        assert "Session: offline-session" in _render_obj(_get_panel(app), 116)
        release.set()
        await pilot.pause()
        assert app.state.latest_facts is not None and not app.state.latest_facts.overview
        assert "Progress:" not in _render_obj(_get_panel(app), 116)
        assert "Session: offline-session" in _render_obj(_get_panel(app), 116)


@pytest.mark.parametrize("reading", [False, True])
async def test_progress_height_resize_keeps_transcript_anchor_tail_and_copy(tmp_path, reading):
    from textual.geometry import Offset
    from textual.selection import Selection
    from src.ui.core.state import TranscriptEntry
    app, workflow = _workflow_app(tmp_path)
    async with app.run_test(size=(120, 32)) as pilot:
        app.state = replace(app.state, transcript=tuple(TranscriptEntry("system", f"History entry {i}") for i in range(100)))
        app._recompute_view()
        await pilot.pause()
        if reading:
            app.transcript_log.scroll_to(y=30, animate=False, immediate=True, force=True)
        top = app.transcript_log.scroll_y
        before_lines = list(app.transcript_log.lines)
        app.screen.selections = {app.transcript_log: Selection(Offset(0, 30), Offset(12, 30))}
        copied = app.screen.get_selected_text()
        app.state = replace(app.state, banner_data=replace(app.state.banner_data, model="long-model-" * 40))
        app.refresh_assessment_progress()
        await pilot.pause()
        assert app.screen.get_selected_text() == copied
        if reading:
            assert app.transcript_log.scroll_y == top
        else:
            assert app.transcript_log.is_vertical_scroll_end
        assert all(a is b for a, b in zip(before_lines, app.transcript_log.lines))
        for width, height in [(45, 24), (80, 14), (120, 32)]:
            await pilot.resize_terminal(width, height)
            assert app.transcript_log.region.height >= 3
            assert app.input_static.region.height >= 1
            assert app.input_panel.region.bottom <= height
            assert app.overview_scroll.region.height <= height * 0.4
            if height < 24:
                assert app.overview_scroll.max_scroll_y > 0
                app.overview_scroll.scroll_end(animate=False, immediate=True)
                assert app.overview_scroll.scroll_y > 0
            assert app.screen.get_selected_text() == copied
            if reading:
                assert app.transcript_log.scroll_y == top
            else:
                assert app.transcript_log.is_vertical_scroll_end
