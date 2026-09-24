from __future__ import annotations
from tests.helpers.ui_fakes import make_test_config_snapshot

import asyncio
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from src.agent.agent import Agent
from src.config.config import Backend
from src.ui.core.app import AppProps, ConfigSnapshot, KAgent
from src.ui.core.state import Clear
from src.ui.widgets.banner import BannerData


def _make_app(cols: int = 80, lines: int = 24) -> KAgent:
    agent = MagicMock()
    agent.skills = []
    agent.tools = []
    agent.is_running.return_value = False
    agent.approx_tokens.return_value = 0
    agent.tools_token_estimate.return_value = 0
    agent.get_auto_compact_threshold.return_value = 0
    agent.get_memory_stats.return_value.items = 0
    agent.target.base_url.return_value = None
    agent.target.name.return_value = "target"
    agent.model_name.return_value = "chat-model"

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
            show_splash=False,
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
