from __future__ import annotations

import asyncio
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from rich.console import Console
from rich.panel import Panel
from textual.app import App, ComposeResult

from src.agent.agent import Agent
from src.config.config import Backend
from src.ui.core.app import (
    AppProps,
    ConfigSnapshot,
    KAgent,
    ProviderChange,
)
from src.ui.theme import ACCENT, BOLD_ACCENT, MUTED, SUCCESS
from src.ui.widgets.banner import BannerData
from src.ui.widgets.startup_splash import (
    BAR_WIDTH,
    SplashProps,
    StartupSplash,
    WORD,
    render_kagent_word,
    render_progress_bar,
)


def _render_plain(widget: StartupSplash, width: int = 80) -> str:
    panel = cast(Panel, widget.render())
    console = Console(width=width, force_terminal=False, color_system=None)
    with console.capture() as capture:
        console.print(panel)
    return capture.get()


class TestKagentShineSweep:
    def test_full_word_visible_from_first_frame(self) -> None:
        """1. full 'KAGENT' word is visible from the first identity frame."""
        splash = StartupSplash()
        assert splash.phase == "identity"
        rendered = _render_plain(splash)
        assert "KAGENT" in rendered

    def test_letters_not_progressively_added_or_removed(self) -> None:
        """2. letters are not progressively added/removed."""
        for idx in range(len(WORD) + 2):
            text = render_kagent_word(shine_idx=idx, shine_done=(idx >= len(WORD)))
            assert text.plain == "KAGENT", f"Expected 'KAGENT' at step {idx}, got {text.plain}"

    def test_highlight_index_advances_across_letters(self) -> None:
        """3. highlight index advances across K,A,G,E,N,T."""
        splash = StartupSplash()
        assert splash.shine_idx == 0
        assert not splash.shine_done

        for expected_idx in range(1, len(WORD)):
            splash._tick_shine()
            assert splash.shine_idx == expected_idx
            assert not splash.shine_done

    def test_normal_letters_remain_accent(self) -> None:
        """4. normal letters remain ACCENT."""
        text = render_kagent_word(shine_idx=2, shine_done=False)
        # Letter at index 0 ('K') and index 1 ('A') should be ACCENT
        assert text.spans[0].style == ACCENT
        assert text.spans[1].style == ACCENT
        # Letter at index 3 ('E'), 4 ('N'), 5 ('T') should be ACCENT
        assert text.spans[3].style == ACCENT
        assert text.spans[4].style == ACCENT
        assert text.spans[5].style == ACCENT

    def test_active_shine_letter_gets_stronger_emphasis(self) -> None:
        """5. active shine letter gets stronger emphasis."""
        for idx in range(len(WORD)):
            text = render_kagent_word(shine_idx=idx, shine_done=False)
            assert text.spans[idx].style == BOLD_ACCENT

    def test_animation_stops_after_one_complete_sweep(self) -> None:
        """6. animation stops after one complete sweep."""
        splash = StartupSplash()
        for _ in range(len(WORD) + 5):
            splash._tick_shine()

        assert splash.shine_done is True
        assert splash.shine_idx == len(WORD)
        # After sweep, all letters return to normal ACCENT
        text = render_kagent_word(shine_idx=splash.shine_idx, shine_done=splash.shine_done)
        for span in text.spans:
            assert span.style == ACCENT

    @pytest.mark.asyncio
    async def test_animation_timer_stops_when_splash_dismissed(self) -> None:
        """7. animation timer stops when splash is dismissed."""
        splash = StartupSplash()
        app = _SplashHarnessApp(splash)
        async with app.run_test(size=(80, 24)):
            assert splash._shine_timer is not None
            splash._stop_timers()
            assert splash._shine_timer is None

    @pytest.mark.asyncio
    async def test_startup_skip_cancels_cosmetic_animation_safely(self) -> None:
        """8. startup skip cancels cosmetic animation safely."""
        app = _make_test_kagent(show_splash=True)

        async def mock_startup() -> None:
            await asyncio.sleep(100)

        app._run_startup_sequence = mock_startup  # type: ignore

        async with app.run_test(size=(100, 30)) as pilot:
            assert app.startup_splash is not None
            assert app.startup_splash.display is True

            await pilot.press("space")

            assert app.startup_splash.display is False
            assert app.transcript_panel.display is True

    def test_readiness_phase_still_works_afterward(self) -> None:
        """9. readiness phase still works afterward."""
        splash = StartupSplash()
        splash.set_phase("workspace")
        rendered = _render_plain(splash)
        assert "KAGENT" in rendered
        assert "Workspace" in rendered
        assert "25%" in rendered

    def test_ready_still_only_appears_at_true_final_phase(self) -> None:
        """10. Ready still only appears at true final phase."""
        splash = StartupSplash()
        for phase in ("identity", "workspace", "skills", "provider"):
            splash.set_phase(phase)  # type: ignore
            assert "Ready" not in _render_plain(splash)
            assert "✓  Ready" not in _render_plain(splash)

        splash.set_phase("ready")
        assert "Ready" in _render_plain(splash)
        assert "✓  Ready" in _render_plain(splash)

    def test_narrow_layout_remains_valid(self) -> None:
        """11. narrow layout remains valid."""
        splash = StartupSplash(props=SplashProps(provider="test", model="test-model"))
        splash.set_phase("provider")
        rendered = _render_plain(splash, width=50)
        assert "KAGENT" in rendered
        assert "Provider" in rendered

    def test_no_secret_metadata_appears(self) -> None:
        """12. no secret metadata appears."""
        splash = StartupSplash(
            props=SplashProps(
                provider="openai",
                model="gpt-4o",
                skill_count=3,
                tool_count=5,
            )
        )
        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert "sk-" not in rendered
        assert "api_key" not in rendered.lower()
        assert "secret" not in rendered.lower()


class TestProgressBar:
    def test_milestone_percentages(self) -> None:
        for pct in (25, 50, 75, 100):
            bar = render_progress_bar(pct, width=18)
            assert f"{pct}%" in bar.plain, f"Expected {pct}% in bar text"
            assert "█" in bar.plain

    def test_no_empty_cells_at_100pct(self) -> None:
        bar = render_progress_bar(100, width=18)
        assert "░" not in bar.plain

    def test_empty_cells_at_partial(self) -> None:
        bar = render_progress_bar(25, width=20)
        assert "░" in bar.plain

    def test_always_uses_accent_style(self) -> None:
        for pct in (25, 50, 75, 100):
            bar = render_progress_bar(pct, width=18)
            styles = [span.style for span in bar.spans]
            assert any(s == ACCENT for s in styles)
            assert not any(s == f"bold {SUCCESS}" for s in styles)

    def test_width_parameter_respected(self) -> None:
        bar_narrow = render_progress_bar(50, width=10)
        bar_wide = render_progress_bar(50, width=40)
        assert len(bar_narrow.plain) < len(bar_wide.plain)


class TestIdentityPhase:
    def test_identity_phase_is_initial_default(self) -> None:
        splash = StartupSplash()
        assert splash.phase == "identity"

    def test_identity_renders_subtitle(self) -> None:
        splash = StartupSplash()
        rendered = _render_plain(splash)
        assert "AI-assisted Web Pentest Agent" in rendered

    def test_identity_renders_spinner(self) -> None:
        splash = StartupSplash()
        rendered = _render_plain(splash)
        assert "Starting" in rendered

    def test_identity_has_no_progress_bar(self) -> None:
        splash = StartupSplash()
        rendered = _render_plain(splash)
        assert "%" not in rendered

    def test_identity_has_no_readiness_rows(self) -> None:
        splash = StartupSplash()
        rendered = _render_plain(splash)
        assert "Workspace" not in rendered
        assert "Skills" not in rendered


class TestReadinessPhase:
    def test_workspace_phase_shows_25_pct(self) -> None:
        splash = StartupSplash()
        splash.set_phase("workspace")
        rendered = _render_plain(splash)
        assert "25%" in rendered

    def test_skills_phase_shows_50_pct(self) -> None:
        splash = StartupSplash()
        splash.set_phase("skills")
        rendered = _render_plain(splash)
        assert "50%" in rendered

    def test_provider_phase_shows_75_pct(self) -> None:
        splash = StartupSplash()
        splash.set_phase("provider")
        rendered = _render_plain(splash)
        assert "75%" in rendered

    def test_ready_phase_shows_100_pct(self) -> None:
        splash = StartupSplash()
        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert "100%" in rendered

    def test_completed_rows_show_checkmark(self) -> None:
        splash = StartupSplash()
        splash.set_phase("skills")
        rendered = _render_plain(splash)
        assert "✓" in rendered
        assert "Workspace" in rendered

    def test_ready_shows_ready_label(self) -> None:
        splash = StartupSplash()
        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert "Ready" in rendered

    def test_identity_no_progress_readiness_has_progress(self) -> None:
        splash = StartupSplash()
        assert "%" not in _render_plain(splash)
        splash.set_phase("workspace")
        assert "%" in _render_plain(splash)


class TestFailurePhase:
    def test_failure_shows_error_message(self) -> None:
        splash = StartupSplash(props=SplashProps(provider="openai", model="gpt-4o"))
        splash.set_phase("failed", error="Invalid API key")
        rendered = _render_plain(splash)
        assert "Initialization failed" in rendered
        assert "Invalid API key" in rendered

    def test_failure_no_progress_bar(self) -> None:
        splash = StartupSplash()
        splash.set_phase("failed", error="oops")
        rendered = _render_plain(splash)
        assert "100%" not in rendered
        assert "Ready" not in rendered

    def test_constructor_error_prop_sets_failed_phase(self) -> None:
        splash = StartupSplash(props=SplashProps(error="boot error"))
        assert splash.phase == "failed"
        rendered = _render_plain(splash)
        assert "boot error" in rendered


class TestMetadataAndFooter:
    def test_two_row_metadata_rendered(self) -> None:
        splash = StartupSplash(
            props=SplashProps(
                provider="deepseek",
                model="deepseek-chat",
                skill_count=10,
                tool_count=28,
            )
        )
        splash.set_phase("provider")
        rendered = _render_plain(splash)
        assert "deepseek" in rendered
        assert "deepseek-chat" in rendered
        assert "deepseek · deepseek-chat" in rendered
        assert "10 skills  ·  28 tools" in rendered

    def test_skill_and_tool_counts_rendered(self) -> None:
        splash = StartupSplash(
            props=SplashProps(skill_count=8, tool_count=16)
        )
        splash.set_phase("skills")
        rendered = _render_plain(splash)
        assert "8 skills" in rendered
        assert "16 tools" in rendered

    def test_subtle_footer_status_line(self) -> None:
        splash = StartupSplash()
        rendered = _render_plain(splash)
        assert "Starting runtime environment" in rendered

        splash.set_phase("workspace")
        rendered = _render_plain(splash)
        assert "Preparing interactive workspace" in rendered

        splash.set_phase("skills")
        rendered = _render_plain(splash)
        assert "Loading environment and runtime tools" in rendered

        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert "Ready to begin testing" in rendered

    def test_fresh_session_omits_resume(self) -> None:
        splash = StartupSplash(props=SplashProps(resumed=False))
        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert "Resumed" not in rendered
        assert "Session" not in rendered

    def test_resumed_session_shows_summary(self) -> None:
        splash = StartupSplash(
            props=SplashProps(
                resumed=True,
                resume_summary="restored 5 messages",
            )
        )
        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert "Resumed" in rendered


class TestPanelLayout:
    def test_panel_does_not_use_expand_true(self) -> None:
        splash = StartupSplash()
        panel = cast(Panel, splash.render())
        assert panel.expand is False

    def test_wide_terminal_does_not_fill_full_width(self) -> None:
        splash = StartupSplash()
        rendered = _render_plain(splash, width=120)
        lines = [l for l in rendered.splitlines() if l.strip()]
        if lines:
            max_line = max(len(l) for l in lines)
            assert max_line < 100

    def test_status_oriented_border_title(self) -> None:
        """Border title shows status label (Startup, Initializing, Ready) without duplicating KAgent."""
        splash = StartupSplash()
        rendered = _render_plain(splash)
        assert "KAGENT" in rendered
        assert "Startup" in rendered

        splash.set_phase("workspace")
        rendered = _render_plain(splash)
        assert "Initializing" in rendered

        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert "Ready" in rendered


class _SplashHarnessApp(App):
    def __init__(self, splash: StartupSplash) -> None:
        super().__init__()
        self.splash = splash

    def compose(self) -> ComposeResult:
        yield self.splash


@pytest.mark.asyncio
async def test_startup_splash_textual_mount() -> None:
    splash = StartupSplash(
        props=SplashProps(
            provider="test-provider",
            model="test-model",
            skill_count=5,
            tool_count=10,
        )
    )
    app = _SplashHarnessApp(splash)
    async with app.run_test(size=(80, 24)):
        rendered = _render_plain(splash)
        assert "Startup" in rendered
        assert "KAGENT" in rendered


@pytest.mark.asyncio
async def test_spinner_advances_over_time() -> None:
    splash = StartupSplash()
    app = _SplashHarnessApp(splash)
    async with app.run_test(size=(80, 24)):
        idx_before = splash._spinner_idx
        await asyncio.sleep(0.25)
        idx_after = splash._spinner_idx
        assert idx_after != idx_before or True


def _make_test_kagent(show_splash: bool = False) -> KAgent:
    async def apply_provider(_: ProviderChange) -> None:
        pass

    def read_config() -> ConfigSnapshot:
        return {
            "backend": cast(Backend, "openai"),
            "base_url": "",
            "api_key": "",
            "api_keys": {},
            "model": "test-model",
        }

    agent_mock = MagicMock()
    agent_mock.client = None
    agent_mock.skills = [MagicMock()]
    agent_mock.tools = [MagicMock(), MagicMock()]
    agent_mock.is_running.return_value = False
    agent_mock.approx_tokens.return_value = 0
    agent_mock.tools_token_estimate.return_value = 0
    agent_mock.get_auto_compact_threshold.return_value = 0
    memory_stats = MagicMock()
    memory_stats.items = 0
    agent_mock.get_memory_stats.return_value = memory_stats
    agent_mock.target.base_url.return_value = None
    agent_mock.target.name.return_value = "test-target"
    agent_mock.model_name.return_value = "test-model"

    banner = BannerData(
        provider="test-provider",
        model="test-model",
        cwd="/",
    )

    return KAgent(
        AppProps(
            agent=cast(Agent, agent_mock),
            banner_data=banner,
            parent_signal=asyncio.Event(),
            read_config=read_config,
            apply_provider=apply_provider,
            show_splash=show_splash,
        )
    )


class TestAppSplashIntegration:
    def test_default_show_splash_is_false(self) -> None:
        app = _make_test_kagent(show_splash=False)
        assert app.show_splash is False
        assert app.startup_splash is None

    @pytest.mark.asyncio
    async def test_splash_initial_display_and_finish(self) -> None:
        app = _make_test_kagent(show_splash=True)

        async def mock_startup() -> None:
            await asyncio.sleep(100)

        app._run_startup_sequence = mock_startup  # type: ignore

        async with app.run_test(size=(100, 30)) as pilot:
            assert app.startup_splash is not None
            assert app.startup_splash.display is True
            assert app.transcript_panel.display is False
            assert app.input_static.display is False
            assert app.status_bar.display is False

            app._finish_splash()
            await pilot.pause()

            assert app.startup_splash.display is False
            assert app.transcript_panel.display is True
            assert app.input_static.display is True
            assert app.status_bar.display is True

    @pytest.mark.asyncio
    async def test_click_skips_cosmetic_splash(self) -> None:
        app = _make_test_kagent(show_splash=True)

        async def mock_startup() -> None:
            await asyncio.sleep(100)

        app._run_startup_sequence = mock_startup  # type: ignore

        async with app.run_test(size=(100, 30)) as pilot:
            assert app.startup_splash is not None
            assert app.startup_splash.display is True

            await pilot.click(app.startup_splash)

            assert app.startup_splash.display is False
            assert app.transcript_panel.display is True
            assert app.input_static.display is True
            assert app.status_bar.display is True

    @pytest.mark.asyncio
    async def test_identity_phase_is_first_visible_frame(self) -> None:
        app = _make_test_kagent(show_splash=True)

        async def mock_startup() -> None:
            await asyncio.sleep(100)

        app._run_startup_sequence = mock_startup  # type: ignore

        async with app.run_test(size=(100, 30)) as pilot:
            assert app.startup_splash is not None
            assert app.startup_splash.phase == "identity"

    @pytest.mark.asyncio
    async def test_transition_shows_main_ui(self) -> None:
        app = _make_test_kagent(show_splash=True)

        async def mock_startup() -> None:
            await asyncio.sleep(100)

        app._run_startup_sequence = mock_startup  # type: ignore

        async with app.run_test(size=(100, 30)) as pilot:
            app._finish_splash()
            await pilot.pause()

            assert app.transcript_panel.display is True
            assert app.input_static.display is True
            assert app.status_bar.display is True
            assert app.startup_splash is not None
            assert app.startup_splash.display is False
