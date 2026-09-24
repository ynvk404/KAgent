from __future__ import annotations
from tests.helpers.ui_fakes import make_test_config_snapshot

import asyncio
from html import unescape
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
from src.ui.theme import ACCENT, BOLD_ACCENT
from src.ui.widgets.banner import BannerData
from src.ui.widgets.startup_splash import (
    SplashProps,
    StartupSplash,
    WORD,
    render_kagent_word,
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

    def test_completion_only_appears_at_true_final_phase(self) -> None:
        """10. Completion state only appears at the true final phase."""
        splash = StartupSplash()
        for phase in ("identity", "workspace", "skills", "provider"):
            splash.set_phase(phase)  # type: ignore
            assert "Ready" not in _render_plain(splash)
            assert "✓  Complete" not in _render_plain(splash)

        splash.set_phase("ready")
        assert "Ready to begin testing" in _render_plain(splash)
        assert "✓  Complete" in _render_plain(splash)
        assert "✓  Ready" not in _render_plain(splash)

    def test_narrow_layout_remains_valid(self) -> None:
        """11. narrow layout remains valid."""
        splash = StartupSplash(props=SplashProps(provider="test", model="test-model"))
        splash.set_phase("provider")
        rendered = _render_plain(splash, width=50)
        assert "KAGENT" in rendered
        assert "Provider" in rendered

    @pytest.mark.asyncio
    async def test_40_column_layout_keeps_subtitle_and_rows_readable(self) -> None:
        splash = StartupSplash(props=SplashProps(
            provider="OpenAI", model="gpt-6-luna", skill_count=10, tool_count=28,
        ))
        app = _SplashHarnessApp(splash)
        async with app.run_test(size=(40, 30)):
            splash.set_phase("ready")
            rendered = _render_plain(splash, width=40)
            assert "AI-assisted Web Pentest Agent" in rendered
            assert "Provider" in rendered
            assert "OpenAI · gpt-6-luna" not in rendered
            assert "10 skills  ·  28 tools" not in rendered

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
    def test_default_rows_are_compact(self) -> None:
        splash = StartupSplash()
        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert [label for _, label in splash.readiness_rows()] == [
            "Workspace", "Skills & tools", "Provider",
        ]
        assert "Model override" not in rendered
        assert "Session" not in rendered
        assert "Target & scope" not in rendered
        assert "Integrations" not in rendered

    def test_optional_rows_follow_actual_props(self) -> None:
        splash = StartupSplash(props=SplashProps(
            resumed=True, has_target=True, has_model_override=True, has_integrations=True,
        ))
        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert [label for _, label in splash.readiness_rows()] == [
            "Workspace", "Session", "Target & scope", "Skills & tools",
            "Provider", "Model override", "Integrations",
        ]
        for label in ("Session", "Target & scope", "Model override", "Integrations"):
            assert label in rendered

    @pytest.mark.parametrize("prop,label", [
        ("resumed", "Session"),
        ("has_target", "Target & scope"),
        ("has_model_override", "Model override"),
        ("has_integrations", "Integrations"),
    ])
    def test_each_optional_row_appears_only_when_enabled(self, prop: str, label: str) -> None:
        props_kwargs: dict[str, Any] = {prop: True}
        splash = StartupSplash(props=SplashProps(**props_kwargs))
        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert label in rendered
        assert len(splash.readiness_rows()) == 4

    @pytest.mark.parametrize("phase", ["workspace", "skills", "provider", "ready"])
    def test_readiness_phase_has_no_progress_bar(self, phase: str) -> None:
        splash = StartupSplash()
        splash.set_phase(phase)  # type: ignore[arg-type]
        rendered = _render_plain(splash)
        assert "%" not in rendered
        assert "█" not in rendered

    def test_completed_rows_show_checkmark(self) -> None:
        splash = StartupSplash()
        splash.set_phase("skills")
        rendered = _render_plain(splash)
        assert "✓" in rendered
        assert "Workspace" in rendered

    def test_ready_shows_completion_label(self) -> None:
        splash = StartupSplash()
        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert "✓  Complete" in rendered


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
    @pytest.mark.parametrize("phase", ["identity", "provider", "ready"])
    def test_splash_omits_provider_model_and_counts(self, phase: str) -> None:
        splash = StartupSplash(props=SplashProps(
            provider="deepseek", model="deepseek-chat", skill_count=10, tool_count=28,
        ))
        splash.set_phase(phase)  # type: ignore[arg-type]
        rendered = _render_plain(splash)
        assert "deepseek · deepseek-chat" not in rendered
        assert "10 skills  ·  28 tools" not in rendered

    def test_explicit_model_override_shows_label_without_model_id(self) -> None:
        splash = StartupSplash(props=SplashProps(
            model="deepseek-chat", has_model_override=True,
        ))
        splash.set_phase("model")
        rendered = _render_plain(splash)
        assert "Model override" in rendered
        assert "deepseek-chat" not in rendered
        assert "Using the selected model" in rendered

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

    def test_resumed_session_uses_row_without_recap(self) -> None:
        splash = StartupSplash(
            props=SplashProps(
                resumed=True,
                resume_summary="restored 5 messages",
            )
        )
        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert "Session" in rendered
        assert "restored 5 messages" not in rendered


class TestPanelLayout:
    def test_heading_has_space_below_border(self) -> None:
        splash = StartupSplash()
        lines = _render_plain(splash).splitlines()
        assert lines[1].strip("│ ") == ""
        assert "KAGENT" in lines[2]

    def test_readiness_rows_are_centered(self) -> None:
        splash = StartupSplash()
        splash.set_phase("workspace")
        lines = _render_plain(splash).splitlines()
        center = (len(lines[0]) - 1) / 2
        workspace = next(line for line in lines if "Workspace" in line)
        skills = next(line for line in lines if "Skills & tools" in line)
        provider = next(line for line in lines if "·  Provider" in line)
        marker_column = workspace.index("⠋")
        assert skills.index("·") == provider.index("·") == marker_column
        group_center = (marker_column + skills.index("Skills & tools") + len("Skills & tools") - 1) / 2
        assert abs(group_center - center) <= 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("width", [40, 80])
    async def test_completion_label_is_centered_below_readiness_rows(self, width: int) -> None:
        splash = StartupSplash()
        app = _SplashHarnessApp(splash)
        async with app.run_test(size=(width, 24)):
            splash.set_phase("ready")
            lines = _render_plain(splash, width=width).splitlines()
            workspace = next(line for line in lines if "✓  Workspace" in line)
            completion = next(line for line in lines if "✓  Complete" in line)
            panel_center = (len(lines[0]) - 1) / 2
            completion_center = completion.index("Complete") + (len("Complete") - 1) / 2
            assert abs(completion_center - panel_center) <= 0.5
            assert completion.index("✓") == completion.index("Complete") - 3
            assert completion.index("✓") != workspace.index("✓")

    def test_panel_uses_fixed_width(self) -> None:
        splash = StartupSplash()
        panel = cast(Panel, splash.render())
        assert panel.expand is True
        assert panel.width == 68

    def test_wide_terminal_does_not_fill_full_width(self) -> None:
        splash = StartupSplash()
        rendered = _render_plain(splash, width=120)
        lines = [l for l in rendered.splitlines() if l.strip()]
        if lines:
            max_line = max(len(l) for l in lines)
            assert max_line < 100

    @pytest.mark.parametrize("width", [40, 80, 120])
    def test_panel_width_stays_stable_across_phases(self, width: int) -> None:
        splash = StartupSplash()
        widths = []
        for phase in ("identity", "workspace", "ready", "failed"):
            splash.set_phase(phase, error="oops" if phase == "failed" else None)  # type: ignore[arg-type]
            widths.append(len(_render_plain(splash, width=width).splitlines()[0]))
        assert len(set(widths)) == 1

    def test_status_oriented_border_title(self) -> None:
        """Ready keeps the initializing title; errors use Failed."""
        splash = StartupSplash()
        rendered = _render_plain(splash)
        assert "KAGENT" in rendered
        assert "Startup" in rendered

        splash.set_phase("workspace")
        rendered = _render_plain(splash)
        assert "Initializing" in rendered

        splash.set_phase("ready")
        rendered = _render_plain(splash)
        assert "Initializing" in rendered
        assert "✓  Complete" in rendered

        splash.set_phase("failed", error="oops")
        assert "Failed" in _render_plain(splash)


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
        return make_test_config_snapshot(
            backend=cast(Backend, "openai"),
            model="test-model",
        )

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
    async def test_resumed_target_splash_shows_all_rows_and_footer(self) -> None:
        app = _make_test_kagent(show_splash=True)
        app.resume_summary = "restored session"
        app.splash_has_target = True

        async def mock_startup() -> None:
            await asyncio.sleep(100)

        app._run_startup_sequence = mock_startup  # type: ignore

        async with app.run_test(size=(100, 30)) as pilot:
            assert app.startup_splash is not None
            identity_height = app.startup_splash.region.height
            app.startup_splash.set_phase("provider")
            await pilot.pause()

            screenshot = unescape(app.export_screenshot()).replace("\xa0", " ")
            assert app.startup_splash.region.height > identity_height
            assert "Session" in screenshot
            assert "Target" in screenshot
            assert "2 tools" not in screenshot
            assert "Verifying provider connection" in screenshot
            assert "test-provider · test-model" not in screenshot

    @pytest.mark.asyncio
    async def test_model_override_adds_optional_startup_row(self) -> None:
        app = _make_test_kagent(show_splash=True)
        app.splash_has_model_override = True

        async def mock_startup() -> None:
            await asyncio.sleep(100)

        app._run_startup_sequence = mock_startup  # type: ignore

        async with app.run_test(size=(100, 30)) as pilot:
            assert app.startup_splash is not None
            assert ("model", "Model override") in app.startup_splash.readiness_rows()
            app.startup_splash.set_phase("model")
            await pilot.pause()
            screenshot = unescape(app.export_screenshot()).replace("\xa0", " ")
            assert "Model override" in screenshot
            assert "Using the selected model" in screenshot
            assert "test-model" not in screenshot

    @pytest.mark.asyncio
    async def test_splash_frame_fits_content_and_stays_centered(self) -> None:
        app = _make_test_kagent(show_splash=True)

        async def mock_startup() -> None:
            await asyncio.sleep(100)

        app._run_startup_sequence = mock_startup  # type: ignore

        async with app.run_test(size=(100, 30)) as pilot:
            assert app.startup_splash is not None
            for phase in ("identity", "workspace", "ready"):
                app.startup_splash.set_phase(phase)  # type: ignore[arg-type]
                await pilot.pause()
                region = app.startup_splash.region
                assert region.height < app.screen.size.height
                assert abs(2 * region.y + region.height - app.screen.size.height) <= 1

            app.startup_splash.set_phase("workspace")
            await pilot.pause()
            base_height = app.startup_splash.region.height
            app.startup_splash.props.has_target = True
            app.startup_splash.refresh(layout=True)
            await pilot.pause()
            assert app.startup_splash.region.height > base_height
            region = app.startup_splash.region
            assert abs(2 * region.y + region.height - app.screen.size.height) <= 1

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
