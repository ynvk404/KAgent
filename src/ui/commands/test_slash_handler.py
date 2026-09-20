from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import cast
import pytest
from src.agent.agent import Agent
from src.ui.core.app import KAgent, RunAgentOptions
from src.ui.commands.slash_handler import build_help_text, handle_slash
from src.ui.commands.slash_items import SLASH_ITEMS
from src.ui.core.app import KAgent
from src.ui.core.state import Append, Clear


@dataclass(slots=True)
class DummyState:
    yolo: bool = False


@dataclass(slots=True)
class DummyTarget:
    value: str = ""

    def base_url(self) -> str:
        return self.value

    def set_base_url(self, url: str) -> None:
        self.value = url

    def clear(self) -> None:
        self.value = ""


@dataclass(slots=True)
class DummyAgent:
    max_steps: int = 20
    thinking: bool = False
    target: DummyTarget = field(default_factory=DummyTarget)
    sys_prompt: str = ""
    history: list = field(default_factory=list)
    reset_calls: int = 0

    def get_max_steps(self) -> int:
        return self.max_steps

    def set_max_steps(self, n: int) -> None:
        self.max_steps = n

    def thinking_is_enabled(self) -> bool:
        return self.thinking

    def is_running(self) -> bool:
        return False

    async def set_thinking_enabled(self, enabled: bool) -> None:
        self.thinking = enabled

    async def set_target_base_url(self, url: str) -> None:
        self.target.set_base_url(url)

    async def clear_target(self) -> None:
        self.target.clear()

    async def coverage_context(self, signal) -> str:
        return "coverage fixture"

    def rebuild_system_prompt(self) -> None:
        # Mirrors the real agent's contract: rebuild_system_prompt() runs
        # synchronously and refreshes sys_prompt from current target state.
        # slash_handler.py reads/writes agent.history and agent.sys_prompt
        # right after calling this (via
        # ensure_system_prompt(agent.history, agent.sys_prompt)), so both
        # fields must exist on the dummy, not just this method.
        self.sys_prompt = f"system prompt (target={self.target.base_url()!r})"

    async def save(self) -> None:
        # slash_handler.py's /target branch persists to disk via
        # `await agent.save()` in a background task after
        # rebuild_system_prompt(), and swallows any exception into a
        # "target save failed ..." transcript message. Without this method
        # the dummy raises AttributeError there, which silently overwrites
        # the "target set to ..." / "target cleared ..." message the tests
        # assert on. No-op is sufficient — tests don't assert persistence.
        pass

    async def reset(self) -> None:
        self.reset_calls += 1


@dataclass(slots=True)
class HelpSkills:
    def list_enabled(self) -> list[str]:
        return ["web", "auth"]

    def list(self) -> list[str]:
        return ["web", "auth", "burp"]


@dataclass(slots=True)
class HelpMemory:
    items: int = 4
    compactions: int = 1


@dataclass(slots=True)
class HelpClient:
    def model(self) -> str:
        return "fallback-model"


@dataclass(slots=True)
class HelpAgent:
    skills: HelpSkills = field(default_factory=HelpSkills)
    target: DummyTarget = field(default_factory=lambda: DummyTarget("https://lab.test"))
    client: HelpClient = field(default_factory=HelpClient)

    def get_memory_stats(self) -> HelpMemory:
        return HelpMemory()

    def get_max_steps(self) -> int:
        return 20

    def get_auto_compact_threshold(self) -> int:
        return 8_000

    def thinking_is_enabled(self) -> bool:
        return True


@dataclass(slots=True)
class DummyApp:
    agent: DummyAgent = field(default_factory=DummyAgent)
    state: DummyState = field(default_factory=DummyState)
    actions: list[object] = field(default_factory=list)
    turns: list[tuple[str, RunAgentOptions | None]] = field(default_factory=list)
    def dispatch(self, action: object) -> None:
        self.actions.append(action)

    def apply_yolo(self, on: bool) -> None:
        self.state.yolo = on

    async def run_agent_turn(self, value: str, opts=None) -> None:
        self.turns.append((value, opts))


def last_text(app: DummyApp) -> str:
    action = app.actions[-1]
    assert isinstance(action, Append)
    return action.entry.text


def test_normal_clear_is_not_a_slash_command():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "clear") is False
    assert app.actions == []


def test_clear_only_requests_transcript_replacement_and_preserves_agent_state():
    app = DummyApp()
    app.agent.history = ["existing conversation"]
    app.agent.target.set_base_url("https://lab.test")

    assert handle_slash(cast(KAgent, app), "/clear")

    assert app.actions == [Clear()]
    assert app.agent.history == ["existing conversation"]
    assert app.agent.target.base_url() == "https://lab.test"


@pytest.mark.asyncio
async def test_reset_keeps_reset_invocation_and_replaces_the_transcript_with_a_status_line():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/reset")
    await asyncio.sleep(0)

    assert app.agent.reset_calls == 1
    assert app.actions == [Clear(message="conversation reset")]


def test_help_groups_commands_and_keeps_runtime_summary_compact():
    text = build_help_text(
        cast(Agent, HelpAgent()),
        lambda: {"backend": "openrouter", "model": "configured-model"},
    )

    assert "Session" in text
    assert "provider   openrouter" in text
    assert "model      configured-model" in text
    assert "target     https://lab.test" in text
    assert "skills     2/3 enabled" in text
    assert "Everyday" in text
    assert "Workflow" in text
    assert "Advanced" in text
    assert "Installed skills" in text
    assert "/exit (/quit)" in text
    assert "/burp [port|stop|status]" in text
    assert "/memory [add <text>|list|forget <text>|clear|intel]  manage saved/session memory" in text
    assert "/model <id|list>" in text
    assert "/skills [<name>|enable|disable <name>|new <name>]    list, toggle, or create skills" in text
    assert "/ then Tab" in text
    assert "browser_capture_*" not in text
    assert "coverage(action=" not in text
    for item in SLASH_ITEMS:
        assert item.name in text


def test_maxsteps_without_argument_shows_current_value():
    app = DummyApp()
    app.agent.set_max_steps(10)

    assert handle_slash(cast(KAgent, app), "/maxsteps")

    assert last_text(app) == "max steps currently 10"
    assert app.agent.get_max_steps() == 10


def test_maxsteps_sets_value():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/maxsteps 10")

    assert app.agent.get_max_steps() == 10
    assert last_text(app) == "max steps set to 10"


def test_maxsteps_default_resets_to_agent_default():
    app = DummyApp()
    app.agent.set_max_steps(10)

    assert handle_slash(cast(KAgent, app), "/maxsteps default")

    assert app.agent.get_max_steps() == 20
    assert last_text(app) == "max steps reset to default (20)"


def test_maxsteps_invalid_argument_shows_usage():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/maxsteps abc")

    assert app.agent.get_max_steps() == 20
    assert last_text(app) == "usage: /maxsteps <n|default>"


def test_thinking_without_argument_shows_current_state():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/thinking")

    assert last_text(app) == "thinking currently off"
    assert not app.agent.thinking_is_enabled()


def test_thinking_on_enables_reasoning_mode():
    async def run() -> None:
        app = DummyApp()

        assert handle_slash(cast(KAgent, app), "/thinking on")
        await asyncio.sleep(0)

        assert app.agent.thinking_is_enabled()
        assert last_text(app) == "thinking enabled"

    asyncio.run(run())


def test_thinking_off_disables_reasoning_mode():
    async def run() -> None:
        app = DummyApp()
        app.agent.thinking = True

        assert handle_slash(cast(KAgent, app), "/thinking off")
        await asyncio.sleep(0)

        assert not app.agent.thinking_is_enabled()
        assert last_text(app) == "thinking disabled"

    asyncio.run(run())


def test_thinking_default_resets_to_off():
    async def run() -> None:
        app = DummyApp()
        app.agent.thinking = True

        assert handle_slash(cast(KAgent, app), "/thinking default")
        await asyncio.sleep(0)

        assert not app.agent.thinking_is_enabled()
        assert last_text(app) == "thinking reset to default (off)"

    asyncio.run(run())


def test_thinking_invalid_argument_shows_usage():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/thinking abc")

    assert not app.agent.thinking_is_enabled()
    assert last_text(app) == "usage: /thinking <on|off|default>"


def test_yolo_without_argument_shows_current_state():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/yolo")

    assert last_text(app) == "yolo currently off"
    assert not app.state.yolo
    assert len(app.actions) == 1


def test_yolo_on_enables_auto_approve():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/yolo on")

    assert app.state.yolo
    assert (
        last_text(app)
        == "YOLO enabled. Tool calls will be auto-approved. Authorized / lab targets only."
    )
    assert len(app.actions) == 1


def test_yolo_off_disables_auto_approve():
    app = DummyApp()
    app.state.yolo = True

    assert handle_slash(cast(KAgent, app), "/yolo off")

    assert not app.state.yolo
    assert last_text(app) == "YOLO disabled. Tool calls will prompt for confirmation."
    assert len(app.actions) == 1


def test_yolo_default_resets_to_off():
    app = DummyApp()
    app.state.yolo = True

    assert handle_slash(cast(KAgent, app), "/yolo default")

    assert not app.state.yolo
    assert last_text(app) == "YOLO reset to default (off)"
    assert len(app.actions) == 1


def test_yolo_invalid_argument_shows_usage():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/yolo abc")

    assert not app.state.yolo
    assert last_text(app) == "usage: /yolo <on|off|default>"
    assert len(app.actions) == 1


def test_target_without_argument_shows_current_target():
    app = DummyApp()
    app.agent.target.set_base_url("http://localhost:3000")

    assert handle_slash(cast(KAgent, app), "/target")

    assert last_text(app) == "target currently: http://localhost:3000"


def test_target_without_argument_reports_no_target():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/target")

    assert last_text(app) == "no target configured"


def test_target_url_sets_target():
    async def run() -> None:
        app = DummyApp()

        assert handle_slash(cast(KAgent, app), "/target http://google.com")
        assert app.agent.target.base_url() == "http://google.com"
        assert last_text(app) == "target set to http://google.com"
        await asyncio.sleep(0)

        assert app.agent.target.base_url() == "http://google.com"
        assert last_text(app) == "target set to http://google.com"

    asyncio.run(run())


def test_target_domain_without_scheme_adds_http():
    async def run() -> None:
        app = DummyApp()

        assert handle_slash(cast(KAgent, app), "/target google.com")
        assert app.agent.target.base_url() == "http://google.com"
        assert last_text(app) == "target set to http://google.com"
        await asyncio.sleep(0)

        assert app.agent.target.base_url() == "http://google.com"
        assert last_text(app) == "target set to http://google.com"

    asyncio.run(run())


def test_target_ip_with_port_without_scheme_adds_http():
    async def run() -> None:
        app = DummyApp()

        assert handle_slash(cast(KAgent, app), "/target 192.168.1.10:3000")
        assert app.agent.target.base_url() == "http://192.168.1.10:3000"
        assert last_text(app) == "target set to http://192.168.1.10:3000"
        await asyncio.sleep(0)

        assert app.agent.target.base_url() == "http://192.168.1.10:3000"
        assert last_text(app) == "target set to http://192.168.1.10:3000"

    asyncio.run(run())


def test_target_clear_removes_target():
    async def run() -> None:
        app = DummyApp()
        app.agent.target.set_base_url("http://localhost:3000")

        assert handle_slash(cast(KAgent, app), "/target clear")
        assert app.agent.target.base_url() == ""
        assert last_text(app) == "target cleared (no target configured)"
        await asyncio.sleep(0)

        assert app.agent.target.base_url() == ""
        assert last_text(app) == "target cleared (no target configured)"

    asyncio.run(run())


def test_target_invalid_input_shows_usage():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/target abc?")

    assert app.agent.target.base_url() == ""
    assert last_text(app) == "usage: /target <url|clear>"


def test_plan_turn_disables_agent_tools():
    async def run() -> None:
        app = DummyApp()

        assert handle_slash(cast(KAgent, app), "/plan fix auth flow")
        await asyncio.sleep(0)

        assert len(app.turns) == 1
        prompt, opts = app.turns[0]
        assert "Plan this objective:" in prompt
        assert "fix auth flow" in prompt
        assert opts is not None
        assert opts.transcript_user_text == "/plan fix auth flow"
        assert opts.system_text == "planning only — tools disabled"
        assert opts.run_options is not None
        assert opts.run_options.tools is False

    asyncio.run(run())


def test_next_turn_disables_agent_tools():
    async def run() -> None:
        app = DummyApp()

        assert handle_slash(cast(KAgent, app), "/next test checkout")
        await asyncio.sleep(0)

        assert len(app.turns) == 1
        prompt, opts = app.turns[0]
        assert "Objective for next steps:" in prompt
        assert "coverage fixture" in prompt
        assert opts is not None
        assert opts.transcript_user_text == "/next test checkout"
        assert opts.system_text == "coverage-driven next steps — tools disabled"
        assert opts.run_options is not None
        assert opts.run_options.tools is False

    asyncio.run(run())
