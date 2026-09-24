from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import cast
import pytest
from src.agent.agent import Agent
from src.config.config import Backend, Config, add_custom_provider, resolve_custom_provider
from src.llm.factory import new_from_config
from src.llm.provider_runtime import build_startup_runtime, switch_provider_transactionally
from src.ui.core.app import KAgent, RunAgentOptions
from src.ui.commands.slash_handler import build_help_text, handle_slash, _handle_model
from src.ui.commands.slash_items import SLASH_ITEMS
from src.ui.core.app import KAgent
from src.ui.core.state import Append, Clear
from src.engagement.state import EngagementState
from src.target.origin import HTTPOrigin


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

    def empty(self) -> bool:
        return not self.value

    def origin(self) -> HTTPOrigin | None:
        return HTTPOrigin.from_url(self.value) if self.value else None


@dataclass(slots=True)
class DummyAgent:
    max_steps: int = 20
    thinking: bool = False
    target: DummyTarget = field(default_factory=DummyTarget)
    sys_prompt: str = ""
    history: list = field(default_factory=list)
    reset_calls: int = 0
    permission_cache_clears: int = 0
    engagement_state: EngagementState = field(default_factory=EngagementState)

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

    def apply_target_base_url(self, url: str) -> None:
        current = self.target.origin()
        next_origin = HTTPOrigin.from_url(url)
        if current != next_origin:
            self.engagement_state.reset_to_origin(url)
            self.permission_cache_clears += 1
        else:
            self.engagement_state.add_origin(url)
        self.target.set_base_url(url)
        self.rebuild_system_prompt()

    def apply_target_clear(self) -> None:
        self.target.clear()
        self.engagement_state.clear()
        self.permission_cache_clears += 1
        self.rebuild_system_prompt()

    def add_scope_origin(self, url: str):
        origin, changed = self.engagement_state.add_origin(url)
        if changed:
            self.permission_cache_clears += 1
        return origin, changed

    def remove_scope_origin(self, url: str):
        origin = HTTPOrigin.from_url(url)
        if origin == self.target.origin():
            raise ValueError("cannot remove the active target origin")
        origin, changed = self.engagement_state.remove_origin(url)
        if changed:
            self.permission_cache_clears += 1
        return origin, changed

    def reset_scope_to_target(self):
        origin, changed = self.engagement_state.reset_to_origin(
            self.target.base_url()
        )
        if changed:
            self.permission_cache_clears += 1
        return origin, changed

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


def last_text(app: DummyApp | SimpleNamespace) -> str:
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
    assert "/ then Tab, Tab" in text
    assert "browser_capture_*" not in text
    assert "coverage(action=" not in text
    for item in SLASH_ITEMS:
        assert item.name in text


def _custom_model_app(*, fail_model: str | None = None):
    cfg = Config(
        backend=Backend.OPENAI_COMPAT,
        model="manual-model",
        base_url="http://localhost:1234/v1",
        api_keys={"openai-compat": "manual-key"},
    )
    profile_id = add_custom_provider(
        cfg,
        "Gateway",
        "https://gateway.example/v1",
        "custom-key",
        "old-model",
    )
    cfg.active_custom_provider_id = profile_id
    runtime, _ = resolve_custom_provider(cfg, profile_id)
    agent = SimpleNamespace(client=new_from_config(runtime))
    agent.set_client = lambda client: setattr(agent, "client", client)
    dispatches: list[object] = []
    saved: list[Config] = []

    def read_config():
        resolved, _profile = resolve_custom_provider(cfg, profile_id)
        return {
            "backend": cfg.backend,
            "model": cfg.model,
            "base_url": cfg.base_url,
            "api_key": cfg.api_key,
            "active_custom_provider_id": profile_id,
            "active_custom_provider_base_url": resolved.base_url,
            "active_custom_provider_api_key": resolved.api_key,
            "active_custom_provider_model": resolved.model,
        }

    async def save(candidate: Config) -> None:
        saved.append(copy.deepcopy(candidate))

    def client_factory(candidate: Config):
        if candidate.model == fail_model:
            raise RuntimeError("client switch failed")
        return new_from_config(candidate)

    async def apply_provider(change) -> None:
        await switch_provider_transactionally(
            cfg,
            agent,
            backend=change.backend,
            model=change.model,
            base_url=change.base_url,
            api_key=change.api_key,
            custom_provider_id=change.custom_provider_id,
            save_config=save,
            client_factory=client_factory,
        )

    app = SimpleNamespace(
        agent=agent,
        read_config=read_config,
        apply_provider=apply_provider,
    )
    return app, cfg, profile_id, dispatches, saved


@pytest.mark.asyncio
async def test_model_command_updates_active_custom_profile_and_restart_uses_new_model(
    monkeypatch,
):
    from src.ui.commands import slash_handler

    monkeypatch.setattr(slash_handler, "list_models", lambda *_args: ["new-model"])
    app, cfg, profile_id, dispatches, saved = _custom_model_app()

    await _handle_model(cast(KAgent, app), ["new-model"], dispatches.append)

    assert app.agent.client.model() == "new-model", dispatches
    assert cfg.custom_providers[profile_id].default_model == "new-model"
    assert cfg.model == "manual-model"
    assert cfg.active_custom_provider_id == profile_id
    assert saved[-1].custom_providers[profile_id].default_model == "new-model"
    assert saved[-1].active_custom_provider_id == profile_id

    restarted = build_startup_runtime(cfg, custom_provider_id=profile_id)
    assert restarted.client.model() == "new-model"
    assert restarted.active_custom_provider_id == profile_id
    assert cfg.model == "manual-model"


@pytest.mark.asyncio
async def test_model_command_switch_failure_preserves_custom_runtime_and_config(
    monkeypatch,
):
    from src.ui.commands import slash_handler

    monkeypatch.setattr(slash_handler, "list_models", lambda *_args: ["new-model"])
    app, cfg, profile_id, dispatches, saved = _custom_model_app(fail_model="new-model")
    old_client = app.agent.client
    old_cfg = copy.deepcopy(cfg)

    await _handle_model(cast(KAgent, app), ["new-model"], dispatches.append)

    assert app.agent.client is old_client
    assert cfg.custom_providers[profile_id].default_model == "old-model"
    assert cfg.active_custom_provider_id == profile_id
    assert cfg.model == "manual-model"
    assert saved == []
    assert last_text(SimpleNamespace(actions=dispatches)) == "model: client switch failed"


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


def test_thinking_status_reports_model_fallback_when_off_is_unavailable():
    class FallbackAgent(DummyAgent):
        def reasoning_status(self, enabled=None):
            preference = self.thinking if enabled is None else enabled
            return (
                "thinking on; model uses low" if preference
                else "thinking off requested; model uses low (fallback)"
            )

    async def run() -> None:
        app = DummyApp()
        app.agent = FallbackAgent()
        assert handle_slash(cast(KAgent, app), "/thinking off")
        await asyncio.sleep(0)
        assert last_text(app) == "thinking off requested; model uses low (fallback)"
        assert handle_slash(cast(KAgent, app), "/thinking")
        assert last_text(app) == "thinking off requested; model uses low (fallback)"

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


def test_scope_show_without_engagement_is_clear():
    app = DummyApp()

    assert handle_slash(cast(KAgent, app), "/scope")
    assert last_text(app) == "No active engagement. Set a target with /target <url>."


@pytest.mark.asyncio
async def test_scope_show_and_add_are_canonical_and_deterministic():
    app = DummyApp()
    app.agent.apply_target_base_url("http://juice.lab:3000/base")
    baseline_revision = app.agent.engagement_state.revision
    baseline_clears = app.agent.permission_cache_clears

    assert handle_slash(cast(KAgent, app), "/scope add HTTP://JUICE.LAB.:4000/path?q=1")
    assert last_text(app) == "Added scope origin: http://juice.lab:4000"
    assert app.agent.engagement_state.revision == baseline_revision + 1
    assert app.agent.permission_cache_clears == baseline_clears + 1
    await asyncio.sleep(0)

    assert handle_slash(cast(KAgent, app), "/scope show")
    assert last_text(app) == (
        "Active target: http://juice.lab:3000/base\n"
        "Allowed origins:\n"
        "  - http://juice.lab:3000\n"
        "  - http://juice.lab:4000\n"
        f"Engagement revision: {baseline_revision + 1}"
    )


@pytest.mark.asyncio
async def test_scope_duplicate_add_is_noop_including_default_port_equivalence():
    app = DummyApp()
    app.agent.apply_target_base_url("https://juice.lab")
    revision = app.agent.engagement_state.revision
    clears = app.agent.permission_cache_clears

    assert handle_slash(cast(KAgent, app), "/scope add https://JUICE.LAB:443/a")
    assert last_text(app) == "Origin is already in scope: https://juice.lab"
    assert app.agent.engagement_state.revision == revision
    assert app.agent.permission_cache_clears == clears
    await asyncio.sleep(0)


@pytest.mark.parametrize(
    ("command", "message"),
    [
        ("/scope add", "usage: /scope add <origin>"),
        ("/scope remove", "usage: /scope remove <origin>"),
        ("/scope add ftp://juice.lab", "invalid scope origin: ftp://juice.lab"),
        ("/scope unknown", "usage: /scope [show|add <origin>|remove <origin>|reset]"),
    ],
)
def test_scope_invalid_or_missing_arguments(command, message):
    app = DummyApp()
    app.agent.apply_target_base_url("http://juice.lab:3000")

    assert handle_slash(cast(KAgent, app), command)
    assert last_text(app) == message


@pytest.mark.asyncio
async def test_scope_remove_missing_real_and_active_target_cases():
    app = DummyApp()
    app.agent.apply_target_base_url("http://juice.lab:3000")
    app.agent.add_scope_origin("http://juice.lab:4000")

    revision = app.agent.engagement_state.revision
    clears = app.agent.permission_cache_clears
    assert handle_slash(cast(KAgent, app), "/scope remove http://missing.test")
    assert last_text(app) == "Origin is not in scope: http://missing.test"
    assert app.agent.engagement_state.revision == revision
    assert app.agent.permission_cache_clears == clears
    await asyncio.sleep(0)

    assert handle_slash(cast(KAgent, app), "/scope remove http://juice.lab:3000/a")
    assert last_text(app) == (
        "Cannot remove the active target origin from scope.\n"
        "Change the active target first."
    )

    assert handle_slash(cast(KAgent, app), "/scope remove http://juice.lab:4000")
    assert last_text(app) == "Removed scope origin: http://juice.lab:4000"
    assert app.agent.engagement_state.revision == revision + 1
    assert app.agent.permission_cache_clears == clears + 1
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_scope_reset_and_reset_noop_keep_active_target():
    app = DummyApp()
    app.agent.apply_target_base_url("http://juice.lab:3000/base")
    app.agent.add_scope_origin("http://juice.lab:4000")

    revision = app.agent.engagement_state.revision
    assert handle_slash(cast(KAgent, app), "/scope reset")
    assert last_text(app) == (
        "Scope reset to active target only:\n  http://juice.lab:3000"
    )
    assert app.agent.target.base_url() == "http://juice.lab:3000/base"
    assert app.agent.engagement_state.revision == revision + 1
    await asyncio.sleep(0)

    clears = app.agent.permission_cache_clears
    assert handle_slash(cast(KAgent, app), "/scope reset")
    assert last_text(app) == (
        "Scope already contains only the active target: http://juice.lab:3000"
    )
    assert app.agent.engagement_state.revision == revision + 1
    assert app.agent.permission_cache_clears == clears
    await asyncio.sleep(0)


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
