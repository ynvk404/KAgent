"""Manual skill selection uses the existing Agent path, entirely offline."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from rich.cells import cell_len

from src.agent.agent import Agent
from src.config import config
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.session.store import Store
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry, Skill
from src.ui.commands.slash_handler import build_help_text
from src.ui.commands.slash_items import SLASH_ITEMS
from src.ui.core.app import KAgent
from src.ui.widgets.skills_modal import SkillsModal
from tests.agent.test_token_accounting_independent_verify import make_agent
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.ui.test_app import make_app
from tests.ui.test_input_rendering import app  # Mounted, offline TUI fixture.
from tests.ui.test_modal_cleanup import assert_control_visible, control_rows
from tests.ui.test_slash_handler import HelpAgent


@pytest.fixture
def registry() -> Registry:
    skills = Registry()
    root = Path(__file__).resolve().parents[2] / "skills"
    skills.load_dir(root)
    assert skills.list() and not skills.load_errors
    assert {skill.name for skill in skills.list()} == {
        path.parent.name for path in root.glob("*/SKILL.md")
        if not path.parent.name.startswith(("_", "."))
    }
    skills.add(custom_skill())  # Include a user-only, operator-defined alias.
    return skills


@pytest.mark.parametrize("disabled", [False, True])
@pytest.mark.parametrize("padding", ["", " \t"])
async def test_installed_skill_aliases_use_normal_agent_prompt_path(registry, disabled, padding):
    tui = make_app()
    agent = make_agent(skills=registry)
    tui.agent = agent
    if disabled:
        registry.set_disabled_names(skill.name for skill in registry.list())
    tui.run_agent_turn = AsyncMock()
    inject = AsyncMock()
    agent.inject_skill = inject
    before = list(agent.history)
    prompts = []
    for skill in registry.list():
        prompt = f"{padding}/{skill.name} ignored arguments\n"
        prompts.append(prompt)
        tui.submit(prompt)
        await asyncio.sleep(0)
    inject.assert_not_called()
    assert [entry.args[0] for entry in tui.run_agent_turn.await_args_list] == prompts
    assert agent.history == before and not agent.pending_skills


def test_live_menu_and_help_have_one_skill_entrypoint(registry):
    tui = make_app()
    tui.agent = make_agent(skills=registry)
    tui.input.set_value("/")
    tui._recompute_menus()
    assert tui.slash_matches == list(SLASH_ITEMS)
    help_text = build_help_text(cast(Agent, HelpAgent()), lambda: {"model": "offline"})
    assert "/skills" in help_text and "/<skill-name>" not in help_text
    for skill in registry.list():
        alias = f"/{skill.name}"
        assert alias not in help_text
        tui.input.set_value(alias)
        tui._recompute_menus()
        assert not tui.slash_matches


async def test_legacy_skill_alias_uses_normal_prompt_without_registry():
    tui = make_app()
    tui.agent = make_agent()
    tui.run_agent_turn = AsyncMock()
    command = "/recon"
    prompt = f" \t{command} previous arguments"
    tui.submit(prompt)
    await asyncio.sleep(0)
    tui.run_agent_turn.assert_awaited_once()
    awaited = tui.run_agent_turn.await_args
    assert awaited is not None
    assert awaited.args[0] == prompt


def custom_skill(name="manual-only", *, user_only=True) -> Skill:
    return Skill(
        name=name, description="A concise summary\n" + "description " * 100,
        tools=["http", "workflow"], disable_model_invocation=user_only,
        path=f"/fixture/{name}/SKILL.md", body="Full playbook proof gate. ${SKILL_DIR}",
    )


async def test_enter_matches_inject_skill_with_one_persisted_playbook(tmp_path):
    skills = Registry()
    skills.add(custom_skill())
    store = Store.new_with_id(tmp_path / "sessions", "skill-picker")
    agent = make_agent(skills=skills, store=store)
    reference = make_agent(skills=skills)
    await reference.inject_skill("manual-only")
    close = Mock()
    first = SkillsModal(agent, close)
    await first.load()
    await first.load()
    await SkillsModal(agent, close).load()  # Reopening before the next prompt.
    assert agent.history[1:] == reference.history[1:]
    assert agent.pending_skills == {"manual-only"} and not agent.active_skills
    assert store.load().messages == agent.history
    assert sum("Full playbook proof gate" in msg.content for msg in agent.history) == 1
    assert "/fixture/manual-only" in agent.history[-1].content
    assert not skills.is_disabled("manual-only")
    close.assert_called_with()

    # Existing next-turn promotion still applies, including user-only skills.
    events = []
    await agent.run("Summarize this playbook only.", FakeSignal(), events.append)
    assert agent.active_skills == {"manual-only"} and not agent.pending_skills
    assert any(event["type"] == "skill-active" and event["name"] == "manual-only" for event in events)


@pytest.mark.parametrize("legacy", [False, True])
async def test_manual_skill_history_keeps_session_compatibility(tmp_path, legacy):
    skills = Registry()
    skills.add(custom_skill())
    store = Store.new_with_id(tmp_path, "skill-history")
    agent = make_agent(skills=skills, store=store)
    await SkillsModal(agent, Mock()).load()
    if legacy:
        agent.history[-1].content = agent.history[-1].content.replace(
            "The user selected skill manual-only via /skills.", "The user invoked /manual-only.",
        )
        await agent.save()
    snapshot = store.load()
    resumed = make_agent(skills=skills, store=store)
    resumed.resume_saved()
    assert resumed.history[1:] == snapshot.messages[1:]
    assert "Full playbook proof gate" in resumed.history[-1].content
    assert resumed.workflow.to_dict() == snapshot.workflow.to_dict()


async def test_picker_disabled_names_round_trip_through_existing_config(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    monkeypatch.setenv("kagent_CONFIG", str(path))
    await config.save(config.Config(model="preserved-model"))

    async def persist(names):
        cfg = config.load()
        cfg.disabled_skills = sorted(names)
        await config.save(cfg)

    skills = Registry()
    skills.add(custom_skill())
    agent = make_agent(skills=skills)
    modal = SkillsModal(agent, Mock(), persist)
    await modal.toggle()
    assert config.load().disabled_skills == ["manual-only"]
    assert config.load().model == "preserved-model"

    restored_skills = Registry()
    restored_skills.add(custom_skill())
    restored_skills.set_disabled_names(config.load().disabled_skills)
    restored = SkillsModal(make_agent(skills=restored_skills), Mock(), persist)
    before = path.read_bytes()
    await restored.load()
    assert "disabled" in (restored.error or "") and path.read_bytes() == before
    await restored.toggle_all(True)
    assert config.load().disabled_skills == []
    before = path.read_bytes()
    await restored.load()
    assert restored.closed and path.read_bytes() == before


async def test_agent_internal_loading_still_uses_registered_tool():
    skills = Registry()
    skills.add(custom_skill("automatic", user_only=False))
    agent = make_agent(skills=skills)
    agent.tools.register(LoadSkillTool(skills))
    agent.set_client(FakeClient([
        ChatResponse(Message("assistant", "", tool_calls=[ToolCall(
            "internal-skill", FunctionCall("load_skill", '{"name":"automatic"}'),
        )]), "tool_calls"),
        ChatResponse(Message("assistant", "done"), "stop"),
    ]))
    events = []
    await agent.run("Use the automatic playbook.", FakeSignal(), events.append)
    assert agent.active_skills == {"automatic"}
    result = next(msg for msg in agent.history if msg.role == "tool" and msg.tool_call_id == "internal-skill")
    assert "Full playbook proof gate" in result.content
    assert skills.get("automatic") is not None


@pytest.mark.parametrize("size", [(160, 40), (100, 30), (48, 20)])
async def test_picker_input_scroll_resize_and_double_enter(app: KAgent, size):
    skills = Registry()
    for index in range(20):
        skills.add(custom_skill(f"skill-{index:02d}"))
    agent = make_agent(skills=skills)
    app.agent = agent
    persisted = AsyncMock()
    app.persist_disabled_skills = persisted
    async with app.run_test(size=size) as pilot:
        await pilot.press(*"/skills", "enter")
        modal = app._get_active_modal()
        assert isinstance(modal, SkillsModal) and modal.idx == 0
        await pilot.press("down", "tab", "up", "shift+tab")
        assert modal.idx == 0
        await pilot.press("space")
        assert skills.disabled_names() == ["skill-00"] and not agent.pending_skills
        persisted.assert_awaited_once_with(["skill-00"])
        await pilot.press("enter")
        assert app._get_active_modal() is modal and "disabled" in (modal.error or "")
        await pilot.press("a")
        assert skills.disabled_names() == []
        await pilot.press("d")
        assert len(skills.disabled_names()) == 20
        await pilot.press("a", *(["down"] * 12))
        assert modal.idx == 12
        assert_control_visible(app, "modal_item", 12)
        await pilot.press("pagedown")
        await pilot.pause()
        manual_scroll = app.overlay_content_static.scroll_y
        app._sync_overlay()
        await pilot.pause()
        assert app.overlay_content_static.scroll_y == manual_scroll
        for viewport in [(48, 20), (100, 30), (160, 40)]:
            await pilot.resize_terminal(*viewport)
            await pilot.pause()
            assert modal.idx == 12
            assert_control_visible(app, "modal_item", 12)
            assert app.overlay_static.region.bottom <= viewport[1]
            assert app.overlay_content_static.max_scroll_x == 0
            assert all(len(control_rows(app, "modal_item", idx)) == 1 for idx in modal.item_lines.values())
            assert all(cell_len(line) <= viewport[0] - 5 for line in modal.render())
        await pilot.press("enter", "enter")
        assert not app.state.pending_skills and app._get_active_modal() is None
        assert agent.pending_skills == {"skill-12"} and skills.disabled_names() == []
        assert sum("Full playbook proof gate" in msg.content for msg in agent.history) == 1
        assert len([entry for entry in app.state.transcript if "loaded skill skill-12" in entry.text]) == 1
        cast(AsyncMock, app.run_agent_turn).assert_not_called()
        for key in ("escape", "q"):
            await pilot.press(*"/skills", "enter", key)
            assert not app.state.pending_skills
