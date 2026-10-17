from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from rich.cells import cell_len

from src.ui.widgets.skills_modal import SkillsModal


class FakeSkill:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description


class FakeSkills:

    def __init__(self):
        self.items = [
            FakeSkill("web_scan", "Web vulnerability scanning"),
            FakeSkill("nmap", "Network enumeration"),
            FakeSkill("report", "Generate report"),
        ]

        self.disabled = set()


    def list(self):
        return self.items


    def is_disabled(self, name: str):
        return name in self.disabled


    def disabled_names(self):
        return list(self.disabled)



class FakeAgent:

    def __init__(self):
        self.skills = FakeSkills()
        self.pending_skills = set()
        self.running = False
        self.inject_skill = AsyncMock(side_effect=self._inject)
        self.set_skill_enabled = AsyncMock(
            side_effect=self._set
        )

    async def _inject(self, name: str):
        if self.running:
            raise RuntimeError("cannot load a skill while a turn is in flight")
        if self.skills.is_disabled(name):
            raise RuntimeError(f'skill "{name}" is disabled - enable it from /skills first')
        self.pending_skills.add(name)
        return name

    async def _set(
        self,
        name: str,
        enabled: bool,
    ):

        if enabled:
            self.skills.disabled.discard(name)
        else:
            self.skills.disabled.add(name)

        return True


async def press_action(modal: SkillsModal, key: str) -> None:
    action = modal.handle_key(key)
    assert action is not None
    await action

def test_render_skills():

    agent = FakeAgent()

    modal = SkillsModal(
        agent=agent,
        on_close=Mock(),
    )


    frame = "\n".join(
        modal.render()
    )


    assert "3/3 enabled" in frame
    assert "web_scan" in frame
    assert "nmap" in frame

def test_down_changes_selection():

    agent = FakeAgent()

    modal = SkillsModal(
        agent,
        Mock(),
    )


    assert modal.idx == 0

    modal.handle_key("down")

    assert modal.idx == 1



def test_up_wraps():

    agent = FakeAgent()

    modal = SkillsModal(
        agent,
        Mock(),
    )


    modal.handle_key("up")

    assert modal.idx == 2


def test_tab_and_shift_tab_navigate_without_toggling():
    agent = FakeAgent()
    modal = SkillsModal(agent, Mock())

    modal.handle_key("tab")
    assert modal.idx == 1
    agent.set_skill_enabled.assert_not_called()

    modal.handle_key("shift+tab")
    assert modal.idx == 0
    agent.set_skill_enabled.assert_not_called()


def test_number_select():

    agent = FakeAgent()

    modal = SkillsModal(
        agent,
        Mock(),
    )


    modal.handle_key("3")

    assert modal.idx == 2


@pytest.mark.asyncio
async def test_toggle_skill():

    agent = FakeAgent()

    modal = SkillsModal(
        agent,
        Mock(),
    )


    await modal.toggle()


    assert (
        "web_scan"
        in agent.skills.disabled
    )



@pytest.mark.asyncio
async def test_toggle_all_disable():

    agent = FakeAgent()

    modal = SkillsModal(
        agent,
        Mock(),
    )


    await modal.toggle_all(False)


    assert len(agent.skills.disabled) == 3



@pytest.mark.asyncio
async def test_toggle_all_enable():

    agent = FakeAgent()

    agent.skills.disabled = {
        "web_scan",
        "nmap",
    }


    modal = SkillsModal(
        agent,
        Mock(),
    )


    await modal.toggle_all(True)


    assert len(agent.skills.disabled) == 0


def test_escape_close():

    agent = FakeAgent()

    close = Mock()

    modal = SkillsModal(
        agent,
        close,
    )


    modal.handle_key("escape")

    close.assert_called_once()

    close.assert_called_once()

def test_skills_modal_long_list_windowing():
    class DummySkill:
        def __init__(self, name: str) -> None:
            self.name = name
            self.description = f"description for {name}"

    skills_list = [DummySkill(f"skill_{i:02d}") for i in range(20)]

    class DummySkills:
        def list(self):
            return skills_list

        def is_disabled(self, name: str) -> bool:
            return False

    agent = SimpleNamespace(skills=DummySkills())
    modal = SkillsModal(agent, Mock())

    # 1. At start (idx=0): visible 0..7, 12 hidden below
    frame = "\n".join(modal.render())
    assert "↓ 12 more" in frame
    assert "↑ " not in frame
    assert "skill_00" in frame
    assert "skill_07" in frame
    assert "skill_08" not in frame

    # 2. Navigate to item 10: visible 6..13, 6 hidden above, 6 hidden below
    for _ in range(10):
        modal.handle_key("down")
    assert modal.idx == 10

    frame = "\n".join(modal.render())
    assert "↑ 6 more" in frame
    assert "↓ 6 more" in frame
    assert "skill_05" not in frame
    assert "skill_06" in frame
    assert "› [on]  skill_10" in frame
    assert "skill_13" in frame
    assert "skill_14" not in frame


async def test_space_only_toggles_one_skill_and_persists():
    agent = FakeAgent()
    persist, loaded, close = AsyncMock(), Mock(), Mock()
    modal = SkillsModal(agent, close, persist, loaded)
    modal.handle_key("down")
    await press_action(modal, "space")
    assert agent.skills.disabled == {"nmap"}
    agent.set_skill_enabled.assert_awaited_once_with("nmap", False)
    persist.assert_awaited_once_with(["nmap"])
    agent.inject_skill.assert_not_called()
    loaded.assert_not_called()
    close.assert_not_called()


async def test_enter_uses_selection_without_toggle_or_config_write_and_closes_once():
    agent = FakeAgent()
    persist, loaded, close = AsyncMock(), Mock(), Mock()
    modal = SkillsModal(agent, close, persist, loaded)
    modal.handle_key("tab")
    await press_action(modal, "enter")
    assert modal.handle_key("enter") is None
    await modal.load()  # Also ignore stale async activation after closure.
    agent.inject_skill.assert_awaited_once_with("nmap")
    assert agent.skills.disabled == set() and agent.pending_skills == {"nmap"}
    agent.set_skill_enabled.assert_not_called()
    persist.assert_not_called()
    loaded.assert_called_once_with("nmap")
    close.assert_called_once()


async def test_disabled_enter_stays_open_until_space_enables_it():
    agent = FakeAgent()
    agent.skills.disabled.add("web_scan")
    close = Mock()
    modal = SkillsModal(agent, close)
    await press_action(modal, "enter")
    assert agent.skills.disabled == {"web_scan"} and not agent.pending_skills
    assert "disabled" in (modal.error or "")
    agent.set_skill_enabled.assert_not_called()
    close.assert_not_called()
    await press_action(modal, "space")
    await press_action(modal, "enter")
    assert agent.pending_skills == {"web_scan"}
    close.assert_called_once()


@pytest.mark.parametrize("key,enabled", [("a", True), ("d", False)])
async def test_bulk_keys_preserve_persistence_and_do_not_load(key, enabled):
    agent = FakeAgent()
    agent.skills.disabled = {skill.name for skill in agent.skills.list()} if enabled else set()
    persist = AsyncMock()
    modal = SkillsModal(agent, Mock(), persist)
    await press_action(modal, key)
    assert agent.skills.disabled == (set() if enabled else {"web_scan", "nmap", "report"})
    persist.assert_awaited_once_with(agent.skills.disabled_names())
    agent.inject_skill.assert_not_called()


@pytest.mark.parametrize("key", ["escape", "esc", "q"])
def test_close_keys_never_mutate_or_load(key):
    agent, close = FakeAgent(), Mock()
    modal = SkillsModal(agent, close)
    modal.handle_key(key)
    modal.handle_key("enter")
    close.assert_called_once()
    agent.inject_skill.assert_not_called()
    agent.set_skill_enabled.assert_not_called()


async def test_pending_skill_is_not_injected_again_when_picker_reopens():
    agent = FakeAgent()
    await SkillsModal(agent, Mock()).load()
    await SkillsModal(agent, Mock()).load()
    agent.inject_skill.assert_awaited_once_with("web_scan")


async def test_overlapping_enter_loads_only_once():
    agent, close = FakeAgent(), Mock()
    entered, release = asyncio.Event(), asyncio.Event()

    async def slow_load(name):
        entered.set()
        await release.wait()
        return await agent._inject(name)

    agent.inject_skill.side_effect = slow_load
    modal = SkillsModal(agent, close)
    first = asyncio.create_task(modal.load())
    try:
        await asyncio.wait_for(entered.wait(), timeout=2)
        assert modal.handle_key("enter") is None
        await modal.load()
        agent.inject_skill.assert_awaited_once_with("web_scan")
    finally:
        release.set()
        await first
    assert agent.pending_skills == {"web_scan"}
    close.assert_called_once()


@pytest.mark.parametrize("pending", [False, True])
async def test_in_flight_turn_keeps_agent_load_guard(pending):
    agent, close = FakeAgent(), Mock()
    agent.running = True
    if pending:
        agent.pending_skills.add("web_scan")
    modal = SkillsModal(agent, close)
    await modal.load()
    assert "in flight" in (modal.error or "")
    agent.inject_skill.assert_awaited_once_with("web_scan")
    close.assert_not_called()


@pytest.mark.parametrize("width", [155, 95, 43])
def test_summary_is_one_terminal_line_and_preserves_description(width):
    agent = FakeAgent()
    original = "Long summary 測試 with whitespace\n\n" * 50 + "DESCRIPTION_END"
    agent.skills.items[0].description = original
    modal = SkillsModal(agent, Mock(), width=width)
    lines = modal.render()
    row = next(line for line in lines if "web_scan" in line)
    assert "\n" not in row and "DESCRIPTION_END" not in row
    assert cell_len(row) <= width and row.endswith("…")
    assert agent.skills.items[0].description == original
