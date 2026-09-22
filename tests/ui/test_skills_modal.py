from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

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
        self.set_skill_enabled = AsyncMock(
            side_effect=self._set
        )


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
