from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest

from src.ui.widgets.skills_modal import SkillsModal


# ==========================================================
# Fake skill registry
# ==========================================================

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



# ==========================================================
# Render
# ==========================================================

def test_render_skills():

    agent = FakeAgent()

    modal = SkillsModal(
        agent=agent,
        on_close=Mock(),
    )


    frame = "\n".join(
        modal.render()
    )


    assert "[skills]" in frame
    assert "3/3 enabled" in frame
    assert "web_scan" in frame
    assert "nmap" in frame



# ==========================================================
# Navigation
# ==========================================================

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



# ==========================================================
# Number shortcut
# ==========================================================

def test_number_select():

    agent = FakeAgent()

    modal = SkillsModal(
        agent,
        Mock(),
    )


    modal.handle_key("3")

    assert modal.idx == 2



# ==========================================================
# Toggle
# ==========================================================

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



# ==========================================================
# Close
# ==========================================================

def test_escape_close():

    agent = FakeAgent()

    close = Mock()

    modal = SkillsModal(
        agent,
        close,
    )


    modal.handle_key("escape")


    close.assert_called_once()