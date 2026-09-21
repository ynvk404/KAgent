import asyncio
from typing import cast

import pytest

from src.ui.commands.skills_handler import handle_skills_command
from src.ui.core.state import Append, SetActiveSkill
from src.agent.agent import Agent  


class StubSkills:
    def __init__(self, items=None, disabled=None):
        self._items = list(items or [])
        self._disabled = set(disabled or [])

    def list(self):
        return self._items

    def has(self, name):
        return any(getattr(item, "name", None) == name for item in self._items)

    def is_disabled(self, name):
        return name in self._disabled

    def disabled_names(self):
        return sorted(self._disabled)

    def set_disabled(self, name, on):
        if on:
            if name in self._disabled:
                return False
            self._disabled.add(name)
            return True

        if name not in self._disabled:
            return False

        self._disabled.remove(name)
        return True


class StubAgent:
    def __init__(self):
        self.skills = StubSkills(
            items=[type("Skill", (), {"name": "demo"})()]
        )
        self._enabled = True
        self.active_skills = set()
        self.pending_skills = set()

    async def set_skill_enabled(self, name, enabled):
        self._enabled = enabled
        changed = self.skills.set_disabled(name, not enabled)
        if changed and not enabled:
            self.active_skills.discard(name)
            self.pending_skills.discard(name)
        return changed

    def rebuild_from_skills(self):
        return None


def test_no_loaded_skills_dispatches_message():
    dispatched = []

    class DummyAgent:
        skills = type(
            "Skills",
            (),
            {"list": staticmethod(lambda: [])},
        )()

    handle_skills_command(
        cast(Agent, DummyAgent()),
        [],
        dispatched.append,
        None,
        None,
    )

    assert isinstance(dispatched[0], Append)
    assert dispatched[0].entry.text == "/skills: no skills are loaded"


def test_unknown_skill_dispatches_error():
    dispatched = []
    agent = StubAgent()

    handle_skills_command(
        cast(Agent, agent),
        ["missing"],
        dispatched.append,
        None,
        None,
    )

    assert isinstance(dispatched[0], Append)
    assert (
        dispatched[0].entry.text
        == '/skills: unknown skill "missing". Run /skills to list available skills.'
    )


@pytest.mark.asyncio
async def test_disable_active_skill_refreshes_status_state():
    dispatched = []
    agent = StubAgent()
    agent.active_skills.add("demo")

    handle_skills_command(
        cast(Agent, agent),
        ["disable", "demo"],
        dispatched.append,
        None,
        None,
    )

    await asyncio.sleep(0)

    assert agent.skills.is_disabled("demo")
    assert any(
        isinstance(action, SetActiveSkill) and action.name is None
        for action in dispatched
    )
    assert isinstance(dispatched[-1], Append)
    assert dispatched[-1].entry.text == "/skills: demo disabled"
