import asyncio
import time
from unittest.mock import patch

import pytest
from textual import events

from src.ui.core.app import KAgent
from src.ui.core.state import SetSkillsPicker
from src.ui.widgets.skills_modal import SkillsModal
from tests.ui.test_overview import _make_app
from tests.agent.test_token_accounting_independent_verify import make_agent
from tests.ui.test_skill_entrypoint import custom_skill
from src.skills.registry import Registry
from src.session.store import Store


@pytest.mark.parametrize("ending", ["success", "failure", "cancel", "unmount"])
async def test_skills_persistence_does_not_hold_keyboard_or_leak_mutations(tmp_path, monkeypatch, ending):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    entered, release = asyncio.Event(), asyncio.Event()
    skills = Registry()
    skills.add(custom_skill())
    agent = make_agent(skills=skills, store=Store.new_with_id(tmp_path / "sessions", "skills"))
    await agent.save()
    persisted = []
    calls = []
    async def persist(names):
        calls.append(list(names))
        entered.set()
        await release.wait()
        if ending == "failure":
            raise OSError("synthetic settings failure")
        persisted[:] = names
    app = _make_app()
    app.agent = agent
    app.persist_disabled_skills = persist
    unmount = None
    escaped = asyncio.Event()
    original_key = app._process_key
    async def key(event):
        await original_key(event)
        if event.key == "escape":
            escaped.set()
    app._process_key = key
    async with app.run_test() as pilot:
        app.dispatch(SetSkillsPicker(True))
        modal = app._get_active_modal()
        assert isinstance(modal, SkillsModal)
        app.post_message(events.Key("space", None))
        await asyncio.wait_for(entered.wait(), 1)
        try:
            # Both keyboard paths must ignore duplicate activation.
            app.post_message(events.Key("space", None))
            sent = time.perf_counter()
            app.post_message(events.Key("escape", None))
            await asyncio.wait_for(escaped.wait(), 0.12)
            latency = (time.perf_counter() - sent) * 1000
            print({"skills_escape_ms": latency})
            assert latency < 120
            assert not app.state.pending_skills
            assert len(calls) == 1
            app.run_agent_compact()
            assert app.run_task is None, "compact must wait for the pending skill transaction"
            assert not app.state.busy
            if ending in {"cancel", "unmount"}:
                if ending == "cancel":
                    assert app._skill_task is not None
                    app._skill_task.cancel()
                else:
                    unmount = asyncio.create_task(app.on_unmount())
                    await asyncio.sleep(0)
                    assert not unmount.done()
        finally:
            release.set()
        if ending == "unmount":
            assert unmount is not None
            await unmount
        else:
            assert app._skill_task is not None
            await asyncio.gather(app._skill_task, return_exceptions=True)
        assert skills.disabled_names() == persisted
        assert agent.store is not None
        assert agent.store.load().messages == agent.history
        assert not modal.busy_name
