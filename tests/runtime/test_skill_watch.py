"""Skill hot-reload reacts to edits, without reacting to its own reads."""
import asyncio
from unittest.mock import MagicMock

import pytest
from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirModifiedEvent,
    DirMovedEvent,
    FileClosedEvent,
    FileClosedNoWriteEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileOpenedEvent,
)

from src.cli import runtime
from src.skills.registry import Registry


@pytest.mark.parametrize(
    ("event", "should_reload"),
    [
        (FileOpenedEvent("skills/recon/SKILL.md"), False),
        (FileClosedNoWriteEvent("skills/recon/SKILL.md"), False),
        (FileClosedEvent("skills/recon/SKILL.md"), False),
        (FileCreatedEvent("skills/recon/SKILL.md"), True),
        (FileModifiedEvent("skills/recon/SKILL.md"), True),
        (FileDeletedEvent("skills/recon/SKILL.md"), True),
        # Editors may save by replacing a file rather than writing in place.
        (FileMovedEvent("skills/recon/.tmp", "skills/recon/SKILL.md"), True),
        (DirCreatedEvent("skills/recon"), True),
        (DirModifiedEvent("skills/recon"), True),
        (DirDeletedEvent("skills/recon"), True),
        (DirMovedEvent("skills/recon", "skills/renamed"), True),
    ],
)
async def test_skill_watch_only_reloads_for_mutations(monkeypatch, event, should_reload):
    observer = MagicMock()
    monkeypatch.setattr(runtime, "Observer", lambda: observer)
    callback = MagicMock()

    assert runtime.fs_watch("skills", asyncio.get_running_loop(), callback) is observer
    handler = observer.schedule.call_args.args[0]
    handler.dispatch(event)
    await asyncio.sleep(0)

    assert callback.call_count == int(should_reload)


@pytest.mark.parametrize("save_mode", ["write", "replace"])
async def test_loading_skills_does_not_trigger_real_watcher(tmp_path, save_mode):
    skill_dir = tmp_path / "example"
    skill_dir.mkdir()
    skill_file = skill_dir / "SKILL.md"
    source = "---\nname: example\ndescription: Test skill\nallowed-tools: []\n---\n"
    skill_file.write_text(source + "Original body", encoding="utf-8")
    changed = asyncio.Event()
    observer = runtime.fs_watch(str(tmp_path), asyncio.get_running_loop(), changed.set)
    assert observer is not None

    try:
        registry = Registry()
        registry.load_dir(tmp_path)
        assert registry.has("example")
        # A real load opens/closes SKILL.md. It must leave the watcher idle.
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(changed.wait(), timeout=0.3)

        if save_mode == "replace":
            replacement = skill_dir / ".SKILL.md.tmp"
            replacement.write_text(source + "Updated body", encoding="utf-8")
            replacement.replace(skill_file)
        else:
            skill_file.write_text(source + "Updated body", encoding="utf-8")

        await asyncio.wait_for(changed.wait(), timeout=2)
        registry.load_dir(tmp_path)
        skill = registry.get("example")
        assert skill is not None and skill.body == "Updated body"
    finally:
        observer.stop()
        await asyncio.to_thread(observer.join, 1)
