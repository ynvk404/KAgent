import asyncio
import threading
import time
from pathlib import Path

import pytest

from src.skills.reload import SkillReloader, publish_snapshot
from src.skills.registry import Registry
from tests.agent.test_token_accounting_independent_verify import make_agent
from tests.ui.test_skill_entrypoint import custom_skill


@pytest.mark.parametrize("ending", ["success", "parse_failure", "cancel", "newer_request"])
async def test_reload_builds_off_loop_and_publishes_only_complete_latest_snapshot(tmp_path, monkeypatch, ending):
    skill = tmp_path / "example"
    skill.mkdir()
    source = skill / "SKILL.md"
    metadata = "---\nname: example\ndescription: fixture\nallowed-tools: []\n---\n"
    source.write_text(metadata + "first")
    entered, release = threading.Event(), threading.Event()
    published = []
    original = Path.read_text
    reads = []
    def read(path, *args, **kwargs):
        if path == source:
            reads.append(threading.get_ident())
            captured = original(path, *args, **kwargs)
            if len(reads) == 1:
                entered.set()
                assert release.wait(2)
            if ending == "parse_failure":
                raise OSError("synthetic read failure")
            return captured
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", read)
    reload = SkillReloader(lambda: (str(tmp_path),), published.append)
    closing = None
    reload.request()
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        assert not published
        started = time.perf_counter()
        for _ in range(5):
            await asyncio.sleep(0.01)
            assert not published
        print({"reload_heartbeat_window_ms": (time.perf_counter()-started)*1000})
        if ending == "newer_request":
            source.write_text(metadata + "latest")
            reload.request()
        if ending == "cancel":
            closing = asyncio.create_task(reload.close())
            await asyncio.sleep(0)
            assert not closing.done()
    finally:
        release.set()
    if ending == "cancel":
        assert closing is not None
        await closing
    else:
        assert reload.task is not None
        await reload.task
    assert reads and all(thread != threading.get_ident() for thread in reads)
    if ending in {"cancel", "parse_failure"}:
        assert not published
    else:
        assert len(published) == 1
        assert published[0].get("example").body == ("latest" if ending == "newer_request" else "first")
    await reload.close()
    assert reload.task is not None
    assert reload.task.done()


@pytest.mark.parametrize("failure", [False, True])
def test_atomic_publish_keeps_live_settings_and_rolls_back_prompt_failure(monkeypatch, failure):
    original = Registry()
    original.add(custom_skill("example"))
    agent = make_agent(skills=original)
    original.set_disabled("example", True)  # Changed after the reader snapshot.
    replacement = Registry()
    replacement.add(custom_skill("example"))
    replacement.add(custom_skill("new"))
    history, prompt, mapping = agent.history, agent.sys_prompt, original.skills
    def fail():
        agent.history = []
        agent.sys_prompt = "incomplete"
        raise ValueError("synthetic prompt failure")
    if failure:
        monkeypatch.setattr(agent, "rebuild_from_skills", fail)
        with pytest.raises(ValueError):
            publish_snapshot(agent, replacement)
        assert original.skills is mapping
        assert agent.history is history and agent.sys_prompt == prompt
    else:
        publish_snapshot(agent, replacement)
        assert original.has("new")
    assert agent.skills is original and original.is_disabled("example")
