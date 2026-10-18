"""Serialize hot reloads; only complete snapshots reach the live registry."""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from src.async_io import run_sync
from src.agent.ownership import join
from src.logger.logger import get_logger
from src.skills.registry import Registry


def read_snapshot(directories: tuple[str, ...]) -> Registry:
    snapshot = Registry()
    for directory in directories:
        snapshot.load_dir(directory)
    if snapshot.load_errors:
        raise ValueError("skill reload could not read or parse every playbook")
    return snapshot


def publish_snapshot(agent, snapshot: Registry) -> None:
    """Keep consumer identity and current manual settings across atomic reload."""
    registry = agent.skills
    agent._reconcile_skill_contracts()
    contracts = dict(agent._skill_contracts)
    active, pending, restricted = set(agent.active_skills), set(agent.pending_skills), agent._skill_admission_restricted
    previous = registry.skills, registry.load_errors, registry.disabled
    history, prompt = agent.history, agent.sys_prompt
    try:
        registry.skills = snapshot.skills
        registry.load_errors = snapshot.load_errors
        registry.set_disabled_names(previous[2])
        agent.rebuild_from_skills()
    except BaseException:
        registry.skills, registry.load_errors, registry.disabled = previous
        agent.history, agent.sys_prompt = history, prompt
        agent._skill_contracts = contracts
        agent.active_skills, agent.pending_skills = active, pending
        agent._skill_admission_restricted = restricted
        raise


class SkillReloader:
    def __init__(self, directories: Callable[[], tuple[str, ...]], publish: Callable[[Registry], None]):
        self.directories = directories
        self.publish = publish
        self.task: asyncio.Task | None = None
        self.pending = False
        self.closed = False

    def request(self) -> None:
        if self.closed:
            return
        self.pending = True
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._run(), name="skill-reload")

    async def _run(self) -> None:
        while self.pending and not self.closed:
            self.pending = False
            try:
                snapshot = await run_sync(read_snapshot, self.directories())
                if not self.closed and not self.pending:
                    self.publish(snapshot)
            except asyncio.CancelledError:
                raise
            except Exception:
                get_logger("skills").warning("skill reload failed; previous registry retained", exc_info=True)

    async def close(self) -> None:
        self.closed = True
        self.pending = False
        if self.task is not None and not self.task.done():
            self.task.cancel()
            await join(self.task)
