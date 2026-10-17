"""Rollback manual skill mutations using the current workflow generation."""
from contextlib import asynccontextmanager
import asyncio

from src.logger.logger import get_logger


@asynccontextmanager
async def skill_changes(agent):
    registry = agent.skills
    disabled = list(registry.disabled_names())
    active = set(getattr(agent, "active_skills", set()))
    pending = set(getattr(agent, "pending_skills", set()))
    history = list(agent.history) if hasattr(agent, "history") else None
    state = getattr(agent, "workflow", None)
    generation = getattr(state, "generation", None)
    try:
        yield
    except BaseException:
        async def rollback():
            if agent.skills is not registry:
                return
            if hasattr(registry, "set_disabled_names"):
                registry.set_disabled_names(disabled)
            else:
                registry.disabled = set(disabled)
            if getattr(agent, "workflow", None) is not state or getattr(state, "generation", None) != generation:
                return
            if hasattr(agent, "active_skills"):
                agent.active_skills = active
            if hasattr(agent, "pending_skills"):
                agent.pending_skills = pending
            if history is not None:
                agent.history = history
                agent.rebuild_from_skills()
                await agent.save()

        task = asyncio.create_task(rollback())
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not task.cancelled() and task.exception() is not None:
            get_logger("skills").error("skill rollback checkpoint failed", exc_info=task.exception())
        raise
