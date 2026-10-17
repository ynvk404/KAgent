"""Controller-owned turn lifetime, independent of model/tool invocation IDs."""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Awaitable, TypeVar

T = TypeVar('T')


@dataclass(eq=False)
class TurnOwner:
    agent: Any
    state: Any
    generation: str
    task: asyncio.Task | None
    retired: asyncio.Event = field(default_factory=asyncio.Event)

    def current(self) -> bool:
        return (not self.retired.is_set() and self.agent._active_turn is self
                and self.agent.workflow is self.state and self.state.generation == self.generation)


_turn: ContextVar[TurnOwner | None] = ContextVar('agent_turn_owner', default=None)


def current_owner() -> TurnOwner | None:
    return _turn.get()


def current(agent) -> bool:
    owner = _turn.get()
    return owner is None or owner.agent is not agent or owner.current()


def check(agent) -> None:
    if not current(agent):
        raise asyncio.CancelledError('retired agent turn')


def capture(agent):
    owner = _turn.get()
    return owner if owner is not None and owner.agent is agent else None


def adopt_initial_state(agent) -> None:
    """Accept synchronous target/objective setup before the first model wait."""
    owner = capture(agent)
    if owner is not None:
        if owner.retired.is_set() or agent._active_turn is not owner or agent.workflow is not owner.state:
            raise asyncio.CancelledError('retired agent turn')
        owner.generation = agent.workflow.generation


async def join(task: asyncio.Future[Any]) -> None:
    """Join a retired owner, even if the caller is cancelled repeatedly."""
    caller = asyncio.current_task()
    cancellations = caller.cancelling() if caller else 0
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            pass
        except Exception:
            break
    if not task.cancelled():
        task.exception()
    if caller is not None and caller.cancelling() > cancellations:
        raise asyncio.CancelledError


def retire(agent) -> asyncio.Task | None:
    owner = getattr(agent, '_active_turn', None)
    if owner is None:
        return None
    with owner.state.lifecycle_lock:
        owner.retired.set()
        agent._active_turn = None
    # A reset invoked by an owned callback cannot await its own parent.
    if _turn.get() is owner:
        return None
    if owner.task is not None and not owner.task.done():
        owner.task.cancel()
        return owner.task
    return None


@contextmanager
def checkpoint(path):
    """Linearize an offloaded checkpoint commit against retirement/resume."""
    owner = _turn.get()
    store = owner.agent.store if owner is not None else None
    if owner is None or store is None or path not in (store.path, store.context_snapshot_path()):
        yield
        return
    with owner.state.lifecycle_lock:
        if not owner.current():
            raise ValueError('retired turn cannot publish a checkpoint')
        yield


def owned_turn(function):
    @wraps(function)
    async def run(agent, *args, **kwargs):
        if agent.running:
            return await function(agent, *args, **kwargs)
        owner = TurnOwner(agent, agent.workflow, agent.workflow.generation, asyncio.current_task())
        agent._active_turn = owner
        token = _turn.set(owner)
        try:
            return await function(agent, *args, **kwargs)
        finally:
            if agent._active_turn is owner:
                agent._active_turn = None
            _turn.reset(token)
    return run


async def await_owned(agent, awaitable: Awaitable[T]) -> T:
    """Race a model wait against state replacement; join all owned children."""
    owner = _turn.get()
    if owner is None or owner.agent is not agent:
        return await awaitable
    pending = asyncio.ensure_future(awaitable)
    retired = asyncio.create_task(owner.state.retired.wait())
    try:
        check(agent)
        await asyncio.wait((pending, retired), return_when=asyncio.FIRST_COMPLETED)
        check(agent)
        value = await pending
        check(agent)
        return value
    finally:
        retired.cancel()
        if not pending.done():
            pending.cancel()
        await join(pending)
        await join(retired)
