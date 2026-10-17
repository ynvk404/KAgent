"""Owned blocking calls: cancellation joins the worker before returning.

Workers inherit the existing turn context. Publication checks use that owner,
never a second generation or an authority cache.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
import threading
from typing import Callable, ParamSpec, TypeVar

P = ParamSpec("P")
T = TypeVar("T")
_stopped: ContextVar[threading.Event | None] = ContextVar("blocking_call_stopped", default=None)


def check_worker() -> None:
    stopped = _stopped.get()
    if stopped is not None and stopped.is_set():
        raise asyncio.CancelledError("blocking operation cancelled")
    from src.agent.ownership import current_owner
    owner = current_owner()
    if owner is not None and not owner.current():
        raise asyncio.CancelledError("retired agent turn")


@contextmanager
def publication(check: Callable[[], None] | None = None):
    from src.agent.ownership import current_owner
    owner = current_owner()
    with owner.state.lifecycle_lock if owner is not None else nullcontext():
        check_worker()
        if check is not None:
            check()
        yield


async def run_sync(function: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    stopped = threading.Event()

    def execute():
        token = _stopped.set(stopped)
        try:
            return function(*args, **kwargs)
        finally:
            _stopped.reset(token)

    pending = asyncio.create_task(asyncio.to_thread(execute))
    try:
        return await asyncio.shield(pending)
    except asyncio.CancelledError:
        stopped.set()
        while not pending.done():
            try:
                await asyncio.shield(pending)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not pending.cancelled():
            pending.exception()
        raise
