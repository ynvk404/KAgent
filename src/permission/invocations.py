"""Controller-created review scopes; model arguments never select an identity.

Exact declines suppress repeated dialogs within one turn, not a future turn.
Persistent origin/session revocations are managed separately by policy.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Awaitable, Callable, Coroutine, ParamSpec, TypeVar
import uuid

from src.permission.permission import UserControlledRefusal


@dataclass
class ReviewTurn:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    cleanups: list[Callable[[], None]] = field(default_factory=list)
    closed: bool = False


_turn: ContextVar[ReviewTurn | None] = ContextVar('permission_review_turn', default=None)
P = ParamSpec('P')
R = TypeVar('R')


@contextmanager
def review_turn():
    """Trusted Agent/UI entrypoint only; never called from a tool's arguments."""
    turn = ReviewTurn()
    token = _turn.set(turn)
    try:
        yield turn
    finally:
        turn.closed = True
        for cleanup in turn.cleanups:
            cleanup()
        _turn.reset(token)


def review_id() -> str:
    turn = _turn.get()
    if turn is not None and turn.closed:
        raise UserControlledRefusal('blocked: permission review turn ended')
    return turn.id if turn else 'library'


def on_review_end(cleanup: Callable[[], None]) -> None:
    turn = _turn.get()
    if turn is not None:
        turn.cleanups.append(cleanup)


def permission_turn(function: Callable[P, Awaitable[R]]) -> Callable[P, Coroutine[Any, Any, R]]:
    @wraps(function)
    async def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        with review_turn():
            return await function(*args, **kwargs)
    return wrapped


def permission_invocation(function: Callable[P, Awaitable[R]]) -> Callable[P, Coroutine[Any, Any, R]]:
    @wraps(function)
    async def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        if _turn.get() is not None:
            review_id()  # A detached child cannot reuse a completed turn.
            return await function(*args, **kwargs)
        with review_turn():
            return await function(*args, **kwargs)
    return wrapped
