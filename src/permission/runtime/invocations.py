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
import time
import asyncio

from src.permission.permission import PermissionReviewStale


@dataclass
class ReviewTurn:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    cleanups: list[Callable[[], None]] = field(default_factory=list)
    closed: bool = False


_turn: ContextVar[ReviewTurn | None] = ContextVar('permission_review_turn', default=None)
_admission: ContextVar[Callable[[], None] | None] = ContextVar('controller_tool_admission', default=None)
P = ParamSpec('P')
R = TypeVar('R')

# Human review has its own bounded lease. Dispatch receipts retain their
# separate 60-second lifetime, starting only after the relevant reviews.
REVIEW_TIMEOUT_SECONDS = 15 * 60


@dataclass(frozen=True)
class ReviewGuard:
    owner: ReviewTurn | None
    signal: Any
    expires: float
    clock: Callable[[], float]
    condition: Callable[[], bool] | None = None
    admission_check: Callable[[], None] | None = None

    def owner_is_current(self) -> bool:
        try:
            if self.admission_check is not None:
                self.admission_check()
        except (Exception, asyncio.CancelledError):
            return False
        return (not (self.owner is not None and self.owner.closed)
                and not (getattr(self.signal, 'aborted', False)
                         or getattr(self.signal, 'is_set', lambda: False)()))

    def is_current(self) -> bool:
        try:
            return (self.owner_is_current() and self.clock() < self.expires
                    and (self.condition is None or self.condition()))
        except Exception:
            return False

    def on_close(self, cleanup: Callable[[], None]) -> Callable[[], None]:
        owner = self.owner
        if owner is None:
            return lambda: None
        if owner.closed:
            cleanup()
        else:
            owner.cleanups.append(cleanup)
        def remove() -> None:
            if cleanup in owner.cleanups:
                owner.cleanups.remove(cleanup)
        return remove


def capture_review(*, signal: Any = None, clock: Callable[[], float] = time.monotonic,
                   timeout: float = REVIEW_TIMEOUT_SECONDS,
                   condition: Callable[[], bool] | None = None) -> ReviewGuard:
    review_id()  # Reject capture by a detached child of an already closed turn.
    return ReviewGuard(_turn.get(), signal, clock() + timeout, clock, condition, _admission.get())


@contextmanager
def controller_admission(check: Callable[[], None]):
    """Carry the Agent's skill check through existing review/dispatch guards.

    This transient callback can only restrict admission; it never grants rights
    and is captured per invocation, including native HTTP's inner reviews.
    """
    token = _admission.set(check)
    try:
        yield
    finally:
        _admission.reset(token)


@contextmanager
def review_turn():
    """Trusted Agent/UI entrypoint only; never called from a tool's arguments."""
    turn = ReviewTurn()
    token = _turn.set(turn)
    try:
        yield turn
    finally:
        turn.closed = True
        cleanups, turn.cleanups = turn.cleanups, []
        error: BaseException | None = None
        try:
            for cleanup in cleanups:
                try:
                    cleanup()
                except BaseException as exc:
                    if error is None:
                        error = exc
        finally:
            _turn.reset(token)
        if error is not None:
            raise error


def review_id() -> str:
    turn = _turn.get()
    if turn is not None and turn.closed:
        raise PermissionReviewStale('blocked: permission review turn ended')
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
