from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Optional, cast

from src.permission.permission import (
    Decision,
    PermissionRequest,
    Prompter,
    PermissionReviewStale,
)
from src.permission.runtime.invocations import capture_review, ReviewGuard


@dataclass(slots=True)
class BridgedPermissionRequest(PermissionRequest):
    resolve: Callable[[Decision], None]
    reject: Callable[[BaseException], None]

PermissionPublisher = Callable[[Optional[BridgedPermissionRequest]], None]


class BridgedPrompter(Prompter):
    def __init__(self, publish: PermissionPublisher):
        self._publish = publish
        self._session_allowed: set[str] = set()
        self._generation = 0

        self._busy = False
        self._owner: asyncio.Future[None] | None = None
        self._waiters: list[asyncio.Future[None]] = []
        self._visible: asyncio.Future[Decision] | None = None

    def clear_session_cache(self) -> None:
        self._session_allowed.clear()
        self._generation += 1

    def _key_for(self, req: PermissionRequest) -> str:
        return (
            f"{req.tool} {req.cache_key}"
            if req.cache_key
            else req.tool
        )

    @staticmethod
    def _is_aborted(signal) -> bool:
        return (
            getattr(signal, "aborted", False)
            or getattr(signal, "is_set", lambda: False)()
        )

    async def _await_with_signal(self, future, signal):
        if signal is None:
            return await future

        if self._is_aborted(signal):
            future.cancel()
            raise Exception("aborted")

        wait = getattr(signal, "wait", None)
        if not callable(wait):
            return await future

        abort_waiter = asyncio.create_task(
            cast(Coroutine[Any, Any, Any], wait())
        )
        try:
            done, _ = await asyncio.wait(
                {future, abort_waiter},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if abort_waiter in done:
                future.cancel()
                raise Exception("aborted")
            return future.result()
        finally:
            abort_waiter.cancel()
            await asyncio.gather(abort_waiter, return_exceptions=True)

    def _release_owner(self, owner: asyncio.Future[None]) -> None:
        if self._owner is not owner:
            return

        while self._waiters:
            waiter = self._waiters.pop(0)
            if not waiter.done():
                # Record ownership before waking the request. Its encompassing
                # finally releases this token even if the wait aborts/cancels.
                self._owner = waiter
                waiter.set_result(None)
                return

        self._owner = None
        self._busy = False

    @staticmethod
    def _watch_review(future: asyncio.Future, current: Callable[[], bool]) -> Callable[[], None]:
        # A cancellable timer preserves synchronous modal-clear/FIFO handoff
        # and leaves no background coroutine after a decision is delivered.
        loop = asyncio.get_running_loop()
        handle: asyncio.TimerHandle | None = None
        def tick() -> None:
            nonlocal handle
            if future.done():
                return
            if not current():
                future.set_exception(PermissionReviewStale('blocked: stale permission review'))
                return
            handle = loop.call_later(0.05, tick)
        handle = loop.call_later(0.05, tick)
        def cancel() -> None:
            if handle is not None:
                handle.cancel()
        return cancel

    async def ask(
        self,
        request: PermissionRequest,
        signal=None,
    ) -> Decision:
        if self._is_aborted(signal):
            raise Exception("aborted")

        guard = capture_review(signal=signal, condition=request.is_current)
        if not guard.is_current():
            raise PermissionReviewStale('blocked: stale permission review')

        if (
            request.supports_session and not request.no_session_cache
            and guard.is_current()
            and self._key_for(request) in self._session_allowed
        ):
            return Decision.ALLOW_ONCE

        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[None] = loop.create_future()
        cancel_monitor = self._watch_review(waiter, guard.is_current)
        def retire_waiter() -> None:
            if not waiter.done():
                waiter.set_exception(PermissionReviewStale('blocked: stale permission review'))
        remove_cleanup = guard.on_close(retire_waiter)
        try:
            if self._busy:
                self._waiters.append(waiter)
                await self._await_with_signal(waiter, signal)
            else:
                self._busy = True
                self._owner = waiter
                waiter.set_result(None)

            if self._is_aborted(signal):
                raise Exception("aborted")
            if not guard.is_current():
                raise PermissionReviewStale('blocked: stale permission review')
            if (
                request.supports_session and not request.no_session_cache
                and guard.is_current()
                and self._key_for(request) in self._session_allowed
            ):
                return Decision.ALLOW_ONCE

            return await self._ask_once(request, signal, guard)

        finally:
            if self._owner is waiter:
                self._release_owner(waiter)
            else:
                # A request that stopped before handoff never owned the bridge.
                if waiter in self._waiters:
                    self._waiters.remove(waiter)
            if not waiter.done():
                waiter.cancel()
            remove_cleanup()
            cancel_monitor()
            if waiter.done() and not waiter.cancelled():
                waiter.exception()

    async def _ask_once(
        self,
        req: PermissionRequest,
        signal,
        guard: ReviewGuard,
    ) -> Decision:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Decision] = loop.create_future()
        generation = self._generation
        cleared = False

        def clear_owned() -> None:
            nonlocal cleared
            if self._visible is future:
                self._visible = None
                self._publish(None)
                cleared = True

        def active() -> bool:
            return (not future.done() and not self._is_aborted(signal)
                    and generation == self._generation
                    and guard.is_current())

        def resolve(decision: Decision) -> None:
            if not active():
                # A late callback must neither mint authority nor clear a
                # different invocation's visible modal.
                if not future.done():
                    future.set_exception(PermissionReviewStale("blocked: stale permission review"))
                return
            if decision == Decision.ALLOW_SESSION and not req.supports_session:
                decision = Decision.DENY
            clear_owned()

            if not future.done():
                future.set_result(decision)

        def reject(err: BaseException) -> None:
            if future.done():
                return
            clear_owned()

            if not future.done():
                future.set_exception(err)

        wrapped = BridgedPermissionRequest(
            tool=req.tool,
            summary=req.summary,
            detail=req.detail,
            no_session_cache=req.no_session_cache,
            cache_key=req.cache_key,
            session_scope_display=req.session_scope_display,
            risk_tier=req.risk_tier,
            yolo_auto_approve=req.yolo_auto_approve,
            force_operator=req.force_operator,
            offer_http_lab=req.offer_http_lab,
            is_current=active,
            resolve=resolve,
            reject=reject,
        )

        cancel_monitor = self._watch_review(future, active)
        def retire_visible() -> None:
            if not future.done():
                future.set_exception(PermissionReviewStale('blocked: stale permission review'))
            clear_owned()
        remove_cleanup = guard.on_close(retire_visible)
        try:
            if not guard.is_current():
                raise PermissionReviewStale('blocked: stale permission review')
            self._visible = future
            self._publish(wrapped)
            decision = await self._await_with_signal(future, signal)
            # Commit reusable cache only after the invocation has received its
            # decision. A resolve/abort race must not leave orphaned authority.
            if (generation != self._generation or self._is_aborted(signal)
                    or not guard.is_current()):
                raise PermissionReviewStale("blocked: stale permission review")
            if decision == Decision.ALLOW_SESSION and not req.no_session_cache:
                self._session_allowed.add(self._key_for(req))
            return decision
        finally:
            if not future.done():
                future.cancel()
            if not cleared:
                clear_owned()
            remove_cleanup()
            cancel_monitor()
            if future.done() and not future.cancelled():
                future.exception()
