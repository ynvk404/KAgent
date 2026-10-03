from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Optional, cast

from src.permission.permission import (
    Decision,
    PermissionRequest,
    Prompter,
)


@dataclass(slots=True)
class BridgedPermissionRequest(PermissionRequest):
    resolve: Callable[[Decision], None]
    reject: Callable[[Exception], None]

PermissionPublisher = Callable[[Optional[BridgedPermissionRequest]], None]


class BridgedPrompter(Prompter):
    def __init__(self, publish: PermissionPublisher):
        self._publish = publish
        self._session_allowed: set[str] = set()

        self._busy = False
        self._owner: asyncio.Future[None] | None = None
        self._waiters: list[asyncio.Future[None]] = []

    def clear_session_cache(self) -> None:
        self._session_allowed.clear()

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

    async def ask(
        self,
        request: PermissionRequest,
        signal=None,
    ) -> Decision:
        if self._is_aborted(signal):
            raise Exception("aborted")

        if (
            not request.no_session_cache
            and self._key_for(request) in self._session_allowed
        ):
            return Decision.ALLOW_ONCE

        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[None] = loop.create_future()
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
            if (
                not request.no_session_cache
                and self._key_for(request) in self._session_allowed
            ):
                return Decision.ALLOW_ONCE

            return await self._ask_once(request, signal)

        finally:
            if self._owner is waiter:
                self._release_owner(waiter)
            else:
                # A request that stopped before handoff never owned the bridge.
                if waiter in self._waiters:
                    self._waiters.remove(waiter)
            if not waiter.done():
                waiter.cancel()

    async def _ask_once(
        self,
        req: PermissionRequest,
        signal,
    ) -> Decision:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Decision] = loop.create_future()

        def resolve(decision: Decision) -> None:
            if (
                decision == Decision.ALLOW_SESSION
                and not req.no_session_cache
            ):
                self._session_allowed.add(self._key_for(req))

            self._publish(None)

            if not future.done():
                future.set_result(decision)

        def reject(err: Exception) -> None:
            self._publish(None)

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
            offer_http_lab=req.offer_http_lab,
            resolve=resolve,
            reject=reject,
        )

        try:
            self._publish(wrapped)
            return await self._await_with_signal(future, signal)
        finally:
            if not future.done():
                future.cancel()
            if future.cancelled():
                self._publish(None)
