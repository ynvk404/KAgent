from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable, Optional

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
        self._waiters: list[asyncio.Future[None]] = []

    def _key_for(self, req: PermissionRequest) -> str:
        return (
            f"{req.tool} {req.cache_key}"
            if req.cache_key
            else req.tool
        )

    async def ask(
        self,
        req: PermissionRequest,
        signal=None,
    ) -> Decision:
        if (
            not req.no_session_cache
            and self._key_for(req) in self._session_allowed
        ):
            return Decision.ALLOW_ONCE

        if self._busy:
            loop = asyncio.get_running_loop()
            waiter: asyncio.Future[None] = loop.create_future()
            self._waiters.append(waiter)
            await waiter
        else:
            self._busy = True

        try:
            if (
                not req.no_session_cache
                and self._key_for(req) in self._session_allowed
            ):
                return Decision.ALLOW_ONCE

            return await self._ask_once(req)

        finally:
            if self._waiters:
                waiter = self._waiters.pop(0)
                if not waiter.done():
                    waiter.set_result(None)
            else:
                self._busy = False

    async def _ask_once(
        self,
        req: PermissionRequest,
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
            resolve=resolve,
            reject=reject,
        )

        self._publish(wrapped)

        return await future