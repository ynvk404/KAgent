from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Optional, cast

from src.ask.ask import AskPrompter, Question


@dataclass(slots=True)
class AskRequest:
    question: Question
    resolve: Callable[[str], None]
    reject: Callable[[Exception], None]


AskPublisher = Callable[[Optional[AskRequest]], None]


class BridgedAskPrompter(AskPrompter):
    def __init__(self, publish: AskPublisher):
        self._publish = publish

    async def _await_with_signal(self, future, signal) -> str:
        if signal is None:
            return await future

        if getattr(signal, "aborted", False) or getattr(
            signal, "is_set", lambda: False
        )():
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

    async def ask(self, q: Question, signal: Any = None) -> str:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[str] = loop.create_future()

        if getattr(signal, "aborted", False) or getattr(
            signal, "is_set", lambda: False
        )():
            future.cancel()
            raise Exception("aborted")

        def resolve(label: str) -> None:
            self._publish(None)
            if not future.done():
                future.set_result(label)

        def reject(err: Exception) -> None:
            self._publish(None)
            if not future.done():
                future.set_exception(err)

        self._publish(
            AskRequest(
                question=q,
                resolve=resolve,
                reject=reject,
            )
        )

        try:
            return await self._await_with_signal(future, signal)
        finally:
            if not future.done():
                future.cancel()
            if future.cancelled():
                self._publish(None)
