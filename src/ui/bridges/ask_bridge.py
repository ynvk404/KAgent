from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable, Optional

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

    async def ask(self, question: Question) -> str:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[str] = loop.create_future()

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
                question=question,
                resolve=resolve,
                reject=reject,
            )
        )

        return await future