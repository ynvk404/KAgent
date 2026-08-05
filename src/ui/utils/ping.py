from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

PING_INTERVAL = 15
PING_TIMEOUT = 5


def is_pinger(client: object) -> bool:
    return callable(getattr(client, "ping", None))


class PingTask:

    def __init__(
        self,
        get_client: Callable[[], Any],
        set_ready: Callable[[bool], None],
    ) -> None:
        self._get_client = get_client
        self._set_ready = set_ready
        self._running = False
        self._task: asyncio.Task[None] | None = None

    async def _loop(self) -> None:
        try:
            while self._running:
                client = self._get_client()

                if not is_pinger(client):
                    if self._running:
                        self._set_ready(True)
                else:
                    try:
                        await asyncio.wait_for(
                            client.ping(),
                            timeout=PING_TIMEOUT,
                        )

                        if self._running:
                            self._set_ready(True)

                    except Exception:
                        if self._running:
                            self._set_ready(False)

                if self._running:
                    await asyncio.sleep(PING_INTERVAL)

        except asyncio.CancelledError:
            raise

    def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False

        if self._task is None:
            return

        self._task.cancel()

        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None