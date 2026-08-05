from __future__ import annotations

import asyncio

import pytest

from src.ui.utils.ping import PING_TIMEOUT, PingTask


class DummyClient:
    async def ping(self) -> None:
        return None


class FailingClient:
    async def ping(self) -> None:
        raise RuntimeError("boom")


class SlowClient:
    async def ping(self) -> None:
        await asyncio.sleep(3600)


@pytest.mark.asyncio
async def test_client_without_ping_is_ready(monkeypatch):
    ready: list[bool] = []

    class NoPing:
        pass

    async def fast_sleep(_: float) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)

    task = PingTask(lambda: NoPing(), ready.append)
    task._running = True

    with pytest.raises(asyncio.CancelledError):
        await task._loop()

    assert ready == [True]


@pytest.mark.asyncio
async def test_successful_ping_sets_ready(monkeypatch):
    ready: list[bool] = []

    async def fast_sleep(_: float) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)

    task = PingTask(lambda: DummyClient(), ready.append)
    task._running = True

    with pytest.raises(asyncio.CancelledError):
        await task._loop()

    assert ready == [True]


@pytest.mark.asyncio
async def test_failed_ping_sets_not_ready(monkeypatch):
    ready: list[bool] = []

    async def fast_sleep(_: float) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)

    task = PingTask(lambda: FailingClient(), ready.append)
    task._running = True

    with pytest.raises(asyncio.CancelledError):
        await task._loop()

    assert ready == [False]


@pytest.mark.asyncio
async def test_ping_timeout_sets_not_ready(monkeypatch):
    ready: list[bool] = []

    monkeypatch.setattr(
        "src.ui.utils.ping.PING_TIMEOUT",
        0.01,
    )
    task = PingTask(lambda: SlowClient(), ready.append)
    task._running = True

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(
            task._loop(),
            timeout=0.1,
        )

    assert ready == [False]


@pytest.mark.asyncio
async def test_start_only_creates_one_task():
    ready: list[bool] = []

    task = PingTask(lambda: DummyClient(), ready.append)

    task.start()
    first = task._task

    task.start()

    assert task._task is first

    await task.stop()


@pytest.mark.asyncio
async def test_stop_cancels_background_task():
    ready: list[bool] = []

    task = PingTask(lambda: DummyClient(), ready.append)

    task.start()

    assert task._task is not None

    await task.stop()

    assert task._task is None
    assert task._running is False