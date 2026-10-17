import asyncio
import json
import logging
import threading
import time

import pytest

from src.async_io import run_sync
from src.logger import logger as module
from src.logger.session_debug import FileSessionDebugLog
from src.logger.writer import BackgroundWriter


@pytest.mark.parametrize("kind", ["debug", "normal"])
async def test_slow_writer_keeps_producers_responsive_and_exposes_queue_overflow(tmp_path, kind):
    target = tmp_path / (kind + ".jsonl")
    if kind == "debug":
        log = FileSessionDebugLog("password=synthetic-secret", target)
        writer = log.writer
        emit = lambda index: log.write("fixture", {"index": index, "password": "synthetic-secret"})
        close = log.aclose
    else:
        module.init(target)
        log = logging.getLogger(module.BASE_LOGGER_NAME)
        handler = log.handlers[0]
        assert isinstance(handler, module.SecureRotatingFileHandler)
        writer = handler.writer
        emit = lambda index: log.warning("fixture %s password=synthetic-secret", index)
        close = module.aclose
    writer.max_records = 2
    entered, release = threading.Event(), threading.Event()
    original = writer.write
    io_threads = []
    def hold(text):
        io_threads.append(threading.get_ident())
        if not entered.is_set():
            entered.set()
            assert release.wait(2)
        original(text)
    writer.write = hold
    beats = []
    async def heartbeat():
        while True:
            beats.append(time.monotonic())
            await asyncio.sleep(0.01)
    heartbeat_task = asyncio.create_task(heartbeat())
    emit(0)
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        for index in range(1, 20):
            emit(index)
        for _ in range(5):
            await asyncio.sleep(0.01)
        assert writer.dropped_records >= 17
        assert len(writer.queue) <= 2 and writer.bytes_pending <= writer.max_bytes
        closing = asyncio.create_task(close())
        await asyncio.sleep(0)
        assert not closing.done()
    finally:
        release.set()
    await closing
    heartbeat_task.cancel()
    await asyncio.gather(heartbeat_task, return_exceptions=True)
    assert writer.thread is not None and not writer.thread.is_alive()
    assert all(thread != threading.get_ident() for thread in io_threads)
    text = target.read_text()
    assert "synthetic-secret" not in text and "[REDACTED" in text
    records = [json.loads(line) for line in text.splitlines()]
    assert any(row.get("count", 0) >= 17 for row in records)
    assert target.stat().st_mode & 0o077 == 0
    if kind == "debug":
        sequences = [row["seq"] for row in records if "seq" in row]
        assert sequences == sorted(sequences)
    print({"logging_heartbeat_gap_ms": max(b-a for a,b in zip(beats,beats[1:])) * 1000,
           "dropped_records": writer.dropped_records})


async def test_failed_writer_stops_without_retry_loop_or_sensitive_error():
    def fail(text):
        raise OSError("password=must-not-be-exposed")
    writer = BackgroundWriter(fail)
    writer.submit("safe already redacted line")
    await run_sync(writer.close)
    assert writer.last_error == "OSError" and writer.failed_records == 1
    assert writer.thread is not None and not writer.thread.is_alive()
    assert not writer.submit("later") and writer.dropped_records == 1


async def test_cancelled_shutdown_joins_active_writer_and_records_drain_limit():
    entered, release = threading.Event(), threading.Event()
    writes = []
    def write(text):
        entered.set()
        assert release.wait(2)
        writes.append(text)
    writer = BackgroundWriter(write)
    writer.submit("first")
    assert await asyncio.to_thread(entered.wait, 1)
    writer.submit("queued")
    closing = asyncio.create_task(run_sync(writer.close, 0.01))
    try:
        for _ in range(5):
            await asyncio.sleep(0.01)
        assert writer.flush_timed_out and writer.dropped_records == 1
        closing.cancel()
        await asyncio.sleep(0)
        assert not closing.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await closing
    assert writer.thread is not None
    assert writes == ["first"] and not writer.thread.is_alive()
