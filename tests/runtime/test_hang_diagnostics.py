from __future__ import annotations

import asyncio
import time

import pytest

from src.logger.hang_diagnostics import HangDiagnostics


@pytest.mark.asyncio
async def test_watchdog_dumps_all_threads_when_event_loop_stalls(tmp_path) -> None:
    output = tmp_path / "stalls.log"
    diagnostics = HangDiagnostics(
        output,
        stall_seconds=0.05,
        poll_seconds=0.01,
    )
    diagnostics.set_stage("session.save.replace")
    diagnostics.start()

    try:
        time.sleep(0.12)
        await asyncio.sleep(0.03)
    finally:
        await diagnostics.stop()

    text = output.read_text(encoding="utf-8")
    assert "KAgent event-loop stall" in text
    assert "stage=session.save.replace" in text
    assert "test_watchdog_dumps_all_threads_when_event_loop_stalls" in text
    assert output.stat().st_mode & 0o077 == 0


@pytest.mark.asyncio
async def test_watchdog_does_not_dump_while_loop_is_responsive(tmp_path) -> None:
    output = tmp_path / "stalls.log"
    diagnostics = HangDiagnostics(
        output,
        stall_seconds=0.08,
        poll_seconds=0.01,
    )
    diagnostics.start()

    try:
        await asyncio.sleep(0.15)
    finally:
        await diagnostics.stop()

    assert not output.exists()

