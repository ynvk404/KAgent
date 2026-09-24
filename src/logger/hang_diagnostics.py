"""Event-loop stall diagnostics for explicitly enabled debug sessions."""

from __future__ import annotations

import asyncio
import faulthandler
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path


DEFAULT_STALL_SECONDS = 2.0
DEFAULT_POLL_SECONDS = 0.25
DIAGNOSTIC_FILE_MODE = 0o600
DIAGNOSTIC_DIR_MODE = 0o700


class HangDiagnostics:
    """Dump all Python thread stacks when the asyncio loop stops ticking."""

    def __init__(
        self,
        path: str | Path,
        *,
        stall_seconds: float = DEFAULT_STALL_SECONDS,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
    ) -> None:
        self.path = Path(path)
        self.stall_seconds = stall_seconds
        self.poll_seconds = poll_seconds
        self._last_heartbeat = time.monotonic()
        self._stage = "idle"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._dumped_for_stall = False

    @classmethod
    def beside_debug_log(cls, debug_path: str | Path) -> HangDiagnostics:
        path = Path(debug_path)
        return cls(path.with_name(f"{path.stem}.stacks.log"))

    @property
    def stage(self) -> str:
        return self._stage

    def set_stage(self, stage: str) -> None:
        self._stage = stage

    def clear_stage(self, stage: str) -> None:
        if self._stage == stage:
            self._stage = "idle"

    def heartbeat(self) -> None:
        self._last_heartbeat = time.monotonic()
        self._dumped_for_stall = False

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self.heartbeat()
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(),
            name="event-loop-hang-heartbeat",
        )
        self._thread = threading.Thread(
            target=self._watch,
            name="event-loop-hang-watchdog",
            daemon=True,
        )
        self._thread.start()

    async def stop(self) -> None:
        self._stop.set()
        task = self._heartbeat_task
        self._heartbeat_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        thread = self._thread
        self._thread = None
        if thread is not None:
            await asyncio.to_thread(thread.join, max(1.0, self.poll_seconds * 2))

    async def _heartbeat_loop(self) -> None:
        interval = min(0.25, max(0.01, self.stall_seconds / 4))
        while True:
            self.heartbeat()
            await asyncio.sleep(interval)

    def _watch(self) -> None:
        while not self._stop.wait(self.poll_seconds):
            lag = time.monotonic() - self._last_heartbeat
            if lag < self.stall_seconds or self._dumped_for_stall:
                continue
            self._dumped_for_stall = True
            self._dump(lag)

    def _dump(self, lag: float) -> None:
        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
                mode=DIAGNOSTIC_DIR_MODE,
            )
            fd = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                DIAGNOSTIC_FILE_MODE,
            )
            with os.fdopen(fd, "a", encoding="utf-8") as output:
                timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
                output.write(
                    f"\n=== KAgent event-loop stall {timestamp} "
                    f"lag={lag:.3f}s stage={self._stage} ===\n"
                )
                output.flush()
                faulthandler.dump_traceback(file=output, all_threads=True)
                output.write("=== end stall dump ===\n")
        except Exception:
            # Diagnostics must never turn a suspected hang into a crash.
            return

