"""Bounded ordered log writer. Producers never wait for filesystem I/O."""
from collections import deque
from collections.abc import Callable
import threading


class BackgroundWriter:
    def __init__(self, write: Callable[[str], None], *, max_records: int = 512,
                 max_bytes: int = 2 * 1024 * 1024, drop_record: Callable[[int], str] | None = None):
        self.write = write
        self.max_records, self.max_bytes = max_records, max_bytes
        self.drop_record = drop_record
        self.queue: deque[tuple[str, int]] = deque()
        self.condition = threading.Condition()
        self.thread: threading.Thread | None = None
        self.bytes_pending = 0
        self.active = False
        self.closed = False
        self.dropped_records = 0
        self.failed_records = 0
        self.last_error: str | None = None
        self.flush_timed_out = False
        self._reported_drops = 0

    def submit(self, text: str) -> bool:
        size = len(text.encode("utf-8"))
        with self.condition:
            if self.closed or len(self.queue) >= self.max_records or self.bytes_pending + size > self.max_bytes:
                self.dropped_records += 1
                return False
            self.queue.append((text, size))
            self.bytes_pending += size
            if self.thread is None:
                self.thread = threading.Thread(target=self._run, name="kagent-log-writer", daemon=True)
                self.thread.start()
            self.condition.notify_all()
            return True

    def _run(self):
        while True:
            with self.condition:
                self.condition.wait_for(lambda: self.queue or self.closed)
                if not self.queue:
                    return
                text, size = self.queue.popleft()
                self.active = True
                dropped = self.dropped_records - self._reported_drops
            try:
                if dropped and self.drop_record is not None:
                    self.write(self.drop_record(dropped))
                    self._reported_drops += dropped
                self.write(text)
            except Exception as error:
                with self.condition:
                    self.failed_records += 1
                    self.last_error = type(error).__name__
                    self.dropped_records += len(self.queue)
                    self.queue.clear()
                    self.bytes_pending = size
                    self.closed = True
            finally:
                with self.condition:
                    self.bytes_pending -= size
                    self.active = False
                    self.condition.notify_all()

    def flush(self, timeout: float = 3.0) -> bool:
        with self.condition:
            ready = self.condition.wait_for(lambda: not self.queue and not self.active, timeout)
            self.flush_timed_out |= not ready
            return ready

    def close(self, timeout: float = 3.0) -> None:
        with self.condition:
            self.closed = True
            self.condition.notify_all()
        if not self.flush(timeout):
            with self.condition:
                self.dropped_records += len(self.queue)
                self.bytes_pending -= sum(size for _, size in self.queue)
                self.queue.clear()
                self.condition.notify_all()
        # A running kernel write cannot be interrupted safely. Join that one
        # operation before releasing the file; never leave a writer after close.
        if self.thread is not None:
            self.thread.join()
