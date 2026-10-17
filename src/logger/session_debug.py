from __future__ import annotations

import json
import asyncio
from src.async_io import run_sync
from src.logger.writer import BackgroundWriter
import os
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.logger.logger import get_logger
from src.paths import user_data_root
from src.redaction.redact import redact_payload

log = get_logger("session_debug")
DEBUG_DIR_MODE = 0o700
DEBUG_FILE_MODE = 0o600


class SessionDebugLog(ABC):
    async def aclose(self) -> None:
        """Drain owned resources; disabled/test logs have nothing to close."""
        return None

    @property
    @abstractmethod
    def enabled(self) -> bool: ...

    @property
    @abstractmethod
    def path(self) -> str: ...

    @abstractmethod
    def write(
        self,
        event: str,
        data: dict[str, Any] | None = None,
    ) -> None: ...

    @abstractmethod
    def agent_event(
        self,
        ev: dict[str, Any],
    ) -> None: ...


class DisabledSessionDebugLog(SessionDebugLog):
    @property
    def enabled(self) -> bool:
        return False

    @property
    def path(self) -> str:
        return ""

    def write(
        self,
        event: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        pass

    def agent_event(
        self,
        ev: dict[str, Any],
    ) -> None:
        pass


disabled_session_debug_log = DisabledSessionDebugLog()


class FileSessionDebugLog(SessionDebugLog):
    def __init__(
        self,
        session_id: str,
        path: Path,
    ):
        self._enabled = True
        self._path = path
        self._session_id = session_id
        self._seq = 0
        self._write_failed = False
        self.writer = BackgroundWriter(self._write_line, drop_record=lambda count: json.dumps(redact_payload({
            "event": "debug_records_dropped", "count": count, "session_id": self._session_id})))

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def path(self) -> str:
        return str(self._path)

    def write(
        self,
        event: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        self._seq += 1

        metadata: dict[str, Any] = {
            "ts": (datetime.now(UTC).isoformat().replace("+00:00", "Z")),
            "seq": self._seq,
            "event": event,
            "session_id": self._session_id,
        }

        payload: dict[str, Any] = {}
        if data:
            payload.update(data)
        if payload.get("type") == "tool-result" and payload.get("name") == "workflow":
            from src.workflow.validation_context import without_transient_validation_context
            if isinstance(payload.get("result"), str):
                payload["result"] = without_transient_validation_context(
                    payload["result"], truncated=payload.get("truncated") is True,
                )
        # Event metadata identifies the actual persisted record and must not
        # be forgeable through the public data payload.
        payload.update(metadata)

        try:
            line = json.dumps(redact_payload(payload), ensure_ascii=False)
            if self.writer.closed:
                self.writer.submit(line)
                return
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                if self.writer.thread is None:
                    self._write_line(line)
                else:
                    self.writer.submit(line)
                    self.writer.flush()
            else:
                self.writer.submit(line)
        except Exception:
            self._write_failed = True
            log.warning("session debug record failed", exc_info=True)

    def _write_line(self, line: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=DEBUG_DIR_MODE)
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, DEBUG_FILE_MODE)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), DEBUG_FILE_MODE)
            stream.write(line + "\n")

    @property
    def dropped_records(self) -> int:
        return self.writer.dropped_records

    @property
    def last_error(self) -> str | None:
        return self.writer.last_error

    async def aclose(self) -> None:
        await run_sync(self.writer.close)
        if self.writer.last_error or self.writer.dropped_records:
            log.warning("session debug writer incomplete: failed=%d dropped=%d",
                        self.writer.failed_records, self.writer.dropped_records)

    def agent_event(
        self,
        ev: dict[str, Any],
    ) -> None:
        self.write(
            "agent_event",
            serialize_agent_event(ev),
        )


@dataclass(slots=True)
class SessionDebugOptions:
    enabled: bool
    session_id: str
    path: str | None = None


def create_session_debug_log(
    opts: SessionDebugOptions,
) -> SessionDebugLog:
    if not opts.enabled:
        return disabled_session_debug_log

    path = Path(opts.path) if opts.path else default_debug_path(opts.session_id)

    return FileSessionDebugLog(
        opts.session_id,
        path,
    )


def default_debug_path(
    session_id: str,
) -> Path:
    stamp = (
        datetime.now(UTC)
        .isoformat()
        .replace("+00:00", "Z")
        .replace(":", "-")
        .replace(".", "-")
    )

    return user_data_root() / "debug" / f"session-{session_id}-{stamp}.jsonl"


def serialize_agent_event(
    ev: dict[str, Any],
) -> dict[str, Any]:
    if ev.get("type") == "error":
        return {
            "type": "error",
            "err": serialize_error(
                ev.get("err"),
            ),
        }

    return ev


def serialize_error(
    err: Any,
) -> dict[str, Any]:
    if isinstance(
        err,
        BaseException,
    ):
        return {
            "name": err.__class__.__name__,
            "message": str(err),
            "stack": "".join(
                traceback.format_exception(
                    type(err),
                    err,
                    err.__traceback__,
                )
            ),
        }

    return {
        "message": str(err),
    }
