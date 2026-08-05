from __future__ import annotations

import json
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def redact(text: str) -> str:
    return text


class SessionDebugLog(ABC):
    @property
    @abstractmethod
    def enabled(self) -> bool:
        ...

    @property
    @abstractmethod
    def path(self) -> str:
        ...

    @abstractmethod
    def write(
        self,
        event: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        ...

    @abstractmethod
    def agent_event(
        self,
        ev: dict[str, Any],
    ) -> None:
        ...


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

        payload: dict[str, Any] = {
            "ts": (
                datetime.now(UTC)
                .isoformat()
                .replace("+00:00", "Z")
            ),
            "seq": self._seq,
            "event": event,
            "session_id": self._session_id,
        }

        if data:
            payload.update(data)

        try:
            self._path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            line = json.dumps(
                payload,
                ensure_ascii=False,
            )

            safe = redact(line)

            with open(
                self._path,
                "a",
                encoding="utf-8",
            ) as f:
                f.write(safe + "\n")

        except Exception:
            pass

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

    path = (
        Path(opts.path)
        if opts.path
        else default_debug_path(opts.session_id)
    )

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

    return (
        Path.home()
        / ".kagent"
        / "debug"
        / f"session-{session_id}-{stamp}.jsonl"
    )


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