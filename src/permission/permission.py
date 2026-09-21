from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable, Any


class UserControlledRefusal(PermissionError):
    """A permission request explicitly declined by the operator."""

class Decision(str, Enum):
    ALLOW_ONCE = "allow-once"
    ALLOW_SESSION = "allow-session"
    DENY = "deny"

@dataclass(slots=True)
class PermissionRequest:
    tool: str
    summary: str
    detail: str
    no_session_cache: bool = field(default=False, kw_only=True)
    cache_key: str | None = field(default=None, kw_only=True)
    # Human-readable description of the cache scope.  This is presentation
    # metadata only; cache enforcement continues to use ``cache_key``.
    session_scope_display: str | None = field(default=None, kw_only=True)

@runtime_checkable
class Prompter(Protocol):
    async def ask(
        self,
        request: PermissionRequest,
        signal: Any = None,
    ) -> Decision:
        ...

class YoloPrompter:
    def __init__(
        self,
        inner: Prompter,
        initial: bool = False,
    ) -> None:
        self._inner = inner
        self._yolo = initial

    def set_yolo(
        self,
        enabled: bool,
    ) -> None:
        self._yolo = enabled

    def is_yolo(
        self,
    ) -> bool:
        return self._yolo

    def clear_session_cache(self) -> None:
        clear = getattr(self._inner, "clear_session_cache", None)
        if callable(clear):
            clear()

    async def ask(
        self,
        request: PermissionRequest,
        signal: Any = None,
    ) -> Decision:
        if self._yolo and not request.no_session_cache:
            return Decision.ALLOW_ONCE

        return await self._inner.ask(
            request,
            signal,
        )

class AlwaysAllow:
    async def ask(
        self,
        request: PermissionRequest,
        signal: Any = None,
    ) -> Decision:
        return Decision.ALLOW_ONCE

class AlwaysDeny:
    async def ask(
        self,
        request: PermissionRequest,
        signal: Any = None,
    ) -> Decision:
        return Decision.DENY
