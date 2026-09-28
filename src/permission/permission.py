from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Protocol, runtime_checkable

RiskTier = Literal["routine", "bounded-impact", "high-impact"]
_RISK_TIERS = frozenset({"routine", "bounded-impact", "high-impact"})


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
    risk_tier: RiskTier = field(default="routine", kw_only=True)
    # Set only when the tool has validated the action as routine and in scope.
    # This is deliberately independent of risk_tier and session-cache policy.
    yolo_auto_approve: bool = field(default=False, kw_only=True)

    def __post_init__(self) -> None:
        if self.risk_tier not in _RISK_TIERS:
            raise ValueError(f"unknown permission risk tier: {self.risk_tier}")

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
        if self._yolo and request.yolo_auto_approve:
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
