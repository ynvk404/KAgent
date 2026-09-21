from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.target.origin import HTTPOrigin


class OutOfScopeError(PermissionError):
    """A network destination is outside the current engagement scope."""


@dataclass(slots=True)
class EngagementState:
    version: int = 1
    revision: int = 0
    allowed_origins: frozenset[HTTPOrigin] = field(default_factory=frozenset)

    def add_origin(self, url: str) -> tuple[HTTPOrigin, bool]:
        origin = HTTPOrigin.from_url(url)
        if origin in self.allowed_origins:
            return origin, False
        self.allowed_origins = self.allowed_origins | {origin}
        self.revision += 1
        return origin, True

    def remove_origin(self, url: str) -> tuple[HTTPOrigin, bool]:
        origin = HTTPOrigin.from_url(url)
        if origin not in self.allowed_origins:
            return origin, False
        self.allowed_origins = self.allowed_origins - {origin}
        self.revision += 1
        return origin, True

    def reset_to_origin(self, url: str) -> tuple[HTTPOrigin, bool]:
        origin = HTTPOrigin.from_url(url)
        changed = self.allowed_origins != {origin}
        if changed:
            self.allowed_origins = frozenset({origin})
            self.revision += 1
        return origin, changed

    def initialize_target(self, url: str) -> bool:
        """Set the default exact-origin scope; return whether the origin changed."""
        _, changed = self.reset_to_origin(url)
        return changed

    def clear(self) -> bool:
        changed = bool(self.allowed_origins)
        if changed:
            self.allowed_origins = frozenset()
            self.revision += 1
        return changed

    def is_in_scope(self, url: str) -> bool:
        try:
            return HTTPOrigin.from_url(url) in self.allowed_origins
        except ValueError:
            return False

    def require_in_scope(self, url: str) -> HTTPOrigin:
        origin = HTTPOrigin.from_url(url)
        if origin not in self.allowed_origins:
            configured = ", ".join(
                item.as_url() for item in sorted(self.allowed_origins)
            ) or "(none)"
            raise OutOfScopeError(
                f"network origin {origin.as_url()} is outside the active engagement "
                f"scope; configured origins: {configured}. Use /scope add "
                f"{origin.as_url()} to authorize this additional origin, or /target "
                "<url> to start a new target engagement"
            )
        return origin

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "revision": self.revision,
            "allowed_origins": [
                origin.to_dict() for origin in sorted(self.allowed_origins)
            ],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "EngagementState":
        state = cls()
        if not isinstance(raw, dict):
            return state

        version = raw.get("version")
        revision = raw.get("revision")
        if isinstance(version, int) and not isinstance(version, bool) and version > 0:
            state.version = version
        if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 0:
            state.revision = revision

        origins = raw.get("allowed_origins")
        if isinstance(origins, list):
            state.allowed_origins = frozenset(
                origin
                for item in origins
                if (origin := HTTPOrigin.from_dict(item)) is not None
            )
        return state

    def replace_from(self, other: "EngagementState") -> None:
        self.version = other.version
        self.revision = other.revision
        self.allowed_origins = frozenset(other.allowed_origins)
