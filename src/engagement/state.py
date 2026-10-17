from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Any

from src.target.origin import HTTPOrigin
from src.permission.network.grants import HTTPPermissions


class OutOfScopeError(PermissionError):
    """A network destination is outside the current engagement scope."""


def normalize_tcp_ip(value: object) -> str:
    if not isinstance(value, str) or value != value.strip() or '%' in value:
        raise ValueError("TCP scope requires an exact numeric IP without a zone identifier")
    address = ipaddress.ip_address(value)
    if address.is_unspecified or address.is_multicast or getattr(address, 'ipv4_mapped', None):
        raise ValueError("unsupported TCP destination address")
    return str(address)


def parse_tcp_ports(value: object) -> tuple[int, ...]:
    ports: set[int] = set()
    if isinstance(value, str):
        for part in value.split(','):
            if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", part):
                raise ValueError("ports must be explicit TCP port numbers or ranges")
            bounds = [int(n) for n in part.split('-')]
            first, last = bounds[0], bounds[-1]
            if not 1 <= first <= last <= 65535:
                raise ValueError("TCP ports must be between 1 and 65535")
            ports.update(range(first, last + 1))
    elif isinstance(value, (list, tuple)):
        if any(type(n) is not int or not 1 <= n <= 65535 for n in value):
            raise ValueError("TCP ports must be integers between 1 and 65535")
        ports.update(value)
    else:
        raise ValueError("an explicit TCP port set is required")
    if not ports:
        raise ValueError("TCP port set cannot be empty")
    return tuple(sorted(ports))


def format_tcp_ports(ports: tuple[int, ...]) -> str:
    ranges: list[str] = []
    for number in sorted(set(ports)):
        if ranges and int(ranges[-1].split('-')[-1]) == number - 1:
            ranges[-1] = ranges[-1].split('-')[0] + '-' + str(number)
        else:
            ranges.append(str(number))
    return ','.join(ranges)


@dataclass(frozen=True, order=True, slots=True)
class TCPScope:
    address: str
    ports: tuple[int, ...]


@dataclass(slots=True)
class EngagementState:
    version: int = 1
    revision: int = 0
    allowed_origins: frozenset[HTTPOrigin] = field(default_factory=frozenset)
    http_permissions: HTTPPermissions = field(init=False, repr=False, compare=False)
    allowed_tcp: frozenset[TCPScope] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        self.http_permissions = HTTPPermissions(self)

    def add_origin(self, url: str) -> tuple[HTTPOrigin, bool]:
        origin = HTTPOrigin.from_url(url)
        if origin in self.allowed_origins:
            return origin, False
        self.allowed_origins = self.allowed_origins | {origin}
        self.revision += 1
        self.http_permissions.scope_changed()
        return origin, True

    def remove_origin(self, url: str) -> tuple[HTTPOrigin, bool]:
        origin = HTTPOrigin.from_url(url)
        if origin not in self.allowed_origins:
            return origin, False
        self.allowed_origins = self.allowed_origins - {origin}
        self.revision += 1
        self.http_permissions.scope_changed()
        return origin, True

    def reset_to_origin(self, url: str) -> tuple[HTTPOrigin, bool]:
        origin = HTTPOrigin.from_url(url)
        changed = self.allowed_origins != {origin} or bool(self.allowed_tcp)
        if changed:
            self.allowed_origins = frozenset({origin})
            self.allowed_tcp = frozenset()
            self.revision += 1
            self.http_permissions.scope_changed()
        return origin, changed

    def initialize_target(self, url: str) -> bool:
        """Set the default exact-origin scope; return whether the origin changed."""
        _, changed = self.reset_to_origin(url)
        return changed

    def clear(self) -> bool:
        changed = bool(self.allowed_origins or self.allowed_tcp)
        if changed:
            self.allowed_origins = frozenset()
            self.allowed_tcp = frozenset()
            self.revision += 1
            self.http_permissions.scope_changed()
        return changed

    def add_tcp(self, address: str, ports: object) -> tuple[TCPScope, bool]:
        address = normalize_tcp_ip(address)
        previous = next((entry for entry in self.allowed_tcp if entry.address == address), None)
        merged = tuple(sorted(set(parse_tcp_ports(ports)) | set(previous.ports if previous else ())))
        entry = TCPScope(address, merged)
        changed = entry != previous
        if changed:
            self.allowed_tcp = frozenset(item for item in self.allowed_tcp if item.address != address) | {entry}
            self.revision += 1
            self.http_permissions.scope_changed()
        return entry, changed

    def remove_tcp(self, address: str, ports: object = None) -> bool:
        address = normalize_tcp_ip(address)
        removed = set(parse_tcp_ports(ports)) if ports is not None else None
        previous = next((entry for entry in self.allowed_tcp if entry.address == address), None)
        if previous is None:
            return False
        remaining = tuple(p for p in previous.ports if removed is not None and p not in removed)
        if remaining == previous.ports:
            return False
        self.allowed_tcp = frozenset(entry for entry in self.allowed_tcp if entry.address != address)
        if remaining:
            self.allowed_tcp |= {TCPScope(address, remaining)}
        self.revision += 1
        self.http_permissions.scope_changed()
        return True

    def tcp_allows(self, address: str, ports: object) -> bool:
        address, requested = normalize_tcp_ip(address), set(parse_tcp_ports(ports))
        return any(entry.address == address and requested <= set(entry.ports) for entry in self.allowed_tcp)

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
            "allowed_tcp": [{"address": item.address, "ports": format_tcp_ports(item.ports)}
                            for item in sorted(self.allowed_tcp)],
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
        entries = raw.get("allowed_tcp")
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                try:
                    address = normalize_tcp_ip(entry.get("address"))
                    ports = parse_tcp_ports(entry.get("ports"))
                    previous = next((item for item in state.allowed_tcp if item.address == address), None)
                    merged = tuple(sorted(set(ports) | set(previous.ports if previous else ())))
                    state.allowed_tcp = frozenset(item for item in state.allowed_tcp if item.address != address) | {TCPScope(address, merged)}
                except ValueError:
                    continue
        return state

    def replace_from(self, other: "EngagementState") -> None:
        self.http_permissions.reset(preserve_denial=True)
        self.version = other.version
        self.revision = other.revision
        self.allowed_origins = frozenset(other.allowed_origins)
        self.allowed_tcp = frozenset(other.allowed_tcp)
