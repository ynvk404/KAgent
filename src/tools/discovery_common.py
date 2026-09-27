from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx

from src.engagement.state import EngagementState
from src.target.origin import HTTPOrigin
from src.target.target import Target


@dataclass(frozen=True, slots=True)
class DiscoveryScope:
    origin: HTTPOrigin
    base_url: str
    base_path: str


def resolve_discovery_scope(
    target: Target,
    engagement: EngagementState,
    requested_base: str | None,
) -> DiscoveryScope:
    target_url = target.base_url().strip()
    if not target_url:
        raise ValueError("an active HTTP target is required")
    target_parts = _http_parts(target_url)
    if target_parts.username is not None or target_parts.password is not None:
        raise ValueError("credential-bearing target URLs are not supported")
    active_origin = HTTPOrigin.from_url(target_url)
    normalize_host(active_origin.hostname)
    target_path = target_parts.path or "/"

    if requested_base is None or not requested_base.strip():
        raw_base = target_url
    else:
        raw_base = requested_base.strip()
        if raw_base.startswith(("http://", "https://")):
            pass
        elif raw_base.startswith("/"):
            if "?" in raw_base or "#" in raw_base:
                raise ValueError("base_url must not include a query or fragment")
            raw_base = active_origin.as_url() + raw_base
        else:
            if "://" in raw_base or "?" in raw_base or "#" in raw_base:
                raise ValueError("base_url must be a same-origin URL path")
            raw_base = (
                active_origin.as_url()
                + target_path.rstrip("/")
                + "/"
                + raw_base
            )

    base_parts = _http_parts(raw_base)
    if base_parts.username is not None or base_parts.password is not None:
        raise ValueError("credential-bearing URLs are not supported")
    origin = HTTPOrigin.from_url(raw_base)
    if origin != active_origin:
        raise ValueError("discovery base must match the active target origin")
    if base_parts.query or base_parts.fragment:
        raise ValueError("discovery base must not include a query or fragment")
    engagement.require_in_scope(origin.as_url())
    _validate_base_path(base_parts.path)
    canonical_url = str(httpx.URL(origin.as_url() + (base_parts.path or "/")))
    canonical_parts = _http_parts(canonical_url)
    if HTTPOrigin.from_url(canonical_url) != origin:
        raise ValueError("discovery base must match the active target origin")
    base_path = _canonicalize_base_path(canonical_parts.path).rstrip("/") or ""
    return DiscoveryScope(
        origin=origin,
        base_url=origin.as_url() + base_path,
        base_path=base_path,
    )


def validate_relative_path(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("paths must contain strings")
    path = value.strip().lstrip("/")
    if (
        not path
        or len(path) > 200
        or any(ord(char) < 32 for char in path)
        or "\\" in path
        or "?" in path
        or "#" in path
        or "://" in path
    ):
        raise ValueError("each discovery path must be a non-empty relative path")
    decoded = path
    for _ in range(5):
        if re.search(r"%(?:2f|5c|3f|23)", decoded, re.IGNORECASE):
            raise ValueError("encoded path delimiters are not allowed")
        if any(ord(char) < 32 for char in decoded) or "\\" in decoded:
            raise ValueError("encoded control characters and backslashes are not allowed")
        if decoded.startswith("/") or "?" in decoded or "#" in decoded:
            raise ValueError("encoded path delimiters are not allowed")
        if any(part in {".", ".."} for part in decoded.split("/")):
            raise ValueError("path traversal segments are not allowed")
        decoded_next = unquote(decoded)
        if decoded_next == decoded:
            break
        decoded = decoded_next
    else:
        raise ValueError("path uses excessive percent-encoding")
    return _canonicalize_base_path(path)


def normalize_host(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("target must be a hostname or IP address")
    host = value.strip().rstrip(".").lower()
    if not host or any(char in host for char in "/\\?#,@"):
        raise ValueError("target must be one hostname or IP address")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        address = ipaddress.ip_address(host)
        if getattr(address, "scope_id", None) is not None:
            raise ValueError("scoped IPv6 addresses are not supported")
        return str(address)
    except ValueError:
        if (
            any(char.isspace() for char in host)
            or host.startswith("-")
            or "=" in host
            or len(host) > 253
            or re.fullmatch(r"[0-9.]+", host) is not None
        ):
            raise ValueError("target must be a valid hostname or IP address")
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as err:
            raise ValueError("target hostname is invalid") from err
        labels = ascii_host.split(".")
        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("target must be a valid hostname or IP address")
        return ascii_host


def _validate_base_path(path: str) -> None:
    if any(ord(char) < 32 or char == "\\" or char.isspace() for char in path):
        raise ValueError("discovery base path contains unsupported characters")
    if re.search(r"%(?:2f|5c|3f|23)", path, re.IGNORECASE):
        raise ValueError("encoded path delimiters are not allowed in discovery base")
    decoded = path
    for _ in range(5):
        if re.search(r"%(?:2f|5c|3f|23)", decoded, re.IGNORECASE):
            raise ValueError("encoded path delimiters are not allowed in discovery base")
        if (
            any(ord(char) < 32 or char.isspace() for char in decoded)
            or "\\" in decoded
            or "?" in decoded
            or "#" in decoded
        ):
            raise ValueError("discovery base path contains encoded delimiters")
        if any(part in {".", ".."} for part in decoded.split("/")):
            raise ValueError("dot segments are not allowed in discovery base")
        next_value = unquote(decoded)
        if next_value == decoded:
            return
        decoded = next_value
    raise ValueError("discovery base path uses excessive percent-encoding")


def _canonicalize_base_path(path: str) -> str:
    unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

    def normalize_escape(match: re.Match[str]) -> str:
        value = int(match.group(1), 16)
        character = chr(value)
        return character if character in unreserved else f"%{value:02X}"

    return re.sub(r"%([0-9a-fA-F]{2})", normalize_escape, path)


def validate_ports(value: object, default_ports: tuple[int, ...]) -> tuple[int, ...]:
    if value is None:
        return default_ports
    if not isinstance(value, list) or not value:
        raise ValueError("ports must be a non-empty list of TCP ports")
    if len(value) > 100:
        raise ValueError("at most 100 ports may be scanned per call")
    ports: list[int] = []
    for port in value:
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
        ):
            raise ValueError("each port must be an integer from 1 through 65535")
        if port not in ports:
            ports.append(port)
    return tuple(ports)


def is_aborted(signal: Any) -> bool:
    return signal is not None and bool(getattr(signal, "aborted", False))


async def sleep_or_abort(delay: float, signal: Any) -> bool:
    """Sleep for delay; return False if the supplied signal was aborted."""
    remaining = max(0.0, delay)
    while remaining > 0:
        if is_aborted(signal):
            return False
        step = min(0.05, remaining)
        await asyncio.sleep(step)
        remaining -= step
    return not is_aborted(signal)


def _http_parts(raw: str):
    try:
        parts = urlsplit(raw)
    except ValueError as err:
        raise ValueError("invalid HTTP target URL") from err
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("target must be a valid HTTP or HTTPS URL")
    try:
        _ = parts.port
    except ValueError as err:
        raise ValueError("target URL contains an invalid port") from err
    return parts
