from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import ParseResult, urlparse


@dataclass(frozen=True, order=True, slots=True)
class HTTPOrigin:
    """Canonical HTTP origin: scheme, normalized hostname, effective port."""

    scheme: str
    hostname: str
    port: int

    @classmethod
    def from_url(cls, raw: str) -> "HTTPOrigin":
        try:
            parsed = urlparse(raw)
        except Exception as err:
            raise ValueError(f"invalid URL: {raw}") from err
        return cls.from_parsed(parsed)

    @classmethod
    def from_parsed(cls, parsed: ParseResult) -> "HTTPOrigin":
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError(f"unsupported URL scheme: {parsed.scheme}")

        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            raise ValueError("HTTP URL requires a hostname")

        try:
            normalized_host = str(ipaddress.ip_address(hostname))
        except ValueError:
            if any(char.isspace() for char in hostname):
                raise ValueError("HTTP URL hostname contains whitespace")
            try:
                normalized_host = hostname.encode("idna").decode("ascii")
            except UnicodeError as err:
                raise ValueError("HTTP URL hostname is invalid") from err

        try:
            port = parsed.port
        except ValueError as err:
            raise ValueError(f"invalid URL port: {err}") from err

        return cls(
            scheme=scheme,
            hostname=normalized_host,
            port=port if port is not None else (443 if scheme == "https" else 80),
        )

    def as_url(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        default_port = 443 if self.scheme == "https" else 80
        suffix = "" if self.port == default_port else f":{self.port}"
        return f"{self.scheme}://{host}{suffix}"

    def to_dict(self) -> dict[str, object]:
        return {
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.port,
        }

    @classmethod
    def from_dict(cls, raw: object) -> "HTTPOrigin | None":
        if not isinstance(raw, dict):
            return None
        scheme = raw.get("scheme")
        hostname = raw.get("hostname")
        port = raw.get("port")
        if (
            not isinstance(scheme, str)
            or not isinstance(hostname, str)
            or not isinstance(port, int)
            or isinstance(port, bool)
        ):
            return None
        try:
            return cls.from_url(f"{scheme}://{_url_host(hostname)}:{port}")
        except ValueError:
            return None


def _url_host(hostname: str) -> str:
    if ":" in hostname and not hostname.startswith("["):
        return f"[{hostname}]"
    return hostname
