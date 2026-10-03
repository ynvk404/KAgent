"""Operator-only HTTP control commands and explicit CLI grant specifications."""
from __future__ import annotations

from urllib.parse import urlsplit
from src.permission.network.grants import HTTPLimits
from src.target.origin import HTTPOrigin

GRANT_SYNTAX = "ORIGIN,MODE,SECONDS,REQUESTS,RATE,BURST,CONCURRENCY,REQUEST_BYTES,RESPONSE_BYTES"


def parse_lab_spec(spec: str) -> tuple[str, HTTPLimits, str]:
    parts = spec.split(",")
    if len(parts) != 9:
        raise ValueError(f"grant format: {GRANT_SYNTAX}")
    origin_raw, mode, seconds, requests, rate, burst, concurrency, request_bytes, response_bytes = parts
    parsed = urlsplit(origin_raw)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("grant requires an exact origin, without path/query/credentials")
    origin = HTTPOrigin.from_url(origin_raw)
    if mode not in {"autonomous", "confirm-each"}:
        raise ValueError("grant mode must be autonomous or confirm-each")
    limits = HTTPLimits(float(seconds), int(requests), float(rate), int(burst), int(concurrency), int(request_bytes), int(response_bytes))
    return origin.as_url(), limits, mode
