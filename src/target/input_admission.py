"""Conservative workflow input admission; never resolves or executes requests.

State-relative paths are relative to the origin root. The workflow tool first
expands paths against the active HTTP tool's application base (its existing
append-path contract). Observed absolute request URLs always take precedence.
Identity limits reject instead of truncating/redacting into another identity.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from src.redaction.redact import apply as redact
from src.target.origin import HTTPOrigin


LIMITS = {"objective_id": 80, "target_origin": 500, "method": 24,
          "endpoint": 500, "parameter": 500, "location": 80, "input_type": 80,
          "content_type": 200, "baseline_request_ref": 500,
          "auth_context_ref": 500, "source_ref": 500}
LOCATIONS = frozenset({"query", "path", "body", "form", "json", "header", "cookie", "raw"})


def identity_text(value: Any, name: str, *, required: bool = False) -> str | None:
    if value is None or value == "":
        if required:
            raise ValueError(f"input {name} is required; endpoint observations are not inputs")
        return None
    if not isinstance(value, str):
        raise ValueError(f"input {name} must be a string")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"input {name} has a lossy/unsafe identity; controls are not allowed")
    if name in {"method", "location", "input_type", "content_type"}:
        value = value.strip(" ")
    # Match the existing stored representation without ever accepting loss.
    if (len(value) > LIMITS[name] or "[REDACTED" in value.upper()
            or " ".join(value.split()) != value or redact(value) != value):
        raise ValueError(f"input {name} has a lossy/unsafe identity; supply bounded non-secret exact metadata")
    return value


def canonical_endpoint(endpoint: Any, origin: str, *, base_url: str | None = None) -> str:
    raw = identity_text(endpoint, "endpoint", required=True)
    assert raw is not None
    if any(c.isspace() for c in raw) or "\\" in raw or "#" in raw:
        raise ValueError("input endpoint is ambiguous; retain client-route fragments as source clues and supply the effective HTTP URL")
    parts = urlsplit(raw)
    if parts.username is not None or parts.password is not None or raw.startswith("//"):
        raise ValueError("input endpoint credentials/network-path references are not allowed")
    if parts.scheme:
        absolute = raw
    else:
        if parts.netloc or not parts.path or raw.startswith("?"):
            raise ValueError("input endpoint requires an unambiguous path or absolute HTTP URL")
        if base_url is not None:
            base = urlsplit(base_url)
            if base.query or base.fragment or base.username is not None or base.password is not None:
                raise ValueError("input endpoint requires an observed absolute URL when target base has query/fragment/credentials")
        absolute = (base_url or origin).rstrip("/") + (raw if raw.startswith("/") else "/" + raw)
    parts = urlsplit(absolute)
    if parts.username is not None or parts.password is not None:
        raise ValueError("input endpoint credentials are not allowed")
    if re.search(r"%(?![0-9a-fA-F]{2})|%(?:0[0-9a-f]|1[0-9a-f]|7f)", absolute, re.I):
        raise ValueError("input endpoint has invalid encoding or encoded controls")
    actual = HTTPOrigin.from_url(absolute)
    if actual != HTTPOrigin.from_url(origin):
        raise ValueError("input endpoint origin differs from active target origin; do not expand scope")
    # URL resolvers/clients normalize dot segments. Do not silently bind them
    # to a different request, including encoded dot segments.
    if any(re.fullmatch(r"(?:\.|%2e){1,2}", part, re.I) for part in parts.path.split("/")):
        raise ValueError("input endpoint dot segments are ambiguous; supply the observed effective URL")
    result = actual.as_url() + (parts.path or "/")
    if "?" in absolute:
        result += "?" + parts.query
    identity_text(result, "endpoint", required=True)
    return result


def admit_input_fields(values: dict[str, Any], *, base_url: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {name: identity_text(values.get(name), name,
              required=name in {"objective_id", "target_origin", "method", "endpoint", "parameter", "location"})
              for name in LIMITS}
    origin = HTTPOrigin.from_url(result["target_origin"]).as_url()
    result["target_origin"] = origin
    result["endpoint"] = canonical_endpoint(result["endpoint"], origin, base_url=base_url)
    method = result["method"]
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method):
        raise ValueError("input method must be an HTTP token")
    result["method"] = method.upper()
    result["location"] = result["location"].lower()
    if result["location"] not in LOCATIONS:
        raise ValueError("input location must be query/path/body/form/json/header/cookie/raw; whole-request inputs are not supported by this admission contract")
    if result["input_type"]:
        result["input_type"] = identity_text(result["input_type"].lower(), "input_type")
    return result
