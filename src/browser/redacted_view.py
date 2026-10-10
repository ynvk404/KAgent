"""Model-facing capture views; complete request bytes stay runtime-only."""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit

from src.redaction.redact import apply_evidence, http_credential_redactor, redact_payload, redact_request_context


def _record(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return asdict(cast(Any, value)) if is_dataclass(value) else dict(value.__dict__)


def _headers(value: Any) -> list[dict[str, str]] | None:
    if not value:
        return None
    rows = []
    for item in value:
        row = _record(item)
        name = str(row.get("name", ""))
        header_value = str(row.get("value", ""))
        prefix = f"{name}: "
        safe_header = apply_evidence(prefix + header_value)
        safe_value = safe_header[len(prefix):] if safe_header.startswith(prefix) else "[REDACTED]"
        rows.append({"name": name, "value": safe_value})
    return rows


def request_view(value: Any) -> dict[str, Any]:
    row = _record(value)
    row.pop("raw_request_b64", None)
    row.pop("rawRequestB64", None)
    row.pop("raw_request_oversize", None)
    request_headers = row.get("request_headers") or row.get("requestHeaders")
    response_headers = row.get("response_headers") or row.get("responseHeaders")
    redact = http_credential_redactor(
        ((str(_record(h).get('name', '')), str(_record(h).get('value', '')))
         for headers in (request_headers, response_headers) for h in headers or []))

    def redact_values(value: Any) -> Any:
        if isinstance(value, str):
            return redact(value)
        if isinstance(value, dict):
            return {key: redact_values(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact_values(item) for item in value]
        return value

    def redact_headers(headers: Any) -> list[dict[str, str]] | None:
        values = _headers(headers)
        return [{"name": h["name"], "value": redact(h["value"])} for h in values] if values else None
    content_type = next((h["value"] for h in _headers(request_headers) or []
                         if h["name"].lower() == "content-type"), None)
    for key in ("request_headers", "requestHeaders"):
        if key in row:
            row[key] = redact_headers(request_headers)
    for key in ("response_headers", "responseHeaders"):
        if key in row:
            row[key] = redact_headers(response_headers)
    for key in ("request_body", "requestBody"):
        if key in row and isinstance(row[key], str):
            row[key] = redact(redact_request_context(row[key], content_type))
        elif key in row:
            row[key] = redact_values(redact_payload(row[key]))
    for key in ("response_body", "responseBody"):
        if key in row and isinstance(row[key], str):
            row[key] = redact(redact_request_context(row[key], "application/json"))
    if isinstance(row.get("url"), str):
        try:
            parsed = urlsplit(cast(str, row["url"]))
            # Userinfo belongs only to the runtime baseline. Even a partially
            # masked credential-bearing URL must not become model/UI context.
            safe_url = urlunsplit(parsed._replace(netloc=parsed.netloc.rsplit("@", 1)[-1]))
        except ValueError:
            safe_url = "[Invalid capture URL omitted]"
        row["url"] = redact(safe_url)
    return row


def issue_view(value: Any) -> dict[str, Any]:
    row = _record(value)
    row.pop("raw_request_b64", None)
    row.pop("raw_response_b64", None)
    for key in ("url", "detail", "remediation", "path", "title"):
        if isinstance(row.get(key), str):
            row[key] = redact_payload(row[key])
    return row


def task_view(value: Any) -> dict[str, Any]:
    row = _record(value)
    row.pop("raw_request_b64", None)
    for key in ("url", "target", "notes"):
        if isinstance(row.get(key), str):
            row[key] = apply_evidence(row[key])
    return row


def snapshot_view(value: Any) -> dict[str, Any]:
    row = _record(value)
    for key in ("url", "title"):
        if isinstance(row.get(key), str):
            row[key] = apply_evidence(row[key])
    for key in ("document_cookie", "documentCookie"):
        if key in row and row[key] is not None:
            row[key] = "[REDACTED]"
    if isinstance(row.get("cookies"), list):
        row["cookies"] = [
            {**_record(item), "value": "[REDACTED]"} if isinstance(item, dict) or is_dataclass(item) else "[REDACTED]"
            for item in row["cookies"]
        ]
    for key in ("local_storage", "localStorage", "session_storage", "sessionStorage"):
        if isinstance(row.get(key), dict):
            row[key] = {name: "[REDACTED]" for name in row[key]}
    return row
