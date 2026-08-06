from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Literal

ErrorCategory = Literal[
    "model-not-loaded",
    "model-not-found",
    "backend-down",
    "unknown",
]


@dataclass(slots=True)
class BackendError(Exception):

    backend: str
    category: ErrorCategory
    status_code: int
    detail: str
    retry_after_ms: int | None = None

    def __post_init__(self) -> None:
        if self.status_code != 0:
            msg = f"{self.backend} error {self.status_code}: {self.detail}"
        else:
            msg = f"{self.backend}: {self.detail}"

        Exception.__init__(self, msg)


def is_transient(err: object) -> bool:

    if not isinstance(err, BackendError):
        return False

    if err.category == "backend-down":
        return True

    return err.status_code in (408, 429, 502, 503, 504)


def parse_retry_after(
    header: str | None,
    now: float | None = None,
) -> int | None:

    if not header:
        return None

    header = header.strip()

    if header.isdigit():
        return int(header) * 1000

    try:
        when = parsedate_to_datetime(header)
    except Exception:
        return None

    if now is None:
        now = datetime.now().timestamp()

    delta_ms = int((when.timestamp() - now) * 1000)

    return max(0, delta_ms)

def classify_backend(
    backend: str,
    transport_error: Exception | str | None,
    status_code: int,
    body: str | None,
) -> BackendError:

    if transport_error is not None:

        msg = (
            str(transport_error)
            if isinstance(transport_error, Exception)
            else str(transport_error)
        )

        lower = msg.lower()

        if any(
            s in lower
            for s in (
                "econnrefused",
                "connection refused",
                "enotfound",
                "no such host",
                "etimedout",
                "i/o timeout",
                "network is unreachable",
                "socket hang up",
                "fetch failed",
            )
        ):
            return BackendError(
                backend,
                "backend-down",
                0,
                msg,
            )

        return BackendError(
            backend,
            "unknown",
            0,
            msg,
        )

    msg = (body or "").strip()

    if body:
        try:
            parsed = json.loads(body)

            error = parsed.get("error")

            if isinstance(error, str) and error:
                msg = error

            elif isinstance(error, dict):
                message = error.get("message")
                if isinstance(message, str):
                    msg = message

        except Exception:
            pass

    lower = msg.lower()

    if (
        "rate limit" in lower
        or "rate_limit" in lower
        or "too many requests" in lower
        or "quota exceeded" in lower
    ):
        return BackendError(
            backend,
            "unknown",
            429 if status_code < 400 else status_code,
            msg,
        )

    if (
        "no models loaded" in lower
        or "no model loaded" in lower
        or "model not loaded" in lower
        or "please load a model" in lower
    ):
        return BackendError(
            backend,
            "model-not-loaded",
            status_code,
            msg,
        )

    if (
        "try pulling it first" in lower
        or "model not found" in lower
        or "does not exist" in lower
        or ("model" in lower and "not found" in lower)
    ):
        return BackendError(
            backend,
            "model-not-found",
            status_code,
            msg,
        )

    return BackendError(
        backend,
        "unknown",
        status_code,
        msg,
    )