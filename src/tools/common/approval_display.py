"""Secret redaction for permission display only; never changes execution args."""
from __future__ import annotations

import re

from src.redaction.redact import apply

_VALUE = r'''(?:"(?:\\.|[^"\\])*"|'[^']*'|[^\s;&|]+)'''
_SECRET_FLAGS = re.compile(
    r"(?i)(--(?:password|passwd|token|api[-_]key|secret|client[-_]secret)(?:=|\s+))" + _VALUE,
)
_SECRET_ASSIGNMENTS = re.compile(
    r"(?i)(\b(?:password|passwd|token|api_key|secret|client_secret)=)" + _VALUE,
)
_AUTH_HEADER = re.compile(r"(?i)(\bauthorization:\s*(?:basic|bearer)\s+)[A-Za-z0-9+/=_.-]+")
_USER_PASSWORD = re.compile(r"(?i)((?:--user|-u)\s+)(" + _VALUE + ")")


def redact_approval(text: str) -> str:
    """Keep values of known credential arguments out of both preview modes."""
    text = _SECRET_FLAGS.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _SECRET_ASSIGNMENTS.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _AUTH_HEADER.sub(lambda match: match.group(1) + "[REDACTED]", text)

    def user_password(match: re.Match[str]) -> str:
        value = match.group(2)
        if ":" not in value:
            return match.group(0)
        quote = value[0] if value[0] in {"'", '"'} else ""
        username = value.strip("\"'").split(":", 1)[0]
        return match.group(1) + quote + username + ":[REDACTED]" + quote

    return apply(_USER_PASSWORD.sub(user_password, text))
