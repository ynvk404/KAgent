"""Sanitize presentation copies before previewing, rendering, or copying."""
from __future__ import annotations

import re

from src.redaction.redact import redact_payload
from src.tools.common.approval_display import redact_approval


def sanitize_text(text: str) -> str:
    # An interrupted stream may contain only the opening half of a key block.
    text = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
        "[REDACTED PRIVATE KEY]", text,
    )
    return redact_approval(str(redact_payload(text)))
