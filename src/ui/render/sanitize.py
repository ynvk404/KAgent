"""Sanitize presentation copies before previewing, rendering, or copying."""
from __future__ import annotations

import re

from src.redaction.redact import redact_payload
from src.tools.common.approval_display import redact_approval


def sanitize_text(text: str) -> str:
    # Escape every executable C0/C1 control, including incomplete ESC/CSI/OSC
    # fragments, before trusted application formatting is applied. Visible
    # escapes preserve the preview's content without interpreting terminal
    # commands. Newlines, tabs, and ordinary Unicode remain readable.
    text = text.replace("\r\n", "\n")
    text = re.sub(
        r"[\x00-\x08\x0b-\x1f\x7f-\x9f]",
        lambda match: f"\\x{ord(match.group()):02x}",
        text,
    )
    # An interrupted stream may contain only the opening half of a key block.
    text = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
        "[REDACTED PRIVATE KEY]", text,
    )
    return redact_approval(str(redact_payload(text)))
