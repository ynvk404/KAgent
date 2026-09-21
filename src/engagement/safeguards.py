from __future__ import annotations

import re


_SESSION_AUTHORIZATION_PATTERNS = (
    re.compile(r"(?:^|\s)/scope\s+(?:add|remove|reset)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:i|we|user|operator)\s+(?:have\s+|has\s+)?"
        r"authori[sz](?:e|ed)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:in|out)[ -]of[ -]scope\b", re.IGNORECASE),
    re.compile(
        r"\bscope\s+(?:is|was|includes?|allows?|approved|confirmed)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\btarget\s+(?:is|was|=|:)\s*(?:https?://|[a-z0-9])",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:operator|user)\s+(?:granted|approved|denied)\s+"
        r"(?:the\s+)?(?:permission|approval)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:permission|approval)\s+(?:request\s+)?"
        r"(?:was\s+|is\s+|has\s+been\s+)?(?:granted|approved)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bauthorization\s+(?:was\s+|is\s+|has\s+been\s+)?granted\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bask_user\b", re.IGNORECASE),
    re.compile(r"(?:^|\s)(?:--)?yolo\b", re.IGNORECASE),
)


def is_session_authorization_text(text: str) -> bool:
    """Return whether text records session-only scope or an approval decision."""
    return any(pattern.search(text) for pattern in _SESSION_AUTHORIZATION_PATTERNS)
