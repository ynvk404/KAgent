
import json
import re
from collections.abc import Mapping
from typing import Any


_SECRET_FIELD_NAMES = frozenset(
    {
        "authorization",
        "proxyauthorization",
        "cookie",
        "setcookie",
        "password",
        "passwd",
        "pwd",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "apikey",
        "xapikey",
        "secret",
        "clientsecret",
        "privatekey",
        "credentials",
        "jwt",
    }
)


def _is_secret_field(key: object) -> bool:
    if not isinstance(key, str):
        return False
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return normalized in _SECRET_FIELD_NAMES


def _redacted_secret_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return {key: _redacted_secret_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redacted_secret_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redacted_secret_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return [_redacted_secret_value(item) for item in value]
    return "[REDACTED]"


def redact_payload(value: Any) -> Any:
    """Recursively redact strings and values stored under secret field names."""
    if isinstance(value, str):
        redacted = apply(value)
        if not redacted.lstrip().startswith(("{", "[")):
            return redacted
        try:
            parsed = json.loads(redacted)
        except (TypeError, ValueError, RecursionError):
            return redacted
        sanitized = redact_payload(parsed)
        if sanitized != parsed:
            return json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"))
        return redacted
    if isinstance(value, Mapping):
        return {
            key: (
                _redacted_secret_value(item)
                if _is_secret_field(key) and item is not None
                else redact_payload(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact_payload(item) for item in value)
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [redact_payload(item) for item in value]
    if isinstance(value, BaseException):
        return {
            "name": type(value).__name__,
            "message": apply(str(value)),
        }
    if isinstance(value, (bytes, bytearray)):
        return apply(bytes(value).decode("utf-8", errors="replace"))
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return apply(str(value))

# Regex patterns

PATTERNS = [
    # Bearer token
    re.compile(r"(bearer\s+)([A-Za-z0-9._-]{16,})", re.IGNORECASE),

    # Authorization header
    re.compile(r"(authorization:\s*)(\S+\s+\S+)", re.IGNORECASE),

    # AWS Access Key
    re.compile(r"\b(AKIA|ASIA)([0-9A-Z]{16})\b"),

    # AWS Secret Key
    re.compile(
        r"(aws_secret_access_key\s*[:=]\s*[\"']?)([A-Za-z0-9/+=]{40})",
        re.IGNORECASE,
    ),

    # GitHub Token
    re.compile(r"\b(gh[pousr]_)([A-Za-z0-9]{36,255})\b"),

    # Stripe Key
    re.compile(r"\b(sk_(?:live|test)_)([A-Za-z0-9]{16,})\b"),

    # OpenAI Key
    re.compile(r"\b(sk-)([A-Za-z0-9_-]{20,})\b"),

    # Google API Key
    re.compile(r"\b(AIza)([0-9A-Za-z_-]{35,})\b"),

    # Slack Token
    re.compile(r"\b(xox[abprs]-)([A-Za-z0-9-]{10,})\b"),

    # Password trong URL
    re.compile(
        r"(\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)([^@\s/]+)(?=@)",
        re.IGNORECASE,
    ),

    # JWT
    re.compile(
        r"\b(eyJ[A-Za-z0-9_-]{8,}\.)([A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?)\b"
    ),

    # Short JSON password value
    re.compile(r'("password"\s*:\s*")([^"]+)(?=")', re.IGNORECASE),

    # api_key=...
    re.compile(
        r"([\"']?(?:api[_-]?key|secret|password|passwd|token)[\"']?"
        r"\s*[:=]\s*[\"']?)"
        r"([A-Za-z0-9._\-+/=]{16,})",
        re.IGNORECASE,
    ),

    # password trong query string
    re.compile(
        r"([?&](?:password|passwd|pwd|auth|token|api[_-]?key|access_token|secret)=)"
        r"([^&#\s\"']+)",
        re.IGNORECASE,
    ),

    # Digest response=
    re.compile(
        r"(\bresponse=)(\"?[A-Fa-f0-9]{8,}\"?)"
    ),

    # Generic entropy fallback
    re.compile(
        r"((?:api|auth|token|secret|key|cred)[^\s:=]{0,10}[:=]\s*[\"']?)"
        r"([A-Za-z0-9/+=_-]{32,})",
        re.IGNORECASE,
    ),

    # private_key_id
    re.compile(
        r"([\"']?private_key_id[\"']?\s*[:=]\s*[\"']?)"
        r"([A-Za-z0-9]{16,})",
        re.IGNORECASE,
    ),

    # Cookie header
    re.compile(
        r"((?:set-)?cookie:\s*)([^\r\n]+)",
        re.IGNORECASE,
    ),

    # API Key Header
    re.compile(
        r"((?:x-api-key|api-key|apikey):\s*)([^\r\n]+)",
        re.IGNORECASE,
    ),
]


PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
)


JSON_SECRET_VALUE = re.compile(
    r'("(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|'
    r'password|passwd|pwd|(?:access|refresh|id)?[-_]?token|api[-_]?key|'
    r'x[-_]?api[-_]?key|secret|client[-_]?secret|private[-_]?key|jwt)"\s*:\s*")'
    r'((?:\\.|[^"\\])*)(")',
    re.IGNORECASE,
)


def mask(secret: str) -> str:

    if len(secret) <= 6:
        return "[REDACTED]"

    head = secret[:2]
    tail = secret[-2:]

    bucket = (len(secret) // 4) * 4
    dots = "·" * (bucket // 4)

    return f"{head}…[REDACTED:{dots}]…{tail}"


_MASKED_SECRET = re.compile(
    r"^(?:\[REDACTED\]|.{2}…\[REDACTED:·+\]….{2})$",
    re.DOTALL,
)


class Redactor:

    def apply(self, text: str) -> str:
        if not text:
            return text

        out = PRIVATE_KEY_BLOCK.sub(
            "-----BEGIN PRIVATE KEY-----\n"
            "[REDACTED]\n"
            "-----END PRIVATE KEY-----",
            text,
        )

        def redact_json_secret(match: re.Match[str]) -> str:
            secret = match.group(2)
            if _MASKED_SECRET.fullmatch(secret):
                return match.group(0)
            return match.group(1) + mask(secret) + match.group(3)

        out = JSON_SECRET_VALUE.sub(redact_json_secret, out)

        for pattern in PATTERNS:
            def repl(match):
                prefix = match.group(1)
                secret = match.group(2)
                if _MASKED_SECRET.fullmatch(secret):
                    return match.group(0)
                return prefix + mask(secret)
            out = pattern.sub(repl, out)

        return out


_redactor = Redactor()


def apply(text: str) -> str:
    return _redactor.apply(text)
