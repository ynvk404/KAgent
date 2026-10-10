
import json
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from urllib.parse import unquote_plus


_INJECTION_POINT = "{INJECTION_POINT}"
_REQUEST_CONTEXT_FIELDS = frozenset({"request_template", "sample_payload"})
_FORM_FIELD = re.compile(r"(^|[?&;])([^?&;=]+)=([^?&;]*)")
_MULTIPART_DISPOSITION = re.compile(
    r'content-disposition:\s*form-data\s*;[^\r\n]*?\bname\s*=\s*'
    r'(?:"([^"]+)"|([^;\s]+))',
    re.IGNORECASE,
)


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
        "csrf",
        "csrftoken",
        "xsrf",
        "xsrftoken",
        "sessioncookie",
        "sessionkey",
        "sessiontoken",
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
    if isinstance(value, str) and value == _INJECTION_POINT:
        return _INJECTION_POINT
    return "[REDACTED]"


def _redact_form_encoded(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        key = unquote_plus(match.group(2))
        if not _is_secret_field(key):
            return match.group(0)
        encoded_value = match.group(3)
        if _is_injection_marker(encoded_value):
            return match.group(0)
        if not encoded_value:
            return match.group(0)
        return f"{match.group(1)}{match.group(2)}=[REDACTED]"

    return _FORM_FIELD.sub(replace, value)


def _is_injection_marker(value: str) -> bool:
    return value == _INJECTION_POINT or unquote_plus(value) == _INJECTION_POINT


def _multipart_boundary(content_type: str | None, value: str) -> str | None:
    if content_type:
        match = re.search(
            r"(?:^|;)\s*boundary\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^;\s]+))",
            content_type,
            re.IGNORECASE,
        )
        if match:
            return next((part for part in match.groups() if part), None)
    first_line = next((line for line in value.splitlines() if line.startswith("--")), "")
    if first_line:
        boundary = first_line[2:].removesuffix("--").strip()
        return boundary or None
    return None


def _redact_multipart(value: str, content_type: str | None) -> str:
    boundary = _multipart_boundary(content_type, value)
    if not boundary:
        return "[REDACTED]"
    separator = f"--{boundary}"
    if separator not in value:
        return "[REDACTED]"

    chunks = value.split(separator)
    output = [chunks[0]]
    for chunk in chunks[1:]:
        if chunk.startswith("--"):
            output.append(separator + chunk)
            continue
        split = re.search(r"\r?\n\r?\n", chunk)
        if split is None:
            return "[REDACTED]"
        headers = chunk[:split.start()]
        body = chunk[split.end():]
        disposition = _MULTIPART_DISPOSITION.search(headers)
        if disposition is None:
            output.append(separator + chunk)
            continue
        name = disposition.group(1) or disposition.group(2) or ""
        if not _is_secret_field(name):
            output.append(separator + chunk)
            continue
        trailing = ""
        if body.endswith("\r\n"):
            body, trailing = body[:-2], "\r\n"
        elif body.endswith("\n"):
            body, trailing = body[:-1], "\n"
        if body != _INJECTION_POINT:
            body = "[REDACTED]"
        output.append(separator + chunk[:split.end()] + body + trailing)

    if content_type and content_type.lower().split(";", 1)[0].strip() == "multipart/form-data":
        if not any(_MULTIPART_DISPOSITION.search(chunk) for chunk in chunks[1:]):
            return "[REDACTED]"
    return "".join(output)


def redact_request_context(value: str, content_type: str | None = None) -> str:
    """Redact bounded JSON, form, and multipart request skeletons."""
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    text = value.strip()
    is_multipart = media_type == "multipart/form-data" or bool(
        re.search(r"(?im)^content-disposition:\s*form-data\b", text)
    )
    if is_multipart:
        return _redact_multipart(text, content_type)

    is_json = (
        media_type == "application/json"
        or media_type.endswith("+json")
        or text.startswith(("{", "["))
    )
    if is_json:
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError, RecursionError):
            return "[REDACTED]"
        return json.dumps(
            redact_payload(parsed), ensure_ascii=False, separators=(",", ":")
        )

    return _redact_form_encoded(apply(text))


def redact_payload(value: Any) -> Any:
    """Recursively redact strings and values stored under secret field names."""
    if isinstance(value, str):
        redacted = apply(value)
        if re.search(r"(?im)^content-disposition:\s*form-data\b", redacted):
            return redact_request_context(redacted, "multipart/form-data")
        if not redacted.lstrip().startswith(("{", "[")):
            return _redact_form_encoded(redacted)
        try:
            parsed = json.loads(redacted)
        except (TypeError, ValueError, RecursionError):
            return redacted
        sanitized = redact_payload(parsed)
        if sanitized != parsed:
            return json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"))
        return redacted
    if isinstance(value, Mapping):
        content_type = value.get("content_type")
        return {
            key: (
                _redacted_secret_value(item)
                if _is_secret_field(key) and item is not None
                else redact_request_context(
                    item, content_type if isinstance(content_type, str) else None
                )
                if key in _REQUEST_CONTEXT_FIELDS and isinstance(item, str)
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

    # Authorization header. Anchor to a header line so prose such as
    # "Missing authorization: unauthenticated access" remains readable.
    re.compile(r"^([ \t]*authorization:\s*)([^\r\n]+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^([ \t]*[A-Za-z0-9_-]*(?:auth|cookie|token|api[-_]?key|secret|session|csrf|xsrf)[A-Za-z0-9_-]*:\s*)([^\r\n]+)$", re.IGNORECASE | re.MULTILINE),

    # Password-hash formats that are credentials even without a field label.
    re.compile(r"\b(\$2[aby]\$\d{2}\$)([./A-Za-z0-9]{53})\b"),
    re.compile(r"\b(\$argon2(?:id|i|d)\$)([^\s\"']{16,})", re.IGNORECASE),

    # Hex password hashes when the nearby prose identifies their meaning.
    re.compile(
        r"((?:password(?:[_ -]?hash(?:es)?)?|passwd|pwd|with\s+hash)"
        r"[^\r\n]{0,96}?(?:[:=]\s*|\s+))([A-Fa-f0-9]{32,128})\b",
        re.IGNORECASE,
    ),

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
    re.compile(r'("(?:access[_-]?token|refresh[_-]?token|api[_-]?key|csrf|xsrf|secret)"\s*:\s*")([^"]*)(?=")', re.IGNORECASE),

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
    r'x[-_]?api[-_]?key|secret|client[-_]?secret|private[-_]?key|jwt|'
    r'csrf[-_]?token|xsrf[-_]?token|csrf|xsrf|'
    r'session[-_]?(?:cookie|key|token))"\s*:\s*")'
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


_JSON_FIELD = re.compile(r'("(?:\\.|[^"\\])*")\s*:\s*')


def _redact_json_fields(text: str) -> str:
    """Redact JSON values by decoded key, including JSON embedded in evidence."""
    decoder = json.JSONDecoder()
    output: list[str] = []
    cursor = 0
    for match in _JSON_FIELD.finditer(text):
        if match.start() < cursor:
            continue
        try:
            key = json.loads(match.group(1))
        except ValueError:
            continue
        if not _is_secret_field(key):
            continue
        start = match.end()
        try:
            value, end = decoder.raw_decode(text, start)
        except (ValueError, RecursionError):
            # A truncated/invalid secret value has no trustworthy end offset.
            output.extend((text[cursor:start], '"[REDACTED]"'))
            return "".join(output)
        if isinstance(value, str):
            safe_value = (value if value == _INJECTION_POINT or _MASKED_SECRET.fullmatch(value)
                          else mask(value))
        else:
            safe_value = None if value is None else "[REDACTED]"
        output.extend((text[cursor:start], json.dumps(safe_value, ensure_ascii=False)))
        cursor = end
    output.append(text[cursor:])
    return "".join(output)


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
            if secret == _INJECTION_POINT:
                return match.group(0)
            if _MASKED_SECRET.fullmatch(secret):
                return match.group(0)
            return match.group(1) + mask(secret) + match.group(3)

        out = _redact_json_fields(out)
        out = JSON_SECRET_VALUE.sub(redact_json_secret, out)

        if not out.lstrip().startswith(("{", "[")):
            out = _redact_form_encoded(out)

        for pattern in PATTERNS:
            def repl(match):
                prefix = match.group(1)
                secret = match.group(2)
                if _is_injection_marker(secret):
                    return match.group(0)
                if _MASKED_SECRET.fullmatch(secret):
                    return match.group(0)
                return prefix + mask(secret)
            out = pattern.sub(repl, out)

        if not out.lstrip().startswith(("{", "[")):
            if re.search(r"(?im)^content-disposition:\s*form-data\b", out):
                out = redact_request_context(out, "multipart/form-data")

        return out


_redactor = Redactor()

_EVIDENCE_DIGEST = re.compile(
    r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|"
    r"[A-Fa-f0-9]{96}|[A-Fa-f0-9]{128})\b"
)

# A digest-shaped DNS label is routing metadata in a URL/Host header, not a
# standalone opaque secret. Inspect only already-sanitized text; credentials
# and known credential echoes continue to take precedence over this exception.
_EVIDENCE_HOSTNAME = re.compile(
    r"(?:https?://(?:[^/\s\"'<>@]+@)?|(?im:^\s*host:\s*)|\A)"
    r"(?P<host>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?=[:/\s\"'<>?#]|\Z)",
    re.IGNORECASE,
)


def apply(text: str) -> str:
    return _redactor.apply(text)


def apply_evidence(text: str) -> str:
    """Redact durable proof more conservatively than ordinary prose."""
    cleaned = apply(text)
    hosts = [match.span("host") for match in _EVIDENCE_HOSTNAME.finditer(cleaned)]
    return _EVIDENCE_DIGEST.sub(
        lambda match: match.group(0) if any(start <= match.start() and match.end() <= end
                                           for start, end in hosts) else mask(match.group(0)),
        cleaned,
    )


def http_credential_redactor(*header_sets: Iterable[tuple[str, str]]) -> Callable[[str], str]:
    """Hide known HTTP credentials even in unlabelled echoes; keep raw bytes external."""
    secrets: set[str] = set()
    for headers in header_sets:
        for name, value in headers:
            if value and apply_evidence(f'{name}: {value}') != f'{name}: {value}':
                secrets.add(value)
                if name.lower() == 'authorization':
                    secrets.add(value.partition(' ')[2])
                elif name.lower() in {'cookie', 'set-cookie'}:
                    parts = value.split(';') if name.lower() == 'cookie' else value.split(';')[:1]
                    secrets.update(part.partition('=')[2].strip().strip('"') for part in parts)
    secrets.discard('')

    def redact(text: str) -> str:
        for value in sorted(secrets, key=len, reverse=True):
            if len(value) < 4:
                text = re.sub(r'(?<!\w)' + re.escape(value) + r'(?!\w)', '[REDACTED]', text)
            else:
                text = text.replace(value, '[REDACTED]')
        return apply_evidence(text)

    return redact
