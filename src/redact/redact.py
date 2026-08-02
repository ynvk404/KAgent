"""

Che các thông tin nhạy cảm trước khi:
- gửi cho LLM (compact)
- export markdown
- lưu session snapshot
"""

import re


# ==========================
# Regex patterns
# ==========================

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

    # api_key=...
    re.compile(
        r"((?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"']?)"
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


# ==========================
# Mask secret
# ==========================

def mask(secret: str) -> str:
    """
    Che secret nhưng vẫn giữ 2 ký tự đầu và 2 ký tự cuối.
    """

    if len(secret) <= 6:
        return "[REDACTED]"

    head = secret[:2]
    tail = secret[-2:]

    bucket = (len(secret) // 4) * 4
    dots = "·" * (bucket // 4)

    return f"{head}…[REDACTED:{dots}]…{tail}"


# ==========================
# Redactor
# ==========================

class Redactor:
    """
    Che các credential phổ biến trước khi gửi cho LLM.
    """

    def apply(self, text: str) -> str:
        if not text:
            return text

        # Thay toàn bộ private key
        out = PRIVATE_KEY_BLOCK.sub(
            "-----BEGIN PRIVATE KEY-----\n"
            "[REDACTED]\n"
            "-----END PRIVATE KEY-----",
            text,
        )

        # Thay từng pattern
        for pattern in PATTERNS:

            def repl(match):
                prefix = match.group(1)
                secret = match.group(2)
                return prefix + mask(secret)

            out = pattern.sub(repl, out)

        return out

redact = Redactor()