from __future__ import annotations

import ipaddress
from typing import Final
from urllib.parse import urlparse

LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset(
    {"localhost", "127.0.0.1", "::1"}
)


def validate_base_url(base_url: str) -> str:
    """Reject provider base URLs that would leak the API key in cleartext."""
    if not isinstance(base_url, str) or not base_url:
        raise ValueError("base_url must be an absolute http(s) URL")
    if any(char.isspace() for char in base_url):
        raise ValueError("base_url must not contain whitespace")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in base_url):
        raise ValueError("base_url contains an invalid control character")

    try:
        parsed = urlparse(base_url)
        hostname = parsed.hostname
        _port = parsed.port
    except ValueError:
        raise ValueError("base_url is malformed") from None

    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not hostname:
        raise ValueError("base_url must be an absolute http(s) URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must not contain username or password credentials")
    if "?" in base_url or "#" in base_url or parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain a query or fragment")
    if any(char.isspace() for char in hostname):
        raise ValueError("base_url hostname is malformed")

    if parsed.scheme == "https":
        return base_url

    if parsed.scheme != "http":
        raise ValueError(
            f"base_url must use http or https, got {parsed.scheme or base_url!r}"
        )

    if _is_loopback(hostname):
        return base_url

    raise ValueError(
        "base_url must use https for non-loopback hosts; "
        "refusing to send credentials in cleartext to a remote provider"
    )


def _is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False

    host = hostname.strip("[]").rstrip(".").lower()

    if host in LOOPBACK_HOSTS or host.endswith(".localhost"):
        return True

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# Groq

GROQ_DEFAULT_BASE_URL: Final[str] = (
    "https://api.groq.com/openai/v1"
)

GROQ_DEFAULT_MODEL: Final[str] = (
    "openai/gpt-oss-120b"
)

GROQ_MODELS: Final[tuple[str, ...]] = (
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "qwen/qwen3.6-27b",
)

# OpenRouter

OPENROUTER_DEFAULT_BASE_URL: Final[str] = (
    "https://openrouter.ai/api/v1"
)

OPENROUTER_DEFAULT_MODEL: Final[str] = (
    "openrouter/auto"
)

OPENROUTER_RECOMMENDED_MODELS: Final[tuple[str, ...]] = (
    "openrouter/auto",
)

# OpenAI

OPENAI_DEFAULT_BASE_URL: Final[str] = (
    "https://api.openai.com/v1"
)

OPENAI_DEFAULT_MODEL: Final[str] = (
    "gpt-6-luna"
)

OPENAI_RECOMMENDED_MODELS: Final[tuple[str, ...]] = (
    "gpt-6-luna",
    "gpt-5.6-terra",
    "gpt-6-sol",
)

# Kimi / Moonshot

KIMI_DEFAULT_BASE_URL: Final[str] = (
    "https://api.moonshot.ai/v1"
)

KIMI_DEFAULT_MODEL: Final[str] = (
    "kimi-k2.6"
)

KIMI_MODELS: Final[tuple[str, ...]] = (
    "kimi-k2.7-code",
    "kimi-k2.6",
    "kimi-k2.5",
    "moonshot-v1-auto",
    "moonshot-v1-8k",
    "moonshot-v1-32k",
    "moonshot-v1-128k",
    "moonshot-v1-8k-vision-preview",
    "moonshot-v1-32k-vision-preview",
    "moonshot-v1-128k-vision-preview",
)

KIMI_CONTEXT_WINDOWS: Final[dict[str, int]] = {
    "kimi-k2.7-code": 262_144,
    "kimi-k2.6": 262_144,
    "kimi-k2.5": 262_144,
    "moonshot-v1-auto": 131_072,
    "moonshot-v1-128k": 131_072,
    "moonshot-v1-128k-vision-preview": 131_072,
    "moonshot-v1-32k": 32_768,
    "moonshot-v1-32k-vision-preview": 32_768,
    "moonshot-v1-8k": 8_192,
    "moonshot-v1-8k-vision-preview": 8_192,
}


KIMI_TEMPERATURE_LOCKED_MODELS: Final[frozenset[str]] = frozenset(
    {
        "kimi-k2.7-code",
        "kimi-k2.6",
        "kimi-k2.5",
    }
)

KIMI_DEFAULT_MAX_TOKENS: Final[int] = 2048

def kimi_locks_temperature(model: str) -> bool:
    return model in KIMI_TEMPERATURE_LOCKED_MODELS

def kimi_supports_thinking_toggle(model: str) -> bool:
    return model in {
        "kimi-k2.6",
        "kimi-k2.5",
    }

def kimi_auto_compact_threshold(
    model: str,
) -> int | None:

    window = KIMI_CONTEXT_WINDOWS.get(model)

    if window is None:
        return None

    return window * 3 // 4

# DeepSeek

DEEPSEEK_DEFAULT_BASE_URL: Final[str] = (
    "https://api.deepseek.com"
)

DEEPSEEK_DEFAULT_MODEL: Final[str] = (
    "deepseek-flash"
)

DEEPSEEK_MODELS: Final[tuple[str, ...]] = (
    "deepseek-flash",
    "deepseek-v4-pro",
)

# Anthropic Claude

ANTHROPIC_DEFAULT_BASE_URL: Final[str] = (
    "https://api.anthropic.com/v1"
)

ANTHROPIC_VERSION: Final[str] = (
    "2023-06-01"
)

ANTHROPIC_DEFAULT_MODEL: Final[str] = (
    "claude-sonnet-4-6"
)

ANTHROPIC_DEFAULT_MAX_TOKENS: Final[int] = 16000

ANTHROPIC_MODELS: Final[tuple[str, ...]] = (
    "claude-sonnet-4-6",
    "claude-opus-4-8",
    "claude-haiku-4-5",
)

ANTHROPIC_RECOMMENDED_MODELS: Final[tuple[str, ...]] = (
    *ANTHROPIC_MODELS,
)

def anthropic_accepts_temperature(
    model: str,
) -> bool:

    model = model.lower()

    return not (
        "opus-4-7" in model
        or "opus-4-8" in model
        or "fable-5" in model
        or "mythos-5" in model
    )

# Gemini

GEMINI_DEFAULT_BASE_URL: Final[str] = (
    "https://generativelanguage.googleapis.com/v1beta"
)

GEMINI_DEFAULT_MODEL: Final[str] = (
    "models/gemini-3.8-flash"
)

GEMINI_BEST_FIT_MODELS: Final[tuple[str, ...]] = (
    "models/gemini-3.8-flash",
    "models/gemini-3.7-flash",
    "models/gemini-3.6-flash",
)

GEMINI_CHEAP_MODELS: Final[tuple[str, ...]] = (
    "models/gemini-3.5-flash-lite",
    "models/gemini-3.1-flash-lite",
)

GEMINI_RECOMMENDED_MODELS: Final[tuple[str, ...]] = (
    *GEMINI_BEST_FIT_MODELS,
    *GEMINI_CHEAP_MODELS,
)
