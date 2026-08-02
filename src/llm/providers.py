from __future__ import annotations

from typing import Final


# ============================================================================
# Groq
# ============================================================================

GROQ_DEFAULT_BASE_URL: Final[str] = (
    "https://api.groq.com/openai/v1"
)

GROQ_DEFAULT_MODEL: Final[str] = (
    "openai/gpt-oss-120b"
)

GROQ_MODELS: Final[tuple[str, ...]] = (
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "meta-llama/llama-4-maverick-17b-128e-instruct",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "qwen/qwen3-32b",
    "deepseek-r1-distill-llama-70b",
    "compound-beta",
    "compound-beta-mini",
)


# ============================================================================
# OpenRouter
# ============================================================================

OPENROUTER_DEFAULT_BASE_URL: Final[str] = (
    "https://openrouter.ai/api/v1"
)

OPENROUTER_DEFAULT_MODEL: Final[str] = (
    "openrouter/auto"
)

OPENROUTER_RECOMMENDED_MODELS: Final[tuple[str, ...]] = (
    "openrouter/auto",
)


# ============================================================================
# OpenAI
# ============================================================================

OPENAI_DEFAULT_BASE_URL: Final[str] = (
    "https://api.openai.com/v1"
)

OPENAI_DEFAULT_MODEL: Final[str] = (
    "gpt-4o-mini"
)


# ============================================================================
# Kimi / Moonshot
# ============================================================================

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



# ============================================================================
# DeepSeek
# ============================================================================

DEEPSEEK_DEFAULT_BASE_URL: Final[str] = (
    "https://api.deepseek.com"
)

DEEPSEEK_DEFAULT_MODEL: Final[str] = (
    "deepseek-v4-flash"
)

DEEPSEEK_MODELS: Final[tuple[str, ...]] = (
    "deepseek-v4-flash",
    "deepseek-v4-pro",
    "deepseek-chat",
    "deepseek-reasoner",
)



# ============================================================================
# Anthropic Claude
# ============================================================================

ANTHROPIC_DEFAULT_BASE_URL: Final[str] = (
    "https://api.anthropic.com/v1"
)

ANTHROPIC_VERSION: Final[str] = (
    "2023-06-01"
)

ANTHROPIC_DEFAULT_MODEL: Final[str] = (
    "claude-opus-4-8"
)

ANTHROPIC_DEFAULT_MAX_TOKENS: Final[int] = 16000


ANTHROPIC_MODELS: Final[tuple[str, ...]] = (
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
    "claude-opus-4-5",
    "claude-sonnet-4-5",
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



# ============================================================================
# Gemini
# ============================================================================

GEMINI_DEFAULT_BASE_URL: Final[str] = (
    "https://generativelanguage.googleapis.com/v1beta"
)

GEMINI_DEFAULT_MODEL: Final[str] = (
    "models/gemini-3.5-flash"
)


GEMINI_BEST_FIT_MODELS: Final[tuple[str, ...]] = (
    "models/gemini-3.5-flash",
    "models/gemini-3.1-pro-preview",
    "models/gemini-flash-latest",
    "models/gemini-3-flash-preview",
    "models/gemini-3.1-flash-lite",
    "models/gemini-2.5-flash-lite",
)


GEMINI_CHEAP_MODELS: Final[tuple[str, ...]] = (
    "models/gemini-flash-lite-latest",
    "models/gemini-3.1-flash-lite-preview",
    "models/gemma-4-26b-a4b-it",
)


GEMINI_RECOMMENDED_MODELS: Final[tuple[str, ...]] = (
    *GEMINI_BEST_FIT_MODELS,
    *GEMINI_CHEAP_MODELS,
)