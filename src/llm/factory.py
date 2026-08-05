from __future__ import annotations

from src.config.config import (
    Backend,
    Config,
)

from src.llm.anthropic import AnthropicClient
from src.llm.client import Client
from src.llm.gemini import GeminiClient
from src.llm.openai import OpenAIClient

from src.llm.providers import (
    ANTHROPIC_DEFAULT_BASE_URL,
    ANTHROPIC_DEFAULT_MODEL,
    DEEPSEEK_DEFAULT_BASE_URL,
    DEEPSEEK_DEFAULT_MODEL,
    GEMINI_DEFAULT_BASE_URL,
    GEMINI_DEFAULT_MODEL,
    GROQ_DEFAULT_BASE_URL,
    GROQ_DEFAULT_MODEL,
    KIMI_DEFAULT_BASE_URL,
    KIMI_DEFAULT_MAX_TOKENS,
    KIMI_DEFAULT_MODEL,
    OPENROUTER_DEFAULT_BASE_URL,
    OPENROUTER_DEFAULT_MODEL,
)


def new_from_config(
    cfg: Config,
) -> Client:
    """Build the right Client from the parsed Config."""

    backend = (
        cfg.backend.value
        if isinstance(cfg.backend, Backend)
        else cfg.backend
    )

    gen = {
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
    }

    match backend:

        case "":

            raise ValueError(
                "no LLM backend configured"
            )


        case "openai-compat":

            if not cfg.base_url:
                raise ValueError(
                    "openai-compat backend requires base_url"
                )

            return OpenAIClient(
                cfg.base_url,
                cfg.api_key,
                cfg.model,
                "openai-compat",
                {},
                gen,
            )


        case "kimi":

            if not cfg.api_key:
                raise ValueError(
                    "kimi backend requires api_key or MOONSHOT_API_KEY"
                )

            return OpenAIClient(
                cfg.base_url or KIMI_DEFAULT_BASE_URL,
                cfg.api_key,
                cfg.model or KIMI_DEFAULT_MODEL,
                "kimi",
                {},
                {
                    "temperature": cfg.temperature,
                    "max_tokens": (
                        cfg.max_tokens
                        if cfg.max_tokens is not None
                        else KIMI_DEFAULT_MAX_TOKENS
                    ),
                },
            )


        case "groq":

            if not cfg.api_key:
                raise ValueError(
                    "groq backend requires api_key or GROQ_API_KEY"
                )

            return OpenAIClient(
                cfg.base_url or GROQ_DEFAULT_BASE_URL,
                cfg.api_key,
                cfg.model or GROQ_DEFAULT_MODEL,
                "groq",
                {},
                gen,
            )


        case "openrouter":

            if not cfg.api_key:
                raise ValueError(
                    "openrouter backend requires api_key or OPENROUTER_API_KEY"
                )

            return OpenAIClient(
                cfg.base_url or OPENROUTER_DEFAULT_BASE_URL,
                cfg.api_key,
                cfg.model or OPENROUTER_DEFAULT_MODEL,
                "openrouter",
                {
                    "HTTP-Referer": (
                        "https://github.com/kagent/agent"
                    ),
                    "X-OpenRouter-Title": (
                        "kagent"
                    ),
                },
                gen,
            )


        case "deepseek":

            if not cfg.api_key:
                raise ValueError(
                    "deepseek backend requires api_key or DEEPSEEK_API_KEY"
                )

            return OpenAIClient(
                cfg.base_url or DEEPSEEK_DEFAULT_BASE_URL,
                cfg.api_key,
                cfg.model or DEEPSEEK_DEFAULT_MODEL,
                "deepseek",
                {},
                gen,
            )


        case "gemini":

            if not cfg.api_key:
                raise ValueError(
                    "gemini backend requires api_key or GEMINI_API_KEY"
                )

            return GeminiClient(
                cfg.base_url or GEMINI_DEFAULT_BASE_URL,
                cfg.api_key,
                cfg.model or GEMINI_DEFAULT_MODEL,
                {
                    **gen,
                    "thinkingBudget": (
                        cfg.gemini_thinking_budget
                    ),
                },
            )


        case "anthropic":

            if not cfg.api_key:
                raise ValueError(
                    "anthropic backend requires api_key or ANTHROPIC_API_KEY"
                )

            return AnthropicClient(
                cfg.base_url or ANTHROPIC_DEFAULT_BASE_URL,
                cfg.api_key,
                cfg.model or ANTHROPIC_DEFAULT_MODEL,
                gen,
            )


        case _:

            raise ValueError(
                f"unknown backend: {backend!r}"
            )