from __future__ import annotations

import pytest

from src.config.config import (
    Backend,
    Config,
    add_custom_provider,
    resolve_custom_provider,
)
from src.llm.anthropic import AnthropicClient
from src.llm.client import is_streaming
from src.llm.factory import new_from_config
from src.llm.gemini import GeminiClient
from src.llm.openai import OpenAIClient
from src.llm.types import ChatRequest, Message
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


def _cfg(backend, **kwargs) -> Config:
    api_key = kwargs.pop("api_key", "")
    cfg = Config(backend=backend, **kwargs)
    if api_key:
        cfg.api_keys[str(backend)] = api_key
    return cfg


def test_empty_backend_raises():
    with pytest.raises(ValueError, match="no LLM backend configured"):
        new_from_config(Config())


def test_unknown_backend_raises():
    with pytest.raises(ValueError, match="unknown backend"):
        new_from_config(Config(backend="not-a-backend"))


def test_openai_compat_requires_base_url():
    with pytest.raises(ValueError, match="requires base_url"):
        new_from_config(_cfg(Backend.OPENAI_COMPAT))


def test_openai_compat_builds_client():
    cfg = _cfg(
        Backend.OPENAI_COMPAT,
        base_url="https://example.test/v1",
        model="my-model",
        api_key="sk-abc",
        temperature=0.3,
        max_tokens=123,
    )

    client = new_from_config(cfg)

    assert isinstance(client, OpenAIClient)
    assert client.base_url == "https://example.test/v1"
    assert client.api_key == "sk-abc"
    assert client.model_id == "my-model"
    assert client.name() == "openai-compat"
    assert client.temperature == 0.3
    assert client.max_tokens == 123
    assert is_streaming(client)


def test_custom_provider_resolves_to_existing_openai_client_without_mutating_manual_state():
    cfg = _cfg(
        Backend.OPENAI_COMPAT,
        base_url="http://localhost:1234/v1",
        model="manual-model",
        api_key="manual-key",
    )
    profile_id = add_custom_provider(
        cfg,
        "Token Harbor",
        "https://gateway.example/v1",
        "custom-key",
        "custom-model",
    )

    effective, profile = resolve_custom_provider(cfg, profile_id)
    client = new_from_config(effective)

    assert isinstance(client, OpenAIClient)
    assert client.base_url == "https://gateway.example/v1"
    assert client.model_id == "custom-model"
    assert client.api_key == "custom-key"
    assert client.name() == "openai-compat"
    assert effective.backend == Backend.OPENAI_COMPAT
    assert cfg.backend == Backend.OPENAI_COMPAT
    assert cfg.base_url == "http://localhost:1234/v1"
    assert cfg.model == "manual-model"
    assert cfg.api_keys["openai-compat"] == "manual-key"


def test_custom_provider_missing_key_does_not_fall_back_to_manual_key():
    cfg = _cfg(
        Backend.OPENAI_COMPAT,
        base_url="http://localhost:1234/v1",
        model="manual-model",
        api_key="manual-key",
    )
    profile_id = add_custom_provider(
        cfg,
        "Local Gateway",
        "http://localhost:9000/v1",
        default_model="local-model",
    )

    effective, profile = resolve_custom_provider(cfg, profile_id)
    client = new_from_config(effective)

    assert isinstance(client, OpenAIClient)
    assert client.api_key == ""
    assert cfg.api_keys["openai-compat"] == "manual-key"


@pytest.mark.parametrize("display_name", ["deepseek", "kimi"])
def test_custom_display_name_does_not_change_openai_request_encoding(display_name):
    cfg = Config(
        backend=Backend.OPENAI_COMPAT,
        base_url="https://gateway.example/v1",
        model="generic-model",
        temperature=0.2,
        max_tokens=123,
    )
    profile_id = add_custom_provider(
        cfg,
        display_name,
        "https://gateway.example/v1",
        "custom-key",
        "generic-model",
    )

    effective, _profile = resolve_custom_provider(cfg, profile_id)
    client = new_from_config(effective)
    body = client.encode_request(
        ChatRequest(
            model="generic-model",
            messages=[
                Message(
                    role="assistant",
                    content="reasoning",
                    reasoning_content="provider-specific state",
                ),
                Message(role="user", content="hello"),
            ],
            thinking_enabled=True,
        ),
        False,
    )

    assert isinstance(client, OpenAIClient)
    assert client.name() == "openai-compat"
    assert body["max_tokens"] == 123
    assert body["temperature"] == 0.2
    assert "max_completion_tokens" not in body
    assert "thinking" not in body
    assert "reasoning_content" not in body["messages"][0]


def test_custom_provider_resolution_rejects_missing_or_malformed_profile():
    cfg = Config()
    with pytest.raises(ValueError, match="profile not found"):
        resolve_custom_provider(cfg, "missing")

    cfg.custom_providers["broken"] = object()  # type: ignore[assignment]
    with pytest.raises(ValueError, match="malformed"):
        resolve_custom_provider(cfg, "broken")


@pytest.mark.parametrize(
    "backend",
    [
        Backend.KIMI,
        Backend.GROQ,
        Backend.OPENROUTER,
        Backend.DEEPSEEK,
        Backend.GEMINI,
        Backend.ANTHROPIC,
    ],
)
def test_backends_require_api_key(backend):
    with pytest.raises(ValueError, match="requires api_key"):
        new_from_config(_cfg(backend))


def test_kimi_uses_defaults_and_default_max_tokens():
    client = new_from_config(_cfg(Backend.KIMI, api_key="key"))

    assert isinstance(client, OpenAIClient)
    assert client.base_url == KIMI_DEFAULT_BASE_URL
    assert client.model_id == KIMI_DEFAULT_MODEL
    assert client.name() == "kimi"
    # max_tokens falls back to the kimi default when unset
    assert client.max_tokens == KIMI_DEFAULT_MAX_TOKENS


def test_kimi_respects_explicit_max_tokens():
    client = new_from_config(
        _cfg(Backend.KIMI, api_key="key", max_tokens=42)
    )

    assert isinstance(client, OpenAIClient)
    assert client.max_tokens == 42


def test_groq_uses_defaults():
    client = new_from_config(_cfg(Backend.GROQ, api_key="key"))

    assert isinstance(client, OpenAIClient)
    assert client.base_url == GROQ_DEFAULT_BASE_URL
    assert client.model_id == GROQ_DEFAULT_MODEL
    assert client.name() == "groq"


def test_openrouter_sets_referer_headers():
    client = new_from_config(_cfg(Backend.OPENROUTER, api_key="key"))

    assert isinstance(client, OpenAIClient)
    assert client.base_url == OPENROUTER_DEFAULT_BASE_URL
    assert client.model_id == OPENROUTER_DEFAULT_MODEL
    assert client.name() == "openrouter"
    headers = client.headers()
    assert headers["HTTP-Referer"] == "https://github.com/kagent/agent"
    assert headers["X-OpenRouter-Title"] == "kagent"


def test_deepseek_uses_defaults():
    client = new_from_config(_cfg(Backend.DEEPSEEK, api_key="key"))

    assert isinstance(client, OpenAIClient)
    assert client.base_url == DEEPSEEK_DEFAULT_BASE_URL
    assert client.model_id == DEEPSEEK_DEFAULT_MODEL
    assert client.name() == "deepseek"


def test_gemini_builds_client_with_thinking_budget():
    client = new_from_config(
        _cfg(Backend.GEMINI, api_key="key", gemini_thinking_budget=512)
    )

    assert isinstance(client, GeminiClient)
    assert client.base_url == GEMINI_DEFAULT_BASE_URL.rstrip("/")
    assert client.model_id == GEMINI_DEFAULT_MODEL
    assert client.thinking_budget == 512


def test_anthropic_uses_defaults():
    client = new_from_config(_cfg(Backend.ANTHROPIC, api_key="key"))

    assert isinstance(client, AnthropicClient)
    assert client.base_url == ANTHROPIC_DEFAULT_BASE_URL.rstrip("/")
    assert client.model_id == ANTHROPIC_DEFAULT_MODEL
    assert client.name() == "anthropic"


def test_backend_accepts_plain_string_value():
    client = new_from_config(_cfg("groq", api_key="key"))

    assert isinstance(client, OpenAIClient)
    assert client.name() == "groq"


def test_explicit_base_url_and_model_override_defaults():
    cfg = _cfg(
        Backend.GROQ,
        api_key="key",
        base_url="https://custom.test/v1",
        model="custom-model",
    )

    client = new_from_config(cfg)

    assert isinstance(client, OpenAIClient)
    assert client.base_url == "https://custom.test/v1"
    assert client.model_id == "custom-model"
