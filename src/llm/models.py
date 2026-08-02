from __future__ import annotations

from typing import Any

import requests

from src.config.config import Backend
from .providers import (
    ANTHROPIC_DEFAULT_BASE_URL,
    ANTHROPIC_RECOMMENDED_MODELS,
    ANTHROPIC_VERSION,
    DEEPSEEK_DEFAULT_BASE_URL,
    DEEPSEEK_MODELS,
    GEMINI_DEFAULT_BASE_URL,
    GEMINI_RECOMMENDED_MODELS,
    GROQ_DEFAULT_BASE_URL,
    GROQ_MODELS,
    KIMI_DEFAULT_BASE_URL,
    KIMI_MODELS,
    OPENROUTER_DEFAULT_BASE_URL,
    OPENROUTER_RECOMMENDED_MODELS,
)

DEFAULT_TIMEOUT_S: float = 5.0

DEFAULT_BASE_URL: dict[str, str] = {
    "lmstudio": "http://localhost:1234/v1",
    "openai-compat": "",
    "kimi": KIMI_DEFAULT_BASE_URL,
    "groq": GROQ_DEFAULT_BASE_URL,
    "openrouter": OPENROUTER_DEFAULT_BASE_URL,
    "deepseek": DEEPSEEK_DEFAULT_BASE_URL,
    "gemini": GEMINI_DEFAULT_BASE_URL,
    "anthropic": ANTHROPIC_DEFAULT_BASE_URL,
}


def list_models(
    backend: Backend | str,
    base_url: str = "",
    api_key: str = "",
    timeout: float = DEFAULT_TIMEOUT_S,
) -> list[str]:
    if isinstance(backend, Backend):
        b = backend.value
    else:
        b = backend or "groq"

    base = base_url or DEFAULT_BASE_URL.get(b, "")

    if not base:
        raise ValueError(f"{b} backend requires a base URL")

    headers: dict[str, str] = {}

    if api_key and b == "gemini":
        headers["x-goog-api-key"] = api_key
    elif b == "anthropic":
        if api_key:
            headers["x-api-key"] = api_key
        headers["anthropic-version"] = ANTHROPIC_VERSION
    elif api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    response = requests.get(
        f"{base}/models",
        headers=headers,
        timeout=timeout,
    )

    if response.status_code != 200:
        raise requests.HTTPError(f"{b} list-models returned {response.status_code}")

    return _parse_models(b, response.json())


def _parse_models(backend: str, body: Any) -> list[str]:
    if not isinstance(body, dict):
        return []

    if backend == "gemini":
        models = body.get("models") or []
        names = [
            m.get("name", "")
            for m in models
            if isinstance(m, dict)
            and "generateContent" in (m.get("supportedGenerationMethods") or [])
        ]
        names = [n for n in names if isinstance(n, str) and n]
        return _prefer_gemini_recommended(names)

    data = body.get("data") or []
    ids = [m.get("id", "") for m in data if isinstance(m, dict)]
    ids = [i for i in ids if isinstance(i, str) and i]

    if backend == "kimi":
        return _prefer_known_models(ids, KIMI_MODELS)
    if backend == "groq":
        return _prefer_known_models(ids, GROQ_MODELS)
    if backend == "openrouter":
        return _prefer_openrouter_models(ids)
    if backend == "deepseek":
        return _prefer_known_models(ids, DEEPSEEK_MODELS)
    if backend == "anthropic":
        return _prefer_known_models(ids, ANTHROPIC_RECOMMENDED_MODELS, append_unknown=True)

    return ids


def _prefer_gemini_recommended(models: list[str]) -> list[str]:
    return _prefer_known_models(models, GEMINI_RECOMMENDED_MODELS, append_unknown=True)


def _prefer_openrouter_models(models: list[str]) -> list[str]:
    with_auto = (
        models if "openrouter/auto" in models else [*OPENROUTER_RECOMMENDED_MODELS, *models]
    )
    return _prefer_known_models(with_auto, OPENROUTER_RECOMMENDED_MODELS, append_unknown=True)


def _prefer_known_models(
    models: list[str],
    known: tuple[str, ...],
    *,
    append_unknown: bool = False,
) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    for m in known:
        if m in models and m not in seen:
            out.append(m)
            seen.add(m)

    if not append_unknown:
        return out

    for m in models:
        if m not in seen:
            out.append(m)
            seen.add(m)

    return out