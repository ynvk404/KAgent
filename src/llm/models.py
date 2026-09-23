from __future__ import annotations

import socket
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
    OPENAI_DEFAULT_BASE_URL,
    OPENAI_RECOMMENDED_MODELS,
    validate_base_url,
)
from .errors import (
    ProviderControlError,
    exception_has_type_name,
    provider_http_error,
    provider_transport_error,
)
from .transport import new_provider_session, parse_openai_model_ids

DEFAULT_TIMEOUT_S: float = 5.0

DEFAULT_BASE_URL: dict[str, str] = {
    "openai": OPENAI_DEFAULT_BASE_URL,
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

    validate_base_url(base)

    headers: dict[str, str] = {}

    if api_key and b == "gemini":
        headers["x-goog-api-key"] = api_key
    elif b == "anthropic":
        if api_key:
            headers["x-api-key"] = api_key
        headers["anthropic-version"] = ANTHROPIC_VERSION
    elif api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # Model discovery is provider control-plane traffic, just like chat and
    # health probes.  Do not let pentest/Burp proxy variables capture it.
    try:
        with new_provider_session() as session:
            response = session.get(
                f"{base.rstrip('/')}/models",
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
    except requests.exceptions.SSLError as error:
        raise provider_transport_error("tls-failure") from None
    except requests.exceptions.Timeout:
        raise provider_transport_error("timeout") from None
    except requests.exceptions.ConnectionError as error:
        if isinstance(error, socket.gaierror) or exception_has_type_name(
            error, {"gaierror", "NameResolutionError"}
        ):
            raise provider_transport_error("dns-failure") from None
        if exception_has_type_name(error, {"SSLError", "SSLCertVerificationError"}):
            raise provider_transport_error("tls-failure") from None
        raise provider_transport_error("connection-failure") from None
    except requests.exceptions.RequestException:
        raise provider_transport_error("connection-failure") from None

    if response.status_code != 200:
        raise provider_http_error(response.status_code)

    try:
        body = response.json()
    except ValueError:
        raise ProviderControlError(
            "malformed-json",
            "provider returned invalid JSON from the models endpoint",
        ) from None
    if b in {"openai-compat", "lmstudio"}:
        return parse_openai_model_ids(body)
    return _parse_models(b, body)


def _parse_models(backend: str, body: Any) -> list[str]:
    if backend == "openai":
        return _prefer_known_models(parse_openai_model_ids(body), OPENAI_RECOMMENDED_MODELS)
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
        # New DeepSeek models can appear before KAgent has a release.  Keep
        # documented/recommended IDs first without hiding provider discoveries.
        return _prefer_known_models(ids, DEEPSEEK_MODELS, append_unknown=True)
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
