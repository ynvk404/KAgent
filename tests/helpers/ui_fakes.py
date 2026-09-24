"""Shared test fixtures and helpers for UI tests."""

from __future__ import annotations

from typing import Any
from src.config.config import Backend
from src.ui.core.app import ConfigSnapshot


def make_test_config_snapshot(
    backend: Backend = Backend.OPENAI_COMPAT,
    model: str = "test-model",
    base_url: str = "",
    api_key: str = "",
    api_keys: dict[str, str] | None = None,
    manual_model: str = "",
    manual_base_url: str = "",
    active_provider_name: str = "",
    active_custom_provider_id: str | None = None,
    active_custom_provider_base_url: str = "",
    active_custom_provider_api_key: str = "",
    active_custom_provider_model: str = "",
    **extra: Any,
) -> ConfigSnapshot:
    snap: ConfigSnapshot = {
        "backend": backend,
        "base_url": base_url,
        "api_key": api_key,
        "api_keys": {} if api_keys is None else api_keys,
        "model": model,
        "manual_model": manual_model or model,
        "manual_base_url": manual_base_url or base_url,
        "active_provider_name": active_provider_name,
        "active_custom_provider_id": active_custom_provider_id,
        "active_custom_provider_base_url": active_custom_provider_base_url,
        "active_custom_provider_api_key": active_custom_provider_api_key,
        "active_custom_provider_model": active_custom_provider_model,
    }
    if extra:
        snap.update(extra)  # type: ignore[typeddict-item]
    return snap
