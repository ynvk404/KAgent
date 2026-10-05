"""Shared provider data contracts used by the UI."""

from dataclasses import dataclass
from typing import TypedDict

from src.config.config import Backend


@dataclass(slots=True)
class ProviderChange:
    backend: Backend
    model: str
    base_url: str | None = None
    api_key: str | None = None
    custom_provider_id: str | None = None


class ConfigSnapshot(TypedDict):
    backend: Backend
    base_url: str
    api_key: str
    api_keys: dict[str, str]
    model: str
    manual_model: str
    manual_base_url: str
    active_provider_name: str
    active_custom_provider_id: str | None
    active_custom_provider_base_url: str
    active_custom_provider_api_key: str
    active_custom_provider_model: str
