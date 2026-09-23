from __future__ import annotations

import copy
import inspect
import asyncio
from dataclasses import dataclass, fields
from typing import Any, Awaitable, Callable, Protocol

from src.config.config import (
    Config,
    add_custom_provider,
    delete_custom_provider,
    edit_custom_provider,
)
from src.llm.providers import validate_base_url
from src.llm.models import list_models


@dataclass(frozen=True, slots=True)
class CustomProviderProfile:
    """Non-secret metadata representation of a saved custom provider profile."""
    id: str
    name: str
    base_url: str
    default_model: str = ""
    has_api_key: bool = False


class CustomProviderAdapter(Protocol):
    """UI-facing adapter boundary for managing custom provider profiles."""

    def list_custom_providers(self) -> list[CustomProviderProfile]:
        """Return all saved custom provider profiles."""
        ...

    def get_current_provider_id(self) -> str | None:
        """Return the ID of the currently active custom provider, if any."""
        ...

    def is_active(self, profile_id: str) -> bool:
        """Return True if the specified custom provider is currently active."""
        ...

    async def discover_custom_models(
        self,
        profile_id: str,
        base_url: str | None = None,
        api_key_override: str | None = None,
    ) -> list[str]:
        """Discover models without returning a stored key to the UI."""
        ...

    def add_custom_provider(
        self,
        name: str,
        base_url: str,
        api_key: str = "",
        default_model: str = "",
    ) -> CustomProviderProfile | Awaitable[CustomProviderProfile]:
        """Add a new custom provider profile and return its profile object."""
        ...

    def edit_custom_provider(
        self,
        profile_id: str,
        name: str,
        base_url: str,
        api_key: str | None = None,
        default_model: str = "",
    ) -> CustomProviderProfile | None | Awaitable[CustomProviderProfile | None]:
        """Update an existing custom provider profile.

        If api_key is None, existing key state is retained.
        """
        ...

    def delete_custom_provider(self, profile_id: str) -> bool | Awaitable[bool]:
        """Delete a saved custom provider profile by ID."""
        ...

    def activate_custom_provider(self, profile_id: str | None) -> bool:
        """Set the active profile, or clear it after switching away."""
        ...


class InMemoryCustomProviderAdapter:
    """In-memory reference implementation and test double for CustomProviderAdapter."""

    def __init__(
        self,
        profiles: list[CustomProviderProfile] | None = None,
        active_id: str | None = None,
    ) -> None:
        self._profiles: dict[str, CustomProviderProfile] = {}
        self._keys: dict[str, str] = {}
        self._active_id: str | None = active_id

        if profiles:
            for p in profiles:
                self._profiles[p.id] = p
                if p.has_api_key:
                    self._keys[p.id] = "present"

    def list_custom_providers(self) -> list[CustomProviderProfile]:
        return list(self._profiles.values())

    def get_current_provider_id(self) -> str | None:
        return self._active_id

    def is_active(self, profile_id: str) -> bool:
        return self._active_id == profile_id

    async def discover_custom_models(
        self,
        profile_id: str,
        base_url: str | None = None,
        api_key_override: str | None = None,
    ) -> list[str]:
        profile = self._profiles.get(profile_id)
        if profile is None:
            raise ValueError("custom provider profile not found")
        return await asyncio.to_thread(
            list_models,
            "openai-compat",
            validate_base_url(base_url or profile.base_url),
            api_key_override if api_key_override is not None else self._keys.get(profile_id, ""),
        )

    def add_custom_provider(
        self,
        name: str,
        base_url: str,
        api_key: str = "",
        default_model: str = "",
    ) -> CustomProviderProfile:
        # Generate an ID from name
        import re
        base_slug = re.sub(r"[^a-zA-Z0-9_\-]+", "-", name.strip().lower()).strip("-")
        profile_id = base_slug or "custom"
        counter = 1
        while profile_id in self._profiles:
            profile_id = f"{base_slug}-{counter}"
            counter += 1

        has_key = bool(api_key.strip()) if api_key else False
        if has_key:
            self._keys[profile_id] = api_key

        profile = CustomProviderProfile(
            id=profile_id,
            name=name.strip(),
            base_url=base_url.strip(),
            default_model=default_model.strip(),
            has_api_key=has_key,
        )
        self._profiles[profile_id] = profile
        return profile

    def edit_custom_provider(
        self,
        profile_id: str,
        name: str,
        base_url: str,
        api_key: str | None = None,
        default_model: str = "",
    ) -> CustomProviderProfile | None:
        existing = self._profiles.get(profile_id)
        if not existing:
            return None

        if api_key is not None:
            has_key = bool(api_key.strip())
            if has_key:
                self._keys[profile_id] = api_key
            else:
                self._keys.pop(profile_id, None)
        else:
            has_key = existing.has_api_key

        updated = CustomProviderProfile(
            id=profile_id,
            name=name.strip() if name.strip() else existing.name,
            base_url=base_url.strip() if base_url.strip() else existing.base_url,
            default_model=default_model.strip(),
            has_api_key=has_key,
        )
        self._profiles[profile_id] = updated
        return updated

    def delete_custom_provider(self, profile_id: str) -> bool:
        if profile_id in self._profiles:
            del self._profiles[profile_id]
            self._keys.pop(profile_id, None)
            if self._active_id == profile_id:
                self._active_id = None
            return True
        return False

    def activate_custom_provider(self, profile_id: str | None) -> bool:
        if profile_id is None:
            self._active_id = None
            return True
        if profile_id in self._profiles:
            self._active_id = profile_id
            return True
        return False


class ConfigBackedCustomProviderAdapter:
    """Persistent adapter that exposes only non-secret Config metadata."""

    def __init__(
        self,
        cfg: Config,
        save_config: Callable[[Config], Any],
        runtime_active_id: Callable[[], str | None],
        active_edit: Callable[[Config, str], Awaitable[None]] | None = None,
        mutation_lock: asyncio.Lock | None = None,
    ) -> None:
        self._cfg = cfg
        self._save_config = save_config
        self._runtime_active_id = runtime_active_id
        self._active_edit = active_edit
        self._mutation_lock = mutation_lock or asyncio.Lock()

    def list_custom_providers(self) -> list[CustomProviderProfile]:
        return [
            CustomProviderProfile(
                id=profile_id,
                name=profile.name,
                base_url=profile.base_url,
                default_model=profile.default_model,
                has_api_key=bool(self._cfg.custom_provider_api_keys.get(profile_id)),
            )
            for profile_id, profile in self._cfg.custom_providers.items()
        ]

    def get_current_provider_id(self) -> str | None:
        return self._runtime_active_id()

    def is_active(self, profile_id: str) -> bool:
        return self._runtime_active_id() == profile_id

    async def discover_custom_models(
        self,
        profile_id: str,
        base_url: str | None = None,
        api_key_override: str | None = None,
    ) -> list[str]:
        profile = self._cfg.custom_providers.get(profile_id)
        if profile is None:
            raise ValueError("custom provider profile not found")
        effective_url = validate_base_url(base_url or profile.base_url)
        effective_key = (
            api_key_override
            if api_key_override is not None
            else self._cfg.custom_provider_api_keys.get(profile_id, "")
        )
        return await asyncio.to_thread(
            list_models,
            "openai-compat",
            effective_url,
            effective_key,
        )

    async def add_custom_provider(
        self,
        name: str,
        base_url: str,
        api_key: str = "",
        default_model: str = "",
    ) -> CustomProviderProfile:
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("custom provider name must not be empty")
        normalized_url = validate_base_url(base_url.strip())
        async with self._mutation_lock:
            candidate = copy.deepcopy(self._cfg)
            profile_id = add_custom_provider(
                candidate,
                normalized_name,
                normalized_url,
                api_key,
                default_model,
            )
            await self._save_candidate(candidate)
            return self._profile(profile_id)

    async def edit_custom_provider(
        self,
        profile_id: str,
        name: str,
        base_url: str,
        api_key: str | None = None,
        default_model: str = "",
    ) -> CustomProviderProfile | None:
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("custom provider name must not be empty")
        normalized_url = validate_base_url(base_url.strip())
        async with self._mutation_lock:
            if profile_id not in self._cfg.custom_providers:
                return None
            candidate = copy.deepcopy(self._cfg)
            edit_custom_provider(
                candidate,
                profile_id,
                name=normalized_name,
                base_url=normalized_url,
                api_key=api_key,
                default_model=default_model,
            )

            if self.is_active(profile_id):
                if self._active_edit is None:
                    raise RuntimeError("active Custom profile runtime is unavailable")
                candidate.active_custom_provider_id = profile_id
                await self._active_edit(candidate, profile_id)
            else:
                await self._save_candidate(candidate)
            return self._profile(profile_id)

    async def delete_custom_provider(self, profile_id: str) -> bool:
        async with self._mutation_lock:
            if self.is_active(profile_id) or profile_id not in self._cfg.custom_providers:
                return False
            candidate = copy.deepcopy(self._cfg)
            if candidate.active_custom_provider_id == profile_id:
                runtime_id = self._runtime_active_id()
                candidate.active_custom_provider_id = (
                    runtime_id if runtime_id in candidate.custom_providers else None
                )
            if not delete_custom_provider(candidate, profile_id):
                return False
            await self._save_candidate(candidate)
            return True

    def activate_custom_provider(self, profile_id: str | None) -> bool:
        # Runtime switching owns active state; this adapter only reports it.
        return self._runtime_active_id() == profile_id

    def _profile(self, profile_id: str) -> CustomProviderProfile:
        profile = self._cfg.custom_providers[profile_id]
        return CustomProviderProfile(
            id=profile_id,
            name=profile.name,
            base_url=profile.base_url,
            default_model=profile.default_model,
            has_api_key=bool(self._cfg.custom_provider_api_keys.get(profile_id)),
        )

    async def _save_candidate(self, candidate: Config) -> None:
        try:
            result = self._save_config(candidate)
            if inspect.isawaitable(result):
                await result
        except BaseException:
            # A cancelled save may already have replaced the file. Keep the
            # mutation lock until its compensating write has settled.
            async def restore() -> None:
                result = self._save_config(copy.deepcopy(self._cfg))
                if inspect.isawaitable(result):
                    await result

            rollback = asyncio.create_task(restore())
            while not rollback.done():
                try:
                    await asyncio.shield(rollback)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            try:
                rollback.result()
            except Exception:
                pass
            raise
        for config_field in fields(Config):
            setattr(
                self._cfg,
                config_field.name,
                copy.deepcopy(getattr(candidate, config_field.name)),
            )


_global_adapter: CustomProviderAdapter = InMemoryCustomProviderAdapter()


def get_custom_provider_adapter() -> CustomProviderAdapter:
    """Return the currently configured CustomProviderAdapter."""
    return _global_adapter


def set_custom_provider_adapter(adapter: CustomProviderAdapter) -> None:
    """Set the CustomProviderAdapter to use."""
    global _global_adapter
    _global_adapter = adapter
