from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


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

    def add_custom_provider(
        self,
        name: str,
        base_url: str,
        api_key: str = "",
        default_model: str = "",
    ) -> CustomProviderProfile:
        """Add a new custom provider profile and return its profile object."""
        ...

    def edit_custom_provider(
        self,
        profile_id: str,
        name: str,
        base_url: str,
        api_key: str | None = None,
        default_model: str = "",
    ) -> CustomProviderProfile | None:
        """Update an existing custom provider profile.

        If api_key is None, existing key state is retained.
        """
        ...

    def delete_custom_provider(self, profile_id: str) -> bool:
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


_global_adapter: CustomProviderAdapter = InMemoryCustomProviderAdapter()


def get_custom_provider_adapter() -> CustomProviderAdapter:
    """Return the currently configured CustomProviderAdapter."""
    return _global_adapter


def set_custom_provider_adapter(adapter: CustomProviderAdapter) -> None:
    """Set the CustomProviderAdapter to use."""
    global _global_adapter
    _global_adapter = adapter
