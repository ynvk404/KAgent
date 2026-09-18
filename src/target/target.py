from __future__ import annotations

from dataclasses import dataclass
from typing import Any

@dataclass(slots=True)
class TargetSnapshot:
    baseURL: str = ""
    name: str = ""

class Target:
    def __init__(
        self,
        base_url: str = "",
        name: str = "",
    ) -> None:
        self._base_url = base_url.strip()
        self._name = name.strip()

    def base_url(self) -> str:
        return self._base_url

    def name(self) -> str:
        return self._name

    def set_base_url(
        self,
        url: str,
    ) -> None:
        self._base_url = url.strip()

    def set_name(
        self,
        name: str,
    ) -> None:
        self._name = name.strip()

    def clear(self) -> None:
        self._base_url = ""
        self._name = ""

    def is_empty(self) -> bool:
        return not self._base_url and not self._name

    def empty(self) -> bool:
        return (
            self._base_url == ""
            and self._name == ""
        )

    def copy_from(
        self,
        other: Target | TargetSnapshot | None,
    ) -> None:
        if other is None:
            return

        if isinstance(other, Target):
            self.set_base_url(other._base_url)
            self.set_name(other._name)
            return

        self.set_base_url(other.baseURL)
        self.set_name(other.name)

    def to_dict(self) -> dict[str, str]:
        return {
            "baseURL": self._base_url,
            "name": self._name,
        }

    @classmethod
    def from_dict(
        cls,
        raw: Any,
    ) -> Target:
        target = cls()

        if isinstance(raw, dict):
            base_url = raw.get("baseURL")
            name = raw.get("name")

            if isinstance(base_url, str):
                target.set_base_url(base_url)

            if isinstance(name, str):
                target.set_name(name)

        return target

def new_target() -> Target:
    return Target()
