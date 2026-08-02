from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class TargetSnapshot:
    """Snapshot của target để lưu hoặc khôi phục."""

    baseURL: str = ""
    name: str = ""


class Target:
    """
    Target được chia sẻ giữa Agent và các Tool.

    Dùng để lưu thông tin mục tiêu hiện tại của phiên pentest.
    """

    def __init__(
        self,
        base_url: str = "",
        name: str = "",
    ) -> None:
        self._base_url = base_url.strip()
        self._name = name.strip()

    def base_url(self) -> str:
        """Lấy URL gốc của target."""
        return self._base_url

    def name(self) -> str:
        """Lấy tên của target."""
        return self._name

    def set_base_url(
        self,
        url: str,
    ) -> None:
        """Cập nhật URL gốc."""
        self._base_url = url.strip()

    def set_name(
        self,
        name: str,
    ) -> None:
        """Cập nhật tên target."""
        self._name = name.strip()

    def clear(self) -> None:
        """Xóa toàn bộ thông tin target."""
        self._base_url = ""
        self._name = ""

    def is_empty(self) -> bool:
        """Kiểm tra target có đang rỗng hay không (chưa set gì cả)."""
        return not self._base_url and not self._name

    def empty(self) -> bool:
        """Kiểm tra target có rỗng hay không."""
        return (
            self._base_url == ""
            and self._name == ""
        )

    def copy_from(
        self,
        other: Target | TargetSnapshot | None,
    ) -> None:
        """
        Sao chép dữ liệu từ Target hoặc TargetSnapshot khác.
        """
        if other is None:
            return

        if isinstance(other, Target):
            self._base_url = other._base_url
            self._name = other._name
            return

        self._base_url = other.baseURL
        self._name = other.name

    def to_dict(self) -> dict[str, str]:
        """
        Chuyển Target thành dictionary.

        Giữ nguyên key 'baseURL' để tương thích với
        phiên bản TypeScript.
        """
        return {
            "baseURL": self._base_url,
            "name": self._name,
        }

    @classmethod
    def from_dict(
        cls,
        raw: Any,
    ) -> Target:
        """
        Khởi tạo Target từ dictionary.
        """
        target = cls()

        if isinstance(raw, dict):
            base_url = raw.get("baseURL")
            name = raw.get("name")

            if isinstance(base_url, str):
                target._base_url = base_url

            if isinstance(name, str):
                target._name = name

        return target


def new_target() -> Target:
    """
    Tạo một Target mới.

    Hàm này tương đương newTarget() trong TypeScript.
    """
    return Target()