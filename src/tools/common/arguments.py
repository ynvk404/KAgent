"""Focused local input checks, independent of provider schema conversion."""
from __future__ import annotations

from typing import Any


def string_fields(
    args: dict[str, Any],
    *,
    required: tuple[str, ...] = (),
    optional: tuple[str, ...] = (),
    nonempty: tuple[str, ...] = (),
) -> None:
    for key in required:
        if key not in args:
            raise ValueError(f"{key} is required and must be a string")
    for key in (*required, *optional):
        if key in args and not isinstance(args[key], str):
            raise ValueError(f"{key} must be a string")
    for key in nonempty:
        if key in args and not args[key]:
            raise ValueError(f"{key} must be a non-empty string")


def positive_integer(value: object) -> bool:
    # JSON Schema's integer includes integral JSON numbers such as 1.0.
    # Avoid converting arbitrary-size Python integers through float.
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and value > 0 and (isinstance(value, int) or value.is_integer()))
