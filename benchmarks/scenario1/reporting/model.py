"""Small normalized projection; raw request and evidence objects never enter it."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ReportModel:
    metadata: dict[str, Any]
    metrics: dict[str, Any]
    cases: tuple[dict[str, Any], ...]
