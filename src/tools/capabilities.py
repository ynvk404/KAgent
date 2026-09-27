from __future__ import annotations

import shutil
from dataclasses import dataclass, replace
from typing import Callable


@dataclass(frozen=True, slots=True)
class ScannerCapabilities:
    """Paths to optional scanners available to this KAgent runtime."""

    ffuf: str | None = None
    nmap: str | None = None

    def prompt_summary(self) -> str:
        available = [
            name for name, path in (("ffuf", self.ffuf), ("nmap", self.nmap))
            if path is not None
        ]
        return ", ".join(available) if available else "native tools only"


class CapabilityInventory:
    """Lazily detect optional executables once per runtime/session."""

    def __init__(self, which: Callable[[str], str | None] | None = None) -> None:
        self._which = which
        self._snapshot: ScannerCapabilities | None = None

    def snapshot(self) -> ScannerCapabilities:
        if self._snapshot is None:
            finder = self._which or shutil.which
            self._snapshot = ScannerCapabilities(
                ffuf=finder("ffuf"),
                nmap=finder("nmap"),
            )
        return self._snapshot

    def mark_unavailable(self, scanner: str, expected_path: str | None = None) -> None:
        """Invalidate a cached capability after its executable cannot be started."""
        if scanner not in {"ffuf", "nmap"}:
            raise ValueError(f"unsupported scanner capability: {scanner}")
        current = self.snapshot()
        if expected_path is not None and getattr(current, scanner) != expected_path:
            return
        self._snapshot = replace(current, **{scanner: None})
