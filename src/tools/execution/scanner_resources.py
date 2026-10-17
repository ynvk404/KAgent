"""Finite resource profile for the trusted Linux scanner adapter."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScannerResources:
    version: str = "linux-scanner-v1"
    address_space: int = 4 * 1024**3
    nofile: int = 4096
    file_bytes: int = 16 * 1024**2
    capture_bytes: int = 64 * 1024
    normalized_bytes: int = 8 * 1024**2
    records: int = 65535
    max_threads: int = 256

    def arguments(self, timeout: int) -> tuple[str, ...]:
        return (f"--as={self.address_space}:{self.address_space}",
                f"--cpu={timeout + 5}:{timeout + 5}",
                f"--nofile={self.nofile}:{self.nofile}",
                f"--fsize={self.file_bytes}:{self.file_bytes}", "--core=0:0", "--")


RESOURCES = ScannerResources()
