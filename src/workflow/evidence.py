"""Compact references to local validation evidence artifacts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_EVIDENCE_BYTES = 2_000_000


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    id: str
    candidate_id: str
    path: str
    sha256: str
    size: int

    @classmethod
    def capture(
        cls, candidate_id: str, path: str, root: Path,
    ) -> EvidenceArtifact:
        base = root.resolve()
        artifact = (base / path).resolve()
        try:
            relative = artifact.relative_to(base)
        except ValueError as exc:
            raise ValueError("evidence path must stay inside the project") from exc
        if not artifact.is_file():
            raise ValueError("evidence artifact does not exist")
        size = artifact.stat().st_size
        if not 0 < size <= MAX_EVIDENCE_BYTES:
            raise ValueError("evidence artifact must be nonempty and at most 2 MB")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        key = hashlib.sha256(
            f"{candidate_id}\0{relative.as_posix()}\0{digest}".encode()
        ).hexdigest()[:20]
        return cls(f"ev_{key}", candidate_id, relative.as_posix(), digest, size)

    def is_resolvable(self, root: Path) -> bool:
        try:
            current = self.capture(self.candidate_id, self.path, root)
        except (OSError, ValueError):
            return False
        return current == self

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "candidate_id": self.candidate_id,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, value: Any) -> EvidenceArtifact | None:
        if not isinstance(value, dict):
            return None
        try:
            item = cls(
                id=value["id"], candidate_id=value["candidate_id"],
                path=value["path"], sha256=value["sha256"], size=value["size"],
            )
        except (KeyError, TypeError):
            return None
        if (
            not all(isinstance(x, str) and x for x in (item.id, item.candidate_id, item.path, item.sha256))
            or not isinstance(item.size, int) or isinstance(item.size, bool)
            or not 0 < item.size <= MAX_EVIDENCE_BYTES
            or not item.id.startswith("ev_")
        ):
            return None
        return item
