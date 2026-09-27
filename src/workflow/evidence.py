"""Compact references to local validation evidence artifacts."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.redact.redact import apply as redact

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

    @classmethod
    def capture_immutable_snapshot(
        cls, candidate_id: str, path: str, root: Path,
    ) -> EvidenceArtifact:
        """Snapshot a project proof into content-addressed, read-only storage."""
        base = root.resolve()
        source = (base / path).resolve()
        try:
            source.relative_to(base)
        except ValueError as exc:
            raise ValueError("evidence path must stay inside the project") from exc
        if not source.is_file():
            raise ValueError("evidence artifact does not exist")
        raw = source.read_bytes()
        if not 0 < len(raw) <= MAX_EVIDENCE_BYTES:
            raise ValueError("evidence artifact must be nonempty and at most 2 MB")
        try:
            snapshot = redact(raw.decode("utf-8")).encode("utf-8")
        except UnicodeDecodeError:
            # Preserve existing binary-proof support; text artifacts pass through
            # the normal secret redactor before becoming durable evidence.
            snapshot = raw
        if not 0 < len(snapshot) <= MAX_EVIDENCE_BYTES:
            raise ValueError("redacted evidence must be nonempty and at most 2 MB")

        digest = hashlib.sha256(snapshot).hexdigest()
        candidate_key = hashlib.sha256(candidate_id.encode("utf-8")).hexdigest()[:24]
        storage = base / ".kagent" / "evidence"
        resolved_storage = storage.resolve()
        try:
            resolved_storage.relative_to(base)
        except ValueError as exc:
            raise ValueError("evidence snapshot path must stay inside the project") from exc
        resolved_storage.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved_storage.chmod(0o700)
        directory = resolved_storage / candidate_key
        directory.mkdir(exist_ok=True, mode=0o700)
        if directory.is_symlink() or directory.resolve().parent != resolved_storage:
            raise ValueError("evidence snapshot directory must stay inside project storage")
        directory.chmod(0o700)
        filename = f"{digest}.proof"
        destination = directory / filename
        relative = destination.relative_to(base)
        if destination.is_symlink():
            raise ValueError("evidence snapshot file cannot be a symbolic link")
        try:
            file_descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(file_descriptor, "wb") as handle:
                handle.write(snapshot)
        except FileExistsError:
            if destination.read_bytes() != snapshot:
                raise ValueError("evidence snapshot hash collision")
        destination.chmod(0o400)
        return cls.capture(candidate_id, relative.as_posix(), base)

    def is_resolvable(self, root: Path) -> bool:
        try:
            current = self.capture(self.candidate_id, self.path, root)
        except (OSError, ValueError):
            return False
        return current == self

    def is_resolvable_for_resume(self, project_root: Path) -> bool:
        """Read old CWD-relative proof when resuming from that same CWD."""
        if self.is_resolvable(project_root):
            return True
        parts = Path(self.path).parts
        if parts and parts[0] == "artifacts":
            return False
        old_root = Path.cwd().resolve()
        try:
            old_root.relative_to(project_root.resolve())
        except ValueError:
            return False
        return old_root != project_root.resolve() and self.is_resolvable(old_root)

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
