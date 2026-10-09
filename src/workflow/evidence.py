"""Compact references to local validation evidence artifacts."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from src.redaction.redact import apply_evidence as redact
from src.tools.execution.sensitive import is_sensitive_path
from src.permission.permission import Prompter, UserControlledRefusal

MAX_EVIDENCE_BYTES = 2_000_000

# A non-interactive status check may reuse a checksum only while the file's
# stat signature is unchanged. This is not a permission cache and is not saved.
_verified_sensitive: dict[tuple[str, str], tuple[int, int, int, int]] = {}


def check_proof_references(content: bytes, candidate_id: str, parents: list[str]) -> None:
    """Bind explicit source claims in an identifiable Markdown candidate entry.

    This is deliberately a narrow source contract, not a narrative verifier.
    Unscoped/ambiguous documents and binary artifacts still use structured
    assessment.excerpts. Examples in fences, quotes and indented code are not
    active claims. Full observation handles on their own line or in explicit
    observation/source ID fields are claims; incidental IDs in prose are not.
    """
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return
    active: list[tuple[int, str]] = []
    fence = None
    quoted = False
    for position, line in enumerate(lines):
        if line.lstrip().startswith(">"):
            quoted = True
            continue
        if quoted and line.strip() and not re.match(r"^ {0,3}(?:#{1,6}\s|[-*+]\s|`{3,}|~{3,})", line):
            continue  # lazy continuation of a quoted example paragraph
        quoted = False
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if fence:
            if (marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence)
                    and not line[marker.end():].strip()):
                fence = None
            continue
        if marker:
            fence = marker[1]
            continue
        if line.startswith(("    ", "\t")):
            continue
        active.append((position, line))

    metadata = re.compile(r"^ {0,3}(?:-\s+)?(?:\*\*)?candidate_id:(?:\*\*)?\s+`?([^\s`]+)`?\s*$")
    headings = []
    entries = []
    for position, line in active:
        heading = re.match(r"^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if heading:
            level = len(heading[1])
            while headings and headings[-1][1] >= level:
                headings.pop()
            headings.append((position, level, heading[2]))
        field = metadata.fullmatch(line)
        if field:
            # Canonical aggregates have Candidate headings; standalone proofs
            # have one candidate_id under their document title (or no title).
            boundary = next((h for h in reversed(headings)
                             if re.match(r"Candidate\b", h[2], re.IGNORECASE)), None)
            boundary = boundary or next((h for h in headings if h[1] == 1), None)
            entries.append((field[1], boundary))
    matches = [boundary for identity, boundary in entries if identity == candidate_id]
    if len(matches) != 1:
        return  # no reliable selected entry; keep the structured excerpt contract
    boundary = matches[0]
    if sum(other == boundary for _, other in entries) != 1:
        return
    start, level = (boundary[0], boundary[1]) if boundary else (0, 0)
    end = len(lines)
    if boundary:
        for position, line in active:
            heading = re.match(r"^ {0,3}(#{1,6})\s+", line)
            if position > start and heading and len(heading[1]) <= level:
                end = position
                break
    # Do not infer that unlabelled Candidate sections elsewhere belong to a
    # standalone document's root marker. Ambiguous scope stays structured.
    if (boundary is None or not re.match(r"Candidate\b", boundary[2], re.IGNORECASE)) and any(
            start < position < end and re.match(r"^ {0,3}#{1,6}\s+Candidate\b", line, re.IGNORECASE)
            for position, line in active):
        return
    observation = r"obs_[0-9a-f]{32}"
    single = re.compile(rf"^ {{0,3}}(?:-\s+)?`?({observation})`?\s*$")
    field = re.compile(r"^ {0,3}(?:-\s+)?(?:\*\*)?(?:observation_ids?|observation(?: ids?)?|source_ids?):(?:\*\*)?\s*(.*)$",
                       re.IGNORECASE)
    # Only a field made of handles/list punctuation/placeholders is unambiguous.
    values = re.compile(rf"(?:{observation}|\[REDACTED(?:[^\]]*)\]|[\s`,;\[\]])+")
    claimed = set()
    for position, line in active:
        if not start <= position < end:
            continue
        match = single.fullmatch(line)
        if match:
            claimed.add(match[1])
        match = field.fullmatch(line)
        if match and values.fullmatch(match[1]):
            claimed.update(re.findall(observation, re.sub(r"\[REDACTED[^\]]*\]", "", match[1])))
    if claimed - set(parents):
        raise ValueError(
            "proof observation reference lacks a declared primary parent; "
            "correct the candidate artifact and dependent claims before re-registering"
        )


def _signature(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    id: str
    candidate_id: str
    path: str
    sha256: str
    size: int
    source_path: str | None = None

    def requires_read_permission(self, root: Path) -> bool:
        return (
            is_sensitive_path(str(root / self.path))
            or is_sensitive_path(str((root / self.path).resolve()))
            or (self.source_path is not None and is_sensitive_path(self.source_path))
        )

    @classmethod
    def capture(
        cls, candidate_id: str, path: str, root: Path, *, sensitive_read_approved: bool = False,
    ) -> EvidenceArtifact:
        base = root.resolve()
        artifact = (base / path).resolve()
        try:
            relative = artifact.relative_to(base)
        except ValueError as exc:
            raise ValueError("evidence path must stay inside the project") from exc
        if not sensitive_read_approved and (
            is_sensitive_path(str(base / path)) or is_sensitive_path(str(artifact))
        ):
            raise UserControlledRefusal("sensitive evidence read requires permission")
        if not artifact.is_file():
            raise ValueError("evidence artifact does not exist")
        before_read = _signature(artifact)
        size = before_read[1]
        if not 0 < size <= MAX_EVIDENCE_BYTES:
            raise ValueError("evidence artifact must be nonempty and at most 2 MB")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        after_read = _signature(artifact)
        if sensitive_read_approved and is_sensitive_path(str(artifact)) and before_read == after_read:
            if len(_verified_sensitive) >= 1024:
                _verified_sensitive.pop(next(iter(_verified_sensitive)))
            _verified_sensitive[(str(artifact), digest)] = after_read
        key = hashlib.sha256(
            f"{candidate_id}\0{relative.as_posix()}\0{digest}".encode()
        ).hexdigest()[:20]
        return cls(f"ev_{key}", candidate_id, relative.as_posix(), digest, size)

    @classmethod
    def capture_immutable_snapshot(
        cls, candidate_id: str, path: str, root: Path, *, sensitive_read_approved: bool = False,
        original_path: str | None = None,
    ) -> EvidenceArtifact:
        """Snapshot a project proof into content-addressed, read-only storage."""
        base = root.resolve()
        source = (base / path).resolve()
        try:
            source.relative_to(base)
        except ValueError as exc:
            raise ValueError("evidence path must stay inside the project") from exc
        provenance_path = original_path or str(base / path)
        sensitive = (
            is_sensitive_path(provenance_path)
            or is_sensitive_path(str(base / path)) or is_sensitive_path(str(source))
        )
        if sensitive and not sensitive_read_approved:
            raise UserControlledRefusal("sensitive evidence snapshot requires permission")
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
        if sensitive:
            directory = directory / "sensitive"
            if directory.is_symlink():
                raise ValueError("sensitive evidence directory cannot be a symbolic link")
            directory.mkdir(exist_ok=True, mode=0o700)
            if not directory.resolve().is_relative_to(resolved_storage):
                raise ValueError("sensitive evidence directory must stay inside project storage")
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
        artifact = cls.capture(
            candidate_id, relative.as_posix(), base,
            sensitive_read_approved=sensitive_read_approved,
        )
        return replace(artifact, source_path=provenance_path)

    def is_resolvable(self, root: Path, *, sensitive_read_approved: bool = False) -> bool:
        if self.requires_read_permission(root) and not sensitive_read_approved:
            return False
        try:
            current = self.capture(
                self.candidate_id, self.path, root,
                sensitive_read_approved=sensitive_read_approved,
            )
        except (OSError, ValueError):
            return False
        return replace(current, source_path=self.source_path) == self

    def _resume_roots(self, project_root: Path) -> list[Path]:
        roots = [project_root]
        old_root = Path.cwd().resolve()
        if (
            not (Path(self.path).parts and Path(self.path).parts[0] == "artifacts")
            and old_root != project_root.resolve()
            and old_root.is_relative_to(project_root.resolve())
        ):
            roots.append(old_root)
        return roots

    async def is_resolvable_with_permission(
        self, root: Path, prompter: Prompter, signal: Any = None,
        *, approved_paths: set[str] | None = None,
    ) -> bool:
        from src.tools.execution.file import gate_sensitive_path
        from src.permission.runtime.execution import policy_for

        for base in self._resume_roots(root):
            path = base / self.path
            if not path.resolve().is_relative_to(base.resolve()) or not path.is_file():
                continue
            # One approval covers the source restriction and all checksum reads
            # for this immutable derivative in the current operation only.
            policy = policy_for(prompter)
            managed = bool(policy and Path(self.path).parts[:2] == (".kagent", "evidence"))
            if managed:
                assert policy is not None
                policy.require_evidence(self, base)
            gated = self.source_path if self.source_path and (managed or is_sensitive_path(self.source_path)) else str(path)
            if approved_paths is None or gated not in approved_paths:
                await gate_sensitive_path(prompter, gated, "read evidence", signal)
                if approved_paths is not None:
                    approved_paths.add(gated)
            if managed:
                assert policy is not None
                policy.require_evidence(self, base)
            if self.is_resolvable(base, sensitive_read_approved=True):
                return True
        return False

    def is_available_for_resume(self, root: Path) -> bool:
        """Non-interactive status: sensitive contents are verified by gated tools."""
        for base in self._resume_roots(root):
            if not self.requires_read_permission(base):
                if self.is_resolvable(base):
                    return True
                continue
            path = (base / self.path).resolve()
            try:
                if (
                    path.is_relative_to(base.resolve()) and path.is_file()
                    and _verified_sensitive.get((str(path), self.sha256)) == _signature(path)
                ):
                    return True
            except OSError:
                pass
        return False

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
            **({"source_path": self.source_path} if self.source_path is not None else {}),
        }

    @classmethod
    def from_dict(cls, value: Any) -> EvidenceArtifact | None:
        if not isinstance(value, dict):
            return None
        try:
            item = cls(
                id=value["id"], candidate_id=value["candidate_id"],
                path=value["path"], sha256=value["sha256"], size=value["size"],
                source_path=value.get("source_path"),
            )
        except (KeyError, TypeError):
            return None
        if (
            not all(isinstance(x, str) and x for x in (item.id, item.candidate_id, item.path, item.sha256))
            or not isinstance(item.size, int) or isinstance(item.size, bool)
            or not 0 < item.size <= MAX_EVIDENCE_BYTES
            or not item.id.startswith("ev_")
            or (item.source_path is not None and not isinstance(item.source_path, str))
        ):
            return None
        return item


async def verify_evidence_reads(
    artifacts: list[EvidenceArtifact], root: Path, prompter: Prompter, signal: Any,
    *, approved_paths: set[str] | None = None,
) -> bool:
    """Reuse exact read approvals only within this tool operation."""
    if approved_paths is None:
        approved_paths = set()
    for artifact in artifacts:
        if not await artifact.is_resolvable_with_permission(
            root, prompter, signal, approved_paths=approved_paths,
        ):
            return False
    return True
