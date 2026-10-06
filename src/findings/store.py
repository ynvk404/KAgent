from __future__ import annotations

import asyncio
import os
import re
import hashlib
import json
import tempfile
import weakref
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Literal, cast, Any, Callable

from src.paths import project_artifact_root, project_root

Severity = Literal[
    "critical",
    "high",
    "medium",
    "low",
    "info",
]

_SAFE_SLUG_RE = re.compile(r"^[a-z0-9-]+$")
_REPORT_SECTIONS = frozenset({
    "Impact",  # Legacy reports written before observed/potential were split.
    "Observed impact",
    "Potential impact",
    "Payload",
    "Response excerpt",
    "Reproduce",
    "Remediation",
})

# Cooperating Store instances in one process/event loop share the full mutation
# lock. This is deliberately not cross-process compare-and-swap.
_STORE_LOCKS: weakref.WeakValueDictionary[str, asyncio.Lock] = weakref.WeakValueDictionary()
MAX_REPORT_BYTES = 2_000_000


class ClassificationCommittedError(RuntimeError):
    """The replacement is visible even though snapshot recovery failed."""


@dataclass(slots=True)
class Finding:
    title: str
    severity: Severity
    url: str

    observed_impact: str
    potential_impact: str

    parameter: str | None = None
    payload: str | None = None
    method: str | None = None
    responseExcerpt: str | None = None
    curl: str | None = None
    remediation: str | None = None
    vulnerabilityType: str | None = None
    cwe: list[str] | None = None
    owasp: list[str] | None = None

    createdAt: str = ""
    slug: str = ""
    candidate_id: str | None = None
    evidence_refs: list[str] | None = None
    canonical_class: str | None = None
    confirmation_binding: str | None = None
    classification_provenance: dict[str, Any] | None = None
    classification_revision: int = 0

    @property
    def classification_origin(self) -> str | None:
        if not self.cwe:
            return None
        return (self.classification_provenance or {}).get("origin", "legacy/unknown")


class Store:

    def __init__(
        self,
        directory: str | Path | None = None,
        *,
        project_directory: str | Path | None = None,
    ) -> None:
        # Explicit directories are supported for embedded callers and tests.
        # Production passes the project directory, so evidence resolution does
        # not depend on where reports happen to be stored.
        self.project_dir = project_root(
            project_directory if project_directory is not None else
            (Path(directory).resolve().parent if directory is not None else None)
        )
        self.dir = (
            Path(directory).resolve()
            if directory is not None
            else project_artifact_root(self.project_dir) / "findings"
        )
        key = str(self.project_dir)
        self._save_lock = _STORE_LOCKS.setdefault(key, asyncio.Lock())

    def report_for_candidate(self, candidate_id: str) -> Path:
        matches: list[Path] = []
        marker = f"- **Candidate ID:** {candidate_id}".encode("utf-8")
        for directory in dict.fromkeys((self.dir, self.project_dir / "findings")):
            if directory.exists():
                for path in sorted(directory.glob("*.md")):
                    if marker not in report_bytes(path).splitlines():
                        continue
                    if read_report(path).candidate_id == candidate_id:
                        matches.append(path)
        if len(matches) != 1:
            raise ValueError("finding report missing or ambiguous")
        return matches[0]

    async def promote_classification(
        self, path: Path, *, expected_digest: str, expected_revision: int,
        cwe: str, provenance: dict[str, Any], guard: Callable[[], None],
        publish: Callable[[Finding, str], None],
    ) -> tuple[Finding, bool]:
        """One narrow artifact update. The worker thread ONLY prepares a temp.

        os.replace on the controller loop is the visibility/commit point. No
        await lies between final guards, replacement, and snapshot publication.
        Cancelled preparation is drained under the shared lock before cleanup.
        Directory fsync uncertainty never rolls back an already visible report.
        """
        async with self._save_lock:
            guard()
            raw = report_bytes(path)
            if hashlib.sha256(raw).hexdigest() != expected_digest:
                raise ValueError("finding report changed during CWE review")
            snapshot = read_report(path)
            if snapshot.cwe or snapshot.classification_revision != expected_revision:
                raise ValueError("finding already classified or classification revision changed")
            _read_revision(str(expected_revision + 1))
            if (not re.fullmatch(r"CWE-[1-9][0-9]{0,5}", cwe)
                    or provenance.get("origin") != "promoted-external"
                    or provenance.get("selected_cwe") != cwe
                    or provenance.get("revision") != expected_revision + 1):
                raise ValueError("invalid classification update")
            replacement = classification_replacement(raw, cwe, provenance, expected_revision + 1)
            pending = asyncio.create_task(asyncio.to_thread(_prepare_classification, path, replacement))
            temporary = None
            try:
                try:
                    temporary = await asyncio.shield(pending)
                except asyncio.CancelledError:
                    while not pending.done():
                        try:
                            await asyncio.shield(pending)
                        except asyncio.CancelledError:
                            continue
                    temporary = pending.result()
                    raise
                guard()
                if hashlib.sha256(report_bytes(path)).hexdigest() != expected_digest:
                    raise ValueError("finding report changed before CWE commit")
                task = asyncio.current_task()
                if task is not None and task.cancelling():
                    raise asyncio.CancelledError
                os.replace(temporary, path)
                temporary = None  # Commit: the new visible file is authoritative.
                durable = True
                try:
                    _fsync_directory(path.parent)
                except OSError:
                    durable = False
                try:
                    committed = read_report(path)
                except Exception as exc:
                    raise ClassificationCommittedError(
                        "CWE replacement committed; persisted report refresh failed. Reload the visible report."
                    ) from exc
                # Publication is best effort after commit; recovery always reads
                # persisted data. Neither publish nor notifier can roll back.
                try:
                    publish(committed, str(path))
                except Exception:
                    pass
                return committed, durable
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)


    async def save(
        self,
        finding: Finding,
    ) -> str:

        if (
            not isinstance(finding.candidate_id, str)
            or not finding.candidate_id.strip()
            or not isinstance(finding.evidence_refs, list)
            or not finding.evidence_refs
        ):
            raise ValueError(
                "confirmed finding requires candidate and evidence provenance"
            )
        if not all(isinstance(ref, str) and ref.strip() for ref in finding.evidence_refs):
            raise ValueError("confirmed finding evidence references must be non-empty strings")

        if not _SAFE_SLUG_RE.match(finding.slug):
            raise ValueError(
                f"unsafe finding slug: {finding.slug!r}"
            )

        content = render(finding)

        async with self._save_lock:
            pending = asyncio.create_task(asyncio.to_thread(
                self._write_once_for_candidate,
                finding.candidate_id,
                finding.slug,
                content,
            ))
            try:
                path = await asyncio.shield(pending)
            except asyncio.CancelledError:
                # Keep this store's lock until the reserved-file write finishes.
                # A cancelled caller never publishes a proposed retry snapshot.
                while not pending.done():
                    try:
                        await asyncio.shield(pending)
                    except asyncio.CancelledError:
                        continue
                pending.result()
                raise
            snapshot = read_report(Path(path))
            for item in fields(Finding):
                setattr(finding, item.name, getattr(snapshot, item.name))
            return path

    def _write_once_for_candidate(
        self, candidate_id: str | None, slug: str, content: str,
    ) -> str:
        if candidate_id:
            marker = f"- **Candidate ID:** {candidate_id}"
            # Canonical reports win. Legacy reports remain readable for
            # idempotent session resume, but no new report is written there.
            for directory in (self.dir, self.project_dir / "findings"):
                if not directory.exists():
                    continue
                for path in sorted(directory.glob("*.md")):
                    try:
                        if marker in path.read_text(encoding="utf-8").splitlines() and read_report(path).candidate_id == candidate_id:
                            return str(path)
                    except OSError:
                        continue
        return self._write(slug, content)


    def _write(
        self,
        slug: str,
        content: str,
    ) -> str:

        self.dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        i = 1

        while True:

            filename = (
                f"{slug}.md"
                if i == 1
                else f"{slug}-{i}.md"
            )

            path = self.dir / filename

            try:
                fd = os.open(
                    path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )

                try:
                    f = os.fdopen(fd, "w", encoding="utf-8")
                    fd = None  # The file object now owns the descriptor.
                    with f:
                        f.write(content)
                except BaseException:
                    # The name was reserved before writing.  Never leave a
                    # partial report behind if writing or closing fails.
                    try:
                        if fd is not None:
                            os.close(fd)
                    finally:
                        try:
                            os.unlink(path)
                        except FileNotFoundError:
                            pass
                    raise

                return str(path)

            except FileExistsError:
                i += 1


def slugify(
    title: str,
) -> str:
    import unicodedata

    text = unicodedata.normalize(
        "NFKD",
        title.lower(),
    )

    text = re.sub(
        r"[^a-z0-9]+",
        "-",
        text,
    )

    text = re.sub(
        r"(^-+|-+$)",
        "",
        text,
    )

    return text[:64]


def render(
    f: Finding,
) -> str:

    lines: list[str] = []

    lines.append(f"# {_inline(f.title)}")
    lines.append("")

    lines.append(f"- **Severity:** {f.severity}")

    if f.candidate_id:
        lines.append(f"- **Candidate ID:** {_inline(f.candidate_id)}")
    if f.evidence_refs:
        for ref in f.evidence_refs:
            lines.append(f"- **Evidence:** {_inline(ref)}")

    if f.vulnerabilityType:
        lines.append(f"- **Vulnerability Type:** {f.vulnerabilityType}")

    if f.cwe:
        lines.append(f"- **CWE:** {', '.join(f.cwe)}")

    if f.owasp:
        lines.append(f"- **OWASP:** {', '.join(f.owasp)}")

    if f.canonical_class:
        lines.append(f"- **Canonical class:** {_inline(f.canonical_class)}")
    if f.confirmation_binding:
        lines.append(f"- **Confirmation binding:** {f.confirmation_binding}")
    if f.classification_provenance is not None:
        lines.append(f"- **Classification provenance:** {json.dumps(f.classification_provenance, sort_keys=True, separators=(',', ':'))}")
    if f.classification_revision:
        lines.append(f"- **Classification revision:** {f.classification_revision}")

    lines.append(f"- **URL:** {_inline(f.url)}")

    if f.method:
        lines.append(f"- **Method:** {_inline(f.method)}")

    if f.parameter:
        lines.append(f"- **Parameter:** {_inline(f.parameter)}")

    lines.append(f"- **Reported at:** {f.createdAt}")

    lines.extend(
        [
            "",
            "## Observed impact",
            "",
            f.observed_impact,
            "",
            "## Potential impact",
            "",
            f.potential_impact,
            "",
        ]
    )

    if f.payload:
        lines.extend(
            [
                "## Payload",
                "",
                *_fenced(f.payload),
                "",
            ]
        )

    if f.responseExcerpt:
        lines.extend(
            [
                "## Response excerpt",
                "",
                *_fenced(f.responseExcerpt),
                "",
            ]
        )

    if f.curl:
        lines.extend(
            [
                "## Reproduce",
                "",
                *_fenced(f.curl, "sh"),
                "",
            ]
        )

    if f.remediation:
        lines.extend(
            [
                "## Remediation",
                "",
                f.remediation,
                "",
            ]
        )

    return "\n".join(lines)


def read_report(path: Path) -> Finding:
    """Read the persisted snapshot, including legacy Markdown reports.

    This never calls taxonomy: changing the catalog cannot reclassify a report.
    Fenced evidence is not parsed as report metadata or section headings.
    """
    return read_report_bytes(path.read_bytes(), slug=path.stem)


def read_report_bytes(raw: bytes, *, slug: str) -> Finding:
    """Parse one caller-owned byte snapshot with canonical Markdown semantics."""
    lines = raw.decode("utf-8").splitlines()
    if not lines or not lines[0].startswith("# "):
        raise ValueError("persisted finding report has no title")
    metadata: dict[str, list[str]] = {}
    sections: dict[str, list[str]] = {}
    section: str | None = None
    fence: str | None = None
    for line in lines[1:]:
        if fence is not None:
            if line == fence:
                fence = None
            if section is not None:
                sections[section].append(line)
            continue
        fenced = re.fullmatch(r"(`{3,})[a-zA-Z]*", line)
        if fenced:
            fence = fenced[1]
        heading = line[3:] if line.startswith("## ") else None
        if heading in _REPORT_SECTIONS and not fenced:
            section = heading
            sections.setdefault(section, [])
        elif section is not None:
            sections[section].append(line)
        elif (match := re.fullmatch(r"- \*\*(.+?):\*\* (.*)", line)) is not None:
            metadata.setdefault(match[1], []).append(match[2])

    def value(key: str) -> str | None:
        values = metadata.get(key, [])
        return values[0] if values else None

    def body(key: str, *, code: bool = False) -> str | None:
        value = "\n".join(sections.get(key, [])).strip("\n")
        if code and value:
            rows = value.splitlines()
            if len(rows) >= 2 and rows[0].startswith("```") and rows[-1].startswith("```"):
                value = "\n".join(rows[1:-1])
        return value or None

    severity = value("Severity")
    if severity not in {"critical", "high", "medium", "low", "info"}:
        raise ValueError("persisted finding report has invalid severity")
    observed_impact = body("Observed impact")
    if observed_impact is None:
        observed_impact = body("Impact")
    return Finding(
        title=lines[0][2:], severity=cast(Severity, severity), url=value("URL") or "",
        observed_impact=observed_impact or "", potential_impact=body("Potential impact") or "",
        parameter=value("Parameter"), payload=body("Payload", code=True), method=value("Method"),
        responseExcerpt=body("Response excerpt", code=True), curl=body("Reproduce", code=True),
        remediation=body("Remediation"), vulnerabilityType=value("Vulnerability Type"),
        cwe=(value("CWE") or "").split(", ") if value("CWE") else None,
        owasp=(value("OWASP") or "").split(", ") if value("OWASP") else None,
        createdAt=value("Reported at") or "", slug=slug,
        candidate_id=value("Candidate ID"), evidence_refs=metadata.get("Evidence"),
        canonical_class=value("Canonical class"), confirmation_binding=value("Confirmation binding"),
        classification_provenance=_read_provenance(value("Classification provenance")),
        classification_revision=_read_revision(value("Classification revision")),
    )


def _read_revision(value: str | None) -> int:
    if value is None:
        return 0
    if not re.fullmatch(r"[1-9][0-9]{0,8}", value):
        raise ValueError("invalid persisted classification revision")
    return int(value)


def _read_provenance(value: str | None) -> dict[str, Any] | None:
    if value is None:
        return None  # Historical origin remains unknown; never infer taxonomy.
    parsed = json.loads(value)
    if not isinstance(parsed, dict) or parsed.get("origin") not in {"verified-local", "promoted-external", "legacy/unknown"}:
        raise ValueError("invalid persisted classification provenance")
    return parsed


def report_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("unsafe finding report resource")
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if not 0 < len(raw) <= MAX_REPORT_BYTES:
        raise ValueError("finding report exceeds review bound")
    return raw


def classification_header(raw: bytes):
    """Require unambiguous historical bindings before retrieval or mutation."""
    lines = raw.decode("utf-8").splitlines(keepends=True)
    if not lines or not lines[0].startswith("# "):
        raise ValueError("ambiguous report structure")
    boundary = next((i for i, row in enumerate(lines) if row.startswith("## ")), None)
    if boundary is None or lines[boundary].rstrip("\r\n")[3:] not in _REPORT_SECTIONS:
        raise ValueError("ambiguous report sections")
    metadata: dict[str, list[str]] = {}
    positions = {}
    for i, row in enumerate(lines[1:boundary], 1):
        match = re.fullmatch(r"- \*\*(.+?):\*\* (.*)", row.rstrip("\r\n"))
        if match:
            metadata.setdefault(match[1], []).append(match[2])
            positions[match[1]] = i
        elif row.strip():
            raise ValueError("ambiguous report metadata")
    if any(len(values) != 1 for key, values in metadata.items() if key != "Evidence"):
        raise ValueError("duplicate report metadata")
    if not all(metadata.get(key) for key in ("Severity", "URL", "Reported at", "Candidate ID", "Evidence", "Canonical class", "Confirmation binding")):
        raise ValueError("report lacks historical confirmation binding")
    if any(value.strip() for value in metadata.get("CWE", [])):
        raise ValueError("classified report cannot be replaced")
    return lines, boundary, positions


def classification_replacement(raw: bytes, cwe: str, provenance: dict[str, Any], revision: int) -> bytes:
    """Edit only classification header rows, preserving every other byte."""
    lines, boundary, positions = classification_header(raw)
    newline = "\r\n" if lines[0].endswith("\r\n") else "\n"
    updated = {
        "CWE": cwe, "Classification provenance": json.dumps(provenance, sort_keys=True, separators=(",", ":")),
        "Classification revision": str(revision),
    }
    for key, value in updated.items():
        if key in positions:
            lines[positions[key]] = f"- **{key}:** {value}{newline}"
    additions = [f"- **{key}:** {value}{newline}" for key, value in updated.items() if key not in positions]
    lines[boundary:boundary] = additions
    replacement = "".join(lines).encode("utf-8")
    if len(replacement) > MAX_REPORT_BYTES:
        raise ValueError("classification replacement exceeds report bound")
    return replacement


def _prepare_classification(path: Path, raw: bytes) -> Path:
    fd, name = tempfile.mkstemp(prefix=".cwe-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _inline(value: str) -> str:
    """Keep model-controlled metadata on its intended Markdown line."""
    return " ".join(value.splitlines())


def _fenced(value: str, language: str = "") -> list[str]:
    """Use a fence that cannot be closed by backticks in evidence."""
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}{language}", value, fence]
