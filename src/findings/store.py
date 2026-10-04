from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Literal, cast

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
        self._save_lock = asyncio.Lock()


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
    lines = path.read_text(encoding="utf-8").splitlines()
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
        createdAt=value("Reported at") or "", slug=path.stem,
        candidate_id=value("Candidate ID"), evidence_refs=metadata.get("Evidence"),
    )


def _inline(value: str) -> str:
    """Keep model-controlled metadata on its intended Markdown line."""
    return " ".join(value.splitlines())


def _fenced(value: str, language: str = "") -> list[str]:
    """Use a fence that cannot be closed by backticks in evidence."""
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}{language}", value, fence]
