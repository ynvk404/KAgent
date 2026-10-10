"""Compact Markdown derivatives. Canonical Finding persistence stays in store.py."""
from __future__ import annotations

import html
import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote, urlsplit, urlunsplit

from src.findings.store import Finding, _fenced
from src.redaction.redact import _is_secret_field, apply_evidence
from src.workflow.evidence import EvidenceArtifact

if TYPE_CHECKING:
    from src.workflow.state import Candidate, ValidationResult


@dataclass(frozen=True, slots=True)
class SummaryContext:
    location: str | None = None
    criteria: str | None = None
    limitations: str | None = None
    prerequisites: str | None = None
    mutation_performed: bool = False
    cleanup_state: str | None = None
    cleanup_status: str | None = None

    @classmethod
    def from_validation(cls, candidate: Candidate, result: ValidationResult) -> SummaryContext:
        # Callers must first bind these records to the persisted Finding.
        assessment = result.assessment if result.assessment_contract_version >= 2 else {}
        def value(key: str) -> str | None:
            item = assessment.get(key)
            return item if isinstance(item, str) and item.strip() else None
        return cls(candidate.location, value("criteria"), value("limitations"),
                   value("prerequisites"), result.mutation_performed,
                   result.cleanup_state, result.cleanup_status)


@dataclass(frozen=True, slots=True)
class EvidenceLink:
    label: str
    target: str | None = None


def relative_link(path: Path, directory: Path, project: Path) -> str:
    """Only link to project resources; never disclose absolute/source paths."""
    root = project.resolve()
    if not path.resolve().is_relative_to(root) or path.is_symlink():
        raise ValueError("summary reference must stay inside the project")
    return Path(os.path.relpath(path, directory)).as_posix()


def artifact_links(artifacts: Iterable[EvidenceArtifact], project: Path,
                   directory: Path) -> tuple[EvidenceLink, ...]:
    links = []
    for index, artifact in enumerate(artifacts, 1):
        target = None
        label = f"Evidence {index}"
        path = project / artifact.path
        if artifact.requires_read_permission(project):
            label += " (protected; use the registered evidence reader)"
        else:
            try:
                if path.is_file():
                    target = relative_link(path, directory, project)
                else:
                    label += " (file unavailable)"
            except ValueError:
                label += " (path withheld)"
        links.append(EvidenceLink(label, target))
    return tuple(links)


def _without_url_credentials(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            parts = urlsplit(match[0])
            if "@" in parts.netloc:
                return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[1],
                                   parts.path, parts.query, parts.fragment))
        except ValueError:
            return "[URL unavailable]"
        return match[0]
    return re.sub(r"https?://[^\s<>\"']+", replace, text, flags=re.I)


def render_summary(finding: Finding, *, context: SummaryContext | None = None,
                   evidence: tuple[EvidenceLink, ...] = (), source: str | None = None,
                   sanitize: Callable[[str], str] = apply_evidence) -> str:
    """Render recorded facts only, with safe fences and bounded optional blocks.

    No LLM paraphrasing, classification inference or evidence content reads.
    Links are controller-authored; prose and request material stay redacted.
    """
    ctx = context or SummaryContext()

    def text(value: str | None, *, limit: int = 4000) -> str:
        if not value or not value.strip():
            return "Not recorded"
        # A labelled multiline credential has no reliable end after redaction.
        if any(_is_secret_field(m[1]) for m in re.finditer(
                r"(?m)^[ \t]*(?:-[ \t]+)?([^:=\n]+?)\s*[:=]", value)):
            return "[REDACTED]"
        cleaned = _without_url_credentials(sanitize(apply_evidence(value)))
        if len(cleaned) > limit:
            return "Content exceeds the summary limit; see the registered evidence."
        return cleaned.strip()

    def prose(value: str | None, *, inline: bool = False) -> str:
        cleaned = text(value)
        if inline:
            cleaned = " ".join(cleaned.splitlines())
        # Model-supplied HTML/links/headings remain literal report content.
        return re.sub(r"([\\`*_{}\[\]()#+!|])", r"\\\1", html.escape(cleaned, quote=False))

    def link(item: EvidenceLink) -> str:
        label = prose(item.label, inline=True)
        target = item.target
        if not target:
            return label
        if urlsplit(target).scheme or target.startswith(("/", "\\")) or "\\" in target:
            raise ValueError("summary links must be relative")
        return f"[{label}]({quote(target, safe='/.-_')})"

    lines = [f"# {prose(finding.title, inline=True)}", "",
             f"- **Severity:** {prose(finding.severity, inline=True)}",
             f"- **Endpoint:** {prose(finding.method, inline=True) + ' ' if finding.method else ''}"
             f"{prose(finding.url, inline=True)}"]
    if finding.parameter or ctx.location:
        inputs = [prose(v, inline=True) for v in (finding.parameter, ctx.location) if v]
        lines.append(f"- **Input:** {' · '.join(inputs)}")
    classification = [v for v in (finding.vulnerabilityType, *(finding.cwe or []),
                                   *(finding.owasp or [])) if v]
    if classification:
        lines.append("- **Classification:** " + "; ".join(prose(v, inline=True) for v in classification))
    lines.extend(["", "## Observed impact", "", prose(finding.observed_impact), "",
                  "**Confirmation criteria:** " + prose(ctx.criteria), ""])
    if finding.responseExcerpt and len(finding.responseExcerpt) <= 800:
        lines.extend(["Response excerpt:", "", *_fenced(text(finding.responseExcerpt)), ""])
    lines.extend(["## Reproduce", ""])
    if ctx.prerequisites:
        lines.extend(["Prerequisites: " + prose(ctx.prerequisites), ""])
    lines.extend(["See the registered evidence for prerequisites, baseline/control requests "
                  "and expected results. Redacted credentials require authorized session placeholders.", ""])
    if finding.curl:
        command = text(finding.curl, limit=8000)
        # Credential flags lack labelled fields for the ordinary redactor.
        if re.search(r"(?:^|\s)(?:-u\S*|--user(?:\s|=)|--(?:token|secret)(?:\s|=))", command):
            command = "[REDACTED] Credential-bearing command; see the registered evidence."
        lines.extend(_fenced(command, "sh") + [""])
    elif finding.payload:
        lines.extend(["Recorded input:", "", *_fenced(text(finding.payload, limit=2000)), ""])
    else:
        lines.extend(["A reproduction command was not recorded separately; use the linked proof.", ""])
    lines.extend(["## Evidence", ""])
    if evidence:
        lines.extend(f"- {link(item)}" for item in evidence)
    else:
        lines.append("Evidence links are unavailable in this export; consult the canonical finding.")
    if source:
        lines.append("- " + link(EvidenceLink("Canonical finding", source)))
    lines.extend(["", "## Limitations", "", prose(ctx.limitations) if ctx.limitations else
                  "Verification limitations were not recorded separately.", ""])
    if finding.potential_impact:
        lines.extend(["Potential impact (unverified): " + prose(finding.potential_impact), ""])
    if ctx.mutation_performed or ctx.cleanup_state not in {None, "not-required"}:
        lines.extend(["Cleanup: " + prose(ctx.cleanup_state) +
                      (" — " + prose(ctx.cleanup_status) if ctx.cleanup_status else ""), ""])
    if finding.remediation:
        lines.extend(["## Remediation", "", prose(finding.remediation), ""])
    return "\n".join(lines)
