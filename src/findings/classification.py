from __future__ import annotations

from dataclasses import dataclass

from src.skills.registry import normalize_candidate_class


@dataclass(frozen=True, slots=True)
class VulnClassification:
    type: str
    cwe: list[str]
    owasp: list[str]


# Keys are the canonical identifiers shared with Workflow and coverage.mark().
CLASSIFICATION: dict[str, VulnClassification] = {
    "sql-injection": VulnClassification(
        type="SQL Injection",
        cwe=["CWE-89"],
        owasp=["A03:2021 Injection"],
    ),
    "cross-site-scripting": VulnClassification(
        type="Cross-Site Scripting (XSS)",
        cwe=["CWE-79"],
        owasp=["A03:2021 Injection"],
    ),
    "access-control": VulnClassification(
        type="Broken Access Control",
        cwe=[],
        owasp=["A01:2021 Broken Access Control"],
    ),
    "ssrf": VulnClassification(
        type="Server-Side Request Forgery (SSRF)",
        cwe=["CWE-918"],
        owasp=["A10:2021 Server-Side Request Forgery"],
    ),
}


def classify(vuln_class: str) -> VulnClassification | None:
    normalized = normalize_candidate_class(vuln_class)
    if not normalized:
        return None
    classification = CLASSIFICATION.get(normalized)
    if classification is None:
        return None

    # Findings own their classification metadata; callers must not be able to
    # mutate the shared taxonomy (or another finding) through these lists.
    return VulnClassification(
        type=classification.type,
        cwe=list(classification.cwe),
        owasp=list(classification.owasp),
    )
