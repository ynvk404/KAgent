from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VulnClassification:
    type: str
    cwe: list[str]
    owasp: list[str]


# Keys are the canonical identifiers shared with coverage.mark().
CLASSIFICATION: dict[str, VulnClassification] = {
    "sqli": VulnClassification(
        type="SQL Injection",
        cwe=["CWE-89"],
        owasp=["A03:2021 Injection"],
    ),
    "xss": VulnClassification(
        type="Cross-Site Scripting (XSS)",
        cwe=["CWE-79"],
        owasp=["A03:2021 Injection"],
    ),
    "idor": VulnClassification(
        type="Insecure Direct Object Reference (IDOR)",
        cwe=["CWE-639"],
        owasp=["A01:2021 Broken Access Control"],
    ),
    "ssrf": VulnClassification(
        type="Server-Side Request Forgery (SSRF)",
        cwe=["CWE-918"],
        owasp=["A10:2021 Server-Side Request Forgery"],
    ),
}


def classify(vuln_class: str) -> VulnClassification | None:
    normalized = vuln_class.strip().lower()
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
