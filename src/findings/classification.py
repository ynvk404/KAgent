from __future__ import annotations

from dataclasses import dataclass

from src.vulnerability import (
    OWASP_TOP_10_2021,
    VULNERABILITIES,
    VulnerabilityDefinition,
    normalize_candidate_class as normalize_candidate_class,
    resolve,
)


@dataclass(frozen=True, slots=True)
class VulnClassification:
    type: str
    cwe: list[str]
    owasp: list[str]


def _legacy_classification(definition: VulnerabilityDefinition) -> VulnClassification:
    return VulnClassification(
        type=definition.display_name,
        cwe=[definition.primary_cwe] if definition.primary_cwe is not None else [],
        owasp=(
            [OWASP_TOP_10_2021[definition.owasp_2021]]
            if definition.owasp_2021 is not None else []
        ),
    )


# Retain the importable legacy table as a derived snapshot. Resolution always
# uses the immutable core so mutation of these legacy lists cannot affect it.
CLASSIFICATION: dict[str, VulnClassification] = {
    key: _legacy_classification(definition)
    for key, definition in VULNERABILITIES.items()
}


def classify(vuln_class: str) -> VulnClassification | None:
    definition = resolve(vuln_class)
    return _legacy_classification(definition) if definition is not None else None
