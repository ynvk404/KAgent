"""Requested-goal records and deterministic vulnerability-class extraction."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from src.redaction.redact import apply as redact
from src.skills.registry import normalize_candidate_class
from src.vulnerability.taxonomy import CANDIDATE_CLASS_ALIASES, VULNERABILITIES


GoalStatus = Literal[
    "pending",
    "in_progress",
    "tested_confirmed",
    "tested_not_confirmed",
    "no_candidate",
    "blocked",
    "deferred",
    "unsupported",
    "cancelled",
]

GOAL_STATUSES = frozenset({
    "pending", "in_progress", "tested_confirmed", "tested_not_confirmed",
    "no_candidate", "blocked", "deferred", "unsupported", "cancelled",
})


class RequestedGoalsLoadError(ValueError):
    """A present requested-goals payload cannot be safely resumed."""


_OPERATIONAL_RE = re.compile(
    r"\b(?:analy[sz]e|check|enumerate|exploit|inspect|probe|recon|scan|"
    r"test|validat\w*|verif\w*)\b",
    re.IGNORECASE,
)
_STRUCTURED_CLASS_RE = re.compile(
    r"\bcandidate_class\s*=\s*([a-zA-Z0-9_-]+)\b", re.IGNORECASE,
)
_CLAUSE_SPLIT_RE = re.compile(
    r"(?<=[.!?;\n])\s+|\n+|,\s*(?=(?:please\s+)?(?:"
    r"analy[sz]e|check|enumerate|exploit|inspect|probe|scan|test|validat\w*|verif\w*)\b)",
    re.IGNORECASE,
)
_INFORMATIONAL_RE = re.compile(
    r"^\s*(?:please\s+)?(?:explain|describe|define|what\b|how\b)", re.IGNORECASE,
)
_NEGATION_RE = re.compile(
    r"\b(?:do\s+not|don't|dont|not\s+to|avoid|skip|exclude)\s+"
    r"(?:\w+\s+){0,2}(?:analy[sz]e|check|enumerate|inspect|probe|scan|"
    r"test|validat\w*|verif\w*)\b",
    re.IGNORECASE,
)
_NEGATED_MENTION_RE = re.compile(r"\b(?:not|except)\s*$", re.IGNORECASE)
_NEGATION_BOUNDARY_RE = re.compile(
    r"\bbut\b|\band\s+(?=(?:test|check|validat\w*|verif\w*)\b)", re.IGNORECASE,
)


def goal_id_for_class(candidate_class: str) -> str:
    canonical = normalize_candidate_class(candidate_class)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"goal_{digest}"


@dataclass(slots=True)
class RequestedGoal:
    candidate_class: str
    id: str = ""
    status: GoalStatus = "pending"
    candidate_ids: list[str] = field(default_factory=list)
    reason: str | None = None
    review_artifact_ref: str | None = None
    review_binding: str | None = None

    def __post_init__(self) -> None:
        self.candidate_class = normalize_candidate_class(self.candidate_class)
        if not self.candidate_class:
            raise ValueError("requested goal candidate_class is required")
        expected = goal_id_for_class(self.candidate_class)
        if self.id and self.id != expected:
            raise ValueError("requested goal id does not match its canonical class")
        self.id = expected
        if self.status not in GOAL_STATUSES:
            raise ValueError(f"unknown requested goal status: {self.status}")
        if not isinstance(self.candidate_ids, list) or not all(
            isinstance(item, str) for item in self.candidate_ids
        ):
            raise ValueError("requested goal candidate_ids must be a list of strings")
        self.candidate_ids = list(dict.fromkeys(item.strip()[:80] for item in self.candidate_ids if item.strip()))
        if self.reason is not None:
            if not isinstance(self.reason, str):
                raise ValueError("requested goal reason must be a string")
            self.reason = redact(" ".join(self.reason.strip().split()))[:300] or None
        if self.review_artifact_ref is not None:
            if not isinstance(self.review_artifact_ref, str):
                raise ValueError("requested goal review_artifact_ref must be a string")
            self.review_artifact_ref = redact(" ".join(self.review_artifact_ref.strip().split()))[:500] or None
        if self.status == "no_candidate" and not self.review_artifact_ref:
            raise ValueError("no_candidate requested goal requires a review artifact")
        if self.review_binding is not None and (
            not isinstance(self.review_binding, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.review_binding) is None
        ):
            raise ValueError("requested goal review binding must be a SHA-256 digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "candidate_class": self.candidate_class,
            "status": self.status,
            "candidate_ids": list(self.candidate_ids),
            "reason": self.reason,
            "review_artifact_ref": self.review_artifact_ref,
            "review_binding": self.review_binding,
        }

    @classmethod
    def from_dict(cls, value: Any) -> RequestedGoal | None:
        if not isinstance(value, dict):
            return None
        try:
            candidate_class = value.get("candidate_class")
            status = value.get("status", "pending")
            if not isinstance(candidate_class, str) or not isinstance(status, str):
                return None
            candidate_ids = value.get("candidate_ids", [])
            if not isinstance(candidate_ids, list) or not isinstance(value.get("id", ""), str):
                return None
            return cls(
                id=value.get("id", "") if isinstance(value.get("id", ""), str) else "",
                candidate_class=candidate_class,
                status=status,  # type: ignore[arg-type]
                candidate_ids=candidate_ids,
                reason=value.get("reason"),
                review_artifact_ref=value.get("review_artifact_ref"),
                review_binding=value.get("review_binding"),
            )
        except (TypeError, ValueError):
            return None


def extract_requested_classes(
    text: str,
    *,
    registered_classes: tuple[str, ...] | list[str] = (),
) -> list[str]:
    """Extract canonical classes mentioned in operational clauses.

    Taxonomy aliases and registered validator class labels are inputs. Skill
    triggers and prerequisite metadata are intentionally not considered.
    """
    if not isinstance(text, str) or not text.strip():
        return []

    matches: dict[str, str] = {}
    for canonical, definition in VULNERABILITIES.items():
        forms = {canonical, definition.display_name, *definition.aliases}
        forms.update(alias for alias, target in CANDIDATE_CLASS_ALIASES.items() if target == canonical)
        for form in forms:
            _add_form(matches, form, canonical)
    for raw_class in registered_classes:
        canonical = normalize_candidate_class(raw_class)
        _add_form(matches, raw_class, canonical)
        _add_form(matches, canonical, canonical)

    patterns = sorted(
        ((form, canonical, _phrase_pattern(form)) for form, canonical in matches.items()),
        key=lambda item: (-len(item[0]), item[0]),
    )
    all_spans: list[tuple[int, int, str]] = []
    offset = 0
    clauses: list[tuple[int, str]] = []
    for boundary in _CLAUSE_SPLIT_RE.finditer(text):
        clauses.append((offset, text[offset:boundary.start()]))
        offset = boundary.end()
    clauses.append((offset, text[offset:]))
    for offset, clause in clauses:
        if _INFORMATIONAL_RE.search(clause):
            continue
        spans: list[tuple[int, int, str]] = []
        if _OPERATIONAL_RE.search(clause):
            for _form, canonical, pattern in patterns:
                for match in pattern.finditer(clause):
                    if _is_negated(clause, match.start()):
                        continue
                    spans.append((match.start(), match.end(), canonical))
        # Explicit structured labels remain usable without an action verb,
        # and merge with text mentions by their original source offsets.
        for match in _STRUCTURED_CLASS_RE.finditer(clause):
            canonical = normalize_candidate_class(match.group(1))
            if canonical and not _is_negated(clause, match.start()):
                spans.append((match.start(), match.end(), canonical))
        # Greedy left-to-right longest match prevents short aliases from
        # creating a second class inside a longer class label.
        chosen: list[tuple[int, int, str]] = []
        for item in sorted(spans, key=lambda span: (span[0], -(span[1] - span[0]), span[2])):
            if any(item[0] < old[1] and old[0] < item[1] for old in chosen):
                continue
            chosen.append(item)
        all_spans.extend((offset + start, offset + end, canonical) for start, end, canonical in chosen)
    found: list[str] = []
    for _, _, canonical in sorted(all_spans):
        if canonical not in found:
            found.append(canonical)
    return found


def _add_form(forms: dict[str, str], raw: str, canonical: str) -> None:
    form = " ".join(raw.lower().replace("_", " ").replace("-", " ").split())
    if form:
        forms[form] = canonical


def _phrase_pattern(form: str) -> re.Pattern[str]:
    pieces = re.split(r"[\s_-]+", form.strip())
    expression = r"[\s_-]+".join(re.escape(piece) for piece in pieces if piece)
    return re.compile(rf"(?<![a-z0-9]){expression}(?![a-z0-9])", re.IGNORECASE)


def _is_negated(clause: str, start: int) -> bool:
    prefix = clause[:start]
    boundaries = list(_NEGATION_BOUNDARY_RE.finditer(prefix))
    if boundaries:
        prefix = prefix[boundaries[-1].end():]
    return _NEGATION_RE.search(prefix) is not None or _NEGATED_MENTION_RE.search(prefix) is not None
