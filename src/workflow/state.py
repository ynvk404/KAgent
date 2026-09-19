from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal, TypeGuard

from src.skills.registry import normalize_candidate_class, normalize_metadata_name


CandidateStatus = Literal[
    "new",
    "queued",
    "validating",
    "validated",
    "deferred",
    "dismissed",
]

ValidationOutcome = Literal[
    "confirmed",
    "not-confirmed",
    "blocked",
    "insufficient-evidence",
    "deferred",
    "browser-required",
    "authorization-required",
]

CANDIDATE_STATUSES: frozenset[str] = frozenset(
    {"new", "queued", "validating", "validated", "deferred", "dismissed"}
)
VALIDATION_OUTCOMES: frozenset[str] = frozenset(
    {
        "confirmed",
        "not-confirmed",
        "blocked",
        "insufficient-evidence",
        "deferred",
        "browser-required",
        "authorization-required",
    }
)

_MAX_SIGNALS = 12
_MAX_REFS = 20
_MAX_TECHNIQUES = 12
_MAX_ITEM_LENGTH = 500
_MAX_NOTES_LENGTH = 1000


def _text(value: Any, *, limit: int = _MAX_ITEM_LENGTH) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("expected a string")
    normalized = " ".join(value.strip().split())
    return normalized[:limit] or None


def _strings(value: Any, *, maximum: int) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("expected a list of strings")
    result: list[str] = []
    for raw in value:
        item = _text(raw)
        if item and item not in result:
            result.append(item)
        if len(result) == maximum:
            break
    return result


def _method(value: Any) -> str | None:
    method = _text(value, limit=24)
    return method.upper() if method else None


def normalize_candidate_target(value: Any) -> str | None:
    target = _text(value)
    return target.lower().rstrip("/") if target else None


def _identity_payload(
    *,
    target: str | None,
    method: str | None,
    endpoint: str | None,
    parameter: str | None,
    location: str | None,
    candidate_class: str,
) -> dict[str, str]:
    return {
        "target": normalize_candidate_target(target) or "",
        "method": (method or "").strip().upper(),
        "endpoint": (endpoint or "").strip(),
        "parameter": (parameter or "").strip(),
        "location": (location or "").strip().lower(),
        "candidate_class": normalize_candidate_class(candidate_class),
    }


def candidate_fingerprint(
    *,
    target: str | None = None,
    method: str | None = None,
    endpoint: str | None = None,
    parameter: str | None = None,
    location: str | None = None,
    candidate_class: str,
) -> str:
    payload = _identity_payload(
        target=target,
        method=method,
        endpoint=endpoint,
        parameter=parameter,
        location=location,
        candidate_class=candidate_class,
    )
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:20]
    return f"cand_{digest}"


@dataclass(slots=True)
class Candidate:
    candidate_class: str
    id: str = ""
    target: str | None = None
    endpoint: str | None = None
    method: str | None = None
    parameter: str | None = None
    location: str | None = None
    signals: list[str] = field(default_factory=list)
    baseline_request_ref: str | None = None
    auth_context_ref: str | None = None
    source_skill: str | None = None
    status: CandidateStatus = "new"

    def __post_init__(self) -> None:
        self.candidate_class = normalize_candidate_class(self.candidate_class)
        if not self.candidate_class:
            raise ValueError("candidate_class is required")
        self.target = normalize_candidate_target(self.target)
        self.endpoint = _text(self.endpoint)
        self.method = _method(self.method)
        self.parameter = _text(self.parameter)
        self.location = _text(self.location, limit=80)
        self.signals = _strings(self.signals, maximum=_MAX_SIGNALS)
        self.baseline_request_ref = _text(self.baseline_request_ref)
        self.auth_context_ref = _text(self.auth_context_ref)
        self.source_skill = (
            normalize_metadata_name(self.source_skill) if self.source_skill else None
        )
        if not is_candidate_status(self.status):
            raise ValueError(f"unknown candidate status: {self.status}")

        stable_id = candidate_fingerprint(
            target=self.target,
            method=self.method,
            endpoint=self.endpoint,
            parameter=self.parameter,
            location=self.location,
            candidate_class=self.candidate_class,
        )
        if self.id and self.id != stable_id:
            raise ValueError("candidate id does not match its semantic fingerprint")
        self.id = stable_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "candidate_class": self.candidate_class,
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "location": self.location,
            "signals": list(self.signals),
            "baseline_request_ref": self.baseline_request_ref,
            "auth_context_ref": self.auth_context_ref,
            "source_skill": self.source_skill,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, value: Any) -> Candidate | None:
        if not isinstance(value, dict) or not isinstance(value.get("candidate_class"), str):
            return None
        try:
            return cls(
                id=value.get("id", "") if isinstance(value.get("id", ""), str) else "",
                candidate_class=value["candidate_class"],
                target=value.get("target"),
                endpoint=value.get("endpoint"),
                method=value.get("method"),
                parameter=value.get("parameter"),
                location=value.get("location"),
                signals=value.get("signals", []),
                baseline_request_ref=value.get("baseline_request_ref"),
                auth_context_ref=value.get("auth_context_ref"),
                source_skill=value.get("source_skill"),
                status=value.get("status", "new"),
            )
        except (TypeError, ValueError):
            return None


@dataclass(slots=True)
class ValidationResult:
    candidate_id: str
    skill_name: str
    outcome: ValidationOutcome
    evidence_refs: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    repeatable: bool | None = None
    mutation_performed: bool = False
    cleanup_status: str | None = None
    deferred_reason: str | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        self.candidate_id = _text(self.candidate_id, limit=80) or ""
        self.skill_name = normalize_metadata_name(self.skill_name)
        if not self.candidate_id or not self.skill_name:
            raise ValueError("candidate_id and skill_name are required")
        if not is_validation_outcome(self.outcome):
            raise ValueError(f"unknown validation outcome: {self.outcome}")
        self.evidence_refs = _strings(self.evidence_refs, maximum=_MAX_REFS)
        self.techniques = _strings(self.techniques, maximum=_MAX_TECHNIQUES)
        if self.repeatable is not None and not isinstance(self.repeatable, bool):
            raise ValueError("repeatable must be a boolean or null")
        if not isinstance(self.mutation_performed, bool):
            raise ValueError("mutation_performed must be a boolean")
        self.cleanup_status = _text(self.cleanup_status)
        self.deferred_reason = _text(self.deferred_reason)
        self.notes = _text(self.notes, limit=_MAX_NOTES_LENGTH)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "skill_name": self.skill_name,
            "outcome": self.outcome,
            "evidence_refs": list(self.evidence_refs),
            "techniques": list(self.techniques),
            "repeatable": self.repeatable,
            "mutation_performed": self.mutation_performed,
            "cleanup_status": self.cleanup_status,
            "deferred_reason": self.deferred_reason,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ValidationResult | None:
        if not isinstance(value, dict):
            return None
        try:
            candidate_id = value.get("candidate_id")
            skill_name = value.get("skill_name")
            outcome = value.get("outcome")
            if (
                not isinstance(candidate_id, str)
                or not isinstance(skill_name, str)
                or not isinstance(outcome, str)
            ):
                return None
            return cls(
                candidate_id=candidate_id,
                skill_name=skill_name,
                outcome=outcome,  # type: ignore[arg-type]
                evidence_refs=value.get("evidence_refs", []),
                techniques=value.get("techniques", []),
                repeatable=value.get("repeatable"),
                mutation_performed=value.get("mutation_performed", False),
                cleanup_status=value.get("cleanup_status"),
                deferred_reason=value.get("deferred_reason"),
                notes=value.get("notes"),
            )
        except (TypeError, ValueError):
            return None


def validation_result_fingerprint(result: ValidationResult) -> str:
    semantic_identity = {
        "candidate_id": result.candidate_id,
        "skill_name": result.skill_name,
        "outcome": result.outcome,
        "evidence_refs": sorted(result.evidence_refs),
        "techniques": sorted(result.techniques),
        "repeatable": result.repeatable,
        "mutation_performed": result.mutation_performed,
    }
    body = json.dumps(semantic_identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class WorkflowState:
    version: int = 1
    candidates: dict[str, Candidate] = field(default_factory=dict)
    validation_results: list[ValidationResult] = field(default_factory=list)
    active_candidate_ids: set[str] = field(default_factory=set)
    completed_skills: set[str] = field(default_factory=set)
    current_phase: str | None = None

    def add_candidate(self, candidate: Candidate) -> tuple[Candidate, bool]:
        existing = self.candidates.get(candidate.id)
        if existing is not None:
            existing.signals = list(dict.fromkeys([*existing.signals, *candidate.signals]))[
                :_MAX_SIGNALS
            ]
            for field_name in (
                "baseline_request_ref",
                "auth_context_ref",
                "source_skill",
            ):
                if getattr(existing, field_name) is None:
                    setattr(existing, field_name, getattr(candidate, field_name))
            return existing, False

        self.candidates[candidate.id] = candidate
        if candidate.status in {"new", "queued", "validating"}:
            self.active_candidate_ids.add(candidate.id)
        return candidate, True

    def set_candidate_status(self, candidate_id: str, status: CandidateStatus) -> Candidate:
        if not is_candidate_status(status):
            raise ValueError(f"unknown candidate status: {status}")
        candidate = self.candidates.get(candidate_id)
        if candidate is None:
            raise ValueError(f"unknown candidate: {candidate_id}")
        candidate.status = status
        if status in {"new", "queued", "validating"}:
            self.active_candidate_ids.add(candidate_id)
        else:
            self.active_candidate_ids.discard(candidate_id)
        return candidate

    def add_validation_result(
        self,
        result: ValidationResult,
        *,
        force: bool = False,
    ) -> bool:
        if result.candidate_id not in self.candidates:
            raise ValueError(f"unknown candidate: {result.candidate_id}")
        fingerprint = validation_result_fingerprint(result)
        if not force:
            for existing in self.validation_results:
                if validation_result_fingerprint(existing) != fingerprint:
                    continue
                for field_name in ("cleanup_status", "deferred_reason", "notes"):
                    value = getattr(result, field_name)
                    if value is not None:
                        setattr(existing, field_name, value)
                return False
        self.validation_results.append(result)
        terminal_status: CandidateStatus = (
            "deferred"
            if result.outcome
            in {"deferred", "browser-required", "authorization-required"}
            else "validated"
        )
        self.set_candidate_status(result.candidate_id, terminal_status)
        return True

    def relevant_candidate_classes(self) -> frozenset[str]:
        return frozenset(
            candidate.candidate_class
            for candidate_id, candidate in self.candidates.items()
            if candidate_id in self.active_candidate_ids
            and candidate.status in {"new", "queued", "validating"}
        )

    def latest_result(self, candidate_id: str) -> ValidationResult | None:
        return next(
            (
                result
                for result in reversed(self.validation_results)
                if result.candidate_id == candidate_id
            ),
            None,
        )

    def eligible_for_finding(self, candidate_id: str) -> bool:
        result = self.latest_result(candidate_id)
        return result is not None and result.outcome == "confirmed"

    def clear(self) -> None:
        self.candidates.clear()
        self.validation_results.clear()
        self.active_candidate_ids.clear()
        self.completed_skills.clear()
        self.current_phase = None

    def replace_from(self, other: WorkflowState) -> None:
        self.version = other.version
        self.candidates = dict(other.candidates)
        self.validation_results = list(other.validation_results)
        self.active_candidate_ids = set(other.active_candidate_ids)
        self.completed_skills = set(other.completed_skills)
        self.current_phase = other.current_phase

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "candidates": [self.candidates[key].to_dict() for key in sorted(self.candidates)],
            "validation_results": [result.to_dict() for result in self.validation_results],
            "active_candidate_ids": sorted(self.active_candidate_ids),
            "completed_skills": sorted(self.completed_skills),
            "current_phase": self.current_phase,
        }

    @classmethod
    def from_dict(cls, value: Any) -> WorkflowState:
        state = cls()
        if not isinstance(value, dict):
            return state
        version = value.get("version", 1)
        if isinstance(version, int) and not isinstance(version, bool) and version > 0:
            state.version = version

        raw_candidates = value.get("candidates", [])
        if isinstance(raw_candidates, dict):
            raw_candidates = list(raw_candidates.values())
        if isinstance(raw_candidates, list):
            for raw in raw_candidates:
                candidate = Candidate.from_dict(raw)
                if candidate is not None:
                    state.add_candidate(candidate)

        raw_results = value.get("validation_results", [])
        if isinstance(raw_results, list):
            for raw in raw_results:
                result = ValidationResult.from_dict(raw)
                if result is not None and result.candidate_id in state.candidates:
                    # Persistence may contain an intentional forced retest
                    # whose compact result is identical to an earlier attempt.
                    state.add_validation_result(result, force=True)

        active = value.get("active_candidate_ids")
        if isinstance(active, list) and all(isinstance(item, str) for item in active):
            state.active_candidate_ids = {
                item
                for item in active
                if item in state.candidates
                and state.candidates[item].status in {"new", "queued", "validating"}
            }
        completed = value.get("completed_skills")
        if isinstance(completed, list) and all(isinstance(item, str) for item in completed):
            state.completed_skills.update(
                normalize_metadata_name(item) for item in completed if item.strip()
            )
        phase = value.get("current_phase")
        if isinstance(phase, str):
            state.current_phase = _text(phase, limit=80)
        return state


def is_candidate_status(value: str) -> TypeGuard[CandidateStatus]:
    return value in CANDIDATE_STATUSES


def is_validation_outcome(value: str) -> TypeGuard[ValidationOutcome]:
    return value in VALIDATION_OUTCOMES
