from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal, TypeGuard

from src.skills.registry import normalize_candidate_class, normalize_metadata_name
from src.redact.redact import apply as redact
from src.target.origin import HTTPOrigin
from .evidence import EvidenceArtifact


CandidateStatus = Literal[
    "new",
    "queued",
    "validating",
    "validated",
    "deferred",
    "dismissed",
]
CandidatePriority = Literal["high", "medium", "low"]
WorkflowMode = Literal["direct", "candidate_validation", "whole_target"]
InputDisposition = Literal["pending", "analyzed", "dropped", "blocked"]
WorkflowPhase = Literal["recon", "enumeration", "input_analysis"]

WORKFLOW_MODES = frozenset({"direct", "candidate_validation", "whole_target"})
INPUT_DISPOSITIONS = frozenset({"pending", "analyzed", "dropped", "blocked"})
WORKFLOW_PHASES = frozenset({"recon", "enumeration", "input_analysis"})
REQUIRED_WHOLE_TARGET_PHASES = ("recon", "enumeration", "input_analysis")

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
    normalized = redact(" ".join(value.strip().split()))
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


def normalize_target_origin(value: Any) -> str | None:
    text = _text(value)
    if not text:
        return None
    try:
        return HTTPOrigin.from_url(text).as_url()
    except ValueError as exc:
        raise ValueError("target_origin must be an HTTP origin") from exc


def _identity_payload(
    *,
    target: str | None,
    method: str | None,
    endpoint: str | None,
    parameter: str | None,
    location: str | None,
    candidate_class: str,
    test_case: str | None = None,
) -> dict[str, str]:
    payload = {
        "target": normalize_candidate_target(target) or "",
        "method": (method or "").strip().upper(),
        "endpoint": (endpoint or "").strip(),
        "parameter": (parameter or "").strip(),
        "location": (location or "").strip().lower(),
        "candidate_class": normalize_candidate_class(candidate_class),
    }
    # Preserve IDs from older sessions when no distinct test case was recorded.
    if test_case:
        payload["test_case"] = test_case.strip().lower()
    return payload


def candidate_fingerprint(
    *,
    target: str | None = None,
    method: str | None = None,
    endpoint: str | None = None,
    parameter: str | None = None,
    location: str | None = None,
    candidate_class: str,
    test_case: str | None = None,
    objective_id: str | None = None,
) -> str:
    payload = _identity_payload(
        target=target,
        method=method,
        endpoint=endpoint,
        parameter=parameter,
        location=location,
        candidate_class=candidate_class,
        test_case=test_case,
    )
    if objective_id:
        payload["objective_id"] = objective_id.strip()
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
    test_case: str | None = None
    priority: CandidatePriority | None = None
    signals: list[str] = field(default_factory=list)
    baseline_request_ref: str | None = None
    auth_context_ref: str | None = None
    source_skill: str | None = None
    objective_id: str | None = None
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
        self.test_case = _text(self.test_case, limit=120)
        if self.priority is not None and self.priority not in {"high", "medium", "low"}:
            raise ValueError("priority must be high, medium, or low")
        self.signals = _strings(self.signals, maximum=_MAX_SIGNALS)
        self.baseline_request_ref = _text(self.baseline_request_ref)
        self.auth_context_ref = _text(self.auth_context_ref)
        self.source_skill = (
            normalize_metadata_name(self.source_skill) if self.source_skill else None
        )
        self.objective_id = _text(self.objective_id, limit=80)
        if not is_candidate_status(self.status):
            raise ValueError(f"unknown candidate status: {self.status}")

        stable_id = candidate_fingerprint(
            target=self.target,
            method=self.method,
            endpoint=self.endpoint,
            parameter=self.parameter,
            location=self.location,
            candidate_class=self.candidate_class,
            test_case=self.test_case,
            objective_id=self.objective_id,
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
            "test_case": self.test_case,
            "priority": self.priority,
            "signals": list(self.signals),
            "baseline_request_ref": self.baseline_request_ref,
            "auth_context_ref": self.auth_context_ref,
            "source_skill": self.source_skill,
            "objective_id": self.objective_id,
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
                test_case=value.get("test_case"),
                priority=value.get("priority"),
                signals=value.get("signals", []),
                baseline_request_ref=value.get("baseline_request_ref"),
                auth_context_ref=value.get("auth_context_ref"),
                source_skill=value.get("source_skill"),
                objective_id=value.get("objective_id"),
                status=value.get("status", "new"),
            )
        except (TypeError, ValueError):
            return None


@dataclass(slots=True)
class WorkflowObjective:
    id: str
    mode: WorkflowMode
    target_origin: str | None
    candidate_id: str | None = None

    def __post_init__(self) -> None:
        self.id = _text(self.id, limit=80) or ""
        if not self.id:
            raise ValueError("objective id is required")
        if self.mode not in WORKFLOW_MODES:
            raise ValueError(f"unknown workflow mode: {self.mode}")
        self.target_origin = normalize_target_origin(self.target_origin)
        self.candidate_id = _text(self.candidate_id, limit=80)
        if self.mode == "whole_target" and self.target_origin is None:
            raise ValueError("whole-target objective requires target_origin")
        if self.mode == "candidate_validation" and not self.candidate_id:
            raise ValueError("candidate-validation objective requires candidate_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mode": self.mode,
            "target_origin": self.target_origin,
            "candidate_id": self.candidate_id,
        }

    @classmethod
    def from_dict(cls, value: Any) -> WorkflowObjective | None:
        if not isinstance(value, dict):
            return None
        try:
            objective_id = value.get("id")
            mode = value.get("mode")
            if not isinstance(objective_id, str) or not isinstance(mode, str):
                return None
            return cls(
                id=objective_id,
                mode=mode,  # type: ignore[arg-type]
                target_origin=value.get("target_origin"),
                candidate_id=value.get("candidate_id"),
            )
        except (TypeError, ValueError):
            return None


def attack_surface_input_fingerprint(
    *,
    objective_id: str,
    target_origin: str,
    method: str | None,
    endpoint: str | None,
    parameter: str | None,
    location: str | None,
    input_type: str | None,
) -> str:
    payload = {
        "objective_id": objective_id.strip(),
        "target_origin": normalize_target_origin(target_origin) or "",
        "method": (method or "").strip().upper(),
        "endpoint": (endpoint or "").strip(),
        "parameter": (parameter or "").strip(),
        "location": (location or "").strip().lower(),
        "input_type": (input_type or "").strip().lower(),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:20]
    return f"input_{digest}"


@dataclass(slots=True)
class AttackSurfaceInput:
    objective_id: str
    target_origin: str
    method: str | None = None
    endpoint: str | None = None
    parameter: str | None = None
    location: str | None = None
    input_type: str | None = None
    disposition: InputDisposition = "pending"
    candidate_ids: list[str] = field(default_factory=list)
    disposition_reason: str | None = None
    disposition_transitions: list[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        self.objective_id = _text(self.objective_id, limit=80) or ""
        if not self.objective_id:
            raise ValueError("objective_id is required")
        self.target_origin = normalize_target_origin(self.target_origin) or ""
        if not self.target_origin:
            raise ValueError("target_origin is required")
        self.method = _method(self.method)
        self.endpoint = _text(self.endpoint)
        self.parameter = _text(self.parameter)
        self.location = _text(self.location, limit=80)
        if self.location:
            self.location = self.location.lower()
        self.input_type = _text(self.input_type, limit=80)
        if self.input_type:
            self.input_type = self.input_type.lower()
        if self.disposition not in INPUT_DISPOSITIONS:
            raise ValueError(f"unknown input disposition: {self.disposition}")
        self.candidate_ids = _strings(self.candidate_ids, maximum=_MAX_REFS)
        self.disposition_reason = _text(self.disposition_reason, limit=300)
        self.disposition_transitions = _strings(
            self.disposition_transitions, maximum=20
        )
        if self.disposition in {"dropped", "blocked"} and not self.disposition_reason:
            raise ValueError(f"{self.disposition} disposition requires a reason")
        stable_id = attack_surface_input_fingerprint(
            objective_id=self.objective_id,
            target_origin=self.target_origin,
            method=self.method,
            endpoint=self.endpoint,
            parameter=self.parameter,
            location=self.location,
            input_type=self.input_type,
        )
        if self.id and self.id != stable_id:
            raise ValueError("input id does not match its semantic fingerprint")
        self.id = stable_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "objective_id": self.objective_id,
            "target_origin": self.target_origin,
            "method": self.method,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "location": self.location,
            "input_type": self.input_type,
            "disposition": self.disposition,
            "candidate_ids": list(self.candidate_ids),
            "disposition_reason": self.disposition_reason,
            "disposition_transitions": list(self.disposition_transitions),
        }

    @classmethod
    def from_dict(cls, value: Any) -> AttackSurfaceInput | None:
        if not isinstance(value, dict):
            return None
        try:
            objective_id = value.get("objective_id")
            target_origin = value.get("target_origin")
            if not isinstance(objective_id, str) or not isinstance(target_origin, str):
                return None
            return cls(
                id=value.get("id", "") if isinstance(value.get("id", ""), str) else "",
                objective_id=objective_id,
                target_origin=target_origin,
                method=value.get("method"),
                endpoint=value.get("endpoint"),
                parameter=value.get("parameter"),
                location=value.get("location"),
                input_type=value.get("input_type"),
                disposition=value.get("disposition", "pending"),
                candidate_ids=value.get("candidate_ids", []),
                disposition_reason=value.get("disposition_reason"),
                disposition_transitions=value.get("disposition_transitions", []),
            )
        except (TypeError, ValueError):
            return None


@dataclass(slots=True)
class WorkflowPhaseCompletion:
    objective_id: str
    phase: WorkflowPhase
    target_origin: str
    artifact_ref: str

    def __post_init__(self) -> None:
        self.objective_id = _text(self.objective_id, limit=80) or ""
        if not self.objective_id:
            raise ValueError("objective_id is required")
        if self.phase not in WORKFLOW_PHASES:
            raise ValueError(f"unknown workflow phase: {self.phase}")
        self.target_origin = normalize_target_origin(self.target_origin) or ""
        self.artifact_ref = _text(self.artifact_ref, limit=500) or ""
        if not self.target_origin or not self.artifact_ref:
            raise ValueError("phase completion requires target_origin and artifact_ref")

    @property
    def key(self) -> str:
        return f"{self.objective_id}:{self.phase}"

    def to_dict(self) -> dict[str, str]:
        return {
            "objective_id": self.objective_id,
            "phase": self.phase,
            "target_origin": self.target_origin,
            "artifact_ref": self.artifact_ref,
        }

    @classmethod
    def from_dict(cls, value: Any) -> WorkflowPhaseCompletion | None:
        if not isinstance(value, dict):
            return None
        try:
            objective_id = value.get("objective_id")
            phase = value.get("phase")
            target_origin = value.get("target_origin")
            artifact_ref = value.get("artifact_ref")
            if not all(isinstance(item, str) for item in (objective_id, phase, target_origin, artifact_ref)):
                return None
            return cls(objective_id, phase, target_origin, artifact_ref)  # type: ignore[arg-type]
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
    coverage_synced: bool | None = None
    recorded_at: str | None = None
    session_id: str | None = None

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
        if self.coverage_synced is not None and not isinstance(self.coverage_synced, bool):
            raise ValueError("coverage_synced must be a boolean or null")
        self.cleanup_status = _text(self.cleanup_status)
        self.deferred_reason = _text(self.deferred_reason)
        self.notes = _text(self.notes, limit=_MAX_NOTES_LENGTH)
        self.recorded_at = _text(self.recorded_at, limit=80)
        self.session_id = _text(self.session_id, limit=120)

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
            "coverage_synced": self.coverage_synced,
            "recorded_at": self.recorded_at,
            "session_id": self.session_id,
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
                coverage_synced=value.get("coverage_synced"),
                recorded_at=value.get("recorded_at"),
                session_id=value.get("session_id"),
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
    version: int = 3
    objective: WorkflowObjective | None = None
    candidates: dict[str, Candidate] = field(default_factory=dict)
    validation_results: list[ValidationResult] = field(default_factory=list)
    evidence: dict[str, EvidenceArtifact] = field(default_factory=dict)
    attack_surface_inputs: dict[str, AttackSurfaceInput] = field(default_factory=dict)
    phase_completions: dict[str, WorkflowPhaseCompletion] = field(default_factory=dict)
    active_candidate_ids: set[str] = field(default_factory=set)
    completed_skills: set[str] = field(default_factory=set)
    completed_artifacts: dict[str, str] = field(default_factory=dict)
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
                "priority",
            ):
                if getattr(existing, field_name) is None:
                    setattr(existing, field_name, getattr(candidate, field_name))
            return existing, False

        self.candidates[candidate.id] = candidate
        if candidate.status in {"new", "queued", "validating"}:
            self.active_candidate_ids.add(candidate.id)
        return candidate, True

    def objective_candidates(self) -> tuple[Candidate, ...]:
        objective = self.objective
        if objective is None or objective.mode != "whole_target":
            return ()
        return tuple(
            candidate
            for candidate in sorted(self.candidates.values(), key=lambda item: item.id)
            if candidate.objective_id == objective.id
            and candidate_origin(candidate.target) == objective.target_origin
        )

    def objective_inputs(self) -> tuple[AttackSurfaceInput, ...]:
        objective = self.objective
        if objective is None or objective.mode != "whole_target":
            return ()
        return tuple(
            item
            for item in sorted(self.attack_surface_inputs.values(), key=lambda entry: entry.id)
            if item.objective_id == objective.id
            and item.target_origin == objective.target_origin
        )

    def completed_phases(self, objective: WorkflowObjective | None = None) -> frozenset[str]:
        current = objective or self.objective
        if current is None:
            return frozenset()
        return frozenset(
            marker.phase
            for marker in self.phase_completions.values()
            if marker.objective_id == current.id
            and marker.target_origin == current.target_origin
        )

    def add_attack_surface_input(
        self, item: AttackSurfaceInput
    ) -> tuple[AttackSurfaceInput, bool]:
        objective = self.objective
        if (
            objective is None
            or objective.mode != "whole_target"
            or item.objective_id != objective.id
            or item.target_origin != objective.target_origin
        ):
            raise ValueError("input must belong to the active whole-target objective")
        existing = self.attack_surface_inputs.get(item.id)
        if existing is not None:
            if existing.objective_id != item.objective_id:
                raise ValueError("input identity belongs to a different objective")
            for candidate_id in item.candidate_ids:
                if candidate_id not in existing.candidate_ids:
                    existing.candidate_ids.append(candidate_id)
            return existing, False
        self.attack_surface_inputs[item.id] = item
        return item, True

    def set_input_disposition(
        self,
        input_id: str,
        disposition: InputDisposition,
        *,
        reason: str | None = None,
    ) -> AttackSurfaceInput:
        if disposition not in INPUT_DISPOSITIONS:
            raise ValueError(f"unknown input disposition: {disposition}")
        item = self.attack_surface_inputs.get(input_id)
        objective = self.objective
        if item is None:
            raise ValueError(f"unknown input: {input_id}")
        if (
            objective is None
            or objective.mode != "whole_target"
            or item.objective_id != objective.id
            or item.target_origin != objective.target_origin
        ):
            raise ValueError("input does not belong to the active whole-target objective")
        normalized_reason = _text(reason, limit=300)
        if disposition in {"dropped", "blocked"} and not normalized_reason:
            raise ValueError(f"{disposition} disposition requires a reason")
        if item.disposition in {"analyzed", "dropped"} and disposition != item.disposition:
            raise ValueError("analyzed and dropped inputs are terminal")
        if item.disposition == disposition:
            if normalized_reason:
                item.disposition_reason = normalized_reason
            return item
        transition = f"{item.disposition}>{disposition}"
        if transition not in item.disposition_transitions:
            item.disposition_transitions.append(transition)
        item.disposition = disposition
        item.disposition_reason = normalized_reason
        return item

    def link_input_candidate(self, input_id: str, candidate_id: str) -> AttackSurfaceInput:
        item = self.attack_surface_inputs.get(input_id)
        candidate = self.candidates.get(candidate_id)
        objective = self.objective
        if item is None:
            raise ValueError(f"unknown input: {input_id}")
        if candidate is None:
            raise ValueError(f"unknown candidate: {candidate_id}")
        if (
            objective is None
            or objective.mode != "whole_target"
            or item.objective_id != objective.id
            or candidate.objective_id != objective.id
        ):
            raise ValueError("input and candidate must belong to the active objective")
        if item.target_origin != objective.target_origin or candidate_origin(candidate.target) != objective.target_origin:
            raise ValueError("input and candidate must match the active target origin")
        if candidate_id not in item.candidate_ids:
            item.candidate_ids.append(candidate_id)
        return item

    def record_phase_completion(
        self,
        phase: WorkflowPhase,
        *,
        objective_id: str,
        target_origin: str,
        artifact_ref: str,
    ) -> bool:
        objective = self.objective
        marker = WorkflowPhaseCompletion(
            objective_id=objective_id,
            phase=phase,
            target_origin=target_origin,
            artifact_ref=artifact_ref,
        )
        if (
            objective is None
            or objective.mode != "whole_target"
            or objective.id != marker.objective_id
            or objective.target_origin != marker.target_origin
        ):
            raise ValueError("phase completion must match the active objective and target")
        key = marker.key
        existing = self.phase_completions.get(key)
        if existing is not None:
            if existing.to_dict() != marker.to_dict():
                raise ValueError("phase completion is immutable within an objective")
            return False
        self.phase_completions[key] = marker
        return True

    def progress_facts(self) -> frozenset[str]:
        """Return monotonic semantic facts for the active whole-target objective."""
        objective = self.objective
        if objective is None or objective.mode != "whole_target":
            return frozenset()
        facts: set[str] = set()
        for item in self.objective_inputs():
            facts.add(f"input:{item.id}")
            facts.update(
                f"input-disposition:{item.id}:{transition}"
                for transition in item.disposition_transitions
            )
            facts.update(
                f"input-candidate:{item.id}:{candidate_id}"
                for candidate_id in item.candidate_ids
            )
        for marker in self.phase_completions.values():
            if marker.objective_id == objective.id and marker.target_origin == objective.target_origin:
                facts.add(f"phase:{marker.objective_id}:{marker.phase}:{marker.artifact_ref}")
        objective_candidates = {candidate.id: candidate for candidate in self.objective_candidates()}
        for candidate in objective_candidates.values():
            facts.add(f"candidate:{candidate.id}")
        for result in self.validation_results:
            if result.candidate_id not in objective_candidates:
                continue
            fingerprint = validation_result_fingerprint(result)
            candidate = objective_candidates[result.candidate_id]
            facts.add(f"result:{candidate.id}:{fingerprint}")
            coverage_status = {
                "confirmed": "failed",
                "not-confirmed": "passed",
            }.get(result.outcome)
            if coverage_status and candidate.endpoint:
                endpoint = f"{candidate.method} {candidate.endpoint}" if candidate.method else candidate.endpoint
                parameter = candidate.parameter or "(request)"
                if candidate.test_case:
                    parameter = f"{parameter} [subcase: {candidate.test_case}]"
                facts.add(
                    f"coverage:{endpoint}:{parameter}:{candidate.candidate_class}:{coverage_status}:{fingerprint}"
                )
            if result.coverage_synced is True:
                facts.add(f"coverage-sync:{candidate.id}:{fingerprint}")
        for artifact in self.evidence.values():
            if artifact.candidate_id in objective_candidates:
                facts.add(f"evidence:{artifact.id}:{artifact.sha256}")
        return frozenset(facts)

    def whole_target_status(
        self,
        *,
        target_origin: str | None,
        available_phases: frozenset[str],
        validator_classes: frozenset[str],
        coverage_sync_available: bool,
    ) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
        """Return status, actionable work, and blockers for the active objective."""
        objective = self.objective
        if objective is None or objective.mode != "whole_target":
            return "not_applicable", (), ()
        try:
            current_origin = normalize_target_origin(target_origin)
        except ValueError:
            current_origin = None
        if not current_origin or current_origin != objective.target_origin:
            return "blocked", (), ("active target origin changed",)

        actionable: list[str] = []
        blockers: list[str] = []
        normalized_validators = frozenset(
            normalize_candidate_class(item) for item in validator_classes
        )
        completed = self.completed_phases(objective)
        objective_inputs = self.objective_inputs()
        for phase in REQUIRED_WHOLE_TARGET_PHASES:
            if phase in completed:
                continue
            if phase in available_phases:
                if phase == "input_analysis" and any(
                    item.disposition == "blocked" for item in objective_inputs
                ) and not any(item.disposition == "pending" for item in objective_inputs):
                    blockers.append("input analysis is blocked by unresolved inventory inputs")
                else:
                    actionable.append(f"phase:{phase}")
            else:
                blockers.append(f"required phase unavailable:{phase}")
            # Later bounded phases depend on this one, so do not present them
            # as actionable until the earliest open phase is resolved.
            break

        for item in objective_inputs:
            if item.disposition == "pending":
                if (
                    "enumeration" in completed
                    and "input_analysis" in available_phases
                ):
                    actionable.append(f"input:{item.id}")
            elif item.disposition == "blocked":
                blockers.append(f"input:{item.id}:{item.disposition_reason or 'blocked'}")

        terminal_outcomes = {"confirmed", "not-confirmed"}
        for candidate in self.objective_candidates():
            result = self.latest_result(candidate.id)
            if candidate.status in {"new", "queued", "validating"}:
                if candidate.candidate_class in normalized_validators:
                    actionable.append(f"candidate:{candidate.id}")
                else:
                    blockers.append(f"candidate validator unavailable:{candidate.id}")
                continue
            if candidate.status == "deferred":
                reason = result.deferred_reason if result else None
                blockers.append(f"candidate deferred:{candidate.id}:{reason or 'condition not recorded'}")
                continue
            if candidate.status == "dismissed" and (
                result is None or result.outcome not in terminal_outcomes
            ):
                blockers.append(f"candidate dismissed without terminal result:{candidate.id}")
                continue
            if result is None or result.outcome not in terminal_outcomes:
                blockers.append(f"candidate lacks terminal result:{candidate.id}")
                continue
            if result.outcome == "confirmed" and not self.evidence_matches(
                candidate.id, result.evidence_refs
            ):
                blockers.append(f"confirmed candidate lacks linked evidence:{candidate.id}")
                continue
            if result.coverage_synced is False:
                if not candidate.endpoint:
                    blockers.append(f"coverage sync lacks candidate endpoint:{candidate.id}")
                elif coverage_sync_available:
                    actionable.append(f"coverage-sync:{candidate.id}")
                else:
                    blockers.append(f"coverage sync unavailable:{candidate.id}")

        if actionable:
            return "actionable", tuple(actionable), tuple(blockers)
        if blockers:
            return "blocked", (), tuple(blockers)
        if all(phase in completed for phase in REQUIRED_WHOLE_TARGET_PHASES):
            return "completed", (), ()
        return "actionable", (), ("required workflow phase remains incomplete",)

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
        terminal_status: CandidateStatus = (
            "deferred"
            if result.outcome
            in {
                "blocked", "insufficient-evidence", "deferred",
                "browser-required", "authorization-required",
            }
            else "validated"
        )
        fingerprint = validation_result_fingerprint(result)
        if not force:
            existing = self.latest_result(result.candidate_id)
            if existing and validation_result_fingerprint(existing) == fingerprint:
                for field_name in ("cleanup_status", "deferred_reason", "notes"):
                    value = getattr(result, field_name)
                    if value is not None:
                        setattr(existing, field_name, value)
                if self.candidates[result.candidate_id].status == "validating":
                    self.set_candidate_status(result.candidate_id, terminal_status)
                return False
        self.validation_results.append(result)
        self.set_candidate_status(result.candidate_id, terminal_status)
        return True

    def add_evidence(self, artifact: EvidenceArtifact) -> None:
        if artifact.candidate_id not in self.candidates:
            raise ValueError(f"unknown candidate: {artifact.candidate_id}")
        self.evidence[artifact.id] = artifact

    def evidence_matches(self, candidate_id: str, refs: list[str]) -> bool:
        return bool(refs) and all(
            (artifact := self.evidence.get(ref)) is not None
            and artifact.candidate_id == candidate_id
            for ref in refs
        )

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
        return (
            result is not None
            and result.outcome == "confirmed"
            and result.coverage_synced is not False
            and self.evidence_matches(candidate_id, result.evidence_refs)
        )

    def clear(self) -> None:
        self.objective = None
        self.candidates.clear()
        self.validation_results.clear()
        self.evidence.clear()
        self.attack_surface_inputs.clear()
        self.phase_completions.clear()
        self.active_candidate_ids.clear()
        self.completed_skills.clear()
        self.completed_artifacts.clear()
        self.current_phase = None

    def replace_from(self, other: WorkflowState) -> None:
        self.version = other.version
        self.objective = other.objective
        self.candidates = dict(other.candidates)
        self.validation_results = list(other.validation_results)
        self.evidence = dict(other.evidence)
        self.attack_surface_inputs = dict(other.attack_surface_inputs)
        self.phase_completions = dict(other.phase_completions)
        self.active_candidate_ids = set(other.active_candidate_ids)
        self.completed_skills = set(other.completed_skills)
        self.completed_artifacts = dict(other.completed_artifacts)
        self.current_phase = other.current_phase

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "objective": self.objective.to_dict() if self.objective else None,
            "candidates": [self.candidates[key].to_dict() for key in sorted(self.candidates)],
            "validation_results": [result.to_dict() for result in self.validation_results],
            "evidence": [self.evidence[key].to_dict() for key in sorted(self.evidence)],
            "attack_surface_inputs": [
                self.attack_surface_inputs[key].to_dict()
                for key in sorted(self.attack_surface_inputs)
            ],
            "phase_completions": [
                self.phase_completions[key].to_dict()
                for key in sorted(self.phase_completions)
            ],
            "active_candidate_ids": sorted(self.active_candidate_ids),
            "completed_skills": sorted(self.completed_skills),
            "completed_artifacts": dict(sorted(self.completed_artifacts.items())),
            "current_phase": self.current_phase,
        }

    @classmethod
    def from_dict(cls, value: Any) -> WorkflowState:
        state = cls()
        if not isinstance(value, dict):
            return state
        version = value.get("version", 1)
        if isinstance(version, int) and not isinstance(version, bool) and version > 0:
            # Version 1 had no registered evidence or independent subcases.
            # Its candidates/results still load, but legacy free-text evidence
            # references do not become finding-eligible without a new proof.
            state.version = max(3, version)

        state.objective = WorkflowObjective.from_dict(value.get("objective"))

        raw_candidates = value.get("candidates", [])
        if isinstance(raw_candidates, dict):
            raw_candidates = list(raw_candidates.values())
        saved_statuses: dict[str, CandidateStatus] = {}
        if isinstance(raw_candidates, list):
            for raw in raw_candidates:
                candidate = Candidate.from_dict(raw)
                if candidate is not None:
                    state.add_candidate(candidate)
                    if isinstance(raw, dict) and "status" in raw:
                        saved_statuses[candidate.id] = candidate.status

        raw_results = value.get("validation_results", [])
        raw_evidence = value.get("evidence", [])
        if isinstance(raw_evidence, list):
            for raw in raw_evidence:
                artifact = EvidenceArtifact.from_dict(raw)
                if artifact is not None and artifact.candidate_id in state.candidates:
                    state.add_evidence(artifact)
        raw_inputs = value.get("attack_surface_inputs", [])
        if isinstance(raw_inputs, list):
            for raw in raw_inputs:
                item = AttackSurfaceInput.from_dict(raw)
                if item is not None:
                    try:
                        state.attack_surface_inputs[item.id] = item
                    except (TypeError, ValueError):
                        continue
        raw_phases = value.get("phase_completions", [])
        if isinstance(raw_phases, list):
            for raw in raw_phases:
                marker = WorkflowPhaseCompletion.from_dict(raw)
                if marker is not None:
                    state.phase_completions[marker.key] = marker
        if isinstance(raw_results, list):
            for raw in raw_results:
                result = ValidationResult.from_dict(raw)
                if result is not None and result.candidate_id in state.candidates:
                    # Persistence may contain an intentional forced retest
                    # whose compact result is identical to an earlier attempt.
                    state.add_validation_result(result, force=True)

        # Replaying results rebuilds history, but the serialized Candidate
        # status may reflect a later requeue or validation start.
        for candidate_id, status in saved_statuses.items():
            state.set_candidate_status(candidate_id, status)

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
        artifacts = value.get("completed_artifacts")
        if isinstance(artifacts, dict):
            for name, path in artifacts.items():
                if isinstance(name, str) and isinstance(path, str):
                    canonical = normalize_metadata_name(name)
                    if canonical in state.completed_skills:
                        safe_path = _text(path)
                        if safe_path:
                            state.completed_artifacts[canonical] = safe_path
        phase = value.get("current_phase")
        if isinstance(phase, str):
            state.current_phase = _text(phase, limit=80)
        return state


def candidate_origin(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return HTTPOrigin.from_url(value).as_url()
    except ValueError:
        return None


def is_candidate_status(value: str) -> TypeGuard[CandidateStatus]:
    return value in CANDIDATE_STATUSES


def is_validation_outcome(value: str) -> TypeGuard[ValidationOutcome]:
    return value in VALIDATION_OUTCOMES
