from __future__ import annotations

import asyncio
import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Literal, TypeGuard, cast
from urllib.parse import urljoin, urlsplit

from src.skills.registry import normalize_candidate_class, normalize_metadata_name
from src.redact.redact import (
    apply as redact,
    redact_payload,
    redact_request_context,
)
from src.target.origin import HTTPOrigin
from .evidence import EvidenceArtifact
from .goals import GoalStatus, RequestedGoal


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
# observed is an explicit unattested review; only adapters attest performed.
PhaseCoverageStatus = Literal[
    "performed", "observed", "skipped", "not_applicable", "failed", "cancelled"
]
CleanupState = Literal[
    "not-required", "pending", "succeeded", "failed", "requires-user-action"
]

WORKFLOW_MODES = frozenset({"direct", "candidate_validation", "whole_target"})
INPUT_DISPOSITIONS = frozenset({"pending", "analyzed", "dropped", "blocked"})
WORKFLOW_PHASES = frozenset({"recon", "enumeration", "input_analysis"})
PHASE_COVERAGE_STATUSES = frozenset(
    {"performed", "observed", "skipped", "not_applicable", "failed", "cancelled"}
)
CLEANUP_STATES = frozenset(
    {"not-required", "pending", "succeeded", "failed", "requires-user-action"}
)
PHASE_COVERAGE_DIMENSIONS: dict[str, tuple[str, ...]] = {
    "recon": (
        "target_resolution", "reachability", "http_fingerprint", "service_discovery",
    ),
    "enumeration": (
        "html_navigation", "standard_metadata", "api_documentation",
        "javascript_endpoint_extraction", "browser_burp_capture",
        "active_content_discovery",
    ),
}
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
_MAX_REQUEST_CONTEXT_LENGTH = 4000


def _text(value: Any, *, limit: int = _MAX_ITEM_LENGTH) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("expected a string")
    normalized = redact(" ".join(value.strip().split()))
    return normalized[:limit] or None


def _request_context(value: Any, content_type: str | None = None) -> str | None:
    """Keep a compact request skeleton while preserving its structure."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("expected a string")
    normalized = redact_request_context(value, content_type)
    if len(normalized) > _MAX_REQUEST_CONTEXT_LENGTH:
        raise ValueError(
            f"request context must be at most {_MAX_REQUEST_CONTEXT_LENGTH} characters"
        )
    return normalized or None


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


def normalize_media_type(value: str | None) -> str | None:
    """Request shape uses the base media type, never inferred from a body."""
    return value.split(";", 1)[0].strip().lower() or None if value else None


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
    auth_context_ref: str | None = None,
    baseline_request_ref: str | None = None,
    content_type: str | None = None,
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
    if auth_context_ref:
        payload["auth_context_ref"] = auth_context_ref.strip()
    if baseline_request_ref:
        payload["baseline_request_ref"] = baseline_request_ref.strip()
    media_type = normalize_media_type(content_type)
    if media_type:
        payload["media_type"] = media_type
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
    content_type: str | None = None
    # None derives identity for new records; "" pins legacy/unknown IDs even
    # when compatible request context is later enriched. Never rekey links.
    identity_media_type: str | None = None
    request_template: str | None = None
    source_ref: str | None = None

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
        self.content_type = _text(self.content_type, limit=200)
        if self.identity_media_type is None:
            self.identity_media_type = normalize_media_type(self.content_type) or ""
        elif not isinstance(self.identity_media_type, str):
            raise ValueError("identity_media_type must be a string")
        else:
            self.identity_media_type = normalize_media_type(self.identity_media_type) or ""
        if self.identity_media_type and self.identity_media_type != normalize_media_type(self.content_type):
            raise ValueError("media identity conflicts with content_type")
        self.request_template = _request_context(
            self.request_template, self.content_type
        )
        self.source_ref = _text(self.source_ref)
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
            auth_context_ref=self.auth_context_ref,
            baseline_request_ref=self.baseline_request_ref,
            content_type=self.identity_media_type,
        )
        if self.id and self.id != stable_id:
            legacy_id = candidate_fingerprint(
                target=self.target, method=self.method, endpoint=self.endpoint,
                parameter=self.parameter, location=self.location,
                candidate_class=self.candidate_class, test_case=self.test_case,
                objective_id=self.objective_id,
            )
            bound_legacy_id = candidate_fingerprint(
                target=self.target, method=self.method, endpoint=self.endpoint,
                parameter=self.parameter, location=self.location,
                candidate_class=self.candidate_class, test_case=self.test_case,
                objective_id=self.objective_id, auth_context_ref=self.auth_context_ref,
                baseline_request_ref=self.baseline_request_ref,
            )
            if self.id not in {legacy_id, bound_legacy_id}:
                raise ValueError("candidate id does not match its semantic fingerprint")
            self.identity_media_type = ""
            return
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
            "content_type": self.content_type,
            "identity_media_type": self.identity_media_type,
            "request_template": self.request_template,
            "source_ref": self.source_ref,
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
                content_type=value.get("content_type"),
                identity_media_type=value.get("identity_media_type", ""),
                request_template=value.get("request_template"),
                source_ref=value.get("source_ref"),
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
    requested_goals: list[RequestedGoal] = field(default_factory=list)

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
        unique_goals: list[RequestedGoal] = []
        seen_classes: set[str] = set()
        for goal in self.requested_goals:
            if goal.candidate_class not in seen_classes:
                unique_goals.append(goal)
                seen_classes.add(goal.candidate_class)
        self.requested_goals = unique_goals

    def add_requested_goal(self, candidate_class: str) -> RequestedGoal:
        canonical = normalize_candidate_class(candidate_class)
        for goal in self.requested_goals:
            if goal.candidate_class == canonical:
                return goal
        goal = RequestedGoal(candidate_class=canonical)
        self.requested_goals.append(goal)
        return goal

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mode": self.mode,
            "target_origin": self.target_origin,
            "candidate_id": self.candidate_id,
            "requested_goals": [goal.to_dict() for goal in self.requested_goals],
        }

    @classmethod
    def from_dict(cls, value: Any) -> WorkflowObjective | None:
        if not isinstance(value, dict):
            return None
        from src.workflow.goals import RequestedGoalsLoadError

        # Absence is a legacy snapshot; presence must never lose corrupt work.
        goals: list[RequestedGoal] = []
        if "requested_goals" in value:
            raw_goals = value["requested_goals"]
            if not isinstance(raw_goals, list):
                raise RequestedGoalsLoadError("malformed requested goals: expected a list")
            seen_classes: set[str] = set()
            for raw_goal in raw_goals:
                goal = RequestedGoal.from_dict(raw_goal)
                if goal is None:
                    raise RequestedGoalsLoadError("malformed requested goals: invalid goal record")
                if goal.candidate_class in seen_classes:
                    raise RequestedGoalsLoadError("malformed requested goals: duplicate canonical class")
                seen_classes.add(goal.candidate_class)
                goals.append(goal)
        try:
            objective_id = value.get("id")
            mode = value.get("mode")
            if not isinstance(objective_id, str) or not isinstance(mode, str):
                if "requested_goals" in value:
                    raise RequestedGoalsLoadError("malformed requested goals: invalid owning objective")
                return None
            return cls(
                id=objective_id,
                mode=mode,  # type: ignore[arg-type]
                target_origin=value.get("target_origin"),
                candidate_id=value.get("candidate_id"),
                requested_goals=goals,
            )
        except (TypeError, ValueError):
            if "requested_goals" in value:
                raise RequestedGoalsLoadError("malformed requested goals: invalid owning objective") from None
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
    auth_context_ref: str | None = None,
    baseline_request_ref: str | None = None,
    content_type: str | None = None,
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
    if auth_context_ref:
        payload["auth_context_ref"] = auth_context_ref.strip()
    if baseline_request_ref:
        payload["baseline_request_ref"] = baseline_request_ref.strip()
    media_type = normalize_media_type(content_type)
    if media_type:
        payload["media_type"] = media_type
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
    content_type: str | None = None
    # None derives identity for new records; "" pins legacy/unknown IDs even
    # when compatible request context is later enriched. Never rekey links.
    identity_media_type: str | None = None
    sample_payload: str | None = None
    baseline_request_ref: str | None = None
    auth_context_ref: str | None = None
    source_ref: str | None = None

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
        self.content_type = _text(self.content_type, limit=200)
        if self.identity_media_type is None:
            self.identity_media_type = normalize_media_type(self.content_type) or ""
        elif not isinstance(self.identity_media_type, str):
            raise ValueError("identity_media_type must be a string")
        else:
            self.identity_media_type = normalize_media_type(self.identity_media_type) or ""
        if self.identity_media_type and self.identity_media_type != normalize_media_type(self.content_type):
            raise ValueError("media identity conflicts with content_type")
        self.sample_payload = _request_context(self.sample_payload, self.content_type)
        self.baseline_request_ref = _text(self.baseline_request_ref)
        self.auth_context_ref = _text(self.auth_context_ref)
        self.source_ref = _text(self.source_ref)
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
            auth_context_ref=self.auth_context_ref,
            baseline_request_ref=self.baseline_request_ref,
            content_type=self.identity_media_type,
        )
        if self.id and self.id != stable_id:
            legacy_id = attack_surface_input_fingerprint(
                objective_id=self.objective_id, target_origin=self.target_origin,
                method=self.method, endpoint=self.endpoint, parameter=self.parameter,
                location=self.location, input_type=self.input_type,
            )
            bound_legacy_id = attack_surface_input_fingerprint(
                objective_id=self.objective_id, target_origin=self.target_origin,
                method=self.method, endpoint=self.endpoint, parameter=self.parameter,
                location=self.location, input_type=self.input_type,
                auth_context_ref=self.auth_context_ref, baseline_request_ref=self.baseline_request_ref,
            )
            if self.id not in {legacy_id, bound_legacy_id}:
                raise ValueError("input id does not match its semantic fingerprint")
            self.identity_media_type = ""
            return
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
            "content_type": self.content_type,
            "identity_media_type": self.identity_media_type,
            "sample_payload": self.sample_payload,
            "baseline_request_ref": self.baseline_request_ref,
            "auth_context_ref": self.auth_context_ref,
            "source_ref": self.source_ref,
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
                content_type=value.get("content_type"),
                identity_media_type=value.get("identity_media_type", ""),
                sample_payload=value.get("sample_payload"),
                baseline_request_ref=value.get("baseline_request_ref"),
                auth_context_ref=value.get("auth_context_ref"),
                source_ref=value.get("source_ref"),
                disposition=value.get("disposition", "pending"),
                candidate_ids=value.get("candidate_ids", []),
                disposition_reason=value.get("disposition_reason"),
                disposition_transitions=value.get("disposition_transitions", []),
            )
        except (TypeError, ValueError):
            return None


@dataclass(slots=True)
class PhaseCoverage:
    status: PhaseCoverageStatus
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status not in PHASE_COVERAGE_STATUSES:
            raise ValueError(f"unknown phase coverage status: {self.status}")
        self.reason = _text(self.reason, limit=300)
        if self.status != "performed" and not self.reason:
            raise ValueError(f"{self.status} phase coverage requires a reason")

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "reason": self.reason}

    @classmethod
    def from_dict(cls, value: Any) -> PhaseCoverage | None:
        if not isinstance(value, dict):
            return None
        status = value.get("status")
        if not isinstance(status, str) or status not in PHASE_COVERAGE_STATUSES:
            return None
        try:
            return cls(status, value.get("reason"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None


@dataclass(slots=True)
class WorkflowPhaseCompletion:
    objective_id: str
    phase: WorkflowPhase
    target_origin: str
    artifact_ref: str
    no_inputs_discovered: bool = False
    coverage: dict[str, PhaseCoverage] = field(default_factory=dict)

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
        if not isinstance(self.no_inputs_discovered, bool):
            raise ValueError("no_inputs_discovered must be a boolean")
        if self.no_inputs_discovered and self.phase != "input_analysis":
            raise ValueError(
                "no_inputs_discovered is only valid for input analysis completion"
            )
        expected = set(PHASE_COVERAGE_DIMENSIONS.get(self.phase, ()))
        actual = set(self.coverage)
        if expected and actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            raise ValueError(
                f"{self.phase} completion requires coverage for all dimensions "
                f"(missing={missing}, extra={extra})"
            )
        if not expected and actual:
            raise ValueError(f"{self.phase} does not accept discovery coverage")
        if any(not isinstance(item, PhaseCoverage) for item in self.coverage.values()):
            raise ValueError("phase coverage values must be PhaseCoverage records")
        if any(item.status in {"failed", "cancelled"} for item in self.coverage.values()):
            raise ValueError("phase completion cannot contain failed or cancelled coverage")

    @property
    def key(self) -> str:
        return f"{self.objective_id}:{self.phase}"

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "objective_id": self.objective_id,
            "phase": self.phase,
            "target_origin": self.target_origin,
            "artifact_ref": self.artifact_ref,
        }
        if self.no_inputs_discovered:
            value["no_inputs_discovered"] = True
        if self.coverage:
            value["coverage"] = {
                key: item.to_dict() for key, item in sorted(self.coverage.items())
            }
        return value

    @classmethod
    def from_dict(
        cls,
        value: Any,
        *,
        allow_legacy_coverage: bool = False,
    ) -> WorkflowPhaseCompletion | None:
        if not isinstance(value, dict):
            return None
        try:
            objective_id = value.get("objective_id")
            phase = value.get("phase")
            target_origin = value.get("target_origin")
            artifact_ref = value.get("artifact_ref")
            if (
                not isinstance(objective_id, str)
                or not isinstance(phase, str)
                or not isinstance(target_origin, str)
                or not isinstance(artifact_ref, str)
            ):
                return None
            no_inputs_discovered = value.get("no_inputs_discovered", False)
            raw_coverage = value.get("coverage")
            coverage: dict[str, PhaseCoverage] = {}
            if "coverage" in value:
                if not isinstance(raw_coverage, dict):
                    return None
                for dimension, raw_record in raw_coverage.items():
                    record = PhaseCoverage.from_dict(raw_record)
                    if not isinstance(dimension, str) or record is None:
                        return None
                    coverage[dimension] = record
            elif (
                allow_legacy_coverage
                and phase in PHASE_COVERAGE_DIMENSIONS
            ):
                # Only pre-v4 serialized states predate coverage reporting.
                coverage = {
                    dimension: PhaseCoverage(
                        "skipped", "legacy phase completion predates coverage reporting"
                    )
                    for dimension in PHASE_COVERAGE_DIMENSIONS[phase]
                }
            return cls(
                objective_id,
                cast(WorkflowPhase, phase),
                target_origin,
                artifact_ref,
                no_inputs_discovered,
                coverage,
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
    confirmation: dict[str, Any] | None = None
    mutation_performed: bool = False
    cleanup_status: str | None = None
    deferred_reason: str | None = None
    notes: str | None = None
    coverage_synced: bool | None = None
    recorded_at: str | None = None
    session_id: str | None = None
    cleanup_state: CleanupState | None = None
    objective_id: str | None = None
    assessment_source: str | None = None
    assessment_contract_version: int = 1
    result_id: str | None = None
    attempt_id: str | None = None
    candidate_binding: str | None = None
    evidence_manifest: list[dict[str, Any]] = field(default_factory=list)
    assessment: dict[str, Any] = field(default_factory=dict)
    assessment_binding: str | None = None
    supersedes: str | None = None

    def __post_init__(self) -> None:
        self.candidate_id = _text(self.candidate_id, limit=80) or ""
        self.skill_name = normalize_metadata_name(self.skill_name)
        if not self.candidate_id or not self.skill_name:
            raise ValueError("candidate_id and skill_name are required")
        if not is_validation_outcome(self.outcome):
            raise ValueError(f"unknown validation outcome: {self.outcome}")
        if (not isinstance(self.assessment_contract_version, int) or isinstance(self.assessment_contract_version, bool)
                or self.assessment_contract_version not in {1, 2}):
            raise ValueError("unsupported assessment contract version")
        if self.assessment_source not in {None, "agent", "operator", "legacy-verifier"}:
            raise ValueError("invalid assessment source")
        if (not isinstance(self.evidence_manifest, list) or len(self.evidence_manifest) > 32
                or not isinstance(self.assessment, dict)
                or len(json.dumps(self.evidence_manifest)) > 2 * 1024 * 1024):
            raise ValueError("invalid bounded assessment manifest")
        self.evidence_refs = _strings(self.evidence_refs, maximum=_MAX_REFS)
        self.techniques = _strings(self.techniques, maximum=_MAX_TECHNIQUES)
        if self.repeatable is not None and not isinstance(self.repeatable, bool):
            raise ValueError("repeatable must be a boolean or null")
        if self.confirmation is not None:
            if not isinstance(self.confirmation, dict):
                raise ValueError("confirmation must be an object or null")
            encoded = json.dumps(self.confirmation, ensure_ascii=False, default=str)
            if len(encoded) > 6000:
                raise ValueError("confirmation exceeds the structured evidence limit")
            sanitized = redact_payload(self.confirmation)
            if not isinstance(sanitized, dict):
                raise ValueError("confirmation must remain an object after redaction")
            self.confirmation = sanitized
        if not isinstance(self.mutation_performed, bool):
            raise ValueError("mutation_performed must be a boolean")
        self.cleanup_status = _text(self.cleanup_status)
        if self.cleanup_state is None:
            self.cleanup_state = _infer_cleanup_state(
                self.mutation_performed, self.cleanup_status
            )
        elif not isinstance(self.cleanup_state, str) or self.cleanup_state not in CLEANUP_STATES:
            raise ValueError(f"unknown cleanup state: {self.cleanup_state}")
        if self.coverage_synced is not None and not isinstance(self.coverage_synced, bool):
            raise ValueError("coverage_synced must be a boolean or null")
        self.deferred_reason = _text(self.deferred_reason)
        self.notes = _text(self.notes, limit=_MAX_NOTES_LENGTH)
        self.recorded_at = _text(self.recorded_at, limit=80)
        self.session_id = _text(self.session_id, limit=120)
        self.objective_id = _text(self.objective_id, limit=80)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "skill_name": self.skill_name,
            "outcome": self.outcome,
            "evidence_refs": list(self.evidence_refs),
            "techniques": list(self.techniques),
            "repeatable": self.repeatable,
            "confirmation": self.confirmation,
            "mutation_performed": self.mutation_performed,
            "cleanup_status": self.cleanup_status,
            "cleanup_state": self.cleanup_state,
            "deferred_reason": self.deferred_reason,
            "notes": self.notes,
            "coverage_synced": self.coverage_synced,
            "recorded_at": self.recorded_at,
            "session_id": self.session_id,
            "objective_id": self.objective_id,
            **({key: getattr(self, key) for key in (
                "assessment_source", "assessment_contract_version", "result_id", "attempt_id",
                "candidate_binding", "evidence_manifest", "assessment", "assessment_binding", "supersedes",
            )} if self.assessment_contract_version >= 2 else {}),
        }

    def public_dict(self) -> dict[str, Any]:
        """Expose compact evidence handles; retained traffic stays in bounded storage."""
        row = self.to_dict()
        if self.assessment_contract_version >= 2:
            row["evidence_manifest"] = [
                {"hash": entry["hash"], "source": {key: value for key, value in entry["source"].items()
                 if key in {"id", "source_kind", "producer", "role", "required", "method", "url", "status", "complete",
                            "truncated", "execution_status", "elapsed_ms", "attempt_id", "response_cap", "source_details"}}}
                for entry in self.evidence_manifest]
        return row

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
                confirmation=value.get("confirmation"),
                mutation_performed=value.get("mutation_performed", False),
                cleanup_status=value.get("cleanup_status"),
                cleanup_state=value.get("cleanup_state"),
                deferred_reason=value.get("deferred_reason"),
                notes=value.get("notes"),
                coverage_synced=value.get("coverage_synced"),
                recorded_at=value.get("recorded_at"),
                session_id=value.get("session_id"),
                objective_id=value.get("objective_id"),
                **{key: value[key] for key in (
                    "assessment_source", "assessment_contract_version", "result_id", "attempt_id",
                    "candidate_binding", "evidence_manifest", "assessment", "assessment_binding", "supersedes",
                ) if key in value},
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
        "confirmation": result.confirmation,
        "mutation_performed": result.mutation_performed,
    }
    if result.assessment_contract_version >= 2:
        semantic_identity["assessment_binding"] = result.assessment_binding
        semantic_identity["result_id"] = result.result_id
    body = json.dumps(semantic_identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _infer_cleanup_state(
    mutation_performed: bool, cleanup_status: str | None,
) -> CleanupState:
    if not mutation_performed:
        return "not-required"
    detail = (cleanup_status or "").casefold()
    if not detail:
        return "pending"
    if any(term in detail for term in ("not applicable", "not required")):
        return "not-required"
    if any(term in detail for term in (
        "401", "403", "permission denied", "authorization required",
        "requires user", "operator action", "manual action",
    )):
        return "requires-user-action"
    if any(term in detail for term in ("failed", "failure", "error", "denied", "timeout")):
        return "failed"
    if any(term in detail for term in (
        "not cleaned", "not deleted", "not removed", "not restored", "not rolled back",
    )):
        return "pending"
    if any(term in detail for term in (
        "cleaned", "deleted", "removed", "rolled back", "restored", "success",
    )):
        return "succeeded"
    return "pending"


def _merge_compatible_context(
    existing: Any,
    incoming: Any,
    fields: tuple[str, ...],
    *,
    anchors: tuple[str, ...],
) -> bool:
    """Merge missing request context only when overlapping values agree."""
    if any(
        getattr(existing, field_name) is not None
        and getattr(incoming, field_name) is not None
        and (normalize_media_type(getattr(existing, field_name)) != normalize_media_type(getattr(incoming, field_name))
             if field_name == "content_type" else getattr(existing, field_name) != getattr(incoming, field_name))
        for field_name in fields
    ):
        return False
    existing_has_context = any(
        getattr(existing, field_name) is not None for field_name in fields
    )
    incoming_has_context = any(
        getattr(incoming, field_name) is not None for field_name in fields
    )
    fills_context = any(getattr(existing, name) is None and getattr(incoming, name) is not None for name in fields)
    if fills_context and existing_has_context and incoming_has_context and not any(
        getattr(existing, field_name) is not None
        and getattr(existing, field_name) == getattr(incoming, field_name)
        for field_name in anchors
    ):
        return False
    for field_name in fields:
        if getattr(existing, field_name) is None:
            setattr(existing, field_name, getattr(incoming, field_name))
    return True


@dataclass(slots=True)
class WorkflowState:
    version: int = 8
    objective: WorkflowObjective | None = None
    candidates: dict[str, Candidate] = field(default_factory=dict)
    validation_results: list[ValidationResult] = field(default_factory=list)
    evidence: dict[str, EvidenceArtifact] = field(default_factory=dict)
    attack_surface_inputs: dict[str, AttackSurfaceInput] = field(default_factory=dict)
    phase_completions: dict[str, WorkflowPhaseCompletion] = field(default_factory=dict)
    phase_coverage: dict[str, dict[str, PhaseCoverage]] = field(default_factory=dict)
    active_candidate_ids: set[str] = field(default_factory=set)
    completed_skills: set[str] = field(default_factory=set)
    completed_artifacts: dict[str, str] = field(default_factory=dict)
    persisted_findings: dict[str, str] = field(default_factory=dict)
    current_phase: str | None = None
    attempts: dict[str, dict[str, Any]] = field(default_factory=dict)
    selected_sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence_sources: dict[str, list[str]] = field(default_factory=dict)
    mutation_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False, compare=False)

    @staticmethod
    def _media_enrichment_match(existing: Any, incoming: Any, *, candidate: bool) -> bool:
        fields = ("objective_id", "method", "endpoint", "parameter", "location",
                  "baseline_request_ref", "auth_context_ref")
        fields += ("target", "candidate_class", "test_case") if candidate else ("target_origin", "input_type")
        return (
            all(getattr(existing, name) == getattr(incoming, name) for name in fields)
            and not existing.identity_media_type
            and bool(incoming.identity_media_type)
            and normalize_media_type(existing.content_type) in (None, incoming.identity_media_type)
            and any(getattr(existing, name) is not None and getattr(existing, name) == getattr(incoming, name)
                    for name in ("baseline_request_ref", "source_ref", "request_template" if candidate else "sample_payload"))
        )

    def add_candidate(self, candidate: Candidate, *, input_id: str | None = None) -> tuple[Candidate, bool]:
        if input_id is not None:
            self.validate_input_candidate(input_id, candidate)
        existing = self.candidates.get(candidate.id)
        if existing is None:
            existing = next((row for row in self.candidates.values()
                             if self._media_enrichment_match(row, candidate, candidate=True)), None)
        if existing is not None:
            # Check the prospective merge against all existing links before
            # context, signals, status or goal linkage can change.
            prospective = deepcopy(existing)
            for name in ("content_type", "request_template", "baseline_request_ref", "auth_context_ref", "source_ref"):
                if getattr(prospective, name) is None:
                    setattr(prospective, name, getattr(candidate, name))
            if input_id is not None:
                self.validate_input_candidate(input_id, prospective)
            for item in self.attack_surface_inputs.values():
                if existing.id in item.candidate_ids:
                    self.validate_input_candidate(item.id, prospective)
            merged = _merge_compatible_context(
                existing,
                candidate,
                (
                    "content_type",
                    "request_template",
                    "baseline_request_ref",
                    "auth_context_ref",
                    "source_ref",
                ),
                anchors=("baseline_request_ref", "auth_context_ref", "source_ref"),
            )
            if not merged:
                raise ValueError("candidate request context conflicts with existing candidate")
            existing.signals = list(dict.fromkeys([*existing.signals, *candidate.signals]))[
                :_MAX_SIGNALS
            ]
            for field_name in (
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

    @staticmethod
    def candidate_belongs_to_objective(
        candidate: Candidate, objective: WorkflowObjective,
    ) -> bool:
        if objective.mode == "candidate_validation":
            return candidate.id == objective.candidate_id
        if candidate.objective_id != objective.id:
            return False
        if objective.target_origin is None:
            return True
        return candidate_origin(candidate.target) == objective.target_origin

    def link_requested_goal_candidate(
        self, goal_id: str, candidate_id: str,
    ) -> RequestedGoal:
        objective = self.objective
        if objective is None:
            raise ValueError("requested goal linkage requires an active objective")
        goal = next((item for item in objective.requested_goals if item.id == goal_id), None)
        candidate = self.candidates.get(candidate_id)
        if goal is None or candidate is None:
            raise ValueError("requested goal or candidate does not exist")
        if candidate.candidate_class != goal.candidate_class:
            raise ValueError("candidate class does not match requested goal")
        if not self.candidate_belongs_to_objective(candidate, objective):
            raise ValueError("candidate does not belong to the active objective")
        if candidate_id not in goal.candidate_ids:
            goal.candidate_ids.append(candidate_id)
            if goal.status in {
                "tested_confirmed", "tested_not_confirmed", "no_candidate", "blocked", "deferred",
            }:
                goal.status = "in_progress"
                goal.reason = "A new matching objective-scoped candidate requires validation."
            if goal.status != "no_candidate":
                goal.review_artifact_ref = None
                goal.review_binding = None
        if goal.status == "no_candidate":
            # This also repairs malformed persisted state that retained the
            # disposition after linkage was added elsewhere.
            goal.status = "pending"
            goal.reason = "A matching objective-scoped candidate was added after review."
            goal.review_artifact_ref = None
            goal.review_binding = None
        return goal

    def objective_goal_candidates(self, goal: RequestedGoal) -> tuple[Candidate, ...]:
        objective = self.objective
        if objective is None:
            return ()
        return tuple(
            self.candidates[candidate_id]
            for candidate_id in goal.candidate_ids
            if candidate_id in self.candidates
            and self.candidates[candidate_id].candidate_class == goal.candidate_class
            and self.candidate_belongs_to_objective(self.candidates[candidate_id], objective)
        )

    def input_inventory_review_error(self) -> str | None:
        objective = self.objective
        if objective is None or objective.mode != "whole_target":
            return "no-candidate review requires an active whole-target objective"
        marker = self.phase_completions.get(f"{objective.id}:input_analysis")
        if marker is None or marker.target_origin != objective.target_origin:
            return "input analysis has not completed for the active objective"
        if not marker.artifact_ref:
            return "input analysis completion has no review artifact"
        inputs = self.objective_inputs()
        if not inputs and not marker.no_inputs_discovered:
            return "no-input inventory lacks an explicit input-analysis attestation"
        for item in inputs:
            if item.disposition in {"pending", "blocked"}:
                return f"input {item.id} remains {item.disposition}"
            if item.disposition == "dropped" and not _dropped_input_reviewable(item):
                return f"input {item.id} was dropped without a reviewable reason"
        return None

    def no_candidate_review_prerequisite_error(self, goal: RequestedGoal) -> str | None:
        objective = self.objective
        if objective is None or objective.mode != "whole_target":
            return "no-candidate review requires an active whole-target objective"
        if goal not in objective.requested_goals:
            return "requested goal does not belong to the active objective"
        if goal.status == "cancelled":
            return "requested goal was cancelled; a new explicit objective is required"
        inventory_error = self.input_inventory_review_error()
        if inventory_error:
            return inventory_error
        if any(
            candidate.candidate_class == goal.candidate_class
            for candidate in self.objective_candidates()
        ):
            return "a matching candidate exists; validate or disposition that candidate"
        return None

    def no_candidate_review_binding(self, goal: RequestedGoal, artifact_digest: str) -> str:
        """Bind an inventory review to bytes and objective-owned inventory."""
        objective = self.objective
        if objective is None:
            raise ValueError("no-candidate review requires an active objective")
        marker = self.phase_completions.get(f"{objective.id}:input_analysis")
        body = {
            "objective_id": objective.id, "target_origin": objective.target_origin,
            "goal_id": goal.id, "artifact_digest": artifact_digest,
            "input_analysis": marker.to_dict() if marker is not None else None,
            "inputs": [item.to_dict() for item in self.objective_inputs()],
        }
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def mark_goal_no_candidate(
        self, goal_id: str, *, artifact_ref: str, review_binding: str,
    ) -> RequestedGoal:
        objective = self.objective
        if objective is None:
            raise ValueError("no-candidate review requires an active objective")
        goal = next((item for item in objective.requested_goals if item.id == goal_id), None)
        if goal is None:
            raise ValueError("requested goal does not belong to the active objective")
        reason = self.no_candidate_review_prerequisite_error(goal)
        marker = self.phase_completions.get(f"{objective.id}:input_analysis")
        if reason:
            raise ValueError(reason)
        if marker is None or artifact_ref != marker.artifact_ref:
            raise ValueError("review artifact must match the active input-analysis completion")
        goal.status = "no_candidate"
        goal.reason = "No objective-scoped candidate was recorded; class-specific validation was not performed."
        goal.review_artifact_ref = artifact_ref
        goal.review_binding = review_binding
        return goal

    @staticmethod
    def set_requested_goal_status(
        goal: RequestedGoal,
        status: GoalStatus,
        *,
        reason: str | None = None,
    ) -> None:
        if status not in {
            "pending", "in_progress", "tested_confirmed", "tested_not_confirmed",
            "no_candidate", "blocked", "deferred", "unsupported", "cancelled",
        }:
            raise ValueError(f"unknown requested goal status: {status}")
        if status == "no_candidate":
            raise ValueError("no_candidate requires the explicit workflow review action")
        goal.status = status
        goal.reason = reason
        goal.review_artifact_ref = None
        goal.review_binding = None

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

    def is_next_phase(self, phase: WorkflowPhase) -> bool:
        objective = self.objective
        if objective is None or objective.mode != "whole_target":
            return False
        completed = self.completed_phases(objective)
        return next(
            (candidate for candidate in REQUIRED_WHOLE_TARGET_PHASES if candidate not in completed),
            None,
        ) == phase

    def phase_coverage_record(
        self, phase: WorkflowPhase, dimension: str
    ) -> PhaseCoverage | None:
        objective = self.objective
        if objective is None:
            return None
        marker = self.phase_completions.get(f"{objective.id}:{phase}")
        if marker is not None:
            return marker.coverage.get(dimension)
        return self.phase_coverage.get(
            self._phase_coverage_key(objective.id, phase), {}
        ).get(dimension)

    def needs_phase_coverage(
        self, phase: WorkflowPhase, dimension: str
    ) -> bool:
        if not self.is_next_phase(phase):
            return False
        record = self.phase_coverage_record(phase, dimension)
        return record is None or record.status in {"failed", "cancelled"}

    @staticmethod
    def _phase_coverage_key(objective_id: str, phase: WorkflowPhase) -> str:
        return f"{objective_id}:{phase}"

    def record_phase_coverage(
        self,
        phase: WorkflowPhase,
        dimension: str,
        status: PhaseCoverageStatus,
        *,
        objective_id: str,
        target_origin: str,
        reason: str | None = None,
    ) -> bool:
        objective = self.objective
        marker = PhaseCoverage(status, reason)
        if (
            objective is None
            or objective.mode != "whole_target"
            or objective.id != objective_id
            or objective.target_origin != normalize_target_origin(target_origin)
        ):
            raise ValueError("phase coverage must match the active objective and target")
        if phase not in PHASE_COVERAGE_DIMENSIONS:
            raise ValueError(f"{phase} does not require discovery coverage records")
        if dimension not in PHASE_COVERAGE_DIMENSIONS[phase]:
            raise ValueError(f"unknown {phase} coverage dimension: {dimension}")
        key = self._phase_coverage_key(objective_id, phase)
        if key in self.phase_completions:
            raise ValueError("phase coverage cannot change after phase completion")
        records = self.phase_coverage.setdefault(key, {})
        if records.get(dimension) == marker:
            return False
        records[dimension] = marker
        return True

    def _inventory_signature(self) -> str:
        return json.dumps([item.to_dict() for item in self.objective_inputs()], sort_keys=True)

    def _invalidate_inventory_reviews(self, previous: str) -> None:
        if self.objective is None or previous == self._inventory_signature():
            return
        for goal in self.objective.requested_goals:
            if goal.status == "no_candidate":
                goal.status = "pending"
                goal.reason = "Objective input inventory changed; a new review is required."
                goal.review_artifact_ref = None
                goal.review_binding = None

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
        previous = self._inventory_signature()
        existing = self.attack_surface_inputs.get(item.id)
        if existing is None:
            existing = next((row for row in self.attack_surface_inputs.values()
                             if self._media_enrichment_match(row, item, candidate=False)), None)
        prospective = deepcopy(existing or item)
        if existing is not None:
            for name in ("content_type", "sample_payload", "baseline_request_ref", "auth_context_ref", "source_ref"):
                if getattr(prospective, name) is None:
                    setattr(prospective, name, getattr(item, name))
        for candidate_id in dict.fromkeys([*prospective.candidate_ids, *item.candidate_ids]):
            candidate = self.candidates.get(candidate_id)
            if candidate is None:
                raise ValueError(f"unknown candidate: {candidate_id}")
            self._validate_input_candidate(prospective, candidate)
        if existing is not None:
            if existing.objective_id != item.objective_id:
                raise ValueError("input identity belongs to a different objective")
            merged = _merge_compatible_context(
                existing,
                item,
                ("content_type", "sample_payload", "baseline_request_ref", "auth_context_ref", "source_ref"),
                anchors=("sample_payload", "baseline_request_ref", "source_ref"),
            )
            if not merged:
                raise ValueError("input request context conflicts with existing input")
            for candidate_id in item.candidate_ids:
                if candidate_id not in existing.candidate_ids:
                    existing.candidate_ids.append(candidate_id)
            self._invalidate_inventory_reviews(previous)
            return existing, False
        self.attack_surface_inputs[item.id] = item
        self._invalidate_inventory_reviews(previous)
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
        previous = self._inventory_signature()
        if item.disposition == disposition:
            if normalized_reason:
                item.disposition_reason = normalized_reason
            self._invalidate_inventory_reviews(previous)
            return item
        transition = f"{item.disposition}>{disposition}"
        if transition not in item.disposition_transitions:
            item.disposition_transitions.append(transition)
        item.disposition = disposition
        item.disposition_reason = normalized_reason
        self._invalidate_inventory_reviews(previous)
        return item

    def validate_input_candidate(self, input_id: str, candidate: Candidate) -> AttackSurfaceInput:
        """Canonical, read-only compatibility boundary for creation and linkage."""
        item = self.attack_surface_inputs.get(input_id)
        if item is None:
            raise ValueError(f"unknown input: {input_id}")
        self._validate_input_candidate(item, candidate)
        return item

    def _validate_input_candidate(self, item: AttackSurfaceInput, candidate: Candidate) -> None:
        objective = self.objective
        if (objective is None or objective.mode != "whole_target"
                or item.objective_id != objective.id or candidate.objective_id != objective.id):
            raise ValueError("input and candidate must belong to the active objective")
        if item.target_origin != objective.target_origin or candidate_origin(candidate.target) != objective.target_origin:
            raise ValueError("input and candidate must match the active target origin")
        for name in ("method", "parameter", "location", "content_type", "baseline_request_ref", "auth_context_ref"):
            left, right = getattr(item, name), getattr(candidate, name)
            if name == "content_type":
                left, right = normalize_media_type(left), normalize_media_type(right)
            elif name == "location":
                left, right = (left.lower() if left else None), (right.lower() if right else None)
            if left is not None and (right is not None or name in {"baseline_request_ref", "auth_context_ref"}) and left != right:
                raise ValueError(f"candidate {name} conflicts with input")
        def geometry(endpoint: str) -> tuple[str, str, str]:
            url = urljoin(item.target_origin + "/", endpoint)
            parts = urlsplit(url)
            return HTTPOrigin.from_url(url).as_url(), parts.path or "/", parts.query
        for endpoint in (item.endpoint, candidate.endpoint):
            if endpoint and geometry(endpoint)[0] != item.target_origin:
                raise ValueError("endpoint origin conflicts with input")
        if item.endpoint is not None and candidate.endpoint is not None and geometry(item.endpoint) != geometry(candidate.endpoint):
            raise ValueError("candidate endpoint conflicts with input")

    def link_input_candidate(self, input_id: str, candidate_id: str) -> AttackSurfaceInput:
        candidate = self.candidates.get(candidate_id)
        if candidate is None:
            raise ValueError(f"unknown candidate: {candidate_id}")
        item = self.validate_input_candidate(input_id, candidate)
        previous = self._inventory_signature()
        if candidate_id not in item.candidate_ids:
            item.candidate_ids.append(candidate_id)
        self._invalidate_inventory_reviews(previous)
        return item

    def record_phase_completion(
        self,
        phase: WorkflowPhase,
        *,
        objective_id: str,
        target_origin: str,
        artifact_ref: str,
        no_inputs_discovered: bool = False,
        coverage: dict[str, PhaseCoverage] | None = None,
    ) -> bool:
        objective = self.objective
        marker = WorkflowPhaseCompletion(
            objective_id=objective_id,
            phase=phase,
            target_origin=target_origin,
            artifact_ref=artifact_ref,
            no_inputs_discovered=no_inputs_discovered,
            coverage=(
                dict(coverage)
                if coverage is not None
                else dict(self.phase_coverage.get(
                    self._phase_coverage_key(objective_id, phase), {}
                ))
            ),
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
        self.phase_coverage.pop(key, None)
        return True

    def progress_facts(self) -> frozenset[str]:
        """Return semantic state facts for the active whole-target objective."""
        objective = self.objective
        if objective is None or objective.mode != "whole_target":
            return frozenset()
        facts: set[str] = set()
        for goal in objective.requested_goals:
            facts.add(
                f"requested-goal:{goal.id}:{goal.status}:{','.join(sorted(goal.candidate_ids))}:"
                f"{goal.reason or ''}:{goal.review_artifact_ref or ''}"
            )
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
                facts.update(
                    f"phase-coverage:{marker.objective_id}:{marker.phase}:"
                    f"{dimension}:{item.status}:{item.reason or ''}"
                    for dimension, item in marker.coverage.items()
                )
        for key, records in self.phase_coverage.items():
            owner_id, separator, _phase = key.rpartition(":")
            if separator and owner_id == objective.id:
                facts.update(
                    f"phase-coverage-pending:{key}:{dimension}:"
                    f"{item.status}:{item.reason or ''}"
                    for dimension, item in records.items()
                )
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
        for candidate_id, fingerprint in self.persisted_findings.items():
            if candidate_id in objective_candidates:
                facts.add(f"finding:{candidate_id}:{fingerprint}")
        return frozenset(facts)

    def whole_target_status(
        self,
        *,
        target_origin: str | None,
        available_phases: frozenset[str],
        validator_classes: frozenset[str],
        coverage_sync_available: bool,
        invalid_evidence_candidate_ids: frozenset[str] = frozenset(),
        generic_eligible_candidate_ids: frozenset[str] = frozenset(),
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
        input_analysis_marker = self.phase_completions.get(
            f"{objective.id}:input_analysis"
        )
        if (
            "input_analysis" in completed
            and not objective_inputs
            and (
                input_analysis_marker is None
                or not input_analysis_marker.no_inputs_discovered
            )
        ):
            blockers.append(
                "input analysis has no recorded inputs or explicit no-input attestation"
            )
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
            if result and result.cleanup_state == "pending":
                actionable.append(f"cleanup:{candidate.id}")
            elif result and result.cleanup_state in {"failed", "requires-user-action"}:
                blockers.append(
                    f"mutation cleanup requires operator action:{candidate.id}:"
                    f"{result.cleanup_state}"
                )
            if (candidate.status in {"new", "queued", "validating"}
                    or candidate.status == "deferred" and result is None
                    and candidate.id in generic_eligible_candidate_ids):
                if candidate.candidate_class in normalized_validators or candidate.id in generic_eligible_candidate_ids:
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
            evidence_required = result.outcome == "confirmed" or bool(result.evidence_refs)
            evidence_invalid = (
                candidate.id in invalid_evidence_candidate_ids
                or (evidence_required and not self.evidence_matches(
                    candidate.id, result.evidence_refs
                ))
            )
            if evidence_invalid:
                if candidate.candidate_class in normalized_validators:
                    actionable.append(f"revalidate:{candidate.id}")
                else:
                    blockers.append(f"candidate evidence unavailable:{candidate.id}")
                continue
            if result.coverage_synced is False:
                if not candidate.endpoint:
                    blockers.append(f"coverage sync lacks candidate endpoint:{candidate.id}")
                elif coverage_sync_available:
                    actionable.append(f"coverage-sync:{candidate.id}")
                else:
                    blockers.append(f"coverage sync unavailable:{candidate.id}")
                continue
            if result.outcome == "confirmed" and not self.finding_is_persisted(
                candidate.id
            ):
                actionable.append(f"finding:{candidate.id}")

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
            if (existing and existing.objective_id == result.objective_id
                    and validation_result_fingerprint(existing) == fingerprint):
                for field_name in (
                    "cleanup_status", "cleanup_state", "deferred_reason", "notes",
                ):
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
        if result is not None and result.assessment_contract_version >= 2:
            from src.workflow.assessment import accepted_result
            candidate = self.candidates.get(candidate_id)
            if candidate is None or not accepted_result(self, candidate, result):
                return False
        return (
            result is not None
            and result.outcome == "confirmed"
            and result.coverage_synced is not False
            and self.evidence_matches(candidate_id, result.evidence_refs)
        )

    def finding_is_persisted(self, candidate_id: str) -> bool:
        """Return whether the canonical report matches the latest result."""
        result = self.latest_result(candidate_id)
        return bool(
            result is not None
            and result.outcome == "confirmed"
            and self.persisted_findings.get(candidate_id)
            == validation_result_fingerprint(result)
        )

    def mark_finding_persisted(self, candidate_id: str) -> None:
        """Record persistence only after the finding store write succeeds."""
        if not self.eligible_for_finding(candidate_id):
            raise ValueError(
                "candidate is not eligible for persisted finding registration"
            )
        result = self.latest_result(candidate_id)
        assert result is not None
        self.persisted_findings[candidate_id] = validation_result_fingerprint(result)

    def clear(self) -> None:
        self.objective = None
        self.attempts.clear()
        self.selected_sources.clear()
        self.evidence_sources.clear()
        self.candidates.clear()
        self.validation_results.clear()
        self.evidence.clear()
        self.attack_surface_inputs.clear()
        self.phase_completions.clear()
        self.phase_coverage.clear()
        self.active_candidate_ids.clear()
        self.completed_skills.clear()
        self.completed_artifacts.clear()
        self.persisted_findings.clear()
        self.current_phase = None

    def replace_from(self, other: WorkflowState) -> None:
        self.attempts = deepcopy(other.attempts)
        self.selected_sources = deepcopy(other.selected_sources)
        self.evidence_sources = deepcopy(other.evidence_sources)
        self.version = other.version
        self.objective = other.objective
        self.candidates = dict(other.candidates)
        self.validation_results = list(other.validation_results)
        self.evidence = dict(other.evidence)
        self.attack_surface_inputs = dict(other.attack_surface_inputs)
        self.phase_completions = dict(other.phase_completions)
        self.phase_coverage = {
            key: dict(records) for key, records in other.phase_coverage.items()
        }
        self.active_candidate_ids = set(other.active_candidate_ids)
        self.completed_skills = set(other.completed_skills)
        self.completed_artifacts = dict(other.completed_artifacts)
        self.persisted_findings = dict(other.persisted_findings)
        self.current_phase = other.current_phase

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "attempts": deepcopy(self.attempts),
            "selected_sources": deepcopy(self.selected_sources),
            "evidence_sources": deepcopy(self.evidence_sources),
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
            "phase_coverage": {
                key: {
                    dimension: item.to_dict()
                    for dimension, item in sorted(records.items())
                }
                for key, records in sorted(self.phase_coverage.items())
            },
            "active_candidate_ids": sorted(self.active_candidate_ids),
            "completed_skills": sorted(self.completed_skills),
            "completed_artifacts": dict(sorted(self.completed_artifacts.items())),
            "persisted_findings": dict(sorted(self.persisted_findings.items())),
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
            state.version = max(8, version)

        selected = value.get("selected_sources", {})
        if isinstance(selected, dict) and len(selected) <= 256 and len(json.dumps(selected)) <= 16 * 1024 * 1024:
            state.selected_sources = deepcopy(selected)
        raw_attempts = value.get("attempts", {})
        if isinstance(raw_attempts, dict):
            state.attempts = deepcopy({key: row for key, row in raw_attempts.items()
                                      if isinstance(key, str) and isinstance(row, dict)})
            for row in state.attempts.values():
                if row.get("status") == "active":
                    row["status"] = "interrupted"
        state.objective = WorkflowObjective.from_dict(value.get("objective"))

        raw_candidates = value.get("candidates", [])
        if isinstance(raw_candidates, dict):
            raw_candidates = list(raw_candidates.values())
        saved_statuses: dict[str, CandidateStatus] = {}
        if isinstance(raw_candidates, list):
            for raw in raw_candidates:
                if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
                    # A persisted record without an ID cannot be hydrated without
                    # inventing an identity and losing its original linkages.
                    continue
                candidate = Candidate.from_dict(raw)
                if candidate is not None:
                    # Hydration restores accepted identities; runtime enrichment
                    # may merge distinct media IDs and invalidate persisted links.
                    if candidate.id in state.candidates:
                        raise ValueError(f"duplicate persisted candidate id: {candidate.id}")
                    state.candidates[candidate.id] = candidate
                    if candidate.status in {"new", "queued", "validating"}:
                        state.active_candidate_ids.add(candidate.id)
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
        parents = value.get("evidence_sources", {})
        if isinstance(parents, dict):
            state.evidence_sources = {key: list(ids) for key, ids in parents.items()
                if key in state.evidence and isinstance(ids, list) and len(ids) <= 32
                and all(isinstance(x, str) for x in ids) and len(set(ids)) == len(ids)}
        if isinstance(raw_inputs, list):
            for raw in raw_inputs:
                if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
                    continue
                item = AttackSurfaceInput.from_dict(raw)
                if item is not None:
                    if item.id in state.attack_surface_inputs:
                        raise ValueError(f"duplicate persisted input id: {item.id}")
                    state.attack_surface_inputs[item.id] = item
        raw_phases = value.get("phase_completions", [])
        allow_legacy_coverage = (
            not isinstance(version, bool)
            and isinstance(version, int)
            and 0 < version < 4
        )
        if isinstance(raw_phases, list):
            for raw in raw_phases:
                marker = WorkflowPhaseCompletion.from_dict(
                    raw, allow_legacy_coverage=allow_legacy_coverage
                )
                if marker is not None:
                    state.phase_completions[marker.key] = marker
        raw_phase_coverage = value.get("phase_coverage", {})
        if isinstance(raw_phase_coverage, dict):
            for key, raw_records in raw_phase_coverage.items():
                if not isinstance(key, str) or not isinstance(raw_records, dict):
                    continue
                if key in state.phase_completions:
                    continue
                phase = key.rpartition(":")[2]
                allowed_dimensions = set(PHASE_COVERAGE_DIMENSIONS.get(phase, ()))
                if not allowed_dimensions:
                    continue
                records: dict[str, PhaseCoverage] = {}
                for dimension, raw_record in raw_records.items():
                    parsed = PhaseCoverage.from_dict(raw_record)
                    if (
                        isinstance(dimension, str)
                        and dimension in allowed_dimensions
                        and parsed is not None
                    ):
                        records[dimension] = parsed
                if records:
                    state.phase_coverage[key] = records
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
        persisted_findings = value.get("persisted_findings")
        if isinstance(persisted_findings, dict):
            for candidate_id, fingerprint in persisted_findings.items():
                if (
                    isinstance(candidate_id, str)
                    and candidate_id in state.candidates
                    and isinstance(fingerprint, str)
                    and len(fingerprint) == 64
                ):
                    state.persisted_findings[candidate_id] = fingerprint
        phase = value.get("current_phase")
        if isinstance(phase, str):
            state.current_phase = _text(phase, limit=80)
        if state.objective is not None:
            for goal in state.objective.requested_goals:
                if goal.status not in {"tested_confirmed", "tested_not_confirmed"}:
                    continue
                candidates = state.objective_goal_candidates(goal)
                if not candidates or len(candidates) != len(goal.candidate_ids) or any(
                    (result := state.latest_result(candidate.id)) is None
                    or result.objective_id != state.objective.id
                    or result.outcome not in {"confirmed", "not-confirmed"}
                    or not state.evidence_matches(candidate.id, result.evidence_refs)
                    for candidate in candidates
                ):
                    state.set_requested_goal_status(
                        goal, "pending", reason="Persisted terminal goal lacks valid candidate/result linkage.",
                    )
        return state


def candidate_origin(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return HTTPOrigin.from_url(value).as_url()
    except ValueError:
        return None


_DROPPED_INPUT_REVIEW_REASON_RE = re.compile(
    r"\b(?:review(?:ed)?|duplicate|out[- ]of[- ]scope|not in scope|"
    r"not applicable|no user[- ]controlled|not a valid input|false positive|"
    r"irrelevant|excluded after review)\b",
    re.IGNORECASE,
)


def _dropped_input_reviewable(item: AttackSurfaceInput) -> bool:
    return bool(item.disposition_reason and _DROPPED_INPUT_REVIEW_REASON_RE.search(
        item.disposition_reason
    ))


def is_candidate_status(value: str) -> TypeGuard[CandidateStatus]:
    return value in CANDIDATE_STATUSES


def is_validation_outcome(value: str) -> TypeGuard[ValidationOutcome]:
    return value in VALIDATION_OUTCOMES
