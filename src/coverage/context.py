"""Coverage identity projected from persisted workflow records, never authority."""
from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any
from urllib.parse import urljoin, urlsplit

from src.redact.redact import apply as redact
from src.workflow.state import (
    Candidate, ValidationResult, WorkflowState, candidate_origin,
    normalize_media_type, normalize_target_origin,
)


@dataclass(frozen=True)
class CoverageContext:
    objective_id: str | None = None
    target_origin: str | None = None
    method: str | None = None
    location: str | None = None
    media_type: str | None = None
    auth_context_ref: str | None = None
    test_case: str | None = None

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if value is not None and (not isinstance(value, str) or len(value) > 500):
                raise ValueError(f"invalid coverage context: {field.name}")
            object.__setattr__(self, field.name, redact(value.strip()) or None if value else None)
        object.__setattr__(self, "target_origin", normalize_target_origin(self.target_origin))
        object.__setattr__(self, "method", self.method.upper() if self.method else None)
        object.__setattr__(self, "location", self.location.lower() if self.location else None)
        object.__setattr__(self, "media_type", normalize_media_type(self.media_type))
        object.__setattr__(self, "test_case", self.test_case.lower() if self.test_case else None)

    @classmethod
    def parse(cls, value: Any) -> CoverageContext:
        if not isinstance(value, dict) or set(value) - {field.name for field in fields(cls)}:
            raise ValueError("coverage context must contain only identity references")
        return cls(**value)


def normalize_contextual_endpoint(endpoint: str, context: CoverageContext) -> str:
    """Keep the existing method/path display, with origin in context identity."""
    endpoint = endpoint.strip()
    if context.method and endpoint.startswith(context.method + " "):
        endpoint = endpoint[len(context.method) + 1:]
    parts = urlsplit(endpoint)
    absolute_origin = normalize_target_origin(
        urljoin(context.target_origin + "/", endpoint) if context.target_origin else endpoint
    ) if parts.netloc else None
    if absolute_origin and context.target_origin != absolute_origin:
        raise ValueError("coverage endpoint origin conflicts with context")
    if context.target_origin:
        url = urljoin(context.target_origin + "/", endpoint)
        if normalize_target_origin(url) != context.target_origin:
            raise ValueError("coverage endpoint origin conflicts with context")
        endpoint = urlsplit(url).path or "/"
    else:
        endpoint = parts.path or "/"
    return f"{context.method} {endpoint}" if context.method else endpoint


def project_candidate_coverage(
    state: WorkflowState, candidate: Candidate, result: ValidationResult,
) -> tuple[str, str, CoverageContext]:
    """Resolve canonical compatibility without accessing transient/live stores.

    Conflicting reverse links cannot prove any variant tested. Unknown fields
    stay unknown; captures, templates and baseline instances are not identity.
    """
    if (state.candidates.get(candidate.id) is not candidate
            or result.candidate_id != candidate.id):
        raise ValueError("coverage result differs from canonical candidate")
    origin = candidate_origin(candidate.target)
    objective = state.objective
    if objective is not None:
        if (objective.mode == "candidate_validation" and objective.candidate_id != candidate.id
                or objective.mode != "candidate_validation" and candidate.objective_id != objective.id):
            raise ValueError("coverage candidate differs from active objective")
        if origin is not None and objective.target_origin not in (None, origin):
            raise ValueError("coverage candidate differs from objective origin")
        origin = origin or objective.target_origin
    owners = {None, candidate.objective_id}
    if objective is not None and objective.mode == "candidate_validation":
        owners.add(objective.id)
    if result.objective_id not in owners:
        raise ValueError("coverage result differs from candidate objective")
    names = ("method", "endpoint", "parameter", "location", "content_type", "auth_context_ref")
    known: dict[str, set[str]] = {name: set() for name in names}

    def add(record: Any) -> None:
        nonlocal origin
        for name in names:
            value = getattr(record, name)
            if value is None:
                continue
            if name == "endpoint":
                parts = urlsplit(value)
                absolute_origin = normalize_target_origin(
                    urljoin(origin + "/", value) if origin else value
                ) if parts.netloc else None
                if absolute_origin:
                    if origin is not None and absolute_origin != origin:
                        raise ValueError("coverage endpoint origin conflicts with candidate")
                    origin = origin or absolute_origin
                value = urljoin(origin + "/", value) if origin else value
                parts = urlsplit(value)
                # Compatibility uses full query geometry; projection strips it
                # only after ambiguity checks, matching existing tuple semantics.
                value = (parts.path or "/") + ("?" + parts.query if parts.query else "")
            elif name == "content_type":
                value = normalize_media_type(value)
            elif name == "location":
                value = value.lower()
            if value is not None:
                known[name].add(value)

    add(candidate)
    # Reverse links are active inventory only during whole-target work. An
    # explicit retest keeps the Candidate's original owner and historical
    # links, but projects its own result owner and persisted geometry. Do not
    # enrich from historical inputs without a separate owner-safe resolver.
    if objective is not None and objective.mode == "whole_target":
        for item in state.attack_surface_inputs.values():
            if candidate.id in item.candidate_ids:
                state.validate_input_candidate(item.id, candidate)
                add(item)
    if any(len(values) > 1 for values in known.values()):
        raise ValueError("ambiguous canonical coverage context")
    resolved = {name: next(iter(values)) if values else None for name, values in known.items()}
    if not resolved["endpoint"]:
        raise ValueError("coverage sync requires a candidate endpoint")
    context = CoverageContext(
        objective_id=result.objective_id or candidate.objective_id, target_origin=origin,
        method=resolved["method"], location=resolved["location"],
        media_type=resolved["content_type"], auth_context_ref=resolved["auth_context_ref"],
        test_case=candidate.test_case,
    )
    parameter = resolved["parameter"] or "(request)"
    if context.test_case:
        parameter += f" [subcase: {context.test_case}]"
    return normalize_contextual_endpoint(resolved["endpoint"], context), parameter, context
