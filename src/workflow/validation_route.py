"""Shared route resolution. Routes narrow execution; they never grant rights."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from src.skills.registry import Registry, normalize_candidate_class
from src.target.target import Target
from src.workflow.state import Candidate, WorkflowState, normalize_target_origin

GENERIC_VALIDATOR = "generic-bounded-validation"
GENERIC_TOOLS = frozenset({"http", "workflow", "file_write", "ask_user",
                           "permissions_status", "confirm_finding"})


@dataclass(frozen=True)
class ValidationRoute:
    kind: str
    skill_name: str | None = None
    reason: str = ""


def resolve_validation_route(registry: Registry | None, candidate_class: str) -> ValidationRoute:
    canonical = normalize_candidate_class(candidate_class)
    if registry is None:
        return ValidationRoute("unavailable", reason="skill registry unavailable")
    enabled = registry.validators_for_class(canonical)
    if len(enabled) == 1:
        return ValidationRoute("expert", enabled[0].name)
    if len(enabled) > 1:
        return ValidationRoute("ambiguous", reason="ambiguous validator mapping")
    mappings = [s for s in registry.list()
                if s.stage == "validation" and canonical in s.candidate_classes]
    if mappings:
        return ValidationRoute("unavailable", reason="validator mapping disabled or manual-only")
    if registry.load_errors:
        return ValidationRoute("unavailable", reason="skill registry metadata incomplete after load failure")
    return ValidationRoute("generic", GENERIC_VALIDATOR)


def generic_admission(candidate: Candidate, state: WorkflowState, registry: Registry | None,
                      target: Target | None, policy) -> str | None:
    """Current route/provenance/scope binding, also used by stored proof review.

    This is not execution admission. The native boundary separately requires
    an enforceable proposal and controller-verified endpoint/action context.
    """
    route = resolve_validation_route(registry, candidate.candidate_class)
    if route.kind != "generic":
        return route.reason or "candidate has an expert route"
    if policy is None or not policy.validation_context_matches(state, registry, target):
        return "generic runtime restriction/policy unavailable"
    objective = state.objective
    if objective is None:
        return "generic requires a current objective"
    try:
        origin = normalize_target_origin(candidate.target)
        active = normalize_target_origin(target.base_url() if target else None)
    except ValueError:
        return "generic requires a concrete HTTP target"
    if not origin or origin != active or origin != objective.target_origin:
        return "generic candidate origin differs from current objective/active Target"
    if objective.mode == "candidate_validation":
        if objective.candidate_id != candidate.id:
            return "generic candidate differs from candidate-validation objective"
    elif candidate.objective_id != objective.id:
        return "generic candidate lacks current objective provenance"
    endpoint = candidate.endpoint or ""
    parts = urlsplit(endpoint)
    if (not parts.path.startswith("/") or "{" in endpoint or "}" in endpoint
            or parts.fragment or parts.username or parts.password
            or endpoint.startswith("//")):
        return "generic requires a concrete endpoint"
    if parts.scheme and normalize_target_origin(endpoint) != origin:
        return "generic endpoint origin differs from candidate"
    if not policy.engagement.is_in_scope(origin):
        return "generic candidate outside runtime scope"
    if objective.mode == "whole_target" and "input_analysis" not in state.completed_phases():
        return "generic candidate work requires completed discovery phases"
    return None
