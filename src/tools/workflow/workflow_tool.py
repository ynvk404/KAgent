from __future__ import annotations

import json
import hashlib
import re
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urljoin

from src.paths import project_root
from src.permission.permission import Prompter, UserControlledRefusal
from src.permission.runtime.execution import policy_for
from src.tools.execution.file import gate_sensitive_path
from src.redact.redact import apply as redact, redact_payload
from src.coverage.store import CoverageStore, CoverageStatus
from src.coverage.context import project_candidate_coverage
from src.target.target import Target
from src.workflow.state import (
    CANDIDATE_STATUSES,
    CLEANUP_STATES,
    INPUT_DISPOSITIONS,
    PHASE_COVERAGE_DIMENSIONS,
    PHASE_COVERAGE_STATUSES,
    VALIDATION_OUTCOMES,
    Candidate,
    AttackSurfaceInput,
    PhaseCoverageStatus,
    WorkflowPhase,
    ValidationResult,
    CleanupState,
    WorkflowState,
    candidate_origin,
    normalize_target_origin,
    validation_result_fingerprint,
)
from src.workflow.evidence import EvidenceArtifact, verify_evidence_reads
from src.workflow.assessment import (start_attempt, references, resolve_sources, candidate_binding,
                                     seal, accepted_result, check_excerpts)
import uuid
from src.skills.registry import (
    Registry as SkillRegistry,
    Skill,
    normalize_candidate_class,
    normalize_metadata_name,
)
from src.skills.artifacts import completion_artifact_path, resolve_canonical_artifact

from src.tools.common.outcome import ToolOutput
from src.tools.common.types import Tool, arg_bool, arg_number, arg_string
from src.workflow.validation_route import (
    GENERIC_VALIDATOR, generic_admission, resolve_validation_route,
)
from src.workflow.probe import ProbeProposal
from src.workflow.validation_context import resolve_validation_context
from src.tools.http.http_tool import HTTPTool


ACTIONS = (
    "get_input",
    "record_input",
    "set_input_disposition",
    "link_input_candidate",
    "record_candidate",
    "record_evidence",
    "start_validation",
    "record_result",
    "sync_coverage",
    "record_phase_coverage",
    "complete_skill",
    "review_no_candidate",
    "list",
)
DEFAULT_LIST_LIMIT = 8
MAX_LIST_LIMIT = 25
MAX_LIST_COMPLETED_SKILLS = 20
LIST_TEXT_LIMIT = 200
_STATUS_PRIORITY = {"validating": 0, "queued": 1, "new": 2}



class WorkflowTool(Tool):
    """Small runtime bridge between skill playbooks and structured state."""

    def __init__(
        self,
        state: WorkflowState,
        target: Target | None = None,
        coverage: CoverageStore | None = None,
        skills: SkillRegistry | None = None,
        evidence_root: Path | None = None,
        session_id: str | None = None,
        http_tool: HTTPTool | None = None,
    ) -> None:
        self.state = state
        self.target = target
        self.coverage = coverage
        self.skills = skills
        self.evidence_root = evidence_root or project_root()
        self.session_id = session_id
        self.http_tool = http_tool
        from src.permission.runtime.observations import ObservationStore
        self.observations = ObservationStore()
        self.active_attempt = None
        self.evidence_epoch = "epoch_" + uuid.uuid4().hex
        if http_tool is not None:
            http_tool.evidence_store = self.observations

    def name(self) -> str:
        return "workflow"

    def description(self) -> str:
        return (
            "get_input: sanitized details. start_validation declares attempt. "
            "record_result needs candidate_id, skill_name and outcome with primary IDs and assessment. "
            "record_evidence: immutable redacted proof. Performed phases need adapter; other states need reasons."
        )

    def schema(self) -> dict[str, Any]:
        optional_string = {"type": "string"}
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": list(ACTIONS)},
                "candidate_id": {
                    "type": "string",
                    "description": "Required for record_evidence, start_validation, and record_result.",
                },
                "goal_id": {
                    "type": "string",
                },
                "probe": ProbeProposal.schema(),
                "attempt_id": optional_string,
                "related_requests": {"type": "array", "maxItems": 16, "items": {"type": "object"},
                    "description": "At start: role (baseline/control/trigger/readback/cleanup/auxiliary), method, url, optional required."},
                "assessment": {"type": "object", "description": "Bounded hypothesis, criteria, limitations, completed_attempt, observed_impact and severity."},
                "input_id": optional_string,
                "input_type": optional_string,
                "content_type": {
                    "type": "string",
                    "maxLength": 200,
                    "description": "Observed request media type.",
                },
                "sample_payload": {
                    "type": "string",
                    "maxLength": 4000,
                    "description": "Redacted request body skeleton.",
                },
                "disposition": {"type": "string", "enum": sorted(INPUT_DISPOSITIONS)},
                "disposition_reason": optional_string,
                "candidate_class": optional_string,
                "target": {
                    "type": "string",
                    "description": "Candidate target; record_input uses runtime scope.",
                },
                "endpoint": optional_string,
                "method": optional_string,
                "parameter": optional_string,
                "location": optional_string,
                "test_case": {
                    "type": "string",
                    "description": "Stable subcase for one input.",
                },
                "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                "evidence_path": {
                    "type": "string",
                    "description": "Existing project proof file.",
                },
                "observation_ids": {"type": "array", "items": {"type": "string"},
                                    "description": "Primary runtime source IDs."},
                "signals": {"type": "array", "items": {"type": "string"}},
                "baseline_request_ref": optional_string,
                "auth_context_ref": optional_string,
                "source_ref": optional_string,
                "request_template": {
                    "type": "string",
                    "maxLength": 4000,
                    "description": "Body skeleton; mark test value {INJECTION_POINT}. Omit credentials.",
                },
                "source_skill": optional_string,
                "status": {
                    "type": "string",
                    "enum": sorted(CANDIDATE_STATUSES),
                    "description": "Candidate status; not used by record_result.",
                },
                "skill_name": {
                    "type": "string",
                },
                "outcome": {
                    "type": "string",
                    "enum": sorted(VALIDATION_OUTCOMES),
                    "description": "Required for record_result.",
                },
                "evidence_refs": {"type": "array", "items": {"type": "string"}},
                "techniques": {"type": "array", "items": {"type": "string"}},
                "repeatable": {"type": "boolean"},
                "confirmation": {
                    "type": "object",
                },
                "mutation_performed": {"type": "boolean"},
                "cleanup_status": optional_string,
                "cleanup_state": {
                    "type": "string",
                    "enum": sorted(CLEANUP_STATES),
                    "description": (
                        "Mutations default pending; cleanup requires separate authority."
                    ),
                },
                "deferred_reason": optional_string,
                "notes": optional_string,
                "force": {
                    "type": "boolean",
                    "description": "Intentional retest only.",
                },
                "no_inputs_discovered": {
                    "type": "boolean",
                    "description": (
                        "Attest that whole-target enumeration found no inputs."
                    ),
                },
                "current_phase": optional_string,
                "phase": {
                    "type": "string",
                    "enum": sorted(PHASE_COVERAGE_DIMENSIONS),
                    "description": "Phase for record_phase_coverage.",
                },
                "coverage_dimension": {
                    "type": "string",
                    "description": "Required coverage dimension for the selected phase.",
                },
                "coverage_status": {
                    "type": "string",
                    "enum": sorted(PHASE_COVERAGE_STATUSES),
                },
                "coverage_reason": {
                    "type": "string",
                    "description": "Required for non-performed coverage; observed needs source/limitation.",
                },
                "artifact_ref": {
                    "type": "string",
                    "description": "Stage output path.",
                },
                "limit": {
                    "type": "number",
                    "description": (
                        f"List size (default {DEFAULT_LIST_LIMIT}, max {MAX_LIST_LIMIT})."
                    ),
                },
            },
            "required": ["action"],
        }

    def requires_permission(self) -> bool:
        return False

    def context_reduction_policy(self) -> str:
        """Keep same-turn workflow mutations intact for the next LLM call."""
        return "preserve"

    async def run(self, args, signal, prompter):
        async with self.state.mutation_lock:
            return await self._run(args, signal, prompter)

    async def _run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str:
        policy = policy_for(prompter)
        if policy is not None:
            policy.bind_validation_context(self.state, self.skills, self.target)
        action = arg_string(args, "action")
        if (policy is not None and policy.session_id is not None and self.session_id != policy.session_id
                and action in {"start_validation", "record_evidence", "record_result"}):
            return "error: workflow/runtime session identity mismatch"
        if action == "get_input":
            result = self._get_input(args)
        elif action == "record_input":
            result = self._record_input(args)
        elif action == "set_input_disposition":
            result = self._set_input_disposition(args)
        elif action == "link_input_candidate":
            result = self._link_input_candidate(args)
        elif action == "record_candidate":
            result = self._record_candidate(args, policy)
        elif action == "record_evidence":
            result = await self._record_evidence(args, prompter, signal)
        elif action == "start_validation":
            result = await self._start_validation(args, prompter, signal)
        elif action == "record_result":
            result = await self._record_result(args, prompter, signal)
        elif action == "sync_coverage":
            policy = policy_for(prompter)
            latest = self.state.latest_result(arg_string(args, "candidate_id"))
            if latest is not None and latest.skill_name == GENERIC_VALIDATOR:
                try:
                    self._require_generic(latest.candidate_id, policy)
                except ValueError as err:
                    return self._typed_result(f"error: {err}")
            latest = self.state.latest_result(arg_string(args, "candidate_id"))
            candidate = self.state.candidates.get(arg_string(args, "candidate_id"))
            if candidate is None or not accepted_result(self.state, candidate, latest, policy):
                return self._typed_result("error: inadmissible result cannot sync tested coverage")
            assert latest is not None
            before = deepcopy(self.state.to_dict())
            stamp = policy.stamp() if policy else None
            if not await verify_evidence_reads([self.state.evidence[ref] for ref in latest.evidence_refs],
                    self.evidence_root, prompter, signal):
                return self._typed_result("error: coverage evidence changed/unavailable")
            if self.state.to_dict() != before or (policy and policy.stamp() != stamp):
                return self._typed_result("error: coverage submission changed during evidence read")
            result = await self._sync_coverage_action(args)
        elif action == "record_phase_coverage":
            if policy_for(prompter) is not None:
                objective = self.state.objective
                phase = arg_string(args, "phase")
                dimension = arg_string(args, "coverage_dimension")
                requested = arg_string(args, "coverage_status")
                if objective is None or objective.mode != "whole_target":
                    return self._typed_result("error: phase coverage requires an active whole-target objective")
                if objective.target_origin != normalize_target_origin(self._active_target()):
                    return self._typed_result("error: phase coverage must match the active objective and target")
                if phase not in PHASE_COVERAGE_DIMENSIONS:
                    return self._typed_result("error: phase must be recon or enumeration")
                if dimension not in PHASE_COVERAGE_DIMENSIONS[phase]:
                    return self._typed_result(f"error: unknown {phase} coverage dimension: {dimension}")
                if requested not in PHASE_COVERAGE_STATUSES:
                    return self._typed_result("error: coverage_status is invalid")
                existing = self.state.phase_coverage_record(
                    cast(WorkflowPhase, phase), dimension,
                )
                if existing is not None and existing.status == "performed":
                    if requested in {"performed", "observed"}:
                        completed = phase in self.state.completed_phases(objective)
                        return ToolOutput(json.dumps({
                            "ok": True, "phase": phase, "dimension": dimension,
                            "requested_status": requested, "status": "performed",
                            "changed": False, "already_recorded": True,
                            "phase_completed": completed,
                            "message": (
                                "Already recorded as performed; phase is already completed."
                                if completed else "Already recorded as performed."
                            ),
                        }), status="success")
                    return self._typed_result("error: runtime-attested performed coverage cannot be replaced by a model claim")
                if requested == "performed":
                    return self._typed_result("error: performed phase coverage requires an execution adapter observation")
            result = self._record_phase_coverage(args)
        elif action == "complete_skill":
            result = self._complete_skill(args)
        elif action == "review_no_candidate":
            result = await self._review_no_candidate(args, prompter, signal)
        elif action == "list":
            result = self._list(args, policy)
        else:
            result = f"error: action must be one of: {', '.join(ACTIONS)}"
        return self._typed_result(result)

    @staticmethod
    def _typed_result(result: str) -> str:
        """Preserve string compatibility while exposing semantic failures."""
        if result.startswith("error:"):
            return ToolOutput(result, status="error", error_kind="invalid_args")
        try:
            payload = json.loads(result)
        except (TypeError, ValueError):
            return result
        if isinstance(payload, dict) and payload.get("ok") is False:
            return ToolOutput(result, status="error", error_kind="tool_exception")
        return result

    def _record_candidate(self, args: dict[str, Any], policy=None) -> str:
        if "objective_id" in args:
            return "error: objective_id is assigned by the runtime"
        candidate_class = arg_string(args, "candidate_class")
        if not candidate_class:
            return "error: record_candidate requires candidate_class"
        candidate_target = arg_string(args, "target") or self._active_target()
        if not candidate_target:
            return "error: record_candidate requires target or an active Agent target"
        objective = self.state.objective
        objective_id: str | None = None
        requested_input_id = arg_string(args, "input_id")
        input_item = None
        if requested_input_id and (objective is None or objective.mode != "whole_target"):
            return "error: input_id requires an active whole-target objective"
        if objective is not None and objective.mode == "whole_target":
            if candidate_origin(candidate_target) != objective.target_origin:
                return "error: candidate target must match the active whole-target origin"
            objective_id = objective.id
            if requested_input_id:
                input_item = self.state.attack_surface_inputs.get(requested_input_id)
                if (
                    input_item is None
                    or input_item.objective_id != objective.id
                    or input_item.target_origin != objective.target_origin
                ):
                    return "error: input does not belong to the active whole-target objective"
        elif (
            objective is not None
            and objective.mode == "direct"
            and objective.target_origin is not None
            and candidate_origin(candidate_target) != objective.target_origin
        ):
            return "error: candidate target must match the active direct objective origin"
        validators = (
            self.skills.validators_for_class(candidate_class) if self.skills else []
        )
        route = resolve_validation_route(self.skills, candidate_class)
        supported = len(validators) == 1 if self.skills else None
        validator_resolution = "unique" if route.kind == "expert" else route.kind
        if objective is not None and objective.mode == "direct":
            objective_id = objective.id
        endpoint, method, normalization_error = self._normalize_method_endpoint(
            args.get("endpoint"), args.get("method")
        )
        if normalization_error:
            return f"error: {normalization_error}"
        try:
            candidate = Candidate(
                candidate_class=candidate_class,
                target=candidate_target,
                endpoint=(
                    endpoint if endpoint is not None
                    else input_item.endpoint if input_item is not None else None
                ),
                method=(
                    method if method is not None
                    else input_item.method if input_item is not None else None
                ),
                parameter=(
                    args.get("parameter") if args.get("parameter") is not None
                    else input_item.parameter if input_item is not None else None
                ),
                location=(
                    args.get("location") if args.get("location") is not None
                    else input_item.location if input_item is not None else None
                ),
                test_case=args.get("test_case"),
                priority=args.get("priority"),
                signals=args.get("signals", []),
                baseline_request_ref=(args.get("baseline_request_ref")
                                      if args.get("baseline_request_ref") is not None
                                      else input_item.baseline_request_ref if input_item is not None else None),
                auth_context_ref=(args.get("auth_context_ref")
                                  if args.get("auth_context_ref") is not None
                                  else input_item.auth_context_ref if input_item is not None else None),
                content_type=(
                    args.get("content_type")
                    if args.get("content_type") is not None
                    else input_item.content_type if input_item is not None else None
                ),
                request_template=(args.get("request_template")
                                  if args.get("request_template") is not None
                                  else input_item.sample_payload if input_item is not None
                                  and input_item.sample_payload and "{INJECTION_POINT}" in input_item.sample_payload
                                  else None),
                source_ref=(args.get("source_ref") if args.get("source_ref") is not None
                            else input_item.source_ref if input_item is not None else None),
                source_skill=args.get("source_skill"),
                objective_id=objective_id,
                status=("deferred" if supported is False else args.get("status", "queued")),
            )
            reason = route.reason
            if route.kind == "generic":
                reason = generic_admission(candidate, self.state, self.skills, self.target, policy)
                if reason is None:
                    assert policy is not None
                    reason = (policy.generic_validation.admission_reason(
                        policy.generic_validation.http_tool, candidate.id)
                        if candidate.id in self.state.candidates else
                        "generic context-needed: concrete proposal and verified endpoint/action context required")
                supported = reason is None
                candidate.status = "queued" if supported else "deferred"
            elif route.kind != "expert" and self.skills is not None:
                candidate.status = "deferred"
            stored, created = self.state.add_candidate(candidate, input_id=requested_input_id or None)
            input_id = arg_string(args, "input_id")
            if input_id:
                self.state.link_input_candidate(input_id, stored.id)
            if objective is not None and objective.mode in {"direct", "whole_target"}:
                for goal in objective.requested_goals:
                    if goal.candidate_class == stored.candidate_class:
                        self.state.link_requested_goal_candidate(goal.id, stored.id)
            if not created and self.skills and self.state.latest_result(stored.id) is None:
                if supported is False and stored.status in {"new", "queued"}:
                    stored = self.state.set_candidate_status(stored.id, "deferred")
                elif supported and route.kind == "expert" and stored.status == "deferred":
                    stored = self.state.set_candidate_status(stored.id, "queued")
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        phase = arg_string(args, "current_phase")
        if phase:
            self.state.current_phase = phase[:80]
        return json.dumps(
            {
                "ok": True,
                "created": created,
                "candidate": stored.to_dict(),
                "supported": supported,
                "validator_resolution": validator_resolution,
                "validator_reason": reason,
                "recommended_skills": [skill.name for skill in validators],
                "proof_source_path": (
                    str(policy.generic_validation.proof_path(stored).relative_to(policy.root))
                    if validator_resolution == "generic" and policy is not None else None
                ),
            },
            indent=2,
        )

    def _get_input(self, args: dict[str, Any]) -> str:
        input_id = arg_string(args, "input_id")
        if not input_id:
            return "error: get_input requires exact input_id"
        item = self.state.attack_surface_inputs.get(input_id)
        if item is None:
            return f"error: unknown input: {input_id}"
        objective = self.state.objective
        if objective is None or item.objective_id != objective.id:
            return "error: input does not belong to the active objective"
        active_origin = candidate_origin(self._active_target())
        if (item.target_origin != objective.target_origin
                or active_origin is None or item.target_origin != active_origin):
            return "error: input does not belong to the active target origin"
        if item.endpoint and candidate_origin(urljoin(item.target_origin + "/", item.endpoint)) != active_origin:
            return "error: input endpoint does not belong to the active target origin"
        # Constructors enforce canonical redaction and the 4000-character
        # sample bound. This opt-in read never hydrates runtime captures.
        return json.dumps({"ok": True, "input": item.to_dict()}, indent=2)

    def _record_input(self, args: dict[str, Any]) -> str:
        objective = self.state.objective
        if objective is None or objective.mode != "whole_target":
            return "error: record_input requires an active whole-target objective"
        supplied_objective_id = args.get("objective_id")
        if supplied_objective_id and supplied_objective_id != objective.id:
            return (
                "error: objective_id is assigned by the runtime and does not "
                "match the active whole-target objective"
            )
        if self.target is None or self.target.empty():
            return "error: record_input requires an active target"
        target_origin = normalize_target_origin(self.target.base_url())
        if target_origin != objective.target_origin:
            return "error: active target does not match the whole-target objective"
        supplied_origin = args.get("target_origin") or args.get("target")
        if supplied_origin:
            try:
                supplied_target_origin = normalize_target_origin(str(supplied_origin))
            except ValueError as err:
                return f"error: {err}"
            if supplied_target_origin != target_origin:
                return "error: supplied target does not match the active whole-target origin"
        endpoint, method, normalization_error = self._normalize_method_endpoint(
            args.get("endpoint"), args.get("method")
        )
        if normalization_error:
            return f"error: {normalization_error}"
        try:
            item = AttackSurfaceInput(
                objective_id=objective.id,
                target_origin=target_origin or "",
                method=method,
                endpoint=endpoint,
                parameter=args.get("parameter"),
                location=args.get("location"),
                input_type=args.get("input_type"),
                content_type=args.get("content_type"),
                sample_payload=args.get("sample_payload"),
                baseline_request_ref=args.get("baseline_request_ref"),
                auth_context_ref=args.get("auth_context_ref"),
                source_ref=args.get("source_ref"),
            )
            stored, created = self.state.add_attack_surface_input(item)
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "created": created, "input": stored.to_dict()}, indent=2)

    @staticmethod
    def _normalize_method_endpoint(
        endpoint: Any,
        method: Any,
    ) -> tuple[Any, Any, str | None]:
        """Accept a common ``GET /path`` shorthand without storing it twice."""
        if not isinstance(endpoint, str):
            return endpoint, method, None
        match = re.match(
            r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S.*)$",
            endpoint,
            re.IGNORECASE,
        )
        if match is None:
            return endpoint, method, None
        prefixed_method = match.group(1).upper()
        explicit_method = str(method).strip().upper() if method else ""
        if explicit_method and explicit_method != prefixed_method:
            return endpoint, method, "endpoint method prefix conflicts with method"
        return match.group(2).strip(), prefixed_method, None

    def _set_input_disposition(self, args: dict[str, Any]) -> str:
        try:
            item = self.state.set_input_disposition(
                arg_string(args, "input_id"),
                arg_string(args, "disposition"),  # type: ignore[arg-type]
                reason=arg_string(args, "disposition_reason") or None,
            )
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "input": item.to_dict()}, indent=2)

    def _link_input_candidate(self, args: dict[str, Any]) -> str:
        try:
            item = self.state.link_input_candidate(
                arg_string(args, "input_id"), arg_string(args, "candidate_id")
            )
        except ValueError as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "input": item.to_dict()}, indent=2)

    async def _start_validation(self, args: dict[str, Any], prompter: Prompter, signal: Any) -> str:
        candidate_id = arg_string(args, "candidate_id")
        try:
            self._validate_current_objective_candidate(candidate_id)
            objective = self.state.objective
            candidate = self.state.candidates.get(candidate_id)
            if candidate is None:
                raise ValueError(f"unknown candidate: {candidate_id}")
            policy = policy_for(prompter)
            if policy is not None:
                policy.generic_validation.idle()
                if any(c.id != candidate_id and c.status == "validating"
                       for c in policy.generic_validation.candidates()):
                    raise ValueError("another generic validation attempt is active")
            generic = self._is_generic(candidate)
            if generic:
                self._require_generic(candidate_id, policy)
                assert policy is not None
                assert objective is not None
                boundary = policy.generic_validation
                admitted = boundary.admit_probe(boundary.http_tool, candidate_id, args.get("probe"))
                if any(c.id != candidate_id and c.status == "validating"
                       for c in self.state.candidates.values()):
                    raise ValueError("another validation attempt is active")
                running_retest = (candidate.status == "validating"
                    and boundary.started_candidate == candidate.id
                    and objective is not None and boundary.started_objective == objective.id)
                needs_retest = (self.state.latest_result(candidate_id) is not None and not running_retest
                                or candidate.status in {"dismissed", "validated"})
                if needs_retest:
                    if objective is None or objective.id not in boundary.retest_objectives:
                        raise ValueError("generic terminal/deferred candidate requires an explicit candidate retest")
                if running_retest and boundary.attempt != admitted:
                    raise ValueError("generic active proposal cannot change without explicit retest")
            elif self.skills is not None:
                self._require_unique_validator(candidate.candidate_class)
            elif policy is not None:
                raise ValueError("skill registry unavailable for validator resolution")
            latest = self.state.latest_result(candidate_id)
            if (
                not generic and objective is not None
                and objective.mode == "whole_target"
                and latest is not None
                and latest.outcome in {"confirmed", "not-confirmed"}
                and candidate.status not in {"queued", "validating"}
            ):
                evidence_required = latest.outcome == "confirmed" or bool(
                    latest.evidence_refs
                )
                evidence_invalid = evidence_required and not self.state.evidence_matches(
                    candidate_id, latest.evidence_refs,
                )
                if evidence_required and not evidence_invalid:
                    # Evidence permission can yield. Do not commit against the
                    # pre-await records if canonical state or runtime ownership
                    # changed. Capture/auth availability is read only afterwards.
                    before = deepcopy(self.state.to_dict())
                    policy_stamp = policy.stamp() if policy else None
                    target_revision = self.target.revision if self.target is not None else None
                    route = resolve_validation_route(self.skills, candidate.candidate_class)
                    evidence_invalid = not await verify_evidence_reads([
                        self.state.evidence[reference]
                        for reference in latest.evidence_refs
                        if reference in self.state.evidence
                    ], self.evidence_root, prompter, signal)
                    if (self.state.objective is not objective
                            or self.state.candidates.get(candidate_id) is not candidate
                            or self.state.to_dict() != before
                            or (self.target.revision if self.target is not None else None) != target_revision
                            or resolve_validation_route(self.skills, candidate.candidate_class) != route
                            or policy_for(prompter) is not policy
                            or (policy and policy.stamp() != policy_stamp)):
                        raise ValueError("validation state changed during evidence read; retry start_validation")
                if latest.assessment_contract_version >= 2:
                    evidence_invalid = evidence_invalid or not accepted_result(self.state, candidate, latest, policy)
                if not evidence_invalid:
                    raise ValueError(
                        "terminal candidate cannot be reopened during whole-target continuation; "
                        "request an explicit candidate retest or repair its missing/invalid evidence"
                    )
            # No await from the final checks/observation through bookkeeping
            # and response serialization. This is an event-loop boundary, not
            # a turn-wide lock or a guarantee for the later HTTP invocation.
            self._validate_current_objective_candidate(candidate_id)
            if policy is not None:
                if not policy.validation_context_matches(self.state, self.skills, self.target):
                    raise ValueError("validation runtime context changed during evidence read")
                policy.generic_validation.idle()
                if any(c.id != candidate_id and c.status == "validating"
                       for c in policy.generic_validation.candidates()):
                    raise ValueError("another generic validation attempt is active")
            runtime_http = self.http_tool or (policy.generic_validation.http_tool if policy is not None else None)
            context = resolve_validation_context(
                self.state, candidate_id, target=self._active_target() or None, http_tool=runtime_http,
            ).to_dict()
            attempt = start_attempt(self.state, candidate, self.session_id,
                policy.engagement.http_permissions.epoch if policy else self.evidence_epoch,
                requests=args.get("related_requests"), criteria=args.get("assessment"), target_origin=self._active_target() or None, target_revision=self.target.revision if self.target else None)
            self.active_attempt = attempt["id"]
            from src.workflow.assessment import attempt_owner
            self.observations.owner_provider = lambda: attempt_owner(self.state, self.active_attempt,
                self.evidence_epoch, self.target.revision if self.target else None, self.session_id)
            if policy is not None:
                policy.generic_validation.durable_attempt = attempt["id"]
            context["attempt_id"] = attempt["id"]
            if generic:
                assert policy is not None
                assert objective is not None
                context["probe_intent"] = {
                    "observation": admitted.proposal.observation,
                    "capture": admitted.proposal.capture,
                    "stop": admitted.proposal.stop,
                    "input_path": admitted.proposal.input_path,
                    "occurrence": admitted.proposal.occurrence,
                }
                if needs_retest:
                    boundary.retest_objectives.discard(objective.id)
                boundary.started_candidate = candidate.id
                boundary.started_objective = objective.id
                boundary.attempt = admitted
                boundary.expert_attempt = None
            candidate = self.state.set_candidate_status(candidate_id, "validating")
            if not generic and policy is not None and objective is not None:
                policy.generic_validation.select_expert(candidate)
        except ValueError as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "candidate": candidate.to_dict(),
            "validation_context": context,
            "validator_resolution": "generic" if generic else "unique",
            "proof_source_path": (
                str(policy.generic_validation.proof_path(candidate).relative_to(policy.root))
                if generic and policy is not None else None
            )}, indent=2)

    async def _record_evidence(self, args: dict[str, Any], prompter: Prompter, signal: Any) -> str:
        candidate_id = arg_string(args, "candidate_id")
        if candidate_id not in self.state.candidates:
            return f"error: unknown candidate: {candidate_id}"
        try:
            self._validate_current_objective_candidate(candidate_id)
            policy = policy_for(prompter)
            candidate = self.state.candidates[candidate_id]
            identity = candidate_binding(candidate)
            objective = self.state.objective
            target_revision = self.target.revision if self.target else None
            route = resolve_validation_route(self.skills, candidate.candidate_class)
            policy_stamp = policy.stamp() if policy else None
            generic = self._is_generic(candidate)
            snapshot = None
            if generic:
                self._require_generic(candidate_id, policy)
                assert policy is not None
                snapshot = policy.generic_validation.snapshot(candidate_id)
        except ValueError as err:
            return f"error: {err}"
        path = arg_string(args, "evidence_path")
        if not path:
            return "error: record_evidence requires evidence_path"
        try:
            source = self.evidence_root.resolve() / path
            if not source.resolve().is_relative_to(self.evidence_root.resolve()):
                raise ValueError("evidence path must stay inside the project")
            if generic:
                assert policy is not None
                if source.absolute() != policy.generic_validation.proof_path(candidate):
                    raise ValueError("generic evidence source restricted to candidate proof.md")
            real = await gate_sensitive_path(prompter, str(source), "read evidence source", signal)
            if (self.state.candidates.get(candidate_id) is not candidate
                    or candidate_binding(candidate) != identity or self.state.objective is not objective
                    or (self.target.revision if self.target else None) != target_revision
                    or resolve_validation_route(self.skills, candidate.candidate_class) != route
                    or policy_for(prompter) is not policy or (policy and policy.stamp() != policy_stamp)):
                raise ValueError("candidate/objective/route/policy changed during evidence read")
            artifact = EvidenceArtifact.capture_immutable_snapshot(
                candidate_id, real, self.evidence_root, sensitive_read_approved=True,
                original_path=str(source),
            )
            if snapshot is not None:
                assert policy is not None
                policy.generic_validation.unchanged(candidate_id, snapshot)
            if "source_kind" in args or "assessment_source" in args:
                raise ValueError("proof file provenance cannot be promoted by model labels")
            ids = references(args.get("observation_ids", []), "observation_ids")
            aid = policy.generic_validation.durable_attempt if policy else self.active_attempt
            selected = resolve_sources(policy, self.state, candidate, self.state.attempts.get(aid) if aid is not None else None, ids,
                terminal=False, negative=False, store=self.observations) if ids else []
            if ids:
                previous = self.state.evidence_sources.get(artifact.id)
                if previous is not None and previous != ids:
                    raise ValueError("immutable derived evidence source association changed")
            self.state.add_evidence(artifact)
            if ids:
                self.state.evidence_sources[artifact.id] = ids
            for entry in selected:
                self.state.selected_sources[entry["source"]["id"]] = entry
            while len(self.state.selected_sources) > 256 or len(json.dumps(self.state.selected_sources)) > 16 * 1024 * 1024:
                del self.state.selected_sources[next(iter(self.state.selected_sources))]
        except UserControlledRefusal:
            raise
        except (OSError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "evidence": artifact.to_dict(), "evidence_kind": "derived", "primary_parents": ids}, indent=2)

    async def _record_result(self, args: dict[str, Any], prompter: Prompter, signal: Any) -> str:
        try:
            for reserved in ("assessment_source", "assessment_contract_version", "result_id", "assessment_binding", "evidence_manifest", "candidate_binding", "source_kind", "session_id", "objective_id"):
                if reserved in args:
                    raise ValueError("assessment authority/identity fields are controller-owned")
            refs = references(args.get("evidence_refs", []), "evidence_refs", 16)
            ids = references(args.get("observation_ids", []), "observation_ids")
            result = ValidationResult(
                candidate_id=arg_string(args, "candidate_id"),
                skill_name=arg_string(args, "skill_name"),
                outcome=arg_string(args, "outcome"),  # type: ignore[arg-type]
                evidence_refs=refs,
                techniques=args.get("techniques", []),
                repeatable=args.get("repeatable"),
                confirmation=args.get("confirmation"),
                mutation_performed=arg_bool(args, "mutation_performed"),
                cleanup_status=args.get("cleanup_status"),
                cleanup_state=args.get("cleanup_state"),
                deferred_reason=args.get("deferred_reason"),
                notes=args.get("notes"),
                recorded_at=datetime.now(UTC).isoformat(),
                session_id=self.session_id,
                objective_id=(self.state.objective.id if self.state.objective else None),
            )
            candidate = self.state.candidates.get(result.candidate_id)
            if candidate is None:
                raise ValueError(f"unknown candidate: {result.candidate_id}")
            self._validate_current_objective_candidate(result.candidate_id)
            generic = result.skill_name == GENERIC_VALIDATOR or self._is_generic(candidate)
            policy = policy_for(prompter)
            before = deepcopy(self.state.to_dict())
            candidate_object = candidate
            target_revision = self.target.revision if self.target else None
            route_before = resolve_validation_route(self.skills, candidate.candidate_class)
            policy_stamp = policy.stamp() if policy else None
            snapshot = None
            if generic:
                self._require_generic(candidate.id, policy)
                assert policy is not None
                policy.generic_validation.idle()
                if result.skill_name != GENERIC_VALIDATOR:
                    raise ValueError("generic result requires reserved validator identifier")
                if result.mutation_performed:
                    raise ValueError("generic mutation/impact validation unavailable")
                snapshot = policy.generic_validation.snapshot(candidate.id)
            if not generic and result.outcome == "confirmed" and not result.evidence_refs:
                raise ValueError("confirmed result requires an evidence reference")
            if result.evidence_refs and not self.state.evidence_matches(result.candidate_id, result.evidence_refs):
                raise ValueError("evidence references must resolve to this candidate")
            evidence_binding = [self.state.evidence[ref].to_dict() for ref in result.evidence_refs]
            if result.evidence_refs and not await verify_evidence_reads(
                [self.state.evidence[ref] for ref in result.evidence_refs],
                self.evidence_root, prompter, signal,
            ):
                raise ValueError("evidence artifact changed or is unavailable")
            skill = self.skills.get(result.skill_name) if self.skills else None
            if not generic and self.skills is not None:
                validator = self._require_unique_validator(candidate.candidate_class)
                if result.skill_name != validator.name:
                    raise ValueError(
                        "result skill must be the unique validator for candidate class"
                    )
            elif skill and skill.candidate_classes and candidate.candidate_class not in skill.candidate_classes:
                raise ValueError("result skill does not handle candidate class")
            terminal = result.outcome in {"confirmed", "not-confirmed"}
            aid = policy.generic_validation.durable_attempt if policy is not None else self.active_attempt
            attempt = self.state.attempts.get(aid) if aid is not None else None
            # A closed selector is retained for same-revision retries. It is
            # not an execution owner for a different, unstarted Candidate.
            if (attempt is not None and attempt.get("candidate_id") != candidate.id
                    and attempt.get("status") != "active"
                    and args.get("attempt_id") is None and not ids):
                aid, attempt = None, None
            if attempt is not None and (
                    attempt.get("candidate_binding") != candidate_binding(candidate)
                    or attempt.get("session_id") != self.session_id
                    or attempt.get("objective_id") != result.objective_id
                    or attempt.get("epoch") != (policy.engagement.http_permissions.epoch if policy else self.evidence_epoch)
                    or attempt.get("target_revision") != (self.target.revision if self.target else None)
                    or (attempt.get("status") == "active" and attempt.get("result_position") != sum(r.candidate_id == candidate.id for r in self.state.validation_results))):
                raise ValueError("stale active attempt ownership/epoch/target/result position")
            if args.get("attempt_id") is not None and args["attempt_id"] != aid:
                raise ValueError("stale/wrong attempt identity")
            latest = self.state.latest_result(candidate.id)
            # A transport retry/cleanup update preserves the exact revision.
            # An explicit new start has a different attempt and never dedups.
            retry_fields = ("outcome", "skill_name", "evidence_refs", "techniques", "repeatable",
                            "confirmation", "mutation_performed")
            if (latest is not None and latest.assessment_contract_version >= 2
                    and not arg_bool(args, "force")
                    and latest.session_id == self.session_id and latest.objective_id == result.objective_id
                    and latest.candidate_binding == candidate_binding(candidate)
                    and latest.attempt_id == aid and (attempt is None or attempt.get("status") != "active")
                    and all(getattr(latest, key) == getattr(result, key) for key in retry_fields)):
                expected_ids = [entry["source"]["id"] for entry in latest.evidence_manifest]
                expected_assessment = {k: v for k, v in latest.assessment.items() if k not in {"artifacts", "artifact_sources", "attempt"}}
                if ids != expected_ids or args.get("assessment", {}) != expected_assessment:
                    raise ValueError("closed attempt assessment changed; start an explicit retest")
                if self.state.to_dict() != before or latest.assessment_binding != seal(latest):
                    raise ValueError("stale retry assessment")
                if terminal and not accepted_result(self.state, candidate, latest, policy):
                    raise ValueError("retry assessment evidence unavailable")
                latest.cleanup_status, latest.cleanup_state = result.cleanup_status, result.cleanup_state
                self.state.set_candidate_status(candidate.id, "validated" if terminal else "deferred")
                if latest.coverage_synced is False:
                    await self._sync_coverage(candidate, latest)
                return json.dumps({"ok": True, "created": False, "result": latest.public_dict(),
                    "eligible_for_confirm_finding": self.state.eligible_for_finding(candidate.id),
                    "coverage_sync": "synced" if latest.coverage_synced else "not-pending"})
            if terminal and (not attempt or attempt.get("status") != "active"):
                raise ValueError("terminal assessment requires successful start_validation")
            assessment = args.get("assessment", {})
            if not isinstance(assessment, dict) or len(json.dumps(assessment)) > 6000:
                raise ValueError("assessment must be a bounded object")
            if set(assessment) & {"artifacts", "artifact_sources", "attempt", "assessment_source", "assessment_binding"}:
                raise ValueError("assessment provenance/binding fields are controller-owned")
            if terminal:
                if not refs:
                    raise ValueError("both terminal outcomes require registered evidence")
                if not all(isinstance(assessment.get(key), str) and assessment[key].strip()
                           for key in ("hypothesis", "criteria", "limitations", "observed_impact", "severity")):
                    raise ValueError("terminal assessment requires hypothesis, criteria, limitations, observed_impact, severity")
                if assessment["severity"] not in {"info", "low", "medium", "high", "critical"}:
                    raise ValueError("invalid assessment severity")
                if result.outcome == "not-confirmed" and assessment.get("completed_attempt") is not True:
                    raise ValueError("negative assessment requires declared completed bounded attempt")
                if generic and (attempt is None or not isinstance(attempt.get("criteria"), dict)
                        or not all(isinstance(attempt["criteria"].get(k), str) and attempt["criteria"][k].strip()
                                   for k in ("hypothesis", "criteria", "limitations"))):
                    raise ValueError("generic fallback lacks declared criteria; submit unresolved")
            manifest = resolve_sources(policy, self.state, candidate, attempt, ids,
                terminal=terminal, negative=result.outcome == "not-confirmed", store=self.observations)
            check_excerpts(assessment, manifest)
            if terminal and not any(e["source"]["source_kind"] in {"native-http", "imported-capture"}
                    and e["source"].get("complete") and not e["source"].get("truncated")
                    and e["source"].get("execution_status") == "completed" for e in manifest):
                raise ValueError("tool output claims alone cannot establish target request/response evidence")
            if (self.state.to_dict() != before or self.state.candidates.get(candidate.id) is not candidate_object
                    or (self.target.revision if self.target else None) != target_revision
                    or resolve_validation_route(self.skills, candidate.candidate_class) != route_before
                    or policy_for(prompter) is not policy or (policy and policy.stamp() != policy_stamp)):
                raise ValueError("candidate/objective/route/policy changed during result submission")
            if any(not self.state.evidence[ref].is_available_for_resume(self.evidence_root) for ref in refs):
                raise ValueError("evidence integrity changed during result submission")
            if any(parent not in ids for ref in refs for parent in self.state.evidence_sources.get(ref, [])):
                raise ValueError("derived evidence requires its declared primary source parents")
            # Sources are checked again after every evidence permission await.
            result.assessment_contract_version = 2
            result.assessment_source = "agent"
            result.result_id = "result_" + uuid.uuid4().hex
            result.attempt_id = aid
            result.candidate_binding = candidate_binding(candidate)
            result.evidence_manifest = manifest
            result.assessment = {**cast(dict, redact_payload(assessment)), "artifacts": evidence_binding,
                                 "artifact_sources": {ref: list(self.state.evidence_sources.get(ref, [])) for ref in refs},
                                 "attempt": {k:v for k,v in attempt.items() if k != "status"} if attempt else None}
            result.assessment_binding = seal(result)
            coverage_status = self._coverage_status(result)
            if self.coverage is not None and coverage_status:
                result.coverage_synced = False
            if snapshot is not None:
                assert policy is not None
                policy.generic_validation.idle()
                policy.generic_validation.unchanged(candidate.id, snapshot)
                if evidence_binding != [self.state.evidence[ref].to_dict() if ref in self.state.evidence else None
                                        for ref in result.evidence_refs]:
                    raise ValueError("generic evidence ownership/identity changed during result verification")
                if any(not self.state.evidence[ref].is_available_for_resume(self.evidence_root)
                       for ref in result.evidence_refs):
                    raise ValueError("generic evidence integrity changed during result verification")
            if attempt is not None:
                attempt["status"] = "completed" if terminal else "unresolved"
            created = self.state.add_validation_result(
                result,
                force=arg_bool(args, "force"),
            )
            stored = self.state.latest_result(result.candidate_id)
            assert stored is not None
            if generic:
                assert policy is not None
                policy.generic_validation.started_candidate = None
                policy.generic_validation.started_objective = None
                policy.generic_validation.attempt = None
            elif (policy is not None and policy.generic_validation.expert_attempt is not None
                  and policy.generic_validation.expert_attempt[0] == candidate.id):
                policy.generic_validation.expert_attempt = None
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        sync_error: str | None = None
        if stored.coverage_synced is False:
            try:
                await self._sync_coverage(candidate, stored)
            except (OSError, ValueError) as err:
                sync_error = str(err)
        return json.dumps(
            {
                "ok": True,
                "created": created,
                "eligible_for_confirm_finding": self.state.eligible_for_finding(
                    result.candidate_id
                ),
                "coverage_status": coverage_status if self.coverage is not None else None,
                "coverage_sync": "pending" if stored.coverage_synced is False else (
                    "synced" if stored.coverage_synced else "not-applicable"
                ),
                "coverage_error": sync_error,
                "result": stored.public_dict(),
            },
            indent=2,
        )

    @staticmethod
    def _coverage_status(result: ValidationResult) -> CoverageStatus | None:
        if result.outcome == "confirmed":
            return "failed"
        if result.outcome == "not-confirmed":
            return "passed"
        return None

    async def _sync_coverage(self, candidate: Candidate, result: ValidationResult) -> None:
        from src.permission.runtime.execution import current_policy
        policy = current_policy()
        if not accepted_result(self.state, candidate, result, policy):
            raise ValueError("inadmissible current assessment; coverage remains pending")
        if any(not self.state.evidence[ref].is_available_for_resume(self.evidence_root) for ref in result.evidence_refs):
            raise ValueError("coverage evidence integrity unavailable; coverage remains pending")
        if self.coverage is None:
            return
        status = self._coverage_status(result)
        if status is None:
            return
        endpoint, parameter, context = project_candidate_coverage(self.state, candidate, result)
        active_origin = candidate_origin(self._active_target())
        if active_origin is not None and context.target_origin not in (None, active_origin):
            raise ValueError("coverage candidate differs from active target origin")
        target_revision = self.target.revision if self.target is not None else None
        fingerprint = validation_result_fingerprint(result)
        previous = deepcopy(await self.coverage.get(endpoint=endpoint, param=parameter,
            vulnClass=candidate.candidate_class, context=context))
        if (self.state.latest_result(candidate.id) is not result
                or not accepted_result(self.state, candidate, result, policy)
                or any(not self.state.evidence[ref].is_available_for_resume(self.evidence_root) for ref in result.evidence_refs)):
            raise ValueError("canonical assessment changed before coverage persistence")
        legacy_observation_ids = tuple(
            validation_result_fingerprint(previous)
            for previous in self.state.validation_results
            if previous.candidate_id == candidate.id
        )
        await self.coverage.ensure_validation_mark(
            endpoint=endpoint,
            param=parameter,
            vulnClass=candidate.candidate_class,
            status=status,
            notes=f"result={fingerprint[:20]}",
            observation_id=f"candidate:{candidate.id}",
            legacy_observation_ids=legacy_observation_ids,
            context=context,
        )
        # Loading/flushing the projection may yield. A durable historical row
        # cannot mark a replaced or changed canonical outcome/context synced.
        if (self.state.latest_result(candidate.id) is not result
                or validation_result_fingerprint(result) != fingerprint
                or project_candidate_coverage(self.state, candidate, result) != (endpoint, parameter, context)
                or (self.target.revision if self.target is not None else None) != target_revision
                or not accepted_result(self.state, candidate, result, policy)
                or any(not self.state.evidence[ref].is_available_for_resume(self.evidence_root) for ref in result.evidence_refs)):
            await self.coverage.rollback_validation_projection(endpoint=endpoint, param=parameter,
                vulnClass=candidate.candidate_class, context=context,
                expected_notes=f"result={fingerprint[:20]}", previous=previous)
            raise ValueError("canonical coverage context changed during persistence; retry sync")
        result.coverage_synced = True

    async def _sync_coverage_action(self, args: dict[str, Any]) -> str:
        candidate_id = arg_string(args, "candidate_id")
        candidate = self.state.candidates.get(candidate_id)
        result = self.state.latest_result(candidate_id)
        if candidate is None or result is None:
            return f"error: no validation result for candidate: {candidate_id}"
        try:
            self._validate_current_objective_candidate(candidate_id)
        except ValueError as err:
            return f"error: {err}"
        if result.coverage_synced is not False:
            return json.dumps({"ok": True, "coverage_sync": "not-pending"})
        try:
            await self._sync_coverage(candidate, result)
        except (OSError, ValueError) as err:
            return json.dumps({"ok": False, "coverage_sync": "pending", "error": str(err)})
        return json.dumps({"ok": True, "coverage_sync": "synced"})

    def _complete_skill(self, args: dict[str, Any]) -> str:
        skill_name = arg_string(args, "skill_name")
        if not skill_name:
            return "error: complete_skill requires skill_name"
        canonical = normalize_metadata_name(skill_name)[:80]
        if canonical == GENERIC_VALIDATOR:
            return "error: generic validator is an internal result identifier, not a skill"
        artifact_ref = arg_string(args, "artifact_ref")
        skill = self.skills.get(canonical) if self.skills else None
        objective = self.state.objective
        workflow_phase = (
            self._phase_for_skill(canonical, skill)
            if objective is not None and objective.mode == "whole_target" else None
        )
        if workflow_phase is not None:
            readiness = self.phase_completion_readiness(
                canonical,
                artifact_ref=artifact_ref or None,
                no_inputs_discovered=arg_bool(args, "no_inputs_discovered"),
            )
            if not readiness["ready"]:
                return f"error: {readiness['reason']}"
            artifact_ref = readiness["artifact_ref"]
            phase_coverage = self.state.phase_coverage.get(
                f"{objective.id}:{workflow_phase}", {}  # type: ignore[union-attr]
            )
            try:
                self.state.record_phase_completion(
                    workflow_phase,
                    objective_id=objective.id,  # type: ignore[union-attr]
                    target_origin=objective.target_origin or "",  # type: ignore[union-attr]
                    artifact_ref=artifact_ref,
                    coverage={
                        key: phase_coverage[key]
                        for key in PHASE_COVERAGE_DIMENSIONS.get(workflow_phase, ())
                    },
                    no_inputs_discovered=(
                        workflow_phase == "input_analysis"
                        and arg_bool(args, "no_inputs_discovered")
                    ),
                )
            except ValueError as err:
                return f"error: {err}"
        elif skill and skill.completion_artifact:
            target = self._active_target()
            try:
                expected = completion_artifact_path(skill.completion_artifact, target)
                artifact = resolve_canonical_artifact(self.evidence_root, expected)
            except ValueError as err:
                return f"error: {err}"
            if artifact_ref:
                try:
                    supplied = resolve_canonical_artifact(
                        self.evidence_root, artifact_ref
                    )
                except ValueError as err:
                    return f"error: {err}"
                if supplied != artifact:
                    return f"error: {canonical} completion requires {expected}"
            try:
                artifact_ready = artifact.is_file() and artifact.stat().st_size > 0
            except OSError:
                artifact_ready = False
            if not artifact_ready:
                return f"error: {canonical} completion requires {expected}"
            artifact_ref = expected
        self.state.completed_skills.add(canonical)
        if artifact_ref:
            self.state.completed_artifacts[canonical] = redact(artifact_ref)[:500]
        display_phase = arg_string(args, "current_phase")
        if display_phase:
            self.state.current_phase = display_phase[:80]
        return json.dumps({
            "ok": True, "skill_name": canonical,
            "phase": workflow_phase,
            "artifact_ref": self.state.completed_artifacts.get(canonical),
        }, indent=2)

    async def _review_no_candidate(self, args: dict[str, Any], prompter: Prompter, signal: Any) -> str:
        objective = self.state.objective
        goal_id = arg_string(args, "goal_id")
        if objective is None or objective.mode != "whole_target":
            return "error: review_no_candidate requires an active whole-target objective"
        goal = next((item for item in objective.requested_goals if item.id == goal_id), None)
        if goal is None:
            return "error: review_no_candidate requires a goal_id from the active objective"
        if self.target is None or self.target.empty() or normalize_target_origin(
            self.target.base_url()
        ) != objective.target_origin:
            return "error: active target does not match the whole-target objective"
        prerequisite_error = self.state.no_candidate_review_prerequisite_error(goal)
        if prerequisite_error:
            return f"error: {prerequisite_error}"
        marker = self.state.phase_completions.get(f"{objective.id}:input_analysis")
        if marker is None:
            return "error: input analysis has not completed for the active objective"
        supplied_ref = arg_string(args, "artifact_ref")
        if supplied_ref and supplied_ref != marker.artifact_ref:
            return "error: artifact_ref must match the active input-analysis completion"
        try:
            artifact = resolve_canonical_artifact(self.evidence_root, marker.artifact_ref)
            if not artifact.is_file() or artifact.stat().st_size <= 0:
                return "error: input-analysis review artifact is unavailable"
            await gate_sensitive_path(prompter, str(artifact), "read input-analysis review artifact", signal)
            if (self.state.objective is not objective or self.target is None
                    or normalize_target_origin(self.target.base_url()) != objective.target_origin):
                return "error: objective or target changed during no-candidate review"
            policy = policy_for(prompter)
            if policy is not None:
                policy.generic_validation.idle()
            with artifact.open("rb") as handle:
                artifact_digest = hashlib.file_digest(handle, "sha256").hexdigest()
            if artifact.stat().st_size <= 0:
                return "error: input-analysis review artifact is unavailable"
            binding = self.state.no_candidate_review_binding(goal, artifact_digest)
            reviewed = self.state.mark_goal_no_candidate(
                goal.id, artifact_ref=marker.artifact_ref, review_binding=binding,
            )
        except (OSError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({
            "ok": True,
            "goal": reviewed.to_dict(),
            "class_specific_validation_performed": False,
        }, indent=2)

    def phase_completion_readiness(
        self, skill_name: str, *, artifact_ref: str | None = None,
        no_inputs_discovered: bool = False,
    ) -> dict[str, Any]:
        """Read-only version of the whole-target phase completion gate."""
        canonical = normalize_metadata_name(skill_name)[:80]
        skill = self.skills.get(canonical) if self.skills else None
        phase = self._phase_for_skill(canonical, skill)
        objective = self.state.objective
        coverage = self.state.phase_coverage.get(
            f"{objective.id}:{phase}", {}
        ) if objective is not None and phase is not None else {}
        required = PHASE_COVERAGE_DIMENSIONS.get(phase or "", ())
        result: dict[str, Any] = {
            "ready": False, "skill_name": canonical, "phase": phase,
            "artifact_ref": None, "no_inputs_discovered": no_inputs_discovered,
            "objective_id": objective.id if objective is not None else None,
            "target_origin": objective.target_origin if objective is not None else None,
            "prerequisites": (
                ("recon",) if phase == "enumeration" else
                ("enumeration",) if phase == "input_analysis" else ()
            ),
            "required_coverage": {
                dimension: coverage[dimension].status if dimension in coverage else None
                for dimension in required
            },
        }

        def reject(reason: str) -> dict[str, Any]:
            result["reason"] = reason
            return result

        if objective is None or objective.mode != "whole_target" or phase is None:
            return reject("phase completion requires an active whole-target objective")
        if objective.target_origin != normalize_target_origin(self._active_target()):
            return reject("phase completion must match the active objective and target")
        if phase in self.state.completed_phases(objective):
            return reject(f"{phase} phase is already completed")
        if (
            skill is None or skill.disable_model_invocation or self.skills is None
            or self.skills.is_disabled(canonical)
        ):
            return reject(f"{canonical} is unavailable for whole-target phase completion")
        if not skill.completion_artifact:
            return reject(f"{canonical} has no canonical phase artifact")
        try:
            expected = completion_artifact_path(skill.completion_artifact, self._active_target())
            artifact = resolve_canonical_artifact(self.evidence_root, expected)
            if artifact_ref and resolve_canonical_artifact(self.evidence_root, artifact_ref) != artifact:
                return reject(f"{canonical} completion requires {expected}")
            artifact_ready = artifact.is_file() and artifact.stat().st_size > 0
        except ValueError as err:
            return reject(str(err))
        except OSError:
            artifact_ready = False
        result["artifact_ref"] = expected
        if not artifact_ready:
            return reject(f"{canonical} completion requires {expected}")
        phases = self.state.completed_phases(objective)
        if phase == "enumeration" and "recon" not in phases:
            return reject("recon must complete before enumeration")
        if phase == "input_analysis":
            if "enumeration" not in phases:
                return reject("enumeration must complete before input analysis")
            if any(item.disposition in {"pending", "blocked"} for item in self.state.objective_inputs()):
                return reject("input analysis cannot complete while an input is pending or blocked")
            if not self.state.objective_inputs() and not no_inputs_discovered:
                return reject("input analysis requires at least one recorded input or no_inputs_discovered=true")
        missing = [dimension for dimension in required if dimension not in coverage]
        if missing:
            return reject(f"{canonical} completion requires explicit coverage for: {', '.join(missing)}")
        unresolved = [
            dimension for dimension in required
            if coverage[dimension].status in {"failed", "cancelled"}
        ]
        if unresolved:
            return reject(
                f"{canonical} has unresolved failed/cancelled coverage: "
                f"{', '.join(unresolved)}; retry or record an explicit skip reason"
            )
        result["ready"] = True
        result["reason"] = "ready"
        return result

    def _record_phase_coverage(self, args: dict[str, Any]) -> str:
        objective = self.state.objective
        if objective is None or objective.mode != "whole_target":
            return "error: phase coverage requires an active whole-target objective"
        phase = arg_string(args, "phase")
        dimension = arg_string(args, "coverage_dimension")
        status = arg_string(args, "coverage_status")
        reason = arg_string(args, "coverage_reason") or None
        if phase not in PHASE_COVERAGE_DIMENSIONS:
            return "error: phase must be recon or enumeration"
        if status not in PHASE_COVERAGE_STATUSES:
            return "error: coverage_status is invalid"
        try:
            changed = self.state.record_phase_coverage(
                cast(WorkflowPhase, phase),
                dimension,
                cast(PhaseCoverageStatus, status),
                objective_id=objective.id,
                target_origin=objective.target_origin or "",
                reason=reason,
            )
        except ValueError as err:
            return f"error: {err}"
        return json.dumps({
            "ok": True,
            "phase": phase,
            "dimension": dimension,
            "status": status,
            "changed": changed,
        })

    def _validate_current_objective_candidate(self, candidate_id: str) -> None:
        objective = self.state.objective
        candidate = self.state.candidates.get(candidate_id)
        if candidate is None:
            if (
                objective is not None
                and objective.mode == "candidate_validation"
                and candidate_id == objective.candidate_id
            ):
                raise ValueError(
                    "active candidate-validation objective references an unknown candidate"
                )
            raise ValueError("unknown candidate")
        if objective is not None and objective.mode == "whole_target":
            if (
                candidate.objective_id != objective.id
                or candidate_origin(candidate.target) != objective.target_origin
            ):
                raise ValueError("candidate does not belong to the active whole-target objective")
        elif objective is not None and objective.mode == "direct":
            if candidate.objective_id != objective.id:
                raise ValueError("candidate lacks provenance for the active direct objective")
            if objective.target_origin is not None and candidate_origin(candidate.target) != objective.target_origin:
                raise ValueError("candidate target does not match the active direct objective")
        elif objective is not None and objective.mode == "candidate_validation":
            if candidate_id != objective.candidate_id:
                raise ValueError(
                    "candidate does not match the active candidate-validation objective"
                )
            candidate = self.state.candidates.get(candidate_id)
            if candidate is None:
                raise ValueError(
                    "active candidate-validation objective references an unknown candidate"
                )
            candidate_target = candidate_origin(candidate.target)
            active_target = candidate_origin(self._active_target())
            if (
                objective.target_origin is not None
                and candidate_target != objective.target_origin
            ) or (active_target is not None and candidate_target != active_target):
                raise ValueError(
                    "candidate target does not match the active candidate-validation objective"
                )

    def _require_unique_validator(self, candidate_class: str) -> Skill:
        if self.skills is None:
            raise ValueError("skill registry is unavailable for validator resolution")
        route = resolve_validation_route(self.skills, candidate_class)
        if route.kind != "expert":
            reason = "ambiguous" if route.kind == "ambiguous" else "unavailable"
            raise ValueError(
                f"candidate class {candidate_class} has {reason} validator mapping; "
                "exactly one enabled validation skill is required"
            )
        validator = self.skills.get(route.skill_name or "")
        if validator is None:
            raise ValueError("resolved expert validator unavailable")
        return validator

    def _is_generic(self, candidate: Candidate) -> bool:
        latest = self.state.latest_result(candidate.id)
        route = resolve_validation_route(self.skills, candidate.candidate_class)
        return (route.kind == "generic"
                or bool(latest and latest.skill_name == GENERIC_VALIDATOR))

    def _require_generic(self, candidate_id: str, policy) -> Candidate:
        candidate = self.state.candidates.get(candidate_id)
        if candidate is None:
            raise ValueError(f"unknown candidate: {candidate_id}")
        reason = generic_admission(candidate, self.state, self.skills, self.target, policy)
        if reason:
            raise ValueError(reason)
        return candidate

    @staticmethod
    def _phase_for_skill(canonical: str, skill) -> WorkflowPhase | None:
        if canonical == "recon":
            return "recon"
        if canonical == "web-enumeration":
            return "enumeration"
        if canonical == "web-input-analysis":
            return "input_analysis"
        return None

    def _active_target(self) -> str:
        if self.target is None:
            return ""
        return self.target.base_url() or self.target.name()

    def _list(self, args: dict[str, Any], policy=None) -> str:
        candidate_id = arg_string(args, "candidate_id")
        status = arg_string(args, "status")
        candidate_class = arg_string(args, "candidate_class")

        if status and status not in CANDIDATE_STATUSES:
            return f"error: status must be one of: {', '.join(sorted(CANDIDATE_STATUSES))}"

        requested_limit = arg_number(args, "limit")
        limit = (
            DEFAULT_LIST_LIMIT
            if requested_limit is None
            else max(1, min(MAX_LIST_LIMIT, int(requested_limit)))
        )

        candidates = list(self.state.candidates.values())
        if policy is not None and policy.generic_validation.restricted():
            candidates = [c for c in candidates if policy.generic_validation.belongs(c)]
        objective = self.state.objective
        if objective is not None and objective.mode == "whole_target" and not candidate_id:
            candidates = list(self.state.objective_candidates())
        if candidate_id:
            candidate = self.state.candidates.get(candidate_id)
            if candidate is None:
                return f"error: unknown candidate: {candidate_id}"
            candidates = [candidate]
        else:
            if status:
                candidates = [item for item in candidates if item.status == status]
            if candidate_class:
                canonical_class = normalize_candidate_class(candidate_class)
                candidates = [
                    item
                    for item in candidates
                    if item.candidate_class == canonical_class
                ]
            candidates.sort(key=lambda item: _STATUS_PRIORITY.get(item.status, 3))

        total = len(candidates)
        selected = candidates[:limit]
        latest_results = [
            result
            for candidate in selected
            if (result := self.state.latest_result(candidate.id)) is not None
        ]
        return json.dumps(
            {
                "ok": True,
                "total": total,
                "returned": len(selected),
                "truncated": total > len(selected),
                "current_phase": self.state.current_phase,
                "objective": objective.to_dict() if objective else None,
                "requested_goals": [
                    goal.to_dict() for goal in objective.requested_goals
                ] if objective else [],
                "completed_phases": sorted(self.state.completed_phases()),
                "phase_coverage": {
                    key: {
                        dimension: record.to_dict()
                        for dimension, record in sorted(records.items())
                    }
                    for key, records in sorted(self.state.phase_coverage.items())
                    if objective is not None and key.rpartition(":")[0] == objective.id
                },
                "attack_surface_inputs": [
                    self._input_summary(item)
                    for item in self.state.objective_inputs()
                ],
                "completed_skills_total": len(self.state.completed_skills),
                "completed_skills": sorted(self.state.completed_skills)[
                    :MAX_LIST_COMPLETED_SKILLS
                ],
                "completed_artifacts": {
                    name: self._brief(path)
                    for name, path in sorted(self.state.completed_artifacts.items())
                    if name in self.state.completed_skills
                },
                "candidates": [
                    self._candidate_summary(item, include_full_request_template=bool(candidate_id))
                    for item in selected
                ],
                "latest_results": [
                    self._result_summary(result) for result in latest_results
                ],
            },
            indent=2,
        )

    @staticmethod
    def _candidate_summary(
        candidate: Candidate, *, include_full_request_template: bool = False,
    ) -> dict[str, Any]:
        request_template = candidate.request_template or ""
        template_limit = 4000 if include_full_request_template else 1000
        return {
            "id": candidate.id,
            "candidate_class": candidate.candidate_class,
            "target": WorkflowTool._brief(candidate.target),
            "method": candidate.method,
            "endpoint": WorkflowTool._brief(candidate.endpoint),
            "parameter": WorkflowTool._brief(candidate.parameter),
            "location": WorkflowTool._brief(candidate.location),
            "test_case": WorkflowTool._brief(candidate.test_case),
            "priority": candidate.priority,
            "status": candidate.status,
            "signals": [WorkflowTool._brief(item) for item in candidate.signals[:2]],
            "baseline_request_ref": WorkflowTool._brief(
                candidate.baseline_request_ref
            ),
            "auth_context_ref": WorkflowTool._brief(candidate.auth_context_ref),
            "content_type": candidate.content_type,
            "request_template": request_template[:template_limit] or None,
            "request_template_truncated": len(request_template) > template_limit,
            "source_skill": candidate.source_skill,
            "source_ref": WorkflowTool._brief(candidate.source_ref),
            "objective_id": candidate.objective_id,
        }

    @staticmethod
    def _input_summary(item: AttackSurfaceInput) -> dict[str, Any]:
        sample_payload = item.sample_payload or ""
        return {
            "id": item.id,
            "objective_id": item.objective_id,
            "target_origin": item.target_origin,
            "method": item.method,
            "endpoint": WorkflowTool._brief(item.endpoint),
            "parameter": WorkflowTool._brief(item.parameter),
            "location": item.location,
            "input_type": item.input_type,
            "content_type": item.content_type,
            "sample_payload": sample_payload[:500] or None,
            "baseline_request_ref": WorkflowTool._brief(item.baseline_request_ref),
            "auth_context_ref": WorkflowTool._brief(item.auth_context_ref),
            "source_ref": WorkflowTool._brief(item.source_ref),
            "sample_payload_truncated": len(sample_payload) > 500,
            "disposition": item.disposition,
            "disposition_reason": WorkflowTool._brief(item.disposition_reason),
            "disposition_transitions": list(item.disposition_transitions),
            "candidate_ids": list(item.candidate_ids),
        }

    def _result_summary(self, result: ValidationResult) -> dict[str, Any]:
        from src.workflow.assessment import assessment_provenance
        from src.permission.runtime.execution import current_policy
        candidate = self.state.candidates[result.candidate_id]
        return {
            "candidate_id": result.candidate_id,
            "skill_name": result.skill_name,
            "outcome": result.outcome,
            "assessment_provenance": assessment_provenance(self.state, candidate, result, current_policy()),
            "result_id": result.result_id,
            "attempt_id": result.attempt_id,
            "evidence_refs": [
                WorkflowTool._brief(item) for item in result.evidence_refs[:3]
            ],
            "techniques": [
                WorkflowTool._brief(item) for item in result.techniques[:2]
            ],
            "repeatable": result.repeatable,
            "mutation_performed": result.mutation_performed,
            "cleanup_status": WorkflowTool._brief(result.cleanup_status),
            "cleanup_state": result.cleanup_state,
            "deferred_reason": WorkflowTool._brief(result.deferred_reason),
        }

    @staticmethod
    def _brief(value: str | None) -> str | None:
        if value is None:
            return None
        return value[:LIST_TEXT_LIMIT]
