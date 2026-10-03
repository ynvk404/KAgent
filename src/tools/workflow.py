from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from src.paths import project_root
from src.permission.permission import Prompter, UserControlledRefusal
from src.permission.execution import policy_for
from .file import gate_sensitive_path
from src.redact.redact import apply as redact
from src.coverage.store import CoverageStore, CoverageStatus
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
from src.skills.registry import (
    Registry as SkillRegistry,
    Skill,
    normalize_candidate_class,
    normalize_metadata_name,
)
from src.skills.artifacts import completion_artifact_path, resolve_canonical_artifact

from .outcome import ToolOutput
from .types import Tool, arg_bool, arg_number, arg_string


ACTIONS = (
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
    "list",
)
DEFAULT_LIST_LIMIT = 8
MAX_LIST_LIMIT = 25
MAX_LIST_COMPLETED_SKILLS = 20
LIST_TEXT_LIMIT = 200
_STATUS_PRIORITY = {"validating": 0, "queued": 1, "new": 2}
_SQLI_BOOLEAN_CLAIM_RE = re.compile(
    r"\bboolean\s+differential\b|"
    r"\btrue\b.{0,100}\breturns?\b.{0,60}\b(?:rows?|results?|data)\b|"
    r"\bfalse\b.{0,100}\b(?:empty|zero\s+rows?|no\s+rows?)\b",
    re.IGNORECASE,
)


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
    ) -> None:
        self.state = state
        self.target = target
        self.coverage = coverage
        self.skills = skills
        self.evidence_root = evidence_root or project_root()
        self.session_id = session_id

    def name(self) -> str:
        return "workflow"

    def description(self) -> str:
        return (
            "Manage inputs, candidates, evidence, results, coverage and phase completion. "
            "Inputs require a whole-target objective. Before recon/enumeration completion, "
            "account for every coverage dimension: performed is adapter-only; observed is "
            "unattested review with source/limitation; skipped means omitted and "
            "not_applicable means irrelevant. Non-performed statuses require reasons; "
            "retry failed/cancelled work or explain an actual skip. record_evidence stores "
            "redacted immutable snapshots. record_result needs candidate_id, skill_name "
            "and outcome. Use compact references, never raw traffic."
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
                "candidate_class": {
                    "type": "string",
                    "description": "Required for record_candidate.",
                },
                "target": {
                    "type": "string",
                    "description": "Target for record_candidate; omit for record_input (runtime assigns scope).",
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
                                    "description": "Runtime observation IDs; claims alone are not verification."},
                "signals": {"type": "array", "items": {"type": "string"}},
                "baseline_request_ref": optional_string,
                "auth_context_ref": optional_string,
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
                    "description": "Required for record_result and complete_skill.",
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
                    "description": "Structured SQL injection proof.",
                },
                "mutation_performed": {"type": "boolean"},
                "cleanup_status": optional_string,
                "cleanup_state": {
                    "type": "string",
                    "enum": sorted(CLEANUP_STATES),
                    "description": (
                        "Machine-readable cleanup lifecycle. Mutations default to pending; "
                        "do not infer cleanup authorization from the original write."
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
                    "description": "Required for observed (source and attestation limitation), skipped, not_applicable, failed, or cancelled.",
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

    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str:
        action = arg_string(args, "action")
        if action == "record_input":
            result = self._record_input(args)
        elif action == "set_input_disposition":
            result = self._set_input_disposition(args)
        elif action == "link_input_candidate":
            result = self._link_input_candidate(args)
        elif action == "record_candidate":
            result = self._record_candidate(args)
        elif action == "record_evidence":
            result = await self._record_evidence(args, prompter, signal)
        elif action == "start_validation":
            result = await self._start_validation(args, prompter, signal)
        elif action == "record_result":
            result = await self._record_result(args, prompter, signal)
        elif action == "sync_coverage":
            policy = policy_for(prompter)
            if policy is not None:
                latest = self.state.latest_result(arg_string(args, "candidate_id"))
                if latest is None or policy.observations.result(latest.candidate_id, tuple(latest.evidence_refs),
                                                               policy.engagement.http_permissions.epoch,
                                                               self.state.candidates.get(latest.candidate_id)) is None:
                    return self._typed_result("error: unverified result cannot sync tested coverage")
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
        elif action == "list":
            result = self._list(args)
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

    def _record_candidate(self, args: dict[str, Any]) -> str:
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
        validators = (
            self.skills.validators_for_class(candidate_class) if self.skills else []
        )
        supported = len(validators) == 1 if self.skills else None
        validator_resolution = (
            None if self.skills is None
            else "unique" if len(validators) == 1
            else "unavailable" if not validators
            else "ambiguous"
        )
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
                baseline_request_ref=args.get("baseline_request_ref"),
                auth_context_ref=args.get("auth_context_ref"),
                content_type=(
                    args.get("content_type")
                    if args.get("content_type") is not None
                    else input_item.content_type if input_item is not None else None
                ),
                request_template=args.get("request_template"),
                source_skill=args.get("source_skill"),
                objective_id=objective_id,
                status=("deferred" if supported is False else args.get("status", "queued")),
            )
            if candidate.candidate_class == "sql-injection" and any(
                _SQLI_BOOLEAN_CLAIM_RE.search(signal)
                for signal in candidate.signals
            ):
                return (
                    "error: boolean differential claims require structured, "
                    "repeated validation evidence; record only the observed "
                    "candidate signal here"
                )
            stored, created = self.state.add_candidate(candidate)
            input_id = arg_string(args, "input_id")
            if input_id:
                self.state.link_input_candidate(input_id, stored.id)
            if not created and self.skills and self.state.latest_result(stored.id) is None:
                if supported is False and stored.status in {"new", "queued"}:
                    stored = self.state.set_candidate_status(stored.id, "deferred")
                elif supported and stored.status == "deferred":
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
                "recommended_skills": [skill.name for skill in validators],
            },
            indent=2,
        )

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
            candidate = self.state.candidates[candidate_id]
            if self.skills is not None:
                self._require_unique_validator(candidate.candidate_class)
            latest = self.state.latest_result(candidate_id)
            if (
                objective is not None
                and objective.mode == "whole_target"
                and latest is not None
                and latest.outcome in {"confirmed", "not-confirmed"}
                and candidate.status not in {"queued", "validating"}
            ):
                evidence_required = latest.outcome == "confirmed" or bool(
                    latest.evidence_refs
                )
                evidence_invalid = evidence_required and (
                    not self.state.evidence_matches(candidate_id, latest.evidence_refs)
                    or not await verify_evidence_reads([
                        self.state.evidence[reference]
                        for reference in latest.evidence_refs
                        if reference in self.state.evidence
                    ], self.evidence_root, prompter, signal)
                )
                if not evidence_invalid:
                    raise ValueError(
                        "terminal candidate cannot be reopened during whole-target continuation; "
                        "request an explicit candidate retest or repair its missing/invalid evidence"
                    )
            candidate = self.state.set_candidate_status(candidate_id, "validating")
        except ValueError as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "candidate": candidate.to_dict()}, indent=2)

    async def _record_evidence(self, args: dict[str, Any], prompter: Prompter, signal: Any) -> str:
        candidate_id = arg_string(args, "candidate_id")
        if candidate_id not in self.state.candidates:
            return f"error: unknown candidate: {candidate_id}"
        try:
            self._validate_current_objective_candidate(candidate_id)
        except ValueError as err:
            return f"error: {err}"
        path = arg_string(args, "evidence_path")
        if not path:
            return "error: record_evidence requires evidence_path"
        try:
            source = self.evidence_root.resolve() / path
            if not source.resolve().is_relative_to(self.evidence_root.resolve()):
                raise ValueError("evidence path must stay inside the project")
            real = await gate_sensitive_path(prompter, str(source), "read evidence source", signal)
            artifact = EvidenceArtifact.capture_immutable_snapshot(
                candidate_id, real, self.evidence_root, sensitive_read_approved=True,
                original_path=str(source),
            )
            self.state.add_evidence(artifact)
        except UserControlledRefusal:
            raise
        except (OSError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "evidence": artifact.to_dict()}, indent=2)

    async def _record_result(self, args: dict[str, Any], prompter: Prompter, signal: Any) -> str:
        try:
            result = ValidationResult(
                candidate_id=arg_string(args, "candidate_id"),
                skill_name=arg_string(args, "skill_name"),
                outcome=arg_string(args, "outcome"),  # type: ignore[arg-type]
                evidence_refs=args.get("evidence_refs", []),
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
            )
            candidate = self.state.candidates.get(result.candidate_id)
            if candidate is None:
                raise ValueError(f"unknown candidate: {result.candidate_id}")
            self._validate_current_objective_candidate(result.candidate_id)
            if result.outcome == "confirmed" and not result.evidence_refs:
                raise ValueError("confirmed result requires an evidence reference")
            if result.evidence_refs and not self.state.evidence_matches(result.candidate_id, result.evidence_refs):
                raise ValueError("evidence references must resolve to this candidate")
            if result.evidence_refs and not await verify_evidence_reads(
                [self.state.evidence[ref] for ref in result.evidence_refs],
                self.evidence_root, prompter, signal,
            ):
                raise ValueError("evidence artifact changed or is unavailable")
            skill = self.skills.get(result.skill_name) if self.skills else None
            if self.skills is not None:
                validator = self._require_unique_validator(candidate.candidate_class)
                if result.skill_name != validator.name:
                    raise ValueError(
                        "result skill must be the unique validator for candidate class"
                    )
            elif skill and skill.candidate_classes and candidate.candidate_class not in skill.candidate_classes:
                raise ValueError("result skill does not handle candidate class")
            policy = policy_for(prompter)
            if (
                result.outcome == "confirmed"
                and candidate.candidate_class == "sql-injection"
                and policy is None
            ):
                result.confirmation = self._validate_sqli_confirmation(result)
            if policy is not None and result.outcome in {"confirmed", "not-confirmed"}:
                ids = args.get("observation_ids", [])
                verified = policy.observations.result(candidate.id, tuple(result.evidence_refs),
                                                      policy.engagement.http_permissions.epoch, candidate)
                if verified is None:
                    verified = policy.observations.verify(candidate, tuple(result.evidence_refs), ids,
                                                          policy.engagement.http_permissions.epoch)
                if verified is None or verified.outcome != result.outcome:
                    result.outcome = "insufficient-evidence"
                    result.deferred_reason = "class-verifier-unavailable-or-proof-unverified; evidence retained, no confirmed/negative claim"
            coverage_status = self._coverage_status(result)
            if self.coverage is not None and coverage_status:
                result.coverage_synced = False
            created = self.state.add_validation_result(
                result,
                force=arg_bool(args, "force"),
            )
            stored = self.state.latest_result(result.candidate_id)
            assert stored is not None
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
                "result": stored.to_dict(),
            },
            indent=2,
        )

    @staticmethod
    def _validate_sqli_confirmation(
        result: ValidationResult,
    ) -> dict[str, Any] | None:
        """Enforce the reproducible Phase-2 contract at the state boundary."""
        confirmation = result.confirmation
        techniques = {item.strip().lower() for item in result.techniques}
        claims_boolean = any("boolean" in item for item in techniques)
        claims_time = any("time" in item for item in techniques)
        if not claims_boolean and not claims_time:
            if confirmation is None:
                # Preserve error-based and legacy SQLi result compatibility;
                # structured enforcement applies to differential claims.
                return None
            raise ValueError(
                "structured SQL injection confirmation requires a matching technique"
            )
        if result.repeatable is not True:
            raise ValueError(
                "differential SQL injection confirmation requires repeatable=true"
            )
        if not isinstance(confirmation, dict):
            raise ValueError(
                "differential SQL injection requires structured confirmation evidence"
            )
        kind = confirmation.get("kind")
        if claims_time and not claims_boolean:
            if kind != "time-differential":
                raise ValueError(
                    "time-based SQL injection requires time-differential evidence"
                )
            return WorkflowTool._validate_sqli_time_confirmation(
                confirmation, techniques
            )
        if kind != "boolean-differential":
            raise ValueError(
                "boolean-based SQL injection requires boolean-differential evidence"
            )
        template = confirmation.get("request_template")
        true_predicate = confirmation.get("true_predicate")
        false_predicate = confirmation.get("false_predicate")
        if not isinstance(template, str) or "{predicate}" not in template:
            raise ValueError("boolean confirmation request_template must contain {predicate}")
        if (
            not isinstance(true_predicate, str)
            or not true_predicate.strip()
            or not isinstance(false_predicate, str)
            or not false_predicate.strip()
            or true_predicate.strip() == false_predicate.strip()
        ):
            raise ValueError("boolean confirmation requires distinct TRUE and FALSE predicates")
        if re.search(r"\bunion\s+select\b", true_predicate, re.IGNORECASE) or re.search(
            r"\bunion\s+select\b", false_predicate, re.IGNORECASE
        ):
            raise ValueError(
                "UNION success/error observations are not a boolean differential; "
                "record the actual union/error technique without boolean confirmation"
            )
        pairs = confirmation.get("pairs")
        if not isinstance(pairs, list) or len(pairs) < 2:
            raise ValueError("boolean confirmation requires at least two paired repetitions")
        size_tolerance = confirmation.get("size_tolerance", 0)
        if (
            not isinstance(size_tolerance, int)
            or isinstance(size_tolerance, bool)
            or not 0 <= size_tolerance <= 4096
        ):
            raise ValueError("boolean confirmation size_tolerance must be 0 to 4096 bytes")

        normalized_pairs: list[dict[str, Any]] = []
        true_signatures: list[tuple[int, int, str]] = []
        false_signatures: list[tuple[int, int, str]] = []
        seen_repetitions: set[int] = set()
        for raw_pair in pairs[:8]:
            if not isinstance(raw_pair, dict):
                raise ValueError("boolean confirmation pairs must be objects")
            repetition = raw_pair.get("repetition")
            if (
                not isinstance(repetition, int)
                or isinstance(repetition, bool)
                or repetition < 1
                or repetition in seen_repetitions
            ):
                raise ValueError("boolean confirmation repetitions must be unique positive integers")
            seen_repetitions.add(repetition)
            sides: dict[str, dict[str, Any]] = {}
            for side in ("true", "false"):
                raw = raw_pair.get(side)
                if not isinstance(raw, dict):
                    raise ValueError(f"boolean confirmation pair requires {side} observation")
                status = raw.get("status")
                size = raw.get("size")
                marker = raw.get("marker", "")
                if (
                    not isinstance(status, int)
                    or isinstance(status, bool)
                    or status < 100
                    or status > 599
                ):
                    raise ValueError("boolean confirmation status must be an HTTP status integer")
                if (
                    not isinstance(size, int)
                    or isinstance(size, bool)
                    or size < 0
                ):
                    raise ValueError("boolean confirmation size must be a non-negative integer")
                if not isinstance(marker, str):
                    raise ValueError("boolean confirmation marker must be a string")
                marker = redact(marker.strip())[:200]
                sides[side] = {"status": status, "size": size, "marker": marker}
            true_signature = (
                sides["true"]["status"], sides["true"]["size"], sides["true"]["marker"]
            )
            false_signature = (
                sides["false"]["status"], sides["false"]["size"], sides["false"]["marker"]
            )
            if (
                sides["true"]["status"] == sides["false"]["status"]
                and sides["true"]["marker"] == sides["false"]["marker"]
                and abs(sides["true"]["size"] - sides["false"]["size"])
                <= size_tolerance
            ):
                raise ValueError("boolean TRUE and FALSE observations must differ")
            true_signatures.append(true_signature)
            false_signatures.append(false_signature)
            normalized_pairs.append({"repetition": repetition, **sides})

        def stable(signatures: list[tuple[int, int, str]]) -> bool:
            statuses = {status for status, _, _ in signatures}
            markers = {marker for _, _, marker in signatures}
            sizes = [size for _, size, _ in signatures]
            return (
                len(statuses) == 1
                and len(markers) == 1
                and max(sizes) - min(sizes) <= size_tolerance
            )

        if not stable(true_signatures) or not stable(false_signatures):
            raise ValueError("boolean confirmation differential is not reproducible")
        return {
            "kind": kind,
            "request_template": redact(template.strip())[:500],
            "true_predicate": redact(true_predicate.strip())[:200],
            "false_predicate": redact(false_predicate.strip())[:200],
            "size_tolerance": size_tolerance,
            "pairs": normalized_pairs,
        }

    @staticmethod
    def _validate_sqli_time_confirmation(
        confirmation: dict[str, Any], techniques: set[str]
    ) -> dict[str, Any]:
        if not any("time" in item for item in techniques):
            raise ValueError(
                "time-differential confirmation requires a time-based technique"
            )
        template = confirmation.get("request_template")
        expected_delay_ms = confirmation.get("expected_delay_ms")
        pairs = confirmation.get("pairs")
        if not isinstance(template, str) or "{probe}" not in template:
            raise ValueError("time confirmation request_template must contain {probe}")
        if (
            not isinstance(expected_delay_ms, int)
            or isinstance(expected_delay_ms, bool)
            or expected_delay_ms < 1000
        ):
            raise ValueError("time confirmation requires expected_delay_ms >= 1000")
        if not isinstance(pairs, list) or len(pairs) < 2:
            raise ValueError("time confirmation requires at least two paired repetitions")

        normalized: list[dict[str, Any]] = []
        seen_repetitions: set[int] = set()
        for raw_pair in pairs[:8]:
            if not isinstance(raw_pair, dict):
                raise ValueError("time confirmation pairs must be objects")
            repetition = raw_pair.get("repetition")
            if (
                not isinstance(repetition, int)
                or isinstance(repetition, bool)
                or repetition < 1
                or repetition in seen_repetitions
            ):
                raise ValueError("time confirmation repetitions must be unique positive integers")
            seen_repetitions.add(repetition)
            sides: dict[str, dict[str, int]] = {}
            for side in ("control", "probe"):
                raw = raw_pair.get(side)
                if not isinstance(raw, dict):
                    raise ValueError(f"time confirmation pair requires {side} observation")
                status = raw.get("status")
                size = raw.get("size")
                elapsed_ms = raw.get("elapsed_ms")
                if (
                    not isinstance(status, int)
                    or isinstance(status, bool)
                    or not 100 <= status <= 599
                    or not isinstance(size, int)
                    or isinstance(size, bool)
                    or size < 0
                    or not isinstance(elapsed_ms, int)
                    or isinstance(elapsed_ms, bool)
                    or elapsed_ms < 0
                ):
                    raise ValueError(
                        "time confirmation observations require integer status, "
                        "size, and elapsed_ms"
                    )
                sides[side] = {
                    "status": status, "size": size, "elapsed_ms": elapsed_ms,
                }
            if (
                sides["probe"]["elapsed_ms"] - sides["control"]["elapsed_ms"]
                < int(expected_delay_ms * 0.8)
            ):
                raise ValueError("time confirmation delay is not reproducible")
            normalized.append({"repetition": repetition, **sides})
        return {
            "kind": "time-differential",
            "request_template": redact(template.strip())[:500],
            "expected_delay_ms": expected_delay_ms,
            "pairs": normalized,
        }

    @staticmethod
    def _coverage_status(result: ValidationResult) -> CoverageStatus | None:
        if result.outcome == "confirmed":
            return "failed"
        if result.outcome == "not-confirmed":
            return "passed"
        return None

    async def _sync_coverage(self, candidate: Candidate, result: ValidationResult) -> None:
        from src.permission.execution import current_policy
        policy = current_policy()
        if policy is not None and result.outcome in {'confirmed', 'not-confirmed'} and policy.observations.result(
            candidate.id, tuple(result.evidence_refs), policy.engagement.http_permissions.epoch, candidate
        ) is None:
            raise ValueError('unverified: legacy result has no current proof certificate; revalidate or operator review')
        if self.coverage is None:
            return
        status = self._coverage_status(result)
        if status is None:
            return
        if not candidate.endpoint:
            raise ValueError("coverage sync requires a candidate endpoint")
        endpoint = (
            f"{candidate.method} {candidate.endpoint}"
            if candidate.method else candidate.endpoint
        )
        parameter = candidate.parameter or "(request)"
        if candidate.test_case:
            parameter = f"{parameter} [subcase: {candidate.test_case}]"
        fingerprint = validation_result_fingerprint(result)
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
        )
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
        if objective is not None and objective.mode == "whole_target":
            candidate = self.state.candidates.get(candidate_id)
            if (
                candidate is None
                or candidate.objective_id != objective.id
                or candidate_origin(candidate.target) != objective.target_origin
            ):
                raise ValueError("candidate does not belong to the active whole-target objective")
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
        validators = self.skills.validators_for_class(candidate_class)
        if len(validators) != 1:
            reason = "unavailable" if not validators else "ambiguous"
            raise ValueError(
                f"candidate class {candidate_class} has {reason} validator mapping; "
                "exactly one enabled validation skill is required"
            )
        return validators[0]

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

    def _list(self, args: dict[str, Any]) -> str:
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
            "sample_payload_truncated": len(sample_payload) > 500,
            "disposition": item.disposition,
            "disposition_reason": WorkflowTool._brief(item.disposition_reason),
            "disposition_transitions": list(item.disposition_transitions),
            "candidate_ids": list(item.candidate_ids),
        }

    @staticmethod
    def _result_summary(result: ValidationResult) -> dict[str, Any]:
        return {
            "candidate_id": result.candidate_id,
            "skill_name": result.skill_name,
            "outcome": result.outcome,
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
