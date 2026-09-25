from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.paths import project_root
from src.permission.permission import Prompter
from src.redact.redact import apply as redact
from src.coverage.store import CoverageStore, CoverageStatus
from src.target.target import Target
from src.workflow.state import (
    CANDIDATE_STATUSES,
    INPUT_DISPOSITIONS,
    VALIDATION_OUTCOMES,
    Candidate,
    AttackSurfaceInput,
    WorkflowPhase,
    ValidationResult,
    WorkflowState,
    candidate_origin,
    normalize_target_origin,
    validation_result_fingerprint,
)
from src.workflow.evidence import EvidenceArtifact
from src.skills.registry import Registry as SkillRegistry, normalize_candidate_class, normalize_metadata_name
from src.skills.artifacts import completion_artifact_path, resolve_canonical_artifact

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
    "complete_skill",
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
            "Record compact inputs, candidates, evidence, validation results, and completion. "
            "Whole-target only: record_input, set_input_disposition, link_input_candidate. "
            "record_candidate needs candidate_class and target (explicit or active); "
            "record_evidence needs candidate_id and evidence_path; start_validation "
            "needs candidate_id; record_result needs candidate_id, skill_name and "
            "outcome; sync_coverage retries pending writes; complete_skill needs "
            "skill_name. Use compact references; never include raw traffic."
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
                "disposition": {"type": "string", "enum": sorted(INPUT_DISPOSITIONS)},
                "disposition_reason": optional_string,
                "candidate_class": {
                    "type": "string",
                    "description": "Required for record_candidate.",
                },
                "target": optional_string,
                "endpoint": optional_string,
                "method": optional_string,
                "parameter": optional_string,
                "location": optional_string,
                "test_case": {
                    "type": "string",
                    "description": "Stable test subcase on one input.",
                },
                "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                "evidence_path": {
                    "type": "string",
                    "description": "Existing project proof file.",
                },
                "signals": {"type": "array", "items": {"type": "string"}},
                "baseline_request_ref": optional_string,
                "auth_context_ref": optional_string,
                "source_skill": optional_string,
                "status": {
                    "type": "string",
                    "enum": sorted(CANDIDATE_STATUSES),
                    "description": "Candidate status; not used by record_result.",
                },
                "skill_name": {
                    "type": "string",
                    "description": (
                        "Required for record_result and complete_skill."
                    ),
                },
                "outcome": {
                    "type": "string",
                    "enum": sorted(VALIDATION_OUTCOMES),
                    "description": "Required for record_result.",
                },
                "evidence_refs": {"type": "array", "items": {"type": "string"}},
                "techniques": {"type": "array", "items": {"type": "string"}},
                "repeatable": {"type": "boolean"},
                "mutation_performed": {"type": "boolean"},
                "cleanup_status": optional_string,
                "deferred_reason": optional_string,
                "notes": optional_string,
                "force": {
                    "type": "boolean",
                    "description": "Intentional retest only.",
                },
                "current_phase": optional_string,
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
            return self._record_input(args)
        if action == "set_input_disposition":
            return self._set_input_disposition(args)
        if action == "link_input_candidate":
            return self._link_input_candidate(args)
        if action == "record_candidate":
            return self._record_candidate(args)
        if action == "record_evidence":
            return self._record_evidence(args)
        if action == "start_validation":
            return self._start_validation(args)
        if action == "record_result":
            return await self._record_result(args)
        if action == "sync_coverage":
            return await self._sync_coverage_action(args)
        if action == "complete_skill":
            return self._complete_skill(args)
        if action == "list":
            return self._list(args)
        return f"error: action must be one of: {', '.join(ACTIONS)}"

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
        supported = bool(validators) if self.skills else None
        try:
            candidate = Candidate(
                candidate_class=candidate_class,
                target=candidate_target,
                endpoint=args.get("endpoint"),
                method=args.get("method"),
                parameter=args.get("parameter"),
                location=args.get("location"),
                test_case=args.get("test_case"),
                priority=args.get("priority"),
                signals=args.get("signals", []),
                baseline_request_ref=args.get("baseline_request_ref"),
                auth_context_ref=args.get("auth_context_ref"),
                source_skill=args.get("source_skill"),
                objective_id=objective_id,
                status=("deferred" if supported is False else args.get("status", "queued")),
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
                "recommended_skills": [skill.name for skill in validators],
            },
            indent=2,
        )

    def _record_input(self, args: dict[str, Any]) -> str:
        objective = self.state.objective
        if objective is None or objective.mode != "whole_target":
            return "error: record_input requires an active whole-target objective"
        if "objective_id" in args or "target_origin" in args or "target" in args:
            return "error: objective and target origin are assigned by the runtime"
        if self.target is None or self.target.empty():
            return "error: record_input requires an active target"
        target_origin = normalize_target_origin(self.target.base_url())
        if target_origin != objective.target_origin:
            return "error: active target does not match the whole-target objective"
        try:
            item = AttackSurfaceInput(
                objective_id=objective.id,
                target_origin=target_origin or "",
                method=args.get("method"),
                endpoint=args.get("endpoint"),
                parameter=args.get("parameter"),
                location=args.get("location"),
                input_type=args.get("input_type"),
            )
            stored, created = self.state.add_attack_surface_input(item)
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "created": created, "input": stored.to_dict()}, indent=2)

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

    def _start_validation(self, args: dict[str, Any]) -> str:
        candidate_id = arg_string(args, "candidate_id")
        try:
            self._validate_current_objective_candidate(candidate_id)
            candidate = self.state.set_candidate_status(candidate_id, "validating")
        except ValueError as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "candidate": candidate.to_dict()}, indent=2)

    def _record_evidence(self, args: dict[str, Any]) -> str:
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
            artifact = EvidenceArtifact.capture(candidate_id, path, self.evidence_root)
            self.state.add_evidence(artifact)
        except (OSError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "evidence": artifact.to_dict()}, indent=2)

    async def _record_result(self, args: dict[str, Any]) -> str:
        try:
            result = ValidationResult(
                candidate_id=arg_string(args, "candidate_id"),
                skill_name=arg_string(args, "skill_name"),
                outcome=arg_string(args, "outcome"),  # type: ignore[arg-type]
                evidence_refs=args.get("evidence_refs", []),
                techniques=args.get("techniques", []),
                repeatable=args.get("repeatable"),
                mutation_performed=arg_bool(args, "mutation_performed"),
                cleanup_status=args.get("cleanup_status"),
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
            if result.evidence_refs and not all(
                self.state.evidence[ref].is_resolvable_for_resume(self.evidence_root)
                for ref in result.evidence_refs
            ):
                raise ValueError("evidence artifact changed or is unavailable")
            skill = self.skills.get(result.skill_name) if self.skills else None
            if skill and skill.candidate_classes and candidate.candidate_class not in skill.candidate_classes:
                raise ValueError("result skill does not handle candidate class")
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
    def _coverage_status(result: ValidationResult) -> CoverageStatus | None:
        if result.outcome == "confirmed":
            return "failed"
        if result.outcome == "not-confirmed":
            return "passed"
        return None

    async def _sync_coverage(self, candidate: Candidate, result: ValidationResult) -> None:
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
        await self.coverage.ensure_validation_mark(
            endpoint=endpoint,
            param=parameter,
            vulnClass=candidate.candidate_class,
            status=status,
            notes=f"result={validation_result_fingerprint(result)[:20]}",
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
        if skill and skill.completion_artifact:
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
        objective = self.state.objective
        workflow_phase = None
        if objective is not None and objective.mode == "whole_target":
            workflow_phase = self._phase_for_skill(canonical, skill)
            if workflow_phase is not None:
                if (
                    skill is None
                    or skill.disable_model_invocation
                    or self.skills is None
                    or self.skills.is_disabled(canonical)
                ):
                    return f"error: {canonical} is unavailable for whole-target phase completion"
                if not skill.completion_artifact:
                    return f"error: {canonical} has no canonical phase artifact"
                phases = self.state.completed_phases(objective)
                if workflow_phase == "enumeration" and "recon" not in phases:
                    return "error: recon must complete before enumeration"
                if workflow_phase == "input_analysis":
                    if "enumeration" not in phases:
                        return "error: enumeration must complete before input analysis"
                    unresolved = [
                        item for item in self.state.objective_inputs()
                        if item.disposition in {"pending", "blocked"}
                    ]
                    if unresolved:
                        return (
                            "error: input analysis cannot complete while an input "
                            "is pending or blocked"
                        )
                if not artifact_ref:
                    return f"error: {canonical} requires an artifact_ref for phase completion"
                try:
                    self.state.record_phase_completion(
                        workflow_phase,
                        objective_id=objective.id,
                        target_origin=objective.target_origin or "",
                        artifact_ref=artifact_ref,
                    )
                except ValueError as err:
                    return f"error: {err}"
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
                "attack_surface_inputs": [
                    item.to_dict() for item in self.state.objective_inputs()
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
                "candidates": [self._candidate_summary(item) for item in selected],
                "latest_results": [
                    self._result_summary(result) for result in latest_results
                ],
            },
            indent=2,
        )

    @staticmethod
    def _candidate_summary(candidate: Candidate) -> dict[str, Any]:
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
            "source_skill": candidate.source_skill,
            "objective_id": candidate.objective_id,
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
            "deferred_reason": WorkflowTool._brief(result.deferred_reason),
        }

    @staticmethod
    def _brief(value: str | None) -> str | None:
        if value is None:
            return None
        return value[:LIST_TEXT_LIMIT]
