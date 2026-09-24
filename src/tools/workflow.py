from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.permission.permission import Prompter
from src.redact.redact import apply as redact
from src.coverage.store import CoverageStore, CoverageStatus
from src.target.target import Target
from src.workflow.state import (
    CANDIDATE_STATUSES,
    VALIDATION_OUTCOMES,
    Candidate,
    ValidationResult,
    WorkflowState,
    validation_result_fingerprint,
)
from src.workflow.evidence import EvidenceArtifact
from src.skills.registry import Registry as SkillRegistry, normalize_candidate_class, normalize_metadata_name

from .types import Tool, arg_bool, arg_number, arg_string


ACTIONS = (
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
        self.evidence_root = evidence_root or Path.cwd()
        self.session_id = session_id

    def name(self) -> str:
        return "workflow"

    def description(self) -> str:
        return (
            "Record candidates, evidence, results, and completion. "
            "Use compact references, never full traffic. "
            "record_candidate needs candidate_class and a target (explicit or "
            "active); record_evidence needs candidate_id and evidence_path; "
            "start_validation needs candidate_id; record_result needs "
            "candidate_id, skill_name, and outcome; sync_coverage retries a "
            "pending write; complete_skill needs skill_name."
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
        candidate_class = arg_string(args, "candidate_class")
        if not candidate_class:
            return "error: record_candidate requires candidate_class"
        candidate_target = arg_string(args, "target") or self._active_target()
        if not candidate_target:
            return "error: record_candidate requires target or an active Agent target"
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
                status=("deferred" if supported is False else args.get("status", "queued")),
            )
            stored, created = self.state.add_candidate(candidate)
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

    def _start_validation(self, args: dict[str, Any]) -> str:
        candidate_id = arg_string(args, "candidate_id")
        try:
            candidate = self.state.set_candidate_status(candidate_id, "validating")
        except ValueError as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "candidate": candidate.to_dict()}, indent=2)

    def _record_evidence(self, args: dict[str, Any]) -> str:
        candidate_id = arg_string(args, "candidate_id")
        if candidate_id not in self.state.candidates:
            return f"error: unknown candidate: {candidate_id}"
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
            if result.outcome == "confirmed" and not result.evidence_refs:
                raise ValueError("confirmed result requires an evidence reference")
            if result.evidence_refs and not self.state.evidence_matches(result.candidate_id, result.evidence_refs):
                raise ValueError("evidence references must resolve to this candidate")
            if result.evidence_refs and not all(
                self.state.evidence[ref].is_resolvable(self.evidence_root)
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
        self.state.completed_skills.add(normalize_metadata_name(skill_name)[:80])
        canonical = normalize_metadata_name(skill_name)[:80]
        artifact_ref = arg_string(args, "artifact_ref")
        if artifact_ref:
            self.state.completed_artifacts[canonical] = redact(artifact_ref)[:500]
        phase = arg_string(args, "current_phase")
        if phase:
            self.state.current_phase = phase[:80]
        return json.dumps({
            "ok": True, "skill_name": canonical,
            "artifact_ref": self.state.completed_artifacts.get(canonical),
        }, indent=2)

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
