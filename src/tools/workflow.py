from __future__ import annotations

import json
from typing import Any

from src.permission.permission import Prompter
from src.target.target import Target
from src.workflow.state import (
    CANDIDATE_STATUSES,
    VALIDATION_OUTCOMES,
    Candidate,
    ValidationResult,
    WorkflowState,
)
from src.skills.registry import normalize_candidate_class, normalize_metadata_name

from .types import Tool, arg_bool, arg_number, arg_string


ACTIONS = (
    "record_candidate",
    "start_validation",
    "record_result",
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

    def __init__(self, state: WorkflowState, target: Target | None = None) -> None:
        self.state = state
        self.target = target

    def name(self) -> str:
        return "workflow"

    def description(self) -> str:
        return (
            "Record/query compact Candidate and ValidationResult state. Reference "
            "stored evidence; never copy full requests/responses. Use force only "
            "for an intentional retest."
        )

    def schema(self) -> dict[str, Any]:
        optional_string = {"type": "string"}
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": list(ACTIONS)},
                "candidate_id": {"type": "string"},
                "candidate_class": {"type": "string"},
                "target": optional_string,
                "endpoint": optional_string,
                "method": optional_string,
                "parameter": optional_string,
                "location": optional_string,
                "signals": {"type": "array", "items": {"type": "string"}},
                "baseline_request_ref": optional_string,
                "auth_context_ref": optional_string,
                "source_skill": optional_string,
                "status": {"type": "string", "enum": sorted(CANDIDATE_STATUSES)},
                "skill_name": optional_string,
                "outcome": {"type": "string", "enum": sorted(VALIDATION_OUTCOMES)},
                "evidence_refs": {"type": "array", "items": {"type": "string"}},
                "techniques": {"type": "array", "items": {"type": "string"}},
                "repeatable": {"type": "boolean"},
                "mutation_performed": {"type": "boolean"},
                "cleanup_status": optional_string,
                "deferred_reason": optional_string,
                "notes": optional_string,
                "force": {
                    "type": "boolean",
                    "description": "Allow an identical result only for an intentional retest.",
                },
                "current_phase": optional_string,
                "limit": {
                    "type": "number",
                    "description": (
                        "For list: maximum candidates returned "
                        f"(default {DEFAULT_LIST_LIMIT}, max {MAX_LIST_LIMIT})."
                    ),
                },
            },
            "required": ["action"],
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str:
        action = arg_string(args, "action")
        if action == "record_candidate":
            return self._record_candidate(args)
        if action == "start_validation":
            return self._start_validation(args)
        if action == "record_result":
            return self._record_result(args)
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
        try:
            candidate = Candidate(
                candidate_class=candidate_class,
                target=candidate_target,
                endpoint=args.get("endpoint"),
                method=args.get("method"),
                parameter=args.get("parameter"),
                location=args.get("location"),
                signals=args.get("signals", []),
                baseline_request_ref=args.get("baseline_request_ref"),
                auth_context_ref=args.get("auth_context_ref"),
                source_skill=args.get("source_skill"),
                status=args.get("status", "queued"),
            )
            stored, created = self.state.add_candidate(candidate)
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        phase = arg_string(args, "current_phase")
        if phase:
            self.state.current_phase = phase[:80]
        return json.dumps(
            {"ok": True, "created": created, "candidate": stored.to_dict()},
            indent=2,
        )

    def _start_validation(self, args: dict[str, Any]) -> str:
        candidate_id = arg_string(args, "candidate_id")
        try:
            candidate = self.state.set_candidate_status(candidate_id, "validating")
        except ValueError as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "candidate": candidate.to_dict()}, indent=2)

    def _record_result(self, args: dict[str, Any]) -> str:
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
            )
            created = self.state.add_validation_result(
                result,
                force=arg_bool(args, "force"),
            )
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        return json.dumps(
            {
                "ok": True,
                "created": created,
                "eligible_for_confirm_finding": self.state.eligible_for_finding(
                    result.candidate_id
                ),
                "result": result.to_dict(),
            },
            indent=2,
        )

    def _complete_skill(self, args: dict[str, Any]) -> str:
        skill_name = arg_string(args, "skill_name")
        if not skill_name:
            return "error: complete_skill requires skill_name"
        self.state.completed_skills.add(normalize_metadata_name(skill_name)[:80])
        phase = arg_string(args, "current_phase")
        if phase:
            self.state.current_phase = phase[:80]
        return json.dumps({"ok": True, "skill_name": skill_name}, indent=2)

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
