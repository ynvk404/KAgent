"""Immutable, scoped presentation of runtime records; never advance Workflow."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from src.agent.events import AgentEvent, SkillActiveEvent, ToolCallEvent, ToolResultEvent
from src.agent.scope import runtime_scope
from src.permission.runtime.execution import policy_for
from src.ui.core.admission import PendingCall, call_metadata, invocation_call
from src.ui.render.sanitize import sanitize_text
from src.workflow.assessment import accepted_result, candidate_binding
from src.workflow.state import WorkflowState, candidate_origin, validation_result_fingerprint


@dataclass(frozen=True, slots=True)
class ProgressRecord:
    kind: str
    key: str
    label: str
    disposition: str = ""
    detail: str = ""
    evidence: str = ""
    order: int = 0


@dataclass(frozen=True, slots=True)
class OutcomeFacts:
    scope: str = ""
    milestones: tuple[tuple[str, str, str], ...] = ()
    pending: tuple[str, ...] = ()
    validations: int = 0
    records: tuple[ProgressRecord, ...] = ()
    activity: str = ""
    incomplete: int = 0
    goals: int = 0
    blockers: tuple[str, ...] = ()
    activity_skill: str = ""
    stale_event: bool = False
    overview: str = ""
    completion_supported: bool = False


def _evidence_summary(result) -> str:
    """Only called for an accepted result; no traffic enters the UI copy."""
    sources = {row["source"]["id"]: row["source"] for row in result.evidence_manifest
               if isinstance(row.get("source"), dict) and row["source"].get("id")
               and row["source"].get("complete") is True
               and row["source"].get("truncated") is not True
               and row["source"].get("execution_status") == "completed"}
    summaries = []
    for kind, singular, plural in (
            ("native-http", "HTTP observation", "HTTP observations"),
            ("imported-capture", "imported capture", "imported captures"),
            ("tool-output", "tool output", "tool outputs")):
        count = sum(row.get("source_kind") == kind for row in sources.values())
        if count:
            summaries.append(f"{count} {singular if count == 1 else plural}")
    return " · ".join(summaries)


def concise_text(value: str, limit: int = 240, *, shortened_marker: str = "…") -> str:
    """Bound a sanitized presentation copy, without deriving a conclusion."""
    text = " ".join(sanitize_text(value).split())
    if len(text) <= limit:
        return text
    budget = limit - len(shortened_marker) if shortened_marker != "…" else limit
    return text[:max(0, budget)].rsplit(" ", 1)[0] + shortened_marker


def endpoint_label(method: str | None, endpoint: str | None, parameter: str | None = None) -> str:
    # Query values, userinfo and fragments have no place in activity labels.
    try:
        parsed = urlsplit(endpoint or "")
        path = parsed.path or "/"
    except ValueError:
        path = "[invalid endpoint]"
    return sanitize_text(f"{method or '?'} {path}" + (f" · input {parameter}" if parameter else ""))


def runtime_facts(agent: Any, event: AgentEvent | None, calls: tuple[PendingCall, ...]) -> OutcomeFacts:
    workflow = getattr(agent, "workflow", None)
    if not isinstance(workflow, WorkflowState):
        return OutcomeFacts()
    target = agent.target.base_url()
    origin = candidate_origin(target)
    objective = workflow.objective
    policy = policy_for(getattr(agent, "prompter", None))
    scope = runtime_scope(agent)
    call = (call_metadata(event) if isinstance(event, ToolCallEvent) else
            invocation_call(calls, event) if isinstance(event, (ToolResultEvent, SkillActiveEvent)) else None)
    invocation = getattr(event, 'invocation', None)
    event_origin = getattr(event, "target_origin", None)
    event_revision = getattr(event, "target_revision", None)
    event_objective = getattr(event, "objective_id", None)
    if ((invocation is not None and invocation.scope != scope)
            or (invocation is not None and not isinstance(event, ToolCallEvent) and call is None)
            or (call and (call.retired or (call.resolved and isinstance(event, ToolResultEvent))))
            or (call and call.scope and call.scope != scope)
            or (event_origin is not None and candidate_origin(event_origin) != origin)
            or (event_revision is not None and event_revision != getattr(agent.target, "revision", None))
            or (event_objective is not None and event_objective != (objective.id if objective else None))):
        return OutcomeFacts(scope=scope, stale_event=True)
    records: list[ProgressRecord] = []
    milestones: list[tuple[str, str, str]] = []
    pending: list[str] = []
    blockers: list[str] = []
    incomplete = goals = validations = 0
    tool = getattr(agent, "tools", {}).get("workflow")
    root = getattr(tool, "evidence_root", None)
    from src.tools.workflow.workflow_tool import WorkflowTool
    artifact_errors = tool.discovery_artifact_errors() if isinstance(tool, WorkflowTool) else {
        phase: "canonical artifact validator unavailable"
        for phase in workflow.completed_phases()
        if objective is not None and objective.mode == "whole_target"
    }

    def scoped_endpoint(endpoint: str | None) -> bool:
        return not endpoint or candidate_origin(urljoin((origin or "") + "/", endpoint)) == origin

    candidates = [candidate for candidate in workflow.candidates.values()
                  if candidate_origin(candidate.target) == origin and scoped_endpoint(candidate.endpoint)
                  and (objective is None or workflow.candidate_belongs_to_objective(candidate, objective))]
    def validation_label(candidate) -> str:
        label = endpoint_label(candidate.method, candidate.endpoint, candidate.parameter)
        matching = [item for item in candidates
                    if endpoint_label(item.method, item.endpoint, item.parameter) == label]
        if len(matching) > 1:
            label += " · " + candidate.candidate_class
            if sum(item.candidate_class == candidate.candidate_class for item in matching) > 1:
                label += " · candidate " + candidate.id[-8:]
        return sanitize_text(label)
    selected_candidate_ids: set[str] = set()
    for item in workflow.attack_surface_inputs.values():
        if (item.target_origin != origin or not scoped_endpoint(item.endpoint)
                or objective is None or item.objective_id != objective.id):
            continue
        label = endpoint_label(item.method, item.endpoint, item.parameter)
        records.append(ProgressRecord("input", item.id, label, item.disposition))
        records.append(ProgressRecord("endpoint", f"{item.method}:{urlsplit(item.endpoint or '').path}",
                                      endpoint_label(item.method, item.endpoint)))
        if item.candidate_ids:
            records.append(ProgressRecord("selection", item.id, label, "captured" if item.baseline_request_ref else "direct"))
            selected_candidate_ids.update(item.candidate_ids)
        if item.disposition in {"pending", "blocked"}:
            pending.append("input review incomplete")
        if item.disposition == "blocked":
            blockers.append(sanitize_text(f"{label}: {item.disposition_reason}"))

    for candidate in candidates:
        label = endpoint_label(candidate.method, candidate.endpoint, candidate.parameter)
        records.append(ProgressRecord("candidate", candidate.id, label + f" · {candidate.candidate_class}", candidate.status))
        # Candidate geometry is a recorded input selection, not a discovery
        # claim or a vulnerability conclusion.
        if candidate.id not in selected_candidate_ids:
            records.append(ProgressRecord("selection", candidate.id, label,
                                          "captured" if candidate.baseline_request_ref else "direct"))
        persisted = workflow.persisted_findings.get(candidate.id)
        if persisted:
            records.append(ProgressRecord("finding", candidate.id + ":" + persisted, label))
        result = workflow.latest_result(candidate.id)
        recorded_pause = result is not None and result.outcome in {
            "blocked", "authorization-required", "browser-required", "deferred", "insufficient-evidence"}
        if candidate.status == "deferred" and not recorded_pause:
            pending.append("candidate deferred")
            blockers.append(label + ": candidate deferred")
        if result is None:
            incomplete += 1
            pending.append("validation incomplete")
            continue
        if result.cleanup_state in {"pending", "failed", "requires-user-action"}:
            pending.append("cleanup " + result.cleanup_state)
            blockers.append(f"{label}: cleanup {result.cleanup_state}")
        if result.coverage_synced is False:
            pending.append("coverage synchronization pending")
        valid = accepted_result(workflow, candidate, result, policy)
        if isinstance(root, Path):
            valid = valid and all(workflow.evidence[ref].is_available_for_resume(root)
                                  for ref in result.evidence_refs if ref in workflow.evidence)
        if valid:
            validations += 1
            if candidate.status in {"new", "queued", "validating"}:
                incomplete += 1
                pending.append("validation incomplete")
            identity = candidate.id + ":" + validation_result_fingerprint(result)
            impact = result.assessment.get("observed_impact")
            detail = concise_text(impact, shortened_marker="… [shortened]") if isinstance(impact, str) else ""
            records.append(ProgressRecord("validation", identity, validation_label(candidate), result.outcome, detail,
                                          _evidence_summary(result), workflow.validation_results.index(result)))
            if result.outcome == "confirmed" and not workflow.finding_is_persisted(candidate.id):
                records.append(ProgressRecord("unsaved", identity, label))
                pending.append("finding persistence pending")
        else:
            incomplete += 1
            pending.append("current assessment/evidence unavailable" if result.outcome in {"confirmed", "not-confirmed"}
                           else "validation " + result.outcome)
            if recorded_pause:
                reason = sanitize_text(result.deferred_reason or '').strip()
                blockers.append(sanitize_text(f"{label} · {result.outcome}")
                                + (f"\nReason: {reason}" if reason else ""))
            if (isinstance(event, ToolResultEvent) and call and call.operation == "record_result"
                    and call.candidate_id == candidate.id and event.status == "success" and not event.err
                    and result.outcome in {"blocked", "authorization-required", "browser-required", "deferred", "insufficient-evidence"}):
                try:
                    receipt = json.loads(event.result)
                except (ValueError, TypeError):
                    receipt = None
                recorded = receipt.get("result") if isinstance(receipt, dict) else None
                if (isinstance(receipt, dict) and receipt.get("ok") is True and isinstance(recorded, dict)
                        and recorded.get("candidate_id") == candidate.id
                        and recorded.get("outcome") == result.outcome
                        and recorded.get("result_id") == result.result_id
                        and (not call.attempt_id or call.attempt_id == result.attempt_id)):
                    status = "incomplete" if result.outcome == "insufficient-evidence" else "paused"
                    text = f"Validation {status} · {validation_label(candidate)}\n  Reason · {result.outcome.replace('-', ' ')}"
                    if result.deferred_reason:
                        text += ": " + concise_text(result.deferred_reason)
                    milestones.append(("validation-pause:" + candidate.id + ":" + validation_result_fingerprint(result), "warning", text))

    selection = getattr(getattr(agent, "_pending_context", None), "capture_selection", None)
    if selection is None:
        selection = getattr(agent, "pending_capture_selection", None)
    if selection is not None and selection.origin.as_url() == origin:
        for row in selection.requests:
            records.append(ProgressRecord("capture", row.baseline_request_ref or row.signature,
                                          endpoint_label(row.method, row.endpoint), "burp"))

    if objective:
        if objective.target_origin != origin:
            pending.append("active target differs from objective")
            blockers.append("active target differs from objective")
        else:
            for goal in objective.requested_goals:
                if goal.status not in {"tested_confirmed", "tested_not_confirmed", "no_candidate"}:
                    goals += 1
                    pending.append("requested goal " + goal.status.replace("_", " "))
                    if goal.status in {"blocked", "unsupported"}:
                        blockers.append(sanitize_text(f"{goal.candidate_class}: {goal.status}"))
            if objective.mode == "whole_target":
                from src.workflow.state import REQUIRED_WHOLE_TARGET_PHASES
                if any(phase not in workflow.completed_phases(objective) for phase in REQUIRED_WHOLE_TARGET_PHASES):
                    pending.append("required workflow phases incomplete")
                for phase, reason in artifact_errors.items():
                    repair = sanitize_text(f"phase artifact repair required:{phase}: {reason}")
                    pending.append(repair)
                    blockers.append(repair)

    overview = ""
    completion_supported = False
    if objective and objective.mode == "whole_target" and objective.target_origin == origin:
        from src.workflow.state import REQUIRED_WHOLE_TARGET_PHASES
        from src.agent.decision_planner import PlannerContext
        completed = workflow.completed_phases(objective)
        readiness = tool.next_phase_completion_readiness() if isinstance(tool, WorkflowTool) else None
        phase = PlannerContext(objective_mode=objective.mode, completed_phases=completed,
            phase_completion_readiness=readiness,
            pending_input_count=sum(item.disposition == "pending" for item in workflow.objective_inputs()),
            blocked_input_count=sum(item.disposition == "blocked" for item in workflow.objective_inputs())).structured_phase
        work = {"recon": "Recon", "enumeration": "Enumeration", "input_analysis": "Input Analysis",
                "validation": "Validation"}.get(phase or "", "Assessment")
        if readiness and readiness.get("historically_completed"):
            work += " repair"
        if isinstance(tool, WorkflowTool):
            owned = next((handoff for candidate in candidates
                          if (handoff := tool.validation_handoff(candidate.id, policy)) and handoff["owned_active"]), None)
            if owned:
                work = "Validation"
                if owned["probing_stopped"]:
                    work += " finalization"
                elif owned["recovery"]["rejections"] or owned["recovery"]["repair_turns"]:
                    work += " recovery"
        parts = (["Blocked", work] if blockers else [work])
        # Progress summarizes current work; detailed dispositions/results stay
        # in their records. Exclusions and accepted negatives are not findings.
        findings = sum(workflow.finding_is_persisted(candidate.id) for candidate in candidates)
        parts.append(f"{findings} {'finding' if findings == 1 else 'findings'}")
        if parts:
            overview = "Workflow · " + " · ".join(dict.fromkeys(parts))
        completion_supported = all(phase in completed for phase in REQUIRED_WHOLE_TARGET_PHASES) and not pending

    activity = ""
    activity_skill = ""
    if call:
        candidate = workflow.candidates.get(call.candidate_id)
        if candidate in candidates and candidate is not None:
            activity = endpoint_label(candidate.method, candidate.endpoint, candidate.parameter)
            if call.name == "http" and call.activity:
                geometry = endpoint_label(candidate.method, candidate.endpoint)
                activity = call.activity
                if call.activity == geometry and candidate.parameter:
                    activity += sanitize_text(f" · input {candidate.parameter}")
            elif call.operation:
                activity = call.operation.replace("_", " ") + " · " + activity
            # A class route identifies its expert; activation is checked by the reducer.
            from src.workflow.validation.route import resolve_validation_route
            route = resolve_validation_route(getattr(tool, "skills", None), candidate.candidate_class)
            if route.kind == "expert":
                activity_skill = route.skill_name or ""
            if (isinstance(event, ToolResultEvent) and call.operation == "start_validation"
                    and event.status == "success" and not event.err and not event.error_kind):
                try:
                    receipt = json.loads(event.result)
                except (ValueError, TypeError):
                    receipt = None
                context = receipt.get("validation_context") if isinstance(receipt, dict) else None
                attempt_id = context.get("attempt_id") if isinstance(context, dict) else None
                attempt = workflow.attempts.get(attempt_id) if isinstance(attempt_id, str) else None
                if (isinstance(receipt, dict) and receipt.get("ok") is True and isinstance(attempt, dict)
                        and candidate.status == "validating" and attempt.get("status") == "active"
                        and attempt.get("candidate_id") == candidate.id
                        and attempt.get("candidate_binding") == candidate_binding(candidate)
                        and attempt.get("objective_id") == (objective.id if objective else None)
                        and attempt.get("target_origin") == origin
                        and attempt.get("target_revision") == getattr(agent.target, "revision", None)
                        and attempt.get("session_id") == getattr(tool, "session_id", None)
                        and (policy is None or attempt.get("epoch") == policy.engagement.http_permissions.epoch)):
                    milestones.append(("attempt:" + attempt["id"], "info", "Validation started · " +
                                       validation_label(candidate)))
        if (isinstance(event, ToolResultEvent) and event.status == "success" and not event.err
                and event.name == "confirm_finding"):
            receipt = re.match(r'^Finding "([^\n]*)" written to ([^\n]+)', event.result)
            if (receipt and candidate in candidates and candidate is not None
                    and workflow.finding_is_persisted(candidate.id)
                    and accepted_result(workflow, candidate, workflow.latest_result(candidate.id), policy)):
                result = workflow.latest_result(candidate.id)
                assert result is not None
                severity = result.assessment.get("severity")
                label = f" ({severity})" if severity in {"info", "low", "medium", "high", "critical"} else ""
                milestones.append((candidate.id + ":" + validation_result_fingerprint(result), "finding",
                                   f"Finding saved · {concise_text(receipt[1])}{label}\n  {sanitize_text(receipt[2])}"))
    return OutcomeFacts(scope, tuple(milestones), tuple(dict.fromkeys(pending)), validations,
                        tuple(dict.fromkeys(records)), activity, incomplete, goals, tuple(dict.fromkeys(blockers)),
                        activity_skill, overview=overview, completion_supported=completion_supported)
