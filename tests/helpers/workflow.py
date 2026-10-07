from __future__ import annotations

from typing import Any

from src.permission.permission import AlwaysAllow
from src.workflow.state import PHASE_COVERAGE_DIMENSIONS, WorkflowPhase, WorkflowState


def record_completed_phase(
    state: WorkflowState,
    phase: WorkflowPhase,
    *,
    objective_id: str,
    target_origin: str,
    artifact_ref: str,
    no_inputs_discovered: bool = False,
) -> bool:
    """Seed explicit non-production coverage for synthetic workflow fixtures."""
    for dimension in PHASE_COVERAGE_DIMENSIONS.get(phase, ()):
        state.record_phase_coverage(
            phase,
            dimension,
            "not_applicable",
            objective_id=objective_id,
            target_origin=target_origin,
            reason="test fixture does not exercise this discovery dimension",
        )
    return state.record_phase_completion(
        phase,
        objective_id=objective_id,
        target_origin=target_origin,
        artifact_ref=artifact_ref,
        no_inputs_discovered=no_inputs_discovered,
    )


async def record_phase_coverage_for_test(tool: Any, phase: str) -> None:
    for dimension in PHASE_COVERAGE_DIMENSIONS.get(phase, ()):
        await tool.run(
            {
                "action": "record_phase_coverage",
                "phase": phase,
                "coverage_dimension": dimension,
                "coverage_status": "not_applicable",
                "coverage_reason": "test fixture does not exercise this discovery dimension",
            },
            None,
            AlwaysAllow(),
        )


def adopt_fixture_assessment(state, result, *, policy=None, assessment=None):
    """Controller fixture: recorded redacted transport bytes, never proof prose.

    Used by consumer-only tests. Production source/admission is covered with
    actual offline HTTP dispatch in tests/security/test_agent_assessment.py.
    """
    from types import SimpleNamespace
    import uuid
    from src.permission.runtime.observations import ObservationStore
    from src.workflow.assessment import start_attempt, candidate_binding, source_row, seal
    from urllib.parse import urljoin
    if result.outcome not in {"confirmed", "not-confirmed"} or not result.evidence_refs:
        return result
    candidate = state.candidates[result.candidate_id]
    epoch = policy.engagement.http_permissions.epoch if policy else "fixture-epoch"
    attempt = start_attempt(state, candidate, result.session_id, epoch, target_origin=candidate.target or "https://target.test")
    owner = {key: attempt[key] for key in ("id", "candidate_id", "candidate_binding", "session_id", "objective_id", "epoch")}
    store = policy.observations if policy else ObservationStore()
    action = SimpleNamespace(epoch=epoch, method=candidate.method or "GET",
        url=urljoin(candidate.target or "https://target.test", (candidate.endpoint or "/fixture").split(" ")[-1]),
        transport_address="fixture-transport", digest="fixture-request-digest", response_cap=65536)
    oid = store.capture(action, 200, b"Recorded controller fixture response", complete=True, owner=owner)
    item = store._items[oid]
    row = source_row(item)
    row["role"] = "probe"
    result.assessment_contract_version = 2
    result.assessment_source = "agent"
    result.result_id = "result_" + uuid.uuid4().hex
    result.attempt_id = attempt["id"]
    result.candidate_binding = candidate_binding(candidate)
    result.objective_id = state.objective.id if state.objective else None
    result.evidence_manifest = [{"source": row, "hash": item.retained_hash}]
    result.assessment = {"hypothesis": "Fixture hypothesis", "criteria": "Bounded fixture criteria",
        "limitations": "Offline fixture only", "completed_attempt": True,
        "observed_impact": "The linked evidence demonstrates the behavior.", "severity": "medium",
        **(assessment or {}), "artifacts": [state.evidence[ref].to_dict() for ref in result.evidence_refs],
        "attempt": {k:v for k,v in attempt.items() if k != "status"}}
    result.assessment_binding = seal(result)
    attempt["status"] = "completed"
    return result


async def run_workflow_fixture(tool, args, signal, prompter):
    """Prepare primary source fixture only for valid terminal consumer scenarios."""
    import uuid
    from types import SimpleNamespace
    from urllib.parse import urljoin
    from src.permission.runtime.execution import policy_for
    from src.workflow.assessment import start_attempt
    runner = getattr(tool, "_fixture_production_run", tool.run)
    if args.get("action") != "record_result" or args.get("outcome") not in {"confirmed", "not-confirmed"}:
        return await runner(args, signal, prompter)
    args = dict(args)
    candidate = tool.state.candidates.get(args.get("candidate_id"))
    if candidate is None or not args.get("evidence_refs"):
        return await runner(args, signal, prompter)
    if not tool.state.evidence_matches(candidate.id, args["evidence_refs"]):
        return await runner(args, signal, prompter)
    if any(not tool.state.evidence[ref].is_available_for_resume(tool.evidence_root) for ref in args["evidence_refs"]):
        return await runner(args, signal, prompter)
    policy = policy_for(prompter)
    epoch = policy.engagement.http_permissions.epoch if policy else tool.evidence_epoch
    if policy:
        policy.bind_validation_context(tool.state, tool.skills, tool.target)
    latest = tool.state.latest_result(candidate.id)
    fields = ("outcome", "skill_name", "evidence_refs", "techniques", "repeatable", "confirmation", "mutation_performed")
    if (latest and latest.objective_id == (tool.state.objective.id if tool.state.objective else None) and not args.get("force") and latest.attempt_id == tool.active_attempt
            and tool.state.attempts[latest.attempt_id]["status"] != "active"
            and all(getattr(latest, key) == args.get(key, [] if key in {"evidence_refs", "techniques"}
                                                   else False if key == "mutation_performed" else None) for key in fields)):
        args.update(attempt_id=latest.attempt_id, observation_ids=[e["source"]["id"] for e in latest.evidence_manifest],
                    assessment={k:v for k,v in latest.assessment.items() if k not in {"artifacts", "artifact_sources", "attempt"}})
        return await runner(args, signal, prompter)
    attempt = start_attempt(tool.state, candidate, tool.session_id, epoch, target_origin=tool._active_target() or "https://target.test", target_revision=tool.target.revision if tool.target else None)
    tool.active_attempt = attempt["id"]
    if policy:
        policy.generic_validation.durable_attempt = attempt["id"]
    owner = {key: attempt[key] for key in ("id", "candidate_id", "candidate_binding", "session_id", "objective_id", "epoch")}
    store = policy.observations if policy else tool.observations
    action = SimpleNamespace(epoch=epoch, method=candidate.method or "GET",
        url=urljoin(candidate.target or "https://target.test", (candidate.endpoint or "/fixture").split(" ")[-1]),
        transport_address="fixture", digest="fixture-request", response_cap=65536)
    oid = store.capture(action, 200, b"Recorded transport fixture bytes", complete=True, owner=owner)
    args.update(attempt_id=attempt["id"], observation_ids=[oid], assessment={
        "hypothesis": "Fixture hypothesis", "criteria": "Bounded fixture criteria", "limitations": "Offline fixture",
        "completed_attempt": True, "observed_impact": "Fixture response observed.", "severity": "medium"})
    return await runner(args, signal, prompter)


class FixtureWorkflowToolMixin:
    """Explicit offline source adapter for Agent consumer/lifecycle fixtures."""
    async def run(self, args, signal, prompter):
        return await run_workflow_fixture(self, args, signal, prompter)

    async def _fixture_production_run(self, args, signal, prompter):
        parent: Any = super()
        return await parent.run(args, signal, prompter)
