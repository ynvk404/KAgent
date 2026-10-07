"""Commit operator conclusions only while the reviewed workflow state is current."""
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime
import uuid
import json
from typing import Any, cast

from src.permission.permission import PermissionRequest, Decision
from src.permission.runtime.execution import policy_for
from src.workflow.review import review_snapshot
from src.workflow.assessment import accepted_result, seal, resolve_sources, candidate_binding
from src.workflow.state import ValidationResult, ValidationOutcome, validation_result_fingerprint
from src.coverage.context import project_candidate_coverage
from src.tools.workflow.workflow_tool import WorkflowTool
from src.redaction.redact import apply_evidence
from src.ui.core.state import Append, TranscriptEntry
from src.workflow.evidence import verify_evidence_reads
from src.workflow.validation_route import GENERIC_VALIDATOR, ValidationRoute, resolve_validation_route, generic_admission


async def review_result(app: Any, rest: list[str]) -> None:
    agent = app.agent
    policy = policy_for(agent.prompter)
    token = receipt = None
    ticket = cid = None
    try:
        if policy is None or len(rest) < 4:
            raise ValueError("usage: /review-result <candidate-id> <confirmed|not-confirmed> <severity> <observed impact>")
        cid, outcome, severity = rest[:3]
        if outcome not in {"confirmed", "not-confirmed"} or severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("invalid review outcome/severity")
        outcome = cast(ValidationOutcome, outcome)
        candidate = agent.workflow.candidates[cid]
        policy.engagement.require_in_scope(candidate.target or "")
        latest = agent.workflow.latest_result(cid)
        impact = " ".join(rest[3:])
        if not impact.strip():
            raise ValueError("observed impact is required")
        refs = tuple(latest.evidence_refs) if latest else tuple(
            e.id for e in agent.workflow.evidence.values() if e.candidate_id == cid
        )
        artifacts = [agent.workflow.evidence[ref] for ref in refs]
        tool = agent.tools.get("workflow")
        if tool is None:
            raise ValueError("workflow tool unavailable")
        registry = getattr(tool, "skills", None)
        policy.bind_validation_context(agent.workflow, registry, getattr(tool, "target", None))
        route = resolve_validation_route(registry, candidate.candidate_class)
        # Preserve the existing library-only expert review contract. Production
        # always has a registry/objective. This exception cannot select generic
        # or import a saved generic result into the compatibility path.
        legacy_expert = (registry is None and agent.workflow.objective is None
                         and candidate.objective_id is None
                         and (latest is None or latest.skill_name != GENERIC_VALIDATOR))
        if legacy_expert:
            route = ValidationRoute("expert", candidate.candidate_class)
        if route.kind not in {"expert", "generic"}:
            raise ValueError(route.reason)
        generic = route.kind == "generic"
        def check_route():
            if legacy_expert:
                if agent.workflow.objective is not None or getattr(tool, "skills", None) is not None:
                    raise ValueError("legacy expert review context changed")
            elif resolve_validation_route(getattr(tool, "skills", None), candidate.candidate_class) != route:
                raise ValueError("reviewed validator route changed")
            if generic:
                reason = generic_admission(candidate, agent.workflow, getattr(tool, "skills", None),
                                           getattr(tool, "target", None), policy)
                if reason:
                    raise ValueError(reason)
                policy.generic_validation.idle()
        check_route()
        args = {
                "action": "record_result", "candidate_id": cid, "outcome": outcome,
                "evidence_refs": list(refs), "skill_name": route.skill_name,
                "force": True}
        ticket = policy.observations.begin_review(cid)
        snapshot = review_snapshot(agent.workflow, cid)
        receipt = policy.prepare(tool, args)
        token = policy.start(receipt, tool, args, None)
        stamp = policy.stamp()
        epoch = policy.engagement.http_permissions.epoch

        def unchanged(expected: str = snapshot) -> None:
            check_route()
            if (not policy.observations.review_is_current(cid, ticket)
                    or policy.stamp() != stamp
                    or agent.workflow.candidates.get(cid) is not candidate
                    or review_snapshot(agent.workflow, cid) != expected):
                raise ValueError("reviewed candidate/result/policy changed or review superseded")

        if not artifacts or not await verify_evidence_reads(artifacts, policy.root, agent.prompter, None):
            raise ValueError("evidence changed/unavailable")
        unchanged()
        proof = "\n\n".join(apply_evidence(policy.require_evidence(e, policy.root).read_text(errors="replace")) for e in artifacts)
        detail = (f"Source: operator-reviewed, not autonomous. This reviews a conclusion, "
                  f"not execution permission.\n"
                  f"{apply_evidence(json.dumps(candidate.to_dict()))}\n"
                  f"Exact result: {apply_evidence(json.dumps(latest.public_dict() if latest else None))}\n"
                  f"Evidence: {refs}\nImpact: {apply_evidence(impact)}\n\n{proof}")
        review = getattr(agent.prompter, "operator_review_prompter", lambda: agent.prompter)()
        decision = await review.ask(PermissionRequest(
            tool="review_result", summary=f"Review {candidate.candidate_class}: {outcome}",
            detail=detail, no_session_cache=True,
        ), None)
        if decision != Decision.ALLOW_ONCE:
            raise ValueError("conclusion review declined; proof remains unverified")
        unchanged()
        if not await verify_evidence_reads(artifacts, policy.root, agent.prompter, None):
            raise ValueError("reviewed evidence changed/unavailable")
        unchanged()
        # Only a private workflow revision is staged. No semantic certificate
        # or operator authority is visible in canonical state before checkpoint.
        async with agent.workflow.mutation_lock:
            unchanged()
            staged = deepcopy_workflow(agent.workflow)
            if latest is not None and latest.assessment_contract_version >= 2 and latest.evidence_manifest:
                revision = deepcopy(latest)
            else:
                aid = policy.generic_validation.durable_attempt
                attempt = staged.attempts.get(aid)
                ids = [item.id for item in policy.observations._items.values() if item.attempt_id == aid]
                manifest = resolve_sources(policy, staged, candidate, attempt, ids, terminal=True,
                                           negative=outcome == "not-confirmed")
                if not attempt or not manifest:
                    raise ValueError("review requires primary source provenance; legacy summary remains historical")
                assert route.skill_name is not None
                revision = ValidationResult(cid, route.skill_name, outcome,
                    evidence_refs=list(refs), session_id=tool.session_id,
                    objective_id=agent.workflow.objective.id if agent.workflow.objective else None,
                    assessment_contract_version=2, attempt_id=aid,
                    candidate_binding=candidate_binding(candidate), evidence_manifest=manifest,
                    assessment={"hypothesis": "Operator assessment of " + candidate.candidate_class,
                        "criteria": "Operator review of selected primary evidence",
                        "limitations": "Limited to the reviewed bounded observations",
                        "artifacts": [e.to_dict() for e in artifacts],
                        "artifact_sources": {e.id: list(staged.evidence_sources.get(e.id, [])) for e in artifacts},
                        "attempt": {k:v for k,v in attempt.items() if k != "status"}})
                staged.attempts[aid]["status"] = "completed"
            revision.result_id = "result_" + uuid.uuid4().hex
            revision.recorded_at = datetime.now(UTC).isoformat()
            revision.supersedes = latest.result_id if latest else None
            revision.assessment_source = "operator"
            revision.outcome = outcome
            revision.assessment.update(observed_impact=apply_evidence(impact), severity=severity,
                                       completed_attempt=True)
            revision.coverage_synced = False if tool.coverage is not None else None
            revision.assessment_binding = seal(revision)
            staged.add_validation_result(revision, force=True)
            if not accepted_result(staged, staged.candidates[cid], revision, policy):
                raise ValueError("operator review cannot repair inadmissible primary evidence")
            projection = WorkflowTool(staged, tool.target, tool.coverage, tool.skills,
                                      tool.evidence_root, tool.session_id)
            checkpoint_written = False
            coverage_before = None
            projection_context = None
            if tool.coverage is not None:
                endpoint, parameter, context = project_candidate_coverage(staged, staged.candidates[cid], revision)
                projection_context = (endpoint, parameter, context)
                coverage_before = deepcopy(await tool.coverage.get(endpoint=endpoint, param=parameter,
                    vulnClass=candidate.candidate_class, context=context))
                unchanged()
            try:
                if revision.coverage_synced is False:
                    await projection._sync_coverage(staged.candidates[cid], revision)
                unchanged()
                if not await verify_evidence_reads(artifacts, policy.root, agent.prompter, None):
                    raise ValueError("reviewed proof changed/unavailable")
                unchanged()
                checkpoint = asyncio.create_task(agent.save(workflow_override=staged, _workflow_locked=True))
                try:
                    await asyncio.shield(checkpoint)
                    checkpoint_written = True
                except asyncio.CancelledError:
                    # Finish any pending writer before restoring the canonical
                    # checkpoint; an offloaded save cannot publish later.
                    while not checkpoint.done():
                        try:
                            await asyncio.shield(checkpoint)
                        except asyncio.CancelledError:
                            continue
                    checkpoint.result()
                    await agent.save(_workflow_locked=True)
                    raise
                unchanged()
                if not await verify_evidence_reads(artifacts, policy.root, agent.prompter, None):
                    raise ValueError("checkpointed proof changed/unavailable")
                unchanged()
                if not accepted_result(staged, staged.candidates[cid], revision, policy):
                    raise ValueError("checkpointed primary evidence changed/unavailable")
            except BaseException:
                if checkpoint_written:
                    await agent.save(_workflow_locked=True)
                # Projection is derived. Reconcile from the previous canonical
                # result, and never insert the staged operator revision.
                if tool.coverage is not None and projection_context is not None:
                    endpoint, parameter, context = projection_context
                    await tool.coverage.rollback_validation_projection(endpoint=endpoint, param=parameter,
                        vulnClass=candidate.candidate_class, context=context,
                        expected_notes=f"result={validation_result_fingerprint(revision)[:20]}",
                        previous=coverage_before)
                    canonical = agent.workflow.latest_result(cid)
                    if accepted_result(agent.workflow, candidate, canonical, policy):
                        await tool._sync_coverage(candidate, canonical)
                raise
            # The production session writer is synchronous through replace;
            # there is no suspension between final guard and publication.
            if revision.attempt_id in staged.attempts:
                agent.workflow.attempts[revision.attempt_id] = staged.attempts[revision.attempt_id]
            agent.workflow.validation_results.append(revision)
            boundary = policy.generic_validation
            if boundary.started_candidate == cid:
                boundary.started_candidate = boundary.started_objective = None
                boundary.attempt = None
            if boundary.expert_attempt and boundary.expert_attempt[0] == cid:
                boundary.expert_attempt = None
            agent.workflow.set_candidate_status(cid, "validated")
            result = json.dumps({"ok": True, "result": revision.public_dict()})
        app.dispatch(Append(entry=TranscriptEntry(kind="system", text=result)))
    except Exception as exc:
        app.dispatch(Append(entry=TranscriptEntry(kind="error", text=f"Result review: {type(exc).__name__}: {exc}")))
    finally:
        if policy is not None and cid is not None and ticket is not None:
            policy.observations.finish_review(cid, ticket)
        if policy is not None and token is not None:
            policy.stop(token)
        if policy is not None and receipt is not None:
            policy.finish_review(receipt)


def deepcopy_workflow(state):
    from src.workflow.state import WorkflowState
    cloned = WorkflowState.from_dict(state.to_dict())
    cloned.attempts = deepcopy(state.attempts)
    return cloned
