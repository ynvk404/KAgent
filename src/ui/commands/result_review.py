"""Commit operator conclusions only while the reviewed workflow state is current."""
from __future__ import annotations

import json
from typing import Any

from src.permission.permission import PermissionRequest, Decision
from src.permission.runtime.execution import policy_for
from src.workflow.review import review_snapshot
from src.redact.redact import apply_evidence
from src.ui.core.state import Append, TranscriptEntry
from src.workflow.evidence import verify_evidence_reads


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
        args = {**(latest.to_dict() if latest else {}),
                "action": "record_result", "candidate_id": cid, "outcome": outcome,
                "evidence_refs": list(refs), "skill_name": candidate.candidate_class,
                "force": True}
        validators = agent.skills.validators_for_class(candidate.candidate_class)
        if len(validators) == 1:
            args["skill_name"] = validators[0].name
        ticket = policy.observations.begin_review(cid)
        snapshot = review_snapshot(agent.workflow, cid)
        receipt = policy.prepare(tool, args)
        token = policy.start(receipt, tool, args, None)
        stamp = policy.stamp()
        epoch = policy.engagement.http_permissions.epoch

        def unchanged(expected: str = snapshot) -> None:
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
                  f"Exact result: {apply_evidence(json.dumps(latest.to_dict() if latest else None))}\n"
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
        with policy.observations._staged_operator_result(
            candidate, refs, outcome, severity, impact, epoch,
            ticket=ticket, guard=unchanged,
        ) as certificate:
            result = await tool.run(args, None, agent.prompter)
            payload = json.loads(result)
            committed = agent.workflow.latest_result(cid)
            if (payload.get("ok") is not True or committed is None
                    or payload.get("result") != committed.to_dict()
                    or committed.outcome != outcome or committed.coverage_synced is False):
                raise ValueError("record_result did not commit the reviewed conclusion")
            committed_snapshot = review_snapshot(agent.workflow, cid)
            unchanged(committed_snapshot)
            await agent.save()
            unchanged(committed_snapshot)
            if not await verify_evidence_reads(artifacts, policy.root, agent.prompter, None):
                raise ValueError("committed proof changed/unavailable")
            unchanged(committed_snapshot)
            policy.observations._commit_review(
                agent.workflow, candidate, refs, certificate, ticket,
            )
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
