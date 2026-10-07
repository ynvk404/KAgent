"""F1/F2/F3 regressions through offline production HTTP/workflow dispatch."""
from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.agent.agent import Agent, AgentOptions
from src.findings.store import Store
from src.permission.permission import Decision
from src.report.builder import build_report
from src.report.model import Resources, SourceSnapshot
from src.session.store import Store as SessionStore
from src.tools.workflow.finding import ConfirmFindingTool
from src.ui.commands.report_handler import capture_workflow
from src.ui.commands.result_review import review_result
from src.workflow.assessment import accepted_result, digest, seal, source_row
from src.workflow.state import WorkflowObjective
from tests.helpers.agent_fakes import FakeClient
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import ORIGIN, runtime


def declaration(*, required=True, role="readback", path="/readback"):
    return {"role": role, "method": "GET", "url": ORIGIN + path, "required": required}


async def collect(runtime, args, *, path="/readback", cap=65536):
    registry, p, policy, *_ = runtime
    await registry.execute("http", {"url": path, "phase": "validation", "max_response_bytes": cap}, None, p)
    oid = next(reversed(policy.observations._items))
    args["observation_ids"].append(oid)
    return oid


async def enrich(runtime, candidate):
    registry, p, *_ = runtime
    output = json.loads(await registry.execute("workflow", {
        "action": "record_candidate", "candidate_class": candidate.candidate_class,
        "target": candidate.target, "endpoint": candidate.endpoint, "method": candidate.method,
        "parameter": candidate.parameter, "location": candidate.location, "source_ref": "capture:new",
    }, None, p))
    assert not output["created"] and output["candidate"]["id"] == candidate.id


def report(state, policy, tmp_path):
    snapshot = SourceSnapshot(target=ORIGIN, exported_at="2026-10-07T00:00:00+00:00",
                              **capture_workflow(state, ORIGIN, policy))
    return snapshot, build_report(snapshot, Resources(tmp_path, (tmp_path / "artifacts/findings",), tmp_path))


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse", [False, True])
async def test_f1_ambiguous_declarations_rejected_before_new_attempt(runtime, tmp_path, reverse):
    state, candidate, _, _, _ = await setup(runtime, tmp_path)
    registry, p, *_ = runtime
    state.attempts.clear()
    candidate.status = "queued"
    declarations = [declaration(required=False, role="cleanup"), declaration()]
    if reverse:
        declarations.reverse()
    before = deepcopy(state.to_dict())
    output = await registry.execute("workflow", {"action": "start_validation",
        "candidate_id": candidate.id, "related_requests": declarations}, None, p)
    assert output.startswith("error: ambiguous duplicate"), output
    assert state.to_dict() == before and not state.attempts


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
@pytest.mark.parametrize("failure", ["native-truncated", "failed", "incomplete", "missing"])
async def test_f1_required_step_needs_completed_primary(runtime, tmp_path, outcome, failure):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path, related=[declaration()])
    registry, p, policy, *_ = runtime
    if failure != "missing":
        oid = await collect(runtime, args, cap=1 if failure == "native-truncated" else 65536)
        if failure == "native-truncated":
            assert policy.observations._items[oid].truncated is True
            assert policy.observations._items[oid].complete is False
        else:
            item = replace(policy.observations._items[oid], **(
                {"execution_status": "failed"} if failure == "failed" else {"complete": False}))
            policy.observations._items[oid] = replace(item, retained_hash=digest(source_row(item)))
    output = await registry.execute("workflow", {**args, "outcome": outcome}, None, p)
    assert output.startswith("error:"), output
    assert not state.validation_results and not state.eligible_for_finding(candidate.id)
    assert tool.coverage is not None and not await tool.coverage.list()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_f1_complete_required_with_native_optional_partial(runtime, tmp_path, outcome):
    state, candidate, _, args, _ = await setup(runtime, tmp_path, related=[
        declaration(), declaration(required=False, role="cleanup", path="/cleanup")])
    registry, p, policy, *_ = runtime
    await collect(runtime, args)
    partial = await collect(runtime, args, path="/cleanup", cap=1)
    assert policy.observations._items[partial].truncated
    output = json.loads(await registry.execute("workflow", {**args, "outcome": outcome}, None, p))
    assert output["result"]["coverage_synced"]
    assert accepted_result(state, candidate, state.latest_result(candidate.id), policy)


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
@pytest.mark.parametrize("malformed", ["duplicate", "missing-required", "role-override"])
async def test_f1_historical_malformed_manifest_resume_and_review(runtime, tmp_path, reverse, outcome, malformed):
    # Build the old defect from real optional truncated output. Only persisted
    # association metadata is injected; native Observation bytes stay untouched.
    state, candidate, tool, args, _ = await setup(runtime, tmp_path,
        related=[declaration(required=False, role="cleanup")])
    registry, p, policy, operator, *_ = runtime
    oid = await collect(runtime, args, cap=1)
    await registry.execute("workflow", {**args, "outcome": outcome}, None, p)
    latest = state.latest_result(candidate.id)
    assert latest is not None and accepted_result(state, candidate, latest, policy)
    attempt = state.attempts[args["attempt_id"]]
    if malformed == "duplicate":
        attempt["related_requests"].append(declaration())
        if reverse:
            attempt["related_requests"].reverse()
    elif malformed == "missing-required":
        attempt["related_requests"].append(declaration(path="/never-collected"))
    else:
        attempt["related_requests"] = [declaration()]
    latest.assessment["attempt"] = deepcopy({k: v for k, v in attempt.items() if k != "status"})
    latest.assessment_binding = seal(latest)
    assert not accepted_result(state, candidate, latest, policy)
    session = SessionStore.new_with_id(tmp_path / "sessions", "assessment-session")
    await session.save([], workflow=state)
    restored = session.load().workflow
    assert not accepted_result(restored, restored.candidates[candidate.id], restored.latest_result(candidate.id), policy)
    restored_result = restored.latest_result(candidate.id)
    assert restored_result is not None and restored_result.outcome == outcome
    # Resume the workflow tool too, so rejection must come from evidence
    # admissibility rather than a mismatched tool/runtime state object.
    tool.state = restored
    output = []
    app = SimpleNamespace(agent=SimpleNamespace(prompter=p, workflow=restored, tools=registry,
                         save=AsyncMock()), dispatch=output.append)
    operator.decision = Decision.ALLOW_ONCE
    await review_result(app, [candidate.id, "confirmed", "low", "Reviewed fixture."])
    assert output[-1].entry.kind == "error"
    assert "operator review cannot repair inadmissible primary evidence" in output[-1].entry.text
    assert len(operator.requests) == 1 and operator.requests[0].no_session_cache
    assert len(restored.validation_results) == 1
    assert not accepted_result(restored, restored.candidates[candidate.id], restored.latest_result(candidate.id), policy)
    assert policy.observations._items[oid].truncated


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["none", "source_ref", "auth_context_ref", "content_type", "test_case", "manifest", "binding"])
async def test_f2_export_current_v2_binding_without_proof_reads(runtime, tmp_path, drift):
    state, candidate, _, args, _ = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    await registry.execute("workflow", args, None, p)
    registry.register(ConfirmFindingTool(Store(project_directory=tmp_path), workflow=state))
    await registry.execute("confirm_finding", {"candidate_id": candidate.id, "title": "Fixture",
        "url": ORIGIN + "/fixture", "severity": "low", "observed_impact": "Fixture response observed.",
        "potential_impact": "No additional impact assessed."}, None, p)
    latest = state.latest_result(candidate.id)
    assert latest is not None
    if drift == "source_ref":
        await enrich(runtime, candidate)
    elif drift in {"auth_context_ref", "content_type", "test_case"}:
        setattr(candidate, drift, "changed-context")
    elif drift == "manifest":
        latest.evidence_manifest[0]["source"]["required"] = False
        latest.assessment_binding = seal(latest)
    elif drift == "binding":
        latest.assessment_binding = "b" * 64
    before = deepcopy(state.to_dict())
    # Export can retain historical matched reports with missing proof bytes;
    # it checks structural state only and never invokes evidence read gates.
    (tmp_path / state.evidence[args["evidence_refs"][0]].path).unlink()
    snapshot, doc = report(state, policy, tmp_path)
    assert snapshot.results[0].get("current_admissible") is (drift == "none")
    assert snapshot.results[0].get("evidence_manifest") is None
    assert state.to_dict() == before
    if drift == "none":
        assert doc.finding_count == 1 and doc.unfinalized_count == doc.unavailable_count == 0
        assert "assessment source: agent" in doc.validations[0][1]
        assert "Referenced evidence file unavailable" in doc.evidence[0][1]
    else:
        assert doc.finding_count == 0 and doc.unfinalized_count == doc.unavailable_count == 1
        assert "invalid/unavailable" in doc.validations[0][1]
        assert "No confirmed findings recorded in this assessment." not in doc.summary
    assert "not independently revalidated" in " ".join(doc.limitations)


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["source_ref", "manifest", "binding"])
async def test_f2_invalid_negative_cannot_close_or_project_current_coverage(runtime, tmp_path, drift):
    from dataclasses import asdict
    from src.report.model import freeze
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    assert state.objective is not None
    state.objective.mode = "candidate_validation"
    state.objective.candidate_id = candidate.id
    await registry.execute("workflow", {**args, "outcome": "not-confirmed"}, None, p)
    latest = state.latest_result(candidate.id)
    assert latest is not None
    valid, doc = report(state, policy, tmp_path)
    assert "prerequisites satisfied" in doc.status
    if drift == "source_ref":
        candidate.source_ref = "capture:new"
    elif drift == "manifest":
        latest.evidence_manifest[0]["source"]["required"] = False
        latest.assessment_binding = seal(latest)
    else:
        latest.assessment_binding = "b" * 64
    assert tool.coverage is not None
    coverage = tuple(freeze(asdict(row)) for row in await tool.coverage.list())
    snapshot, _ = report(state, policy, tmp_path)
    doc = build_report(replace(snapshot, coverage=coverage), Resources(tmp_path, (), tmp_path))
    assert snapshot.results[0].get("projection") is None
    assert "Partial" in doc.status and "prerequisites satisfied" not in doc.status
    assert all("latest canonical outcome: not-confirmed" not in row[1] for row in doc.coverage)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_f3_public_enrichment_planner_revalidation_and_fresh_ownership(runtime, tmp_path, outcome):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, p, policy, *_, target = runtime
    await registry.execute("workflow", {**args, "outcome": outcome}, None, p)
    await enrich(runtime, candidate)
    assert not accepted_result(state, candidate, state.latest_result(candidate.id), policy)
    assert tool.skills is not None
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=tool.skills,
                  prompter=p, target=target, workflow=state, store=None))
    assert f"revalidate:{candidate.id}" in agent._whole_target_state()[1]
    started = json.loads(await registry.execute("workflow", {"action": "start_validation", "candidate_id": candidate.id}, None, p))
    aid = started["validation_context"]["attempt_id"]
    assert aid != args["attempt_id"]
    submission = {**args, "attempt_id": aid, "outcome": outcome}
    rejected = await registry.execute("workflow", submission, None, p)
    assert rejected.startswith("error:") and "ownership" in rejected
    assert len(state.validation_results) == 1
    submission["observation_ids"] = []
    await collect(runtime, submission, path="/fixture?q=fresh")
    output = json.loads(await registry.execute("workflow", submission, None, p))
    assert output["result"]["attempt_id"] == aid and output["result"]["coverage_synced"]
    assert accepted_result(state, candidate, state.latest_result(candidate.id), policy)


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["valid", "missing-proof", "tampered-proof"])
async def test_f3_terminal_reopen_preserves_explicit_retest_and_proof_repair(runtime, tmp_path, reason):
    state, candidate, _, args, _ = await setup(runtime, tmp_path)
    registry, p, *_ = runtime
    await registry.execute("workflow", args, None, p)
    proof = tmp_path / state.evidence[args["evidence_refs"][0]].path
    if reason == "missing-proof":
        proof.unlink()
    elif reason == "tampered-proof":
        proof.chmod(0o600)
        proof.write_text("changed proof")
    output = await registry.execute("workflow", {"action": "start_validation", "candidate_id": candidate.id}, None, p)
    if reason == "valid":
        assert output.startswith("error: terminal candidate cannot be reopened")
    else:
        assert json.loads(output)["validation_context"]["attempt_id"] != args["attempt_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["candidate", "target", "objective", "route", "policy"])
async def test_f3_reopen_fails_closed_on_evidence_await_drift(runtime, tmp_path, monkeypatch, drift):
    import src.tools.workflow.workflow_tool as module
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, p, policy, *_, target = runtime
    await registry.execute("workflow", args, None, p)
    await enrich(runtime, candidate)
    attempts = set(state.attempts)
    original = module.verify_evidence_reads
    async def changed(*a, **kw):
        readable = await original(*a, **kw)
        if drift == "candidate":
            candidate.auth_context_ref = "changed"
        elif drift == "target":
            target.set_base_url(ORIGIN + "/changed")
        elif drift == "objective":
            state.objective = WorkflowObjective("changed", "whole_target", ORIGIN)
        elif drift == "route":
            assert tool.skills is not None
            tool.skills.set_disabled_names(["cross-site-scripting"])
        else:
            policy.engagement.http_permissions.reset()
        return readable
    monkeypatch.setattr(module, "verify_evidence_reads", changed)
    output = await registry.execute("workflow", {"action": "start_validation", "candidate_id": candidate.id}, None, p)
    assert output.startswith("error:") and "changed" in output
    assert set(state.attempts) == attempts and candidate.status == "validated"
