"""Offline native production dispatch; no target or model is contacted."""
import asyncio
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.coverage.store import CoverageStore
from src.findings.store import Store, read_report
from src.permission.runtime.observations import ObservationStore
from src.permission.permission import Decision
from src.skills.registry import Registry as Skills
from src.tools.workflow.workflow_tool import WorkflowTool
from src.tools.workflow.finding import ConfirmFindingTool
from src.ui.commands.result_review import review_result
from src.workflow.assessment import accepted_result, digest, source_row, candidate_binding
from src.workflow.state import Candidate, WorkflowState, WorkflowObjective
from tests.security.test_execution_policy import runtime, ORIGIN

ASSESSMENT = {"hypothesis": "A bounded fixture response supports this candidate",
              "criteria": "Compare designated fixture behavior under the playbook",
              "limitations": "One bounded fixture attempt; no universal absence claim",
              "completed_attempt": True, "observed_impact": "Fixture response observed.",
              "severity": "low"}


async def setup(runtime, tmp_path, *, candidate_class="xss", related=None):
    registry, prompter, policy, _, _, _, target = runtime
    skills = Skills()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    state = WorkflowState(objective=WorkflowObjective("assessment-objective", "whole_target", ORIGIN))
    assert state.objective is not None
    candidate, _ = state.add_candidate(Candidate(candidate_class=candidate_class,
        target=ORIGIN, endpoint="/fixture", method="GET", parameter="q", location="query",
        objective_id=state.objective.id))
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    tool = WorkflowTool(state, target, coverage, skills, tmp_path, "assessment-session")
    registry.register(tool)
    started = json.loads(await registry.execute("workflow", {"action": "start_validation",
        "candidate_id": candidate.id, "related_requests": related or []}, None, prompter))
    assert started["ok"]
    await registry.execute("http", {"url": "/fixture?q=fixture", "phase": "validation"}, None, prompter)
    oid = next(reversed(policy.observations._items))
    (tmp_path / "proof.md").write_text("Agent analysis of the linked fixture response.")
    evidence = json.loads(await registry.execute("workflow", {"action": "record_evidence",
        "candidate_id": candidate.id, "evidence_path": "proof.md"}, None, prompter))["evidence"]["id"]
    args = {"action": "record_result", "candidate_id": candidate.id,
            "skill_name": "sql-injection" if candidate_class == "sqli" else "cross-site-scripting",
            "outcome": "confirmed", "evidence_refs": [evidence], "observation_ids": [oid],
            "attempt_id": started["validation_context"]["attempt_id"], "assessment": ASSESSMENT.copy()}
    return state, candidate, tool, args, oid


@pytest.mark.asyncio
@pytest.mark.parametrize("candidate_class", ["sqli", "xss"])
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_terminal_agent_assessment_without_verifier(runtime, tmp_path, candidate_class, outcome):
    state, candidate, _, args, _ = await setup(runtime, tmp_path, candidate_class=candidate_class)
    registry, p, policy, operator, _, _, _ = runtime
    assert not policy.observations._verifiers
    payload = json.loads(await registry.execute("workflow", {**args, "outcome": outcome}, None, p))
    assert payload["result"]["outcome"] == outcome
    latest = state.latest_result(candidate.id)
    assert latest is not None
    assert latest.assessment_source == "agent" and latest.coverage_synced
    assert accepted_result(state, candidate, latest, policy)
    assert not operator.requests and not policy.observations._results


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["missing", "body", "complete", "session_id", "objective_id",
    "candidate_id", "attempt_id", "candidate_binding", "epoch", "url", "method"])
async def test_invalid_source_never_publishes(runtime, tmp_path, change):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    if change == "missing":
        args["observation_ids"] = ["obs_missing"]
    else:
        item = policy.observations._items[oid]
        value = {"body": b"substituted", "complete": False, "url": "http://other.test/fixture",
                 "method": "POST"}.get(change, "wrong-owner")
        modified = replace(item, **{change: value})
        # Ownership/identity is tested independently of hash substitution.
        if change != "body":
            modified = replace(modified, retained_hash=digest(source_row(modified)))
        policy.observations._items[oid] = modified
    result = await registry.execute("workflow", args, None, p)
    assert result.startswith("error:"), result
    assert tool.coverage is not None
    assert not state.validation_results and not await tool.coverage.list()
    assert not state.eligible_for_finding(candidate.id)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_model_only_proof_rejected(runtime, tmp_path, outcome):
    state, _, _, args, _ = await setup(runtime, tmp_path)
    registry, p, *_ = runtime
    result = await registry.execute("workflow", {**args, "outcome": outcome, "observation_ids": []}, None, p)
    assert result.startswith("error:") and not state.validation_results


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["blocked", "insufficient-evidence", "deferred", "browser-required", "authorization-required"])
async def test_native_unresolved_kept(runtime, tmp_path, outcome):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    item = replace(policy.observations._items[oid], complete=False)
    policy.observations._items[oid] = replace(item, retained_hash=digest(source_row(item)))
    payload = json.loads(await registry.execute("workflow", {**args, "outcome": outcome}, None, p))
    assert payload["result"]["outcome"] == outcome
    assert tool.coverage is not None
    assert not await tool.coverage.list() and not state.eligible_for_finding(candidate.id)


@pytest.mark.asyncio
async def test_eviction_resume_and_new_attempt_cannot_borrow(runtime, tmp_path):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    await registry.execute("workflow", args, None, p)
    policy.observations._items.clear()  # selected redacted manifest survives eviction
    resumed = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
    assert accepted_result(resumed, resumed.candidates[candidate.id], resumed.latest_result(candidate.id), policy)
    # Explicit controller retest uses a new objective; historical source stays historical.
    state.objective = WorkflowObjective("retest", "candidate_validation", ORIGIN, candidate_id=candidate.id)
    candidate.status = "queued"
    started = json.loads(await registry.execute("workflow", {"action": "start_validation", "candidate_id": candidate.id}, None, p))
    assert started["validation_context"]["attempt_id"] != args["attempt_id"]
    out = await registry.execute("workflow", {**args, "attempt_id": started["validation_context"]["attempt_id"]}, None, p)
    assert out.startswith("error:")
    assert len(state.validation_results) == 1


@pytest.mark.asyncio
async def test_finding_adopts_revision_and_rejects_historical_report(runtime, tmp_path):
    state, candidate, _, args, _ = await setup(runtime, tmp_path)
    registry, p, _, operator, *_ = runtime
    await registry.execute("workflow", args, None, p)
    notifications = []
    store = Store(project_directory=tmp_path)
    registry.register(ConfirmFindingTool(store, lambda f, path: notifications.append(path), state))
    finding_args = {"candidate_id": candidate.id, "title": "Fixture", "url": ORIGIN + "/fixture",
        "observed_impact": "Caller claim", "potential_impact": "No additional impact assessed.", "severity": "critical"}
    first = await registry.execute("confirm_finding", finding_args, None, p)
    saved = read_report(Path(notifications[-1]))
    assert saved.assessment_source == "agent" and saved.severity == "low"
    assert saved.observed_impact == ASSESSMENT["observed_impact"]
    assert await registry.execute("confirm_finding", finding_args, None, p) == first
    output = []
    app = SimpleNamespace(agent=SimpleNamespace(prompter=p, workflow=state, tools=registry,
                        save=AsyncMock()), dispatch=output.append)
    operator.decision = Decision.ALLOW_ONCE
    await review_result(app, [candidate.id, "confirmed", "medium", "Reviewed fixture response."])
    assert output[-1].entry.kind == "system", output[-1]
    latest = state.latest_result(candidate.id)
    assert latest is not None
    assert latest.assessment_source == "operator"
    with pytest.raises(ValueError, match="historical report"):
        await registry.execute("confirm_finding", finding_args, None, p)
    assert not state.finding_is_persisted(candidate.id)
    assert len(notifications) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["save", "coverage", "cancel"])
async def test_private_operator_revision_failure_preserves_agent(runtime, tmp_path, monkeypatch, failure):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, p, policy, operator, *_ = runtime
    await registry.execute("workflow", args, None, p)
    previous = state.latest_result(candidate.id)
    output = []
    save = AsyncMock(side_effect=OSError("checkpoint failure") if failure == "save" else None)
    if failure == "cancel":
        save.side_effect = [asyncio.CancelledError(), None]
    if failure == "coverage":
        monkeypatch.setattr(WorkflowTool, "_sync_coverage", AsyncMock(side_effect=OSError("projection failure")))
    app = SimpleNamespace(agent=SimpleNamespace(prompter=p, workflow=state, tools=registry, save=save), dispatch=output.append)
    operator.decision = Decision.ALLOW_ONCE
    if failure == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await review_result(app, [candidate.id, "confirmed", "medium", "Reviewed response."])
    else:
        await review_result(app, [candidate.id, "confirmed", "medium", "Reviewed response."])
        assert output[-1].entry.kind == "error"
    assert previous is not None
    assert state.latest_result(candidate.id) is previous and previous.assessment_source == "agent"
    assert accepted_result(state, candidate, previous, policy)
    assert not policy.observations._results and not policy.observations._reviews


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["candidate", "target", "session", "objective", "execution"])
async def test_stale_binding_never_publishes(runtime, tmp_path, monkeypatch, mutation):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    if mutation == "execution":
        item = replace(policy.observations._items[oid], execution_status="failed")
        policy.observations._items[oid] = replace(item, retained_hash=digest(source_row(item)))
    elif mutation == "session":
        policy.session_id = "another-session"
    else:
        import src.tools.workflow.workflow_tool as module
        original = module.verify_evidence_reads
        async def changed(*a, **kw):
            readable = await original(*a, **kw)
            if mutation == "candidate":
                candidate.auth_context_ref = "different-identity"
            elif mutation == "target":
                runtime[-1].set_base_url(ORIGIN + "/changed")
            else:
                state.objective = WorkflowObjective("different-objective", "whole_target", ORIGIN)
            return readable
        monkeypatch.setattr(module, "verify_evidence_reads", changed)
    output = await registry.execute("workflow", args, None, p)
    assert output.startswith("error:"), output
    assert not state.validation_results
    assert tool.coverage is not None and not await tool.coverage.list()


@pytest.mark.asyncio
async def test_declared_multistep_required_sources(runtime, tmp_path):
    related = [{"role": "readback", "method": "GET", "url": ORIGIN + "/readback"}]
    state, candidate, _, args, _ = await setup(runtime, tmp_path, related=related)
    registry, p, policy, *_ = runtime
    assert (await registry.execute("workflow", args, None, p)).startswith("error:")
    assert not state.validation_results
    await registry.execute("http", {"url": "/readback", "phase": "validation"}, None, p)
    args["observation_ids"].append(next(reversed(policy.observations._items)))
    payload = json.loads(await registry.execute("workflow", args, None, p))
    assert payload["result"]["assessment_source"] == "agent"
    latest = state.latest_result(candidate.id)
    assert latest is not None
    assert [e["source"]["role"] for e in latest.evidence_manifest] == ["probe", "readback"]


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [True, False])
async def test_derived_excerpt_and_precommit_eviction(runtime, tmp_path, valid):
    import hashlib
    state, candidate, _, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    body = policy.observations._items[oid].body
    args["assessment"]["excerpts"] = [{"source_id": oid, "start": 0, "end": len(body),
        "sha256": hashlib.sha256(body).hexdigest() if valid else "f" * 64}]
    linked = json.loads(await registry.execute("workflow", {"action": "record_evidence",
        "candidate_id": candidate.id, "evidence_path": "proof.md", "observation_ids": [oid]}, None, p))
    assert linked["evidence_kind"] == "derived" and linked["primary_parents"] == [oid]
    assert state.evidence_sources[args["evidence_refs"][0]] == [oid]
    policy.observations._items.clear()
    output = await registry.execute("workflow", args, None, p)
    if valid:
        assert json.loads(output)["result"]["assessment_source"] == "agent"
        restored = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
        assert restored.evidence_sources == state.evidence_sources
        assert accepted_result(restored, restored.candidates[candidate.id], restored.latest_result(candidate.id), policy)
    else:
        assert output.startswith("error:") and not state.validation_results


@pytest.mark.asyncio
@pytest.mark.parametrize("complete,outcome", [(True, "confirmed"), (True, "not-confirmed"), (None, "confirmed")])
async def test_declared_capture_import_keeps_honest_provenance(runtime, tmp_path, complete, outcome):
    from src.browser.store import CaptureStore
    from src.tools.common.browser_capture import BrowserCaptureGetTool
    state, candidate, _, args, _ = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    captures = CaptureStore()
    capture = captures.ingest({"id": "bridge-record", "kind": "burp", "url": ORIGIN + "/fixture",
        "method": "GET", "status": 200, "respBody": '{"password":"fixture-secret-value","ok":true}',
        "elapsedMs": 4.0, "responseComplete": complete})
    registry.register(BrowserCaptureGetTool(captures))
    imported = json.loads(await registry.execute("browser_capture_get", {"id": capture["id"]}, None, p))
    oid = imported["runtime_observation_id"]
    item = policy.observations._items[oid]
    assert item.source_kind == "imported-capture" and item.transport == "import"
    assert item.invocation_id is None and item.elapsed_ms is None
    assert item.source_details is not None
    assert item.source_details["original_owner"] is None and item.source_details["receipt_id"] is None
    assert item.source_details["original_response_hash"] is None
    assert item.source_details["hash_basis"] == "selected-redacted-import"
    assert b"fixture-secret-value" not in item.body
    args.update(observation_ids=[oid], outcome=outcome)
    output = await registry.execute("workflow", args, None, p)
    if complete:
        assert json.loads(output)["result"]["assessment_source"] == "agent"
        latest = state.latest_result(candidate.id)
        assert latest is not None and latest.evidence_manifest[0]["source"]["source_kind"] == "imported-capture"
    else:
        assert output.startswith("error:") and not state.validation_results


@pytest.mark.asyncio
async def test_actual_session_checkpoint_and_source_redaction_resume(runtime, tmp_path):
    from src.session.store import Store as SessionStore
    from src.engagement.state import EngagementState
    from src.permission.runtime.execution import ExecutionPolicy
    state, candidate, _, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    journal = tmp_path / "permissions" / "assessment-session.json"
    policy.load_journal(journal)
    policy.observations.persist()
    assert not policy.observations._verifiers
    payload = json.loads(await registry.execute("workflow", args, None, p))
    assert payload["result"]["outcome"] == "confirmed"
    session = SessionStore.new_with_id(tmp_path / "sessions", "assessment-session")
    await session.save([], workflow=state)
    restored = session.load().workflow
    resumed_policy = ExecutionPolicy(EngagementState(), tmp_path)
    resumed_policy.load_journal(journal)
    assert resumed_policy.observations._items[oid].retained_hash == policy.observations._items[oid].retained_hash
    assert accepted_result(restored, restored.candidates[candidate.id], restored.latest_result(candidate.id), resumed_policy)
    assert not resumed_policy._receipts and not resumed_policy.engagement.http_permissions._receipts
    assert resumed_policy.observations.storage is not None
    assert resumed_policy.observations.storage.stat().st_mode & 0o777 == 0o600
    resumed_policy.session_id = "unrelated-session"
    assert not accepted_result(restored, restored.candidates[candidate.id], restored.latest_result(candidate.id), resumed_policy)


@pytest.mark.asyncio
async def test_operator_checkpoint_failure_from_unresolved_removes_projection(runtime, tmp_path):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, p, policy, operator, *_ = runtime
    await registry.execute("workflow", {**args, "outcome": "insufficient-evidence"}, None, p)
    previous = state.latest_result(candidate.id)
    output = []
    app = SimpleNamespace(agent=SimpleNamespace(prompter=p, workflow=state, tools=registry,
        save=AsyncMock(side_effect=OSError("checkpoint failure"))), dispatch=output.append)
    operator.decision = Decision.ALLOW_ONCE
    await review_result(app, [candidate.id, "confirmed", "low", "Observed fixture response."])
    assert output[-1].entry.kind == "error"
    assert state.latest_result(candidate.id) is previous and not state.eligible_for_finding(candidate.id)
    assert tool.coverage is not None and not await tool.coverage.list()
    assert not await CoverageStore(str(tool.coverage.path)).list()


def test_absent_owner_snapshot_cannot_be_assigned_at_response_time():
    store = ObservationStore()
    store.owner_provider = lambda: {"candidate_id": "new-candidate", "id": "new-attempt"}
    action = SimpleNamespace(epoch="e", method="GET", url="https://target.test/", transport_address="fixture", digest="d")
    oid = store.capture(action, 200, b"genuine pre-attempt response", complete=True, owner=None)
    assert store._items[oid].candidate_id is None and store._items[oid].attempt_id is None


def test_v1_binding_vectors_and_honest_certificate_view(tmp_path):
    from src.permission.runtime.execution import ExecutionPolicy
    from src.engagement.state import EngagementState
    from src.permission.runtime.observations import VerifiedResult
    from src.workflow.evidence import EvidenceArtifact
    from src.workflow.state import ValidationResult, validation_result_fingerprint
    from src.workflow.review import review_snapshot, confirmation_binding
    from src.workflow.assessment import assessment_provenance
    state = WorkflowState(objective=WorkflowObjective("legacy-objective", "whole_target", "https://target.test"))
    candidate, _ = state.add_candidate(Candidate("xss", target="https://target.test", endpoint="/search",
        method="GET", parameter="q", objective_id="legacy-objective"))
    state.add_evidence(EvidenceArtifact("ev_legacy", candidate.id, "proof.md", "a" * 64, 9))
    result = ValidationResult(candidate.id, "cross-site-scripting", "confirmed", evidence_refs=["ev_legacy"],
        recorded_at="2025-01-01T00:00:00Z", session_id="legacy-session", objective_id="legacy-objective")
    state.add_validation_result(result)
    # Golden vectors computed against the pre-migration implementation in HEAD.
    assert validation_result_fingerprint(result) == "f6aee2cc83e97116476e0f98ef26771677d8de3d9f8a485464e07f8112d93f8c"
    assert review_snapshot(state, candidate.id) == "0751e641562242c9ddb86f679a8488c1d4619e0f89d22bebb747fafa55b1ac47"
    assert confirmation_binding(state, candidate.id) == review_snapshot(state, candidate.id)
    serialized = result.to_dict()
    assert "assessment_source" not in serialized and "attempt_id" not in serialized
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    assert assessment_provenance(state, candidate, result, policy)["source"] == "legacy/unknown"
    epoch = policy.engagement.http_permissions.epoch
    legacy = VerifiedResult("confirmed", "Legacy observed behavior", "low", (), verification_source="trusted-adapter")
    policy.observations._results[candidate.id] = (epoch, ("ev_legacy",), legacy,
                                                policy.observations.candidate_identity(candidate))
    view = assessment_provenance(state, candidate, result, policy)
    assert view["source"] == "legacy-verifier" and view["legacy_verification_source"] == "trusted-adapter"
    assert result.to_dict() == serialized and result.assessment_source is None
    repeated = ValidationResult.from_dict(serialized)
    assert repeated is not None
    state.add_validation_result(repeated, force=True)
    assert assessment_provenance(state, candidate, result, policy)["source"] == "legacy/unknown"
    assert not accepted_result(state, candidate, result, policy)


@pytest.mark.asyncio
async def test_review_checkpoint_serializes_ordinary_agent_save(runtime, tmp_path):
    from src.agent.agent import Agent, AgentOptions
    from tests.helpers.agent_fakes import FakeClient
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, p, _, operator, *_, target = runtime
    await registry.execute("workflow", args, None, p)
    previous = state.latest_result(candidate.id)
    entered, release = asyncio.Event(), asyncio.Event()
    saved_sources = []
    async def checkpoint(history, target, memory, workflow, engagement):
        if not entered.is_set():
            entered.set()
            await release.wait()
        latest = workflow.latest_result(candidate.id)
        assert latest is not None
        saved_sources.append(latest.assessment_source)
    assert tool.skills is not None
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=tool.skills,
        prompter=p, target=target, workflow=state, store=None))
    from src.session.store import Store as SessionStore
    agent.store = MagicMock(spec=SessionStore)
    agent.store.save = AsyncMock(side_effect=checkpoint)
    output = []
    app = SimpleNamespace(agent=agent, dispatch=output.append)
    operator.decision = Decision.ALLOW_ONCE
    review = asyncio.create_task(review_result(app, [candidate.id, "confirmed", "low", "Reviewed fixture."]))
    await asyncio.wait_for(entered.wait(), 2)
    ordinary = asyncio.create_task(agent.save())
    await asyncio.sleep(0)
    assert state.latest_result(candidate.id) is previous and not ordinary.done()
    release.set()
    await asyncio.gather(review, ordinary)
    assert output[-1].entry.kind == "system", output[-1]
    assert saved_sources == ["operator", "operator"]


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["artifact", "primary"])
async def test_review_rechecks_evidence_after_checkpoint(runtime, tmp_path, fault):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, operator, *_ = runtime
    await registry.execute("workflow", args, None, p)
    previous = state.latest_result(candidate.id)
    checkpoints, output = [], []
    async def save(*, workflow_override=None, _workflow_locked=False):
        snapshot = workflow_override if workflow_override is not None else state
        latest = snapshot.latest_result(candidate.id)
        assert latest is not None
        checkpoints.append(latest.assessment_source)
        if workflow_override is not None:
            if fault == "artifact":
                path = tmp_path / state.evidence[args["evidence_refs"][0]].path
                path.chmod(0o600)
                path.write_text("changed during checkpoint")
            else:
                policy.observations._items[oid] = replace(policy.observations._items[oid], body=b"substituted")
    app = SimpleNamespace(agent=SimpleNamespace(prompter=p, workflow=state, tools=registry, save=save), dispatch=output.append)
    operator.decision = Decision.ALLOW_ONCE
    await review_result(app, [candidate.id, "confirmed", "low", "Reviewed response."])
    assert output[-1].entry.kind == "error" and state.latest_result(candidate.id) is previous
    assert checkpoints == ["operator", "agent"]
    assert not any(r.assessment_source == "operator" for r in state.validation_results)


@pytest.mark.asyncio
async def test_tampered_artifact_cannot_sync_coverage(runtime, tmp_path):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, p, *_ = runtime
    await registry.execute("workflow", args, None, p)
    path = tmp_path / state.evidence[args["evidence_refs"][0]].path
    path.chmod(0o600)
    path.write_text("substituted proof")
    assert tool.coverage is not None
    await tool.coverage.clear()
    await tool.coverage.flush()
    output = await registry.execute("workflow", {"action": "sync_coverage", "candidate_id": candidate.id}, None, p)
    assert output.startswith("error:") and not await tool.coverage.list()


@pytest.mark.asyncio
async def test_optional_incomplete_source_does_not_erase_completed_primary(runtime, tmp_path):
    related = [{"role": "auxiliary", "method": "GET", "url": ORIGIN + "/optional", "required": False}]
    state, candidate, _, args, _ = await setup(runtime, tmp_path, related=related)
    registry, p, policy, *_ = runtime
    await registry.execute("http", {"url": "/optional", "phase": "validation"}, None, p)
    oid = next(reversed(policy.observations._items))
    partial = replace(policy.observations._items[oid], complete=False, truncated=True, execution_status="failed")
    policy.observations._items[oid] = replace(partial, retained_hash=digest(source_row(partial)))
    args["observation_ids"].append(oid)
    output = json.loads(await registry.execute("workflow", args, None, p))
    assert output["eligible_for_confirm_finding"]
    result = state.latest_result(candidate.id)
    assert result is not None and accepted_result(state, candidate, result, policy)
    assert result.evidence_manifest[-1]["source"]["required"] is False
    state.evidence_sources[args["evidence_refs"][0]] = ["substituted-parent"]
    assert not accepted_result(state, candidate, result, policy) and not state.eligible_for_finding(candidate.id)


@pytest.mark.asyncio
async def test_unresolved_without_execution_has_agent_provenance_and_no_fake_attempt(tmp_path):
    from src.permission.permission import AlwaysAllow
    from src.target.target import Target
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate("xss", target="https://target.test", endpoint="/search"))
    tool = WorkflowTool(state, Target("https://target.test"), evidence_root=tmp_path)
    args = {"action": "record_result", "candidate_id": candidate.id, "skill_name": "cross-site-scripting",
        "outcome": "blocked", "deferred_reason": "No execution context available"}
    first = json.loads(await tool.run(args, None, AlwaysAllow()))
    retry = json.loads(await tool.run(args, None, AlwaysAllow()))
    assert first["created"] and not retry["created"]
    assert first["result"]["assessment_source"] == "agent"
    assert first["result"]["attempt_id"] is None and first["result"]["evidence_manifest"] == []
    assert not state.attempts and not state.eligible_for_finding(candidate.id)


@pytest.mark.asyncio
async def test_closed_other_candidate_selector_allows_unstarted_unresolved_only(runtime, tmp_path):
    state, first, tool, args, _ = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    await registry.execute("workflow", args, None, p)
    prior = state.latest_result(first.id)
    assert state.objective is not None
    other, _ = state.add_candidate(Candidate("ssrf", target=ORIGIN, endpoint="/fetch",
        method="GET", objective_id=state.objective.id))
    submission = {"action": "record_result", "candidate_id": other.id,
        "skill_name": "ssrf", "outcome": "authorization-required",
        "deferred_reason": "Destination testing needs operator intent"}
    for invalid in ({"attempt_id": args["attempt_id"]}, {"observation_ids": args["observation_ids"]},
                    {"outcome": "not-confirmed"}):
        assert (await registry.execute("workflow", {**submission, **invalid}, None, p)).startswith("error:")
        assert state.latest_result(other.id) is None
    payload = json.loads(await registry.execute("workflow", submission, None, p))
    assert payload["result"]["outcome"] == "authorization-required"
    assert payload["result"]["attempt_id"] is None and payload["result"]["evidence_manifest"] == []
    assert state.latest_result(first.id) is prior and accepted_result(state, first, prior, policy)
    assert tool.coverage is not None and len(await tool.coverage.list()) == 1
