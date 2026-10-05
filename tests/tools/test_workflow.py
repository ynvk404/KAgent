from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.coverage.store import CoverageStore
from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as SkillRegistry, Skill, SkillTriggers
from src.target.target import Target
from src.tools.workflow.workflow_tool import DEFAULT_LIST_LIMIT, WorkflowTool
from src.tools.common.outcome import ToolOutput
from src.tools.workflow.coverage import CoverageTool
from src.workflow.evidence import EvidenceArtifact
from src.workflow.state import (
    AttackSurfaceInput,
    Candidate,
    VALIDATION_OUTCOMES,
    ValidationResult,
    WorkflowObjective,
    WorkflowState,
    validation_result_fingerprint,
)
from src.workflow.goals import RequestedGoal
from tests.helpers.workflow import record_completed_phase, record_phase_coverage_for_test


@pytest.mark.asyncio
async def test_no_candidate_review_requires_closed_inventory_and_never_creates_test_records(tmp_path):
    objective = WorkflowObjective(
        id="objective-goal-review", mode="whole_target",
        target_origin="https://target.test",
        requested_goals=[RequestedGoal("cross-site-scripting")],
    )
    state = WorkflowState(objective=objective)
    for phase in ("recon", "enumeration", "input_analysis"):
        ref = f"artifacts/{phase}.md"
        artifact = tmp_path / ref
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("reviewed inventory", encoding="utf-8")
        record_completed_phase(
            state, phase, objective_id=objective.id,
            target_origin="https://target.test", artifact_ref=ref,
            no_inputs_discovered=phase == "input_analysis",
        )
    tool = WorkflowTool(
        state, Target("https://target.test"), evidence_root=tmp_path,
    )
    goal = objective.requested_goals[0]
    args = {"action": "review_no_candidate", "goal_id": goal.id}

    wrong_artifact = await tool.run({
        **args, "artifact_ref": "artifacts/wrong.md",
    }, None, AlwaysAllow())
    assert "must match the active input-analysis completion" in wrong_artifact

    recorded = json.loads(await tool.run(args, None, AlwaysAllow()))
    assert recorded["ok"] is True
    assert recorded["goal"]["status"] == "no_candidate"
    assert recorded["class_specific_validation_performed"] is False
    assert state.validation_results == []
    assert state.evidence == {}
    assert state.persisted_findings == {}
    assert goal.review_artifact_ref == "artifacts/input_analysis.md"

    new_candidate = json.loads(await tool.run({
        "action": "record_candidate", "candidate_class": "xss",
        "target": "https://target.test", "endpoint": "/search",
    }, None, AlwaysAllow()))
    assert new_candidate["ok"] is True
    assert goal.status == "in_progress"
    assert goal.review_artifact_ref is None
    assert goal.candidate_ids == [new_candidate["candidate"]["id"]]


@pytest.mark.asyncio
async def test_dropped_input_needs_review_or_scope_reason_for_no_candidate(tmp_path):
    objective = WorkflowObjective(
        id="objective-dropped-input", mode="whole_target",
        target_origin="https://target.test",
        requested_goals=[RequestedGoal("cross-site-scripting")],
    )
    state = WorkflowState(objective=objective)
    item, _ = state.add_attack_surface_input(AttackSurfaceInput(
        objective.id, "https://target.test", endpoint="/search", parameter="q",
        disposition="dropped", disposition_reason="ignored by analysis",
    ))
    for phase in ("recon", "enumeration", "input_analysis"):
        ref = f"artifacts/{phase}.md"
        artifact = tmp_path / ref
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("inventory", encoding="utf-8")
        record_completed_phase(
            state, phase, objective_id=objective.id,
            target_origin="https://target.test", artifact_ref=ref,
        )
    tool = WorkflowTool(
        state, Target("https://target.test"), evidence_root=tmp_path,
    )
    args = {
        "action": "review_no_candidate",
        "goal_id": objective.requested_goals[0].id,
    }
    rejected = await tool.run(args, None, AlwaysAllow())
    assert "dropped without a reviewable reason" in rejected
    state.set_input_disposition(
        item.id, "dropped", reason="Reviewed and excluded as out of scope",
    )
    accepted = json.loads(await tool.run(args, None, AlwaysAllow()))
    assert accepted["goal"]["status"] == "no_candidate"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("disposition", "reason_fragment"),
    [("pending", "remains pending"), ("blocked", "remains blocked")],
)
async def test_pending_or_blocked_input_prevents_no_candidate_review(
    tmp_path, disposition, reason_fragment,
):
    objective = WorkflowObjective(
        id="objective-open-input", mode="whole_target",
        target_origin="https://target.test",
        requested_goals=[RequestedGoal("cross-site-scripting")],
    )
    state = WorkflowState(objective=objective)
    input_item, _ = state.add_attack_surface_input(AttackSurfaceInput(
        objective.id, "https://target.test", endpoint="/search", parameter="q",
        disposition=disposition,
        disposition_reason="needs review" if disposition == "blocked" else None,
    ))
    for phase in ("recon", "enumeration", "input_analysis"):
        ref = f"artifacts/{phase}.md"
        artifact = tmp_path / ref
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("inventory", encoding="utf-8")
        record_completed_phase(
            state, phase, objective_id=objective.id,
            target_origin="https://target.test", artifact_ref=ref,
        )
    output = await WorkflowTool(
        state, Target("https://target.test"), evidence_root=tmp_path,
    ).run({
        "action": "review_no_candidate", "goal_id": objective.requested_goals[0].id,
    }, None, AlwaysAllow())
    assert output.startswith("error:")
    assert reason_fragment in output
    assert input_item.disposition == disposition
    assert objective.requested_goals[0].status == "pending"


def _confirmed_sqli_args() -> dict:
    return {
        "techniques": ["error-based", "boolean-based"],
        "repeatable": True,
        "confirmation": {
            "kind": "boolean-differential",
            "request_template": "GET /search?q={predicate}",
            "true_predicate": "value' OR 1=1--",
            "false_predicate": "value' OR 1=2--",
            "pairs": [
                {
                    "repetition": repetition,
                    "true": {"status": 200, "size": 900, "marker": "rows=3"},
                    "false": {"status": 200, "size": 30, "marker": "rows=0"},
                }
                for repetition in (1, 2)
            ],
        },
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", sorted(VALIDATION_OUTCOMES))
async def test_record_result_accepts_every_canonical_outcome(outcome, tmp_path):
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="xxe",
        target="https://target.test",
        endpoint="/xml",
        method="POST",
        parameter="body",
        location="body",
    ))
    tool = WorkflowTool(
        state,
        Target("https://target.test"),
        evidence_root=tmp_path,
    )
    evidence_refs: list[str] = []
    if outcome == "confirmed":
        proof = tmp_path / "proof.txt"
        proof.write_text("Harmless external entity marker observed", encoding="utf-8")
        evidence_output = json.loads(await tool.run(
            {
                "action": "record_evidence",
                "candidate_id": candidate.id,
                "evidence_path": "proof.txt",
            },
            None,
            AlwaysAllow(),
        ))
        evidence_refs.append(evidence_output["evidence"]["id"])

    output = await tool.run(
        {
            "action": "record_result",
            "candidate_id": candidate.id,
            "skill_name": "xxe",
            "outcome": outcome,
            "evidence_refs": evidence_refs,
            "deferred_reason": "bounded regression case",
        },
        None,
        AlwaysAllow(),
    )

    response = json.loads(output)
    assert response["ok"] is True
    assert response["result"]["outcome"] == outcome


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome",
    [
        "not confirmed",
        "confirmed (SQLI-2)",
        "insufficient-identity",
        "requires-authorization-for-write",
        "deferred (out of scope)",
    ],
)
async def test_record_result_rejects_noncanonical_outcomes(outcome):
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="xxe",
        target="https://target.test",
        endpoint="/xml",
    ))
    output = await WorkflowTool(state, Target("https://target.test")).run(
        {
            "action": "record_result",
            "candidate_id": candidate.id,
            "skill_name": "xxe",
            "outcome": outcome,
        },
        None,
        AlwaysAllow(),
    )

    assert isinstance(output, ToolOutput)
    assert output.status == "error"
    assert output.startswith(f"error: unknown validation outcome: {outcome}")
    assert state.latest_result(candidate.id) is None


@pytest.mark.asyncio
async def test_workflow_semantic_failure_has_typed_error_status():
    output = await WorkflowTool(WorkflowState()).run(
        {
            "action": "record_input",
            "method": "GET",
            "endpoint": "/search",
            "parameter": "q",
        },
        None,
        AlwaysAllow(),
    )

    assert isinstance(output, ToolOutput)
    assert output.status == "error"
    assert output.error_kind == "invalid_args"
    assert output.startswith("error: record_input requires")


@pytest.mark.asyncio
async def test_candidate_rejects_unstructured_boolean_differential_claim():
    state = WorkflowState()
    output = await WorkflowTool(state, Target("https://target.test")).run(
        {
            "action": "record_candidate",
            "candidate_class": "sql-injection",
            "endpoint": "/search",
            "parameter": "q",
            "signals": [
                "boolean differential: TRUE returns rows while FALSE is empty"
            ],
        },
        None,
        AlwaysAllow(),
    )

    assert isinstance(output, ToolOutput)
    assert output.status == "error"
    assert "structured, repeated validation evidence" in output
    assert state.candidates == {}


@pytest.mark.asyncio
async def test_candidate_handoff_uses_enabled_validator_metadata():
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = WorkflowState()
    tool = WorkflowTool(state, Target("https://target.test"), skills=skills)
    cases = (
        ("sqli", "sql-injection"),
        ("xss", "cross-site-scripting"),
        ("idor", "access-control"),
        ("authentication", "authentication"),
        ("csrf", "csrf"),
        ("ssrf", "ssrf"),
        ("ssti", "ssti"),
        ("nosql-injection", "nosql-injection"),
        ("path-traversal", "path-traversal"),
        ("cors-misconfiguration", "cors-misconfiguration"),
        ("open-redirect", "open-redirect"),
        ("jwt-misconfiguration", "jwt-misconfiguration"),
        ("file-upload", "file-upload"),
        ("command-injection", "command-injection"),
        ("xxe", "xxe"),
    )
    for index, (candidate_class, validator) in enumerate(cases):
        response = json.loads(await tool.run(
            {
                "action": "record_candidate",
                "candidate_class": candidate_class,
                "endpoint": f"/input/{index}",
                "signals": ["specific observed signal"],
            }, None, AlwaysAllow(),
        ))
        assert response["supported"] is True
        assert response["validator_resolution"] == "unique"
        assert response["recommended_skills"] == [validator]
        assert response["candidate"]["status"] == "queued"

    unsupported = json.loads(await tool.run(
        {"action": "record_candidate", "candidate_class": "unhandled-class", "endpoint": "/redirect"},
        None, AlwaysAllow(),
    ))
    assert unsupported["supported"] is False
    assert unsupported["validator_resolution"] == "generic"
    assert "policy unavailable" in unsupported["validator_reason"]
    assert unsupported["recommended_skills"] == []
    assert unsupported["candidate"]["status"] == "deferred"
    forced = json.loads(await tool.run(
        {"action": "record_candidate", "candidate_class": "unhandled-class",
         "endpoint": "/redirect-2", "status": "queued"},
        None, AlwaysAllow(),
    ))
    assert forced["candidate"]["status"] == "deferred"

    skills.set_disabled("ssrf", True)
    disabled = json.loads(await tool.run(
        {"action": "record_candidate", "candidate_class": "ssrf", "endpoint": "/input/5"},
        None, AlwaysAllow(),
    ))
    assert disabled["supported"] is False
    assert disabled["created"] is False
    assert disabled["candidate"]["status"] == "deferred"
    skills.set_disabled("ssrf", False)
    restored = json.loads(await tool.run(
        {"action": "record_candidate", "candidate_class": "ssrf", "endpoint": "/input/5"},
        None, AlwaysAllow(),
    ))
    assert restored["supported"] is True
    assert restored["candidate"]["status"] == "queued"


@pytest.mark.asyncio
async def test_candidate_handoff_and_start_validation_fail_closed_for_duplicate_validators():
    skills = SkillRegistry()
    for name in ("first-validator", "second-validator"):
        skills.add(Skill(
            name=name,
            description=name,
            tools=[],
            disable_model_invocation=False,
            path=f"/tmp/{name}/SKILL.md",
            body="",
            stage="validation",
            triggers=SkillTriggers(),
            candidate_classes=["sql-injection"],
        ))
    state = WorkflowState()
    tool = WorkflowTool(state, Target("https://target.test"), skills=skills)

    response = json.loads(await tool.run({
        "action": "record_candidate",
        "candidate_class": "sql-injection",
        "endpoint": "/search",
    }, None, AlwaysAllow()))

    assert response["supported"] is False
    assert response["validator_resolution"] == "ambiguous"
    assert response["recommended_skills"] == ["first-validator", "second-validator"]
    assert response["candidate"]["status"] == "deferred"
    assert "ambiguous validator mapping" in await tool.run({
        "action": "start_validation",
        "candidate_id": response["candidate"]["id"],
    }, None, AlwaysAllow())
    assert state.candidates[response["candidate"]["id"]].status == "deferred"

    result = await tool.run({
        "action": "record_result",
        "candidate_id": response["candidate"]["id"],
        "skill_name": "first-validator",
        "outcome": "not-confirmed",
    }, None, AlwaysAllow())
    assert "ambiguous validator mapping" in result
    assert state.validation_results == []


@pytest.mark.asyncio
async def test_direct_input_can_have_multiple_independent_candidate_classes():
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = WorkflowState()
    tool = WorkflowTool(state, Target("https://target.test"), skills=skills)
    ids = []
    for candidate_class in ("cross-site-scripting", "ssti"):
        response = json.loads(await tool.run(
            {
                "action": "record_candidate", "candidate_class": candidate_class,
                "method": "GET", "endpoint": "/render", "parameter": "template",
            }, None, AlwaysAllow(),
        ))
        ids.append(response["candidate"]["id"])
        assert response["supported"] is True
    assert len(set(ids)) == 2
    assert len(state.candidates) == 2


@pytest.mark.asyncio
async def test_confirmed_requires_registered_candidate_evidence(tmp_path):
    state = WorkflowState()
    first, _ = state.add_candidate(Candidate(candidate_class="xss", target="https://target.test", endpoint="/a"))
    second, _ = state.add_candidate(Candidate(candidate_class="xss", target="https://target.test", endpoint="/b"))
    tool = WorkflowTool(state, evidence_root=tmp_path)
    (tmp_path / "proof.txt").write_text("Request and response", encoding="utf-8")
    evidence = json.loads(await tool.run(
        {"action": "record_evidence", "candidate_id": first.id, "evidence_path": "proof.txt"},
        None, AlwaysAllow(),
    ))["evidence"]["id"]
    base = {"action": "record_result", "candidate_id": second.id,
            "skill_name": "cross-site-scripting", "outcome": "confirmed"}
    assert "requires an evidence reference" in await tool.run(base, None, AlwaysAllow())
    assert "must resolve to this candidate" in await tool.run(
        {**base, "evidence_refs": [evidence]}, None, AlwaysAllow(),
    )
    assert "must resolve" in await tool.run(
        {**base, "evidence_refs": ["ev_invented"]}, None, AlwaysAllow(),
    )
    (tmp_path / state.evidence[evidence].path).unlink()
    assert "changed or is unavailable" in await tool.run(
        {**base, "candidate_id": first.id, "evidence_refs": [evidence]}, None, AlwaysAllow(),
    )
    assert state.validation_results == []


@pytest.mark.asyncio
async def test_record_evidence_snapshots_mutable_shared_artifact_per_candidate(tmp_path):
    state = WorkflowState()
    first, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test", endpoint="/login",
    ))
    second, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test", endpoint="/search",
    ))
    tool = WorkflowTool(state, evidence_root=tmp_path)
    aggregate = tmp_path / "results.md"
    aggregate.write_text(
        "Candidate A proof\nCookie: session=raw-sensitive-value\n",
        encoding="utf-8",
    )

    first_result = json.loads(await tool.run({
        "action": "record_evidence", "candidate_id": first.id,
        "evidence_path": "results.md",
    }, None, AlwaysAllow()))
    first_artifact = state.evidence[first_result["evidence"]["id"]]
    first_snapshot = tmp_path / first_artifact.path
    assert ".kagent/evidence/" in first_artifact.path
    assert "raw-sensitive-value" not in first_snapshot.read_text(encoding="utf-8")
    assert first_snapshot.stat().st_mode & 0o222 == 0
    assert first_snapshot.parent.stat().st_mode & 0o077 == 0

    aggregate.write_text("Candidate B proof, independently captured\n", encoding="utf-8")
    second_result = json.loads(await tool.run({
        "action": "record_evidence", "candidate_id": second.id,
        "evidence_path": "results.md",
    }, None, AlwaysAllow()))
    second_artifact = state.evidence[second_result["evidence"]["id"]]

    assert first_artifact.path != second_artifact.path
    assert first_artifact.is_resolvable(tmp_path)
    assert second_artifact.is_resolvable(tmp_path)
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.evidence[first_artifact.id].is_resolvable(tmp_path)
    assert restored.evidence[second_artifact.id].is_resolvable(tmp_path)


@pytest.mark.asyncio
async def test_validation_attempts_share_one_logical_coverage_observation(tmp_path):
    coverage_path = tmp_path / "coverage.json"
    coverage = CoverageStore(str(coverage_path))
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="cross-site-scripting", target="https://target.test",
        method="POST", endpoint="/feedback", parameter="comment",
    ))
    tool = WorkflowTool(state, coverage=coverage, evidence_root=tmp_path)
    aggregate = tmp_path / "results.md"

    aggregate.write_text("First attempt: no execution marker\n", encoding="utf-8")
    first_evidence = json.loads(await tool.run({
        "action": "record_evidence", "candidate_id": candidate.id,
        "evidence_path": "results.md",
    }, None, AlwaysAllow()))["evidence"]["id"]
    first = json.loads(await tool.run({
        "action": "record_result", "candidate_id": candidate.id,
        "skill_name": "cross-site-scripting", "outcome": "not-confirmed",
        "evidence_refs": [first_evidence], "techniques": ["baseline"],
    }, None, AlwaysAllow()))
    assert first["coverage_sync"] == "synced"

    aggregate.write_text("Second attempt: reproducible execution marker\n", encoding="utf-8")
    second_evidence = json.loads(await tool.run({
        "action": "record_evidence", "candidate_id": candidate.id,
        "evidence_path": "results.md",
    }, None, AlwaysAllow()))["evidence"]["id"]
    await tool.run({
        "action": "start_validation", "candidate_id": candidate.id,
    }, None, AlwaysAllow())
    second = json.loads(await tool.run({
        "action": "record_result", "candidate_id": candidate.id,
        "skill_name": "cross-site-scripting", "outcome": "confirmed",
        "evidence_refs": [second_evidence], "techniques": ["reflected marker"],
        "repeatable": True,
    }, None, AlwaysAllow()))

    assert second["coverage_sync"] == "synced"
    assert len(state.validation_results) == 2
    entries = await coverage.list()
    assert len(entries) == 1
    assert entries[0].status == "failed"
    assert entries[0].count == 1
    assert entries[0].observationIds == [f"candidate:{candidate.id}"]

    restored_coverage = CoverageStore(str(coverage_path))
    restored_entries = await restored_coverage.list()
    assert len(restored_entries) == 1
    assert restored_entries[0].count == 1
    assert restored_entries[0].status == "failed"
    restored_state = WorkflowState.from_dict(state.to_dict())
    assert len(restored_state.validation_results) == 2
    latest = restored_state.latest_result(candidate.id)
    assert latest is not None
    assert latest.evidence_refs == [second_evidence]


@pytest.mark.asyncio
async def test_legacy_attempt_observations_collapse_to_candidate_identity(tmp_path):
    coverage = CoverageStore(str(tmp_path / "legacy-coverage.json"))
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="cross-site-scripting", target="https://target.test",
        method="POST", endpoint="/feedback", parameter="comment",
    ))
    first = ValidationResult(
        candidate.id, "cross-site-scripting", "not-confirmed",
        evidence_refs=["ev_first"], techniques=["baseline"],
        coverage_synced=True,
    )
    second = ValidationResult(
        candidate.id, "cross-site-scripting", "not-confirmed",
        evidence_refs=["ev_second"], techniques=["baseline"],
        coverage_synced=False,
    )
    state.add_validation_result(first)
    state.add_validation_result(second, force=True)
    for result in (first, second):
        await coverage.mark(
            endpoint="POST /feedback", param="comment",
            vulnClass="cross-site-scripting", status="passed",
            observation_id=validation_result_fingerprint(result),
        )
    before = await coverage.list()
    assert before[0].count == 2

    tool = WorkflowTool(state, coverage=coverage)
    synced = json.loads(await tool.run({
        "action": "sync_coverage", "candidate_id": candidate.id,
    }, None, AlwaysAllow()))

    assert synced == {"ok": True, "coverage_sync": "synced"}
    after = await coverage.list()
    assert len(after) == 1
    assert after[0].count == 1
    assert after[0].observationIds == [f"candidate:{candidate.id}"]


@pytest.mark.asyncio
async def test_cleanup_lifecycle_updates_without_creating_a_new_validation_attempt(tmp_path):
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="cross-site-scripting", target="https://target.test",
        endpoint="/feedback", parameter="comment",
    ))
    tool = WorkflowTool(state, evidence_root=tmp_path)
    proof = tmp_path / "proof.md"
    proof.write_text("Bounded proof for the confirmed behavior.", encoding="utf-8")
    evidence = json.loads(await tool.run({
        "action": "record_evidence", "candidate_id": candidate.id,
        "evidence_path": "proof.md",
    }, None, AlwaysAllow()))["evidence"]["id"]

    pending = json.loads(await tool.run({
        "action": "record_result", "candidate_id": candidate.id,
        "skill_name": "cross-site-scripting", "outcome": "confirmed",
        "evidence_refs": [evidence], "mutation_performed": True,
        "cleanup_status": "waiting for separate permission",
    }, None, AlwaysAllow()))
    assert pending["result"]["cleanup_state"] == "pending"
    assert pending["eligible_for_confirm_finding"] is True

    succeeded = json.loads(await tool.run({
        "action": "record_result", "candidate_id": candidate.id,
        "skill_name": "cross-site-scripting", "outcome": "confirmed",
        "evidence_refs": [evidence], "mutation_performed": True,
        "cleanup_status": "resource deletion verified",
        "cleanup_state": "succeeded",
    }, None, AlwaysAllow()))
    assert succeeded["created"] is False
    assert succeeded["result"]["cleanup_state"] == "succeeded"
    assert len(state.validation_results) == 1


@pytest.mark.asyncio
async def test_result_coverage_sync_failure_is_retryable(tmp_path):
    class FailOnceCoverage(CoverageStore):
        def __init__(self, path):
            super().__init__(path)
            self.fail = True

        async def _persist(self):
            if self.fail:
                self.fail = False
                raise OSError("simulated save failure")
            await super()._persist()

    coverage = FailOnceCoverage(str(tmp_path / "coverage.json"))
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test",
        method="GET", endpoint="/search", parameter="q",
    ))
    tool = WorkflowTool(state, coverage=coverage, evidence_root=tmp_path)
    (tmp_path / "proof.txt").write_text("Differential request and response", encoding="utf-8")
    evidence = json.loads(await tool.run(
        {"action": "record_evidence", "candidate_id": candidate.id, "evidence_path": "proof.txt"},
        None, AlwaysAllow(),
    ))["evidence"]["id"]
    recorded = json.loads(await tool.run({
        "action": "record_result", "candidate_id": candidate.id,
        "skill_name": "sql-injection", "outcome": "confirmed", "evidence_refs": [evidence],
        **_confirmed_sqli_args(),
    }, None, AlwaysAllow()))
    assert recorded["coverage_sync"] == "pending"
    assert recorded["eligible_for_confirm_finding"] is False
    latest = state.latest_result(candidate.id)
    assert latest is not None and latest.coverage_synced is False
    retried = json.loads(await tool.run(
        {"action": "sync_coverage", "candidate_id": candidate.id}, None, AlwaysAllow(),
    ))
    assert retried == {"ok": True, "coverage_sync": "synced"}
    assert state.eligible_for_finding(candidate.id) is True
    assert len(await coverage.list()) == 1
    assert (await coverage.list())[0].status == "failed"
    assert (await coverage.list())[0].count == 1

    duplicate = json.loads(await CoverageTool(coverage).run({
        "action": "mark", "endpoint": "GET /search", "param": "q",
        "vuln_class": "sql-injection", "status": "failed",
        "notes": "duplicate manual mark after workflow sync",
    }, None, AlwaysAllow()))
    assert duplicate["entry"]["count"] == 1
    assert duplicate["created"] is False
    assert duplicate["updated"] is False
    assert duplicate["deduplicated"] is True
    assert (await coverage.list())[0].count == 1


@pytest.mark.asyncio
async def test_manual_coverage_mark_before_workflow_sync_is_adopted(tmp_path):
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    await coverage.mark(
        endpoint="GET /search",
        param="q",
        vulnClass="sql-injection",
        status="failed",
        notes="manual finding mark",
    )
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection",
        target="https://target.test",
        method="GET",
        endpoint="/search",
        parameter="q",
    ))
    proof = tmp_path / "proof.txt"
    proof.write_text("repeatable paired evidence", encoding="utf-8")
    tool = WorkflowTool(state, coverage=coverage, evidence_root=tmp_path)
    evidence = json.loads(await tool.run({
        "action": "record_evidence",
        "candidate_id": candidate.id,
        "evidence_path": "proof.txt",
    }, None, AlwaysAllow()))["evidence"]["id"]

    output = json.loads(await tool.run({
        "action": "record_result",
        "candidate_id": candidate.id,
        "skill_name": "sql-injection",
        "outcome": "confirmed",
        "evidence_refs": [evidence],
        **_confirmed_sqli_args(),
    }, None, AlwaysAllow()))

    assert output["coverage_sync"] == "synced"
    entries = await coverage.list()
    assert len(entries) == 1
    assert entries[0].count == 1
    assert entries[0].observationIds


@pytest.mark.asyncio
async def test_error_based_sqli_confirmation_remains_backward_compatible(tmp_path):
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection",
        target="https://target.test",
        endpoint="/search",
        parameter="q",
    ))
    proof = tmp_path / "proof.txt"
    proof.write_text("database parser error evidence", encoding="utf-8")
    tool = WorkflowTool(state, evidence_root=tmp_path)
    evidence = json.loads(await tool.run({
        "action": "record_evidence",
        "candidate_id": candidate.id,
        "evidence_path": "proof.txt",
    }, None, AlwaysAllow()))["evidence"]["id"]

    output = json.loads(await tool.run({
        "action": "record_result",
        "candidate_id": candidate.id,
        "skill_name": "sql-injection",
        "outcome": "confirmed",
        "evidence_refs": [evidence],
        "techniques": ["error-based"],
    }, None, AlwaysAllow()))

    assert output["eligible_for_confirm_finding"] is True
    assert output["result"]["confirmation"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutate,expected",
    [
        (
            lambda confirmation: confirmation["pairs"].pop(),
            "at least two paired repetitions",
        ),
        (
            lambda confirmation: confirmation["pairs"][1].update(
                {"true": {"status": 200, "size": 901, "marker": "rows=3"}}
            ),
            "not reproducible",
        ),
        (
            lambda confirmation: confirmation["pairs"][0].update(
                {"true": {"status": 200, "size": 30, "marker": "rows=0"}}
            ),
            "TRUE and FALSE observations must differ",
        ),
    ],
)
async def test_confirmed_sqli_rejects_unrepeated_or_contradictory_boolean_evidence(
    tmp_path, mutate, expected,
):
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test",
        method="GET", endpoint="/search", parameter="q",
    ))
    proof = tmp_path / "proof.txt"
    proof.write_text("bounded request/response observations", encoding="utf-8")
    tool = WorkflowTool(state, evidence_root=tmp_path)
    evidence = json.loads(await tool.run({
        "action": "record_evidence", "candidate_id": candidate.id,
        "evidence_path": proof.name,
    }, None, AlwaysAllow()))["evidence"]["id"]
    contract = _confirmed_sqli_args()
    mutate(contract["confirmation"])

    output = await tool.run({
        "action": "record_result", "candidate_id": candidate.id,
        "skill_name": "sql-injection", "outcome": "confirmed",
        "evidence_refs": [evidence], **contract,
    }, None, AlwaysAllow())

    assert isinstance(output, ToolOutput) and output.status == "error"
    assert expected in output
    assert state.validation_results == []


def test_confirmed_sqli_accepts_repeated_time_differential_contract():
    result = ValidationResult(
        "candidate", "sql-injection", "confirmed",
        techniques=["time-based"], repeatable=True,
        confirmation={
            "kind": "time-differential",
            "request_template": "POST /login body={probe}",
            "expected_delay_ms": 5000,
            "pairs": [
                {
                    "repetition": repetition,
                    "control": {"status": 200, "size": 30, "elapsed_ms": 100},
                    "probe": {"status": 200, "size": 30, "elapsed_ms": 5100},
                }
                for repetition in (1, 2)
            ],
        },
    )

    normalized = WorkflowTool._validate_sqli_confirmation(result)

    assert normalized is not None
    assert normalized["kind"] == "time-differential"
    assert len(normalized["pairs"]) == 2


@pytest.mark.asyncio
async def test_coverage_keeps_candidate_subcases_separate(tmp_path):
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    state = WorkflowState()
    tool = WorkflowTool(state, coverage=coverage, evidence_root=tmp_path)
    for role in ("viewer", "admin"):
        candidate, _ = state.add_candidate(Candidate(
            candidate_class="access-control", target="https://target.test",
            endpoint="/objects/1", method="GET", parameter="id", test_case=role,
        ))
        result = json.loads(await tool.run({
            "action": "record_result", "candidate_id": candidate.id,
            "skill_name": "access-control", "outcome": "not-confirmed",
        }, None, AlwaysAllow()))
        assert result["coverage_sync"] == "synced"
    rows = await coverage.list()
    assert len(rows) == 2
    assert {row.param for row in rows} == {
        "id [subcase: viewer]", "id [subcase: admin]",
    }


@pytest.mark.asyncio
async def test_non_terminal_validation_outcomes_remain_revisitable(tmp_path):
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    state = WorkflowState()
    tool = WorkflowTool(state, coverage=coverage)
    for index, outcome in enumerate(("blocked", "insufficient-evidence", "authorization-required", "browser-required", "deferred")):
        candidate, _ = state.add_candidate(Candidate(
            candidate_class="xss", endpoint=f"/input/{index}", target="https://target.test",
        ))
        response = json.loads(await tool.run({
            "action": "record_result", "candidate_id": candidate.id,
            "skill_name": "cross-site-scripting", "outcome": outcome,
            "deferred_reason": "condition not available",
        }, None, AlwaysAllow()))
        assert response["result"]["outcome"] == outcome
        assert candidate.status == "deferred"
        assert state.set_candidate_status(candidate.id, "queued").status == "queued"
    rows = await coverage.list()
    assert rows == []


@pytest.mark.asyncio
async def test_start_validation_rejects_terminal_whole_target_candidate_without_retest():
    objective = WorkflowObjective(
        id="whole-objective", mode="whole_target", target_origin="https://target.test",
    )
    state = WorkflowState(objective=objective)
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="xss", target="https://target.test", endpoint="/search",
        objective_id=objective.id,
    ))
    state.add_validation_result(ValidationResult(
        candidate.id, "cross-site-scripting", "not-confirmed",
    ))
    tool = WorkflowTool(state, Target("https://target.test"))

    blocked = await tool.run({
        "action": "start_validation", "candidate_id": candidate.id,
    }, None, AlwaysAllow())

    assert blocked.startswith("error: terminal candidate cannot be reopened")
    assert candidate.status == "validated"

    # A prior structured requeue is an explicit workflow state transition.
    state.set_candidate_status(candidate.id, "queued")
    reopened = await tool.run({
        "action": "start_validation", "candidate_id": candidate.id,
    }, None, AlwaysAllow())
    assert json.loads(reopened)["candidate"]["status"] == "validating"

    state.set_candidate_status(candidate.id, "validated")
    state.objective = WorkflowObjective(
        id="explicit-retest", mode="candidate_validation",
        target_origin="https://target.test", candidate_id=candidate.id,
    )
    explicit_retest = await tool.run({
        "action": "start_validation", "candidate_id": candidate.id,
    }, None, AlwaysAllow())
    assert json.loads(explicit_retest)["candidate"]["status"] == "validating"


@pytest.mark.asyncio
async def test_start_validation_allows_broken_terminal_evidence_to_be_repaired(tmp_path):
    objective = WorkflowObjective(
        id="whole-objective", mode="whole_target", target_origin="https://target.test",
    )
    state = WorkflowState(objective=objective)
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test",
        endpoint="/search", objective_id=objective.id,
    ))
    proof = tmp_path / "proof.md"
    proof.write_text("first proof bytes", encoding="utf-8")
    artifact = EvidenceArtifact.capture(candidate.id, "proof.md", tmp_path)
    state.add_evidence(artifact)
    state.add_validation_result(ValidationResult(
        candidate.id, "sql-injection", "confirmed", evidence_refs=[artifact.id],
    ))
    proof.write_text("changed proof bytes", encoding="utf-8")
    tool = WorkflowTool(
        state, Target("https://target.test"), evidence_root=tmp_path,
    )

    reopened = await tool.run({
        "action": "start_validation", "candidate_id": candidate.id,
    }, None, AlwaysAllow())

    assert json.loads(reopened)["candidate"]["status"] == "validating"


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome,final_status", [
    ("not-confirmed", "validated"), ("deferred", "deferred"),
])
async def test_duplicate_result_finishes_restarted_validation_without_new_history(
    outcome, final_status,
):
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="xss", target="https://target.test", endpoint="/search",
    ))
    tool = WorkflowTool(state)
    args = {
        "action": "record_result", "candidate_id": candidate.id,
        "skill_name": "cross-site-scripting", "outcome": outcome,
    }
    first = json.loads(await tool.run(args, None, AlwaysAllow()))
    assert first["created"] is True
    assert candidate.status == final_status

    await tool.run({"action": "start_validation", "candidate_id": candidate.id},
                   None, AlwaysAllow())
    assert candidate.status == "validating"
    repeated = json.loads(await tool.run(args, None, AlwaysAllow()))

    assert repeated["created"] is False
    assert len(state.validation_results) == 1
    assert candidate.status == final_status
    assert candidate.id not in state.active_candidate_ids


def test_workflow_preserves_same_turn_result_context():
    tool = WorkflowTool(WorkflowState())

    assert tool.context_reduction_policy() == "preserve"


def test_schema_describes_action_specific_required_fields():
    tool = WorkflowTool(WorkflowState())
    schema = tool.schema()

    assert schema["required"] == ["action"]
    assert "record_result needs candidate_id, skill_name and outcome" in (
        tool.description()
    )
    assert "Required for record_evidence, start_validation, and record_result" in (
        schema["properties"]["candidate_id"]["description"]
    )
    assert "Required for record_result" in (
        schema["properties"]["outcome"]["description"]
    )
    assert "not used by record_result" in (
        schema["properties"]["status"]["description"]
    )


@pytest.mark.asyncio
async def test_structured_candidate_to_validation_handoff_and_dedup(tmp_path):
    state = WorkflowState()
    tool = WorkflowTool(
        state, Target("https://target.test"),
        evidence_root=tmp_path, session_id="session-1",
    )
    args = {
        "action": "record_candidate",
        "candidate_class": "sqli",
        "method": "POST",
        "endpoint": "/product",
        "parameter": "id",
        "source_skill": "web-input-analysis",
        "signals": ["syntax differential"],
    }
    first = json.loads(await tool.run(args, None, AlwaysAllow()))
    second = json.loads(await tool.run(args, None, AlwaysAllow()))
    candidate_id = first["candidate"]["id"]

    assert first["created"] is True
    assert second["created"] is False
    assert state.relevant_candidate_classes() == frozenset({"sql-injection"})

    await tool.run(
        {"action": "start_validation", "candidate_id": candidate_id},
        None,
        AlwaysAllow(),
    )
    (tmp_path / "sql-proof.txt").write_text("Request and response differential", encoding="utf-8")
    evidence = json.loads(await tool.run(
        {"action": "record_evidence", "candidate_id": candidate_id, "evidence_path": "sql-proof.txt"},
        None, AlwaysAllow(),
    ))["evidence"]["id"]
    result = json.loads(
        await tool.run(
            {
                "action": "record_result",
                "candidate_id": candidate_id,
                "skill_name": "sql-injection",
                "outcome": "confirmed",
                "evidence_refs": [evidence],
                **_confirmed_sqli_args(),
            },
            None,
            AlwaysAllow(),
        )
    )

    assert result["eligible_for_confirm_finding"] is True
    assert result["result"]["session_id"] == "session-1"
    assert result["result"]["recorded_at"].endswith("+00:00")
    assert state.candidates[candidate_id].status == "validated"


@pytest.mark.asyncio
async def test_candidate_uses_active_target_when_argument_is_omitted():
    state = WorkflowState()
    target = Target("https://a.example")
    tool = WorkflowTool(state, target)
    args = {
        "action": "record_candidate",
        "candidate_class": "sqli",
        "method": "POST",
        "endpoint": "/product",
        "parameter": "id",
    }

    first = json.loads(await tool.run(args, None, AlwaysAllow()))
    target.set_base_url("https://b.example")
    second = json.loads(await tool.run(args, None, AlwaysAllow()))
    explicit = json.loads(
        await tool.run(
            {**args, "target": "https://explicit.example"},
            None,
            AlwaysAllow(),
        )
    )

    assert first["candidate"]["target"] == "https://a.example"
    assert second["candidate"]["target"] == "https://b.example"
    assert explicit["candidate"]["target"] == "https://explicit.example"
    assert first["candidate"]["id"] != second["candidate"]["id"]


@pytest.mark.asyncio
async def test_record_candidate_requires_resolvable_target():
    output = await WorkflowTool(WorkflowState(), Target()).run(
        {
            "action": "record_candidate",
            "candidate_class": "xss",
            "endpoint": "/search",
        },
        None,
        AlwaysAllow(),
    )
    assert output.startswith("error: record_candidate requires target")


@pytest.mark.asyncio
async def test_list_is_bounded_prioritized_and_supports_specific_lookup():
    state = WorkflowState()
    candidates = []
    for index in range(DEFAULT_LIST_LIMIT + 5):
        candidate, _ = state.add_candidate(
            Candidate(
                candidate_class="xss",
                target="https://target.test",
                endpoint=f"/search/{index}/" + "e" * 500,
                parameter="p" * 500,
                location="query" * 50,
                signals=["s" * 500, "t" * 500, "omitted"],
                baseline_request_ref="b" * 500,
                auth_context_ref="a" * 500,
            )
        )
        candidates.append(candidate)
    state.set_candidate_status(candidates[-1].id, "validating")
    tool = WorkflowTool(state, Target("https://target.test"))

    listed = json.loads(
        await tool.run({"action": "list"}, None, AlwaysAllow())
    )
    specific = json.loads(
        await tool.run(
            {"action": "list", "candidate_id": candidates[-2].id},
            None,
            AlwaysAllow(),
        )
    )

    assert listed["total"] == DEFAULT_LIST_LIMIT + 5
    assert listed["returned"] == DEFAULT_LIST_LIMIT
    assert listed["truncated"] is True
    assert listed["candidates"][0]["id"] == candidates[-1].id
    assert len(json.dumps(listed)) < 20_000
    assert len(listed["candidates"][0]["endpoint"]) == 200
    assert len(listed["candidates"][0]["signals"]) == 2
    assert specific["returned"] == 1
    assert specific["candidates"][0]["id"] == candidates[-2].id


@pytest.mark.asyncio
async def test_skill_completion_is_explicit():
    state = WorkflowState()
    tool = WorkflowTool(state)

    output = json.loads(
        await tool.run(
            {
                "action": "complete_skill", "skill_name": "web_input_analysis",
                "artifact_ref": "web-input-analysis/target/candidates.md",
                "current_phase": "validation",
            },
            None,
            AlwaysAllow(),
        )
    )

    assert output["ok"] is True
    assert state.completed_skills == {"web-input-analysis"}
    assert state.completed_artifacts == {
        "web-input-analysis": "web-input-analysis/target/candidates.md"
    }
    assert WorkflowState.from_dict(state.to_dict()).completed_artifacts == state.completed_artifacts
    assert state.current_phase == "validation"


@pytest.mark.asyncio
async def test_sqli_completion_requires_and_reuses_canonical_artifact(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = WorkflowState()
    tool = WorkflowTool(
        state,
        Target("http://juice.lab:3000"),
        skills=skills,
        evidence_root=tmp_path,
    )

    missing = await tool.run(
        {"action": "complete_skill", "skill_name": "sql-injection"},
        None,
        AlwaysAllow(),
    )
    assert "artifacts/sql-injection/juice-lab-3000/results.md" in missing
    assert "sql-injection" not in state.completed_skills

    legacy_path = tmp_path / "sql-injection/juice-lab-3000/results.md"
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_text("legacy result", encoding="utf-8")
    legacy_only = await tool.run(
        {"action": "complete_skill", "skill_name": "sql-injection"},
        None,
        AlwaysAllow(),
    )
    assert "requires artifacts/sql-injection/juice-lab-3000/results.md" in legacy_only
    assert "sql-injection" not in state.completed_skills

    result_path = tmp_path / "artifacts/sql-injection/juice-lab-3000/results.md"
    result_path.parent.mkdir(parents=True)
    result_path.touch()
    empty = await tool.run(
        {"action": "complete_skill", "skill_name": "sql-injection"},
        None,
        AlwaysAllow(),
    )
    assert "requires artifacts/sql-injection/juice-lab-3000/results.md" in empty
    assert "sql-injection" not in state.completed_skills
    result_path.write_text("confirmed SQLi result", encoding="utf-8")
    wrong = await tool.run(
        {
            "action": "complete_skill",
            "skill_name": "sql-injection",
            "artifact_ref": "artifacts/sql-injection/juice-lab/results.md",
        },
        None,
        AlwaysAllow(),
    )
    assert "requires artifacts/sql-injection/juice-lab-3000/results.md" in wrong

    completed = json.loads(await tool.run(
        {"action": "complete_skill", "skill_name": "sql-injection"},
        None,
        AlwaysAllow(),
    ))
    resumed = WorkflowState.from_dict(state.to_dict())
    repeated = json.loads(await WorkflowTool(
        resumed,
        Target("http://juice.lab:3000"),
        skills=skills,
        evidence_root=tmp_path,
    ).run(
        {"action": "complete_skill", "skill_name": "sql-injection"},
        None,
        AlwaysAllow(),
    ))

    expected = "artifacts/sql-injection/juice-lab-3000/results.md"
    assert completed["artifact_ref"] == expected
    assert repeated["artifact_ref"] == expected
    assert resumed.completed_artifacts == {"sql-injection": expected}
    assert list(result_path.parent.iterdir()) == [result_path]


@pytest.mark.asyncio
async def test_recon_and_web_enumeration_completion_artifacts(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = WorkflowState()
    target = Target("http://juice.lab:3000")
    tool = WorkflowTool(state, target, skills=skills, evidence_root=tmp_path)

    missing_recon = await tool.run(
        {"action": "complete_skill", "skill_name": "recon"},
        None,
        AlwaysAllow(),
    )
    assert "requires artifacts/recon/juice-lab-3000/summary.md" in missing_recon

    recon_path = tmp_path / "artifacts/recon/juice-lab-3000/summary.md"
    recon_path.parent.mkdir(parents=True, exist_ok=True)
    recon_path.write_text("", encoding="utf-8")
    empty_recon = await tool.run(
        {"action": "complete_skill", "skill_name": "recon"},
        None,
        AlwaysAllow(),
    )
    assert "requires artifacts/recon/juice-lab-3000/summary.md" in empty_recon

    recon_path.write_text("# Recon Summary\nReconnaissance done.", encoding="utf-8")
    wrong_recon = await tool.run(
        {
            "action": "complete_skill",
            "skill_name": "recon",
            "artifact_ref": "artifacts/recon/wrong/summary.md",
        },
        None,
        AlwaysAllow(),
    )
    assert "requires artifacts/recon/juice-lab-3000/summary.md" in wrong_recon

    completed_recon = json.loads(await tool.run(
        {"action": "complete_skill", "skill_name": "recon"},
        None,
        AlwaysAllow(),
    ))
    expected_recon = "artifacts/recon/juice-lab-3000/summary.md"
    assert completed_recon["artifact_ref"] == expected_recon
    assert "recon" in state.completed_skills
    assert state.completed_artifacts["recon"] == expected_recon

    missing_enum = await tool.run(
        {"action": "complete_skill", "skill_name": "web-enumeration"},
        None,
        AlwaysAllow(),
    )
    assert "requires artifacts/web-enumeration/juice-lab-3000/inventory.md" in missing_enum

    enum_path = tmp_path / "artifacts/web-enumeration/juice-lab-3000/inventory.md"
    enum_path.parent.mkdir(parents=True, exist_ok=True)
    enum_path.write_text("", encoding="utf-8")
    empty_enum = await tool.run(
        {"action": "complete_skill", "skill_name": "web-enumeration"},
        None,
        AlwaysAllow(),
    )
    assert "requires artifacts/web-enumeration/juice-lab-3000/inventory.md" in empty_enum

    enum_path.write_text("# Inventory\nEndpoints found.", encoding="utf-8")
    completed_enum = json.loads(await tool.run(
        {"action": "complete_skill", "skill_name": "web-enumeration"},
        None,
        AlwaysAllow(),
    ))
    expected_enum = "artifacts/web-enumeration/juice-lab-3000/inventory.md"
    assert completed_enum["artifact_ref"] == expected_enum
    assert "web-enumeration" in state.completed_skills
    assert state.completed_artifacts["web-enumeration"] == expected_enum

    resumed = WorkflowState.from_dict(state.to_dict())
    assert resumed.completed_artifacts == {
        "recon": expected_recon,
        "web-enumeration": expected_enum,
    }


@pytest.mark.asyncio
async def test_web_input_analysis_completion_requires_canonical_artifact(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = WorkflowState()
    missing = await WorkflowTool(
        state, Target("https://target.test"), skills=skills, evidence_root=tmp_path,
    ).run({"action": "complete_skill", "skill_name": "web-input-analysis"}, None, AlwaysAllow())
    assert "requires artifacts/web-input-analysis/target-test/candidates.md" in missing
    artifact = tmp_path / "artifacts/web-input-analysis/target-test/candidates.md"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("No candidates", encoding="utf-8")

    output = json.loads(await WorkflowTool(
        state, Target("https://target.test"), skills=skills, evidence_root=tmp_path,
    ).run(
        {
            "action": "complete_skill", "skill_name": "web-input-analysis",
            "artifact_ref": "artifacts/web-input-analysis/target-test/candidates.md",
        },
        None,
        AlwaysAllow(),
    ))

    assert output["ok"] is True
    assert state.completed_skills == {"web-input-analysis"}
    assert output["artifact_ref"] == "artifacts/web-input-analysis/target-test/candidates.md"


@pytest.mark.asyncio
async def test_workflow_tool_rejects_result_without_candidate():
    output = await WorkflowTool(WorkflowState()).run(
        {
            "action": "record_result",
            "candidate_id": "cand_missing",
            "skill_name": "cross-site-scripting",
            "outcome": "blocked",
        },
        None,
        AlwaysAllow(),
    )
    assert output.startswith("error: unknown candidate")


def whole_target_tool_state() -> WorkflowState:
    state = WorkflowState()
    state.objective = WorkflowObjective(
        id="objective-active",
        mode="whole_target",
        target_origin="https://target.test",
    )
    return state


@pytest.mark.asyncio
async def test_phase_readiness_matches_completion_gate_for_artifact_coverage_and_prerequisites(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = whole_target_tool_state()
    tool = WorkflowTool(state, Target("https://target.test"), skills=skills, evidence_root=tmp_path)
    ref = "artifacts/web-enumeration/target-test/inventory.md"
    artifact = tmp_path / ref

    async def rejected(expected: str) -> None:
        readiness = tool.phase_completion_readiness("web-enumeration")
        assert readiness["ready"] is False and expected in readiness["reason"]
        output = await tool.run({"action": "complete_skill", "skill_name": "web-enumeration"}, None, AlwaysAllow())
        assert expected in output

    await rejected("requires " + ref)
    artifact.parent.mkdir(parents=True)
    artifact.write_text("", encoding="utf-8")
    await rejected("requires " + ref)
    artifact.write_text("inventory", encoding="utf-8")
    await rejected("recon must complete")
    record_completed_phase(state, "recon", objective_id="objective-active",
                           target_origin="https://target.test", artifact_ref="artifacts/recon.md")
    await rejected("explicit coverage")
    await record_phase_coverage_for_test(tool, "enumeration")
    state.record_phase_coverage("enumeration", "active_content_discovery", "failed",
                                objective_id="objective-active", target_origin="https://target.test",
                                reason="bounded scan failed")
    await rejected("unresolved failed/cancelled")
    state.record_phase_coverage("enumeration", "active_content_discovery", "cancelled",
                                objective_id="objective-active", target_origin="https://target.test",
                                reason="operator cancelled")
    await rejected("unresolved failed/cancelled")
    state.record_phase_coverage("enumeration", "active_content_discovery", "skipped",
                                objective_id="objective-active", target_origin="https://target.test",
                                reason="bounded retry unavailable")
    readiness = tool.phase_completion_readiness("web-enumeration")
    assert readiness["ready"] is True
    assert readiness["objective_id"] == "objective-active"
    assert readiness["target_origin"] == "https://target.test"
    assert readiness["prerequisites"] == ("recon",)
    assert set(readiness["required_coverage"]) == set(state.phase_coverage["objective-active:enumeration"])
    assert readiness["artifact_ref"] == ref
    assert "requires " + ref in (await tool.run({
        "action": "complete_skill", "skill_name": "web-enumeration",
        "artifact_ref": "artifacts/wrong.md",
    }, None, AlwaysAllow()))
    completed = json.loads(await tool.run({
        "action": "complete_skill", "skill_name": "web-enumeration",
        "artifact_ref": ref,
    }, None, AlwaysAllow()))
    assert completed["phase"] == "enumeration"
    assert tool.phase_completion_readiness("web-enumeration")["ready"] is False


@pytest.mark.asyncio
async def test_input_analysis_readiness_requires_input_resolution_or_explicit_no_inputs(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = whole_target_tool_state()
    tool = WorkflowTool(state, Target("https://target.test"), skills=skills, evidence_root=tmp_path)
    ref = "artifacts/web-input-analysis/target-test/candidates.md"
    artifact = tmp_path / ref
    artifact.parent.mkdir(parents=True)
    artifact.write_text("analysis", encoding="utf-8")
    assert "enumeration must complete" in tool.phase_completion_readiness(
        "web-input-analysis", no_inputs_discovered=True)["reason"]
    for phase in ("recon", "enumeration"):
        record_completed_phase(state, phase, objective_id="objective-active",
                               target_origin="https://target.test", artifact_ref=f"artifacts/{phase}.md")
    assert "no_inputs_discovered=true" in tool.phase_completion_readiness(
        "web-input-analysis")["reason"]
    readiness = tool.phase_completion_readiness("web-input-analysis", no_inputs_discovered=True)
    assert readiness["ready"] is True and readiness["artifact_ref"] == ref
    item = json.loads(await tool.run({
        "action": "record_input", "method": "GET", "endpoint": "/search",
        "parameter": "q", "location": "query",
    }, None, AlwaysAllow()))["input"]
    assert "pending or blocked" in tool.phase_completion_readiness("web-input-analysis")["reason"]
    await tool.run({"action": "set_input_disposition", "input_id": item["id"],
                    "disposition": "blocked", "disposition_reason": "fixture blocker"},
                   None, AlwaysAllow())
    assert "pending or blocked" in tool.phase_completion_readiness("web-input-analysis")["reason"]
    await tool.run({"action": "set_input_disposition", "input_id": item["id"],
                    "disposition": "analyzed"}, None, AlwaysAllow())
    assert tool.phase_completion_readiness("web-input-analysis")["ready"] is True
    result = json.loads(await tool.run({"action": "complete_skill", "skill_name": "web-input-analysis",
                                        "artifact_ref": ref}, None, AlwaysAllow()))
    assert result["phase"] == "input_analysis"


@pytest.mark.asyncio
async def test_whole_target_tool_assigns_candidate_scope_and_tracks_input(tmp_path):
    state = whole_target_tool_state()
    target = Target("https://target.test")
    tool = WorkflowTool(state, target, evidence_root=tmp_path)
    input_args = {
        "action": "record_input", "method": "GET", "endpoint": "/search",
        "parameter": "q", "location": "query", "input_type": "text",
    }
    input_args.update({
        "method": "POST", "endpoint": "/api/v1/auth/login",
        "parameter": "email", "location": "body", "input_type": "string",
        "content_type": "application/json",
        "sample_payload": '{"email":"user@example.test","password":"example-secret"}',
    })
    first = json.loads(await tool.run(input_args, None, AlwaysAllow()))
    duplicate = json.loads(await tool.run(input_args, None, AlwaysAllow()))
    assert first["created"] is True and duplicate["created"] is False
    input_id = first["input"]["id"]
    assert first["input"]["content_type"] == "application/json"
    assert "example-secret" not in first["input"]["sample_payload"]
    assert duplicate["input"]["sample_payload"] == first["input"]["sample_payload"]

    candidate = json.loads(await tool.run({
        "action": "record_candidate", "candidate_class": "xss",
        "target": "https://TARGET.test:443/any-path", "input_id": input_id,
        "request_template": '{"email":"{INJECTION_POINT}","password":"example-secret"}',
        "baseline_request_ref": "captures/login-baseline.json",
        "auth_context_ref": "captures/auth-context.md",
    }, None, AlwaysAllow()))
    candidate_id = candidate["candidate"]["id"]
    assert candidate["candidate"]["objective_id"] == "objective-active"
    assert candidate["candidate"]["method"] == "POST"
    assert candidate["candidate"]["endpoint"] == "/api/v1/auth/login"
    assert candidate["candidate"]["parameter"] == "email"
    assert candidate["candidate"]["content_type"] == "application/json"
    assert "example-secret" not in candidate["candidate"]["request_template"]
    assert candidate["candidate"]["baseline_request_ref"] == "captures/login-baseline.json"
    assert candidate["candidate"]["auth_context_ref"] == "captures/auth-context.md"
    assert state.attack_surface_inputs[input_id].candidate_ids == [candidate_id]

    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.attack_surface_inputs[input_id].content_type == "application/json"
    restored_candidate = restored.candidates[candidate_id]
    assert restored_candidate.request_template == candidate["candidate"]["request_template"]
    assert restored_candidate.baseline_request_ref == "captures/login-baseline.json"
    assert restored_candidate.auth_context_ref == "captures/auth-context.md"
    listed = json.loads(await tool.run({"action": "list"}, None, AlwaysAllow()))
    listed_input = listed["attack_surface_inputs"][0]
    listed_candidate = listed["candidates"][0]
    assert listed_input["content_type"] == "application/json"
    assert listed_input["sample_payload"].startswith('{"email":')
    assert listed_candidate["content_type"] == "application/json"
    assert listed_candidate["request_template"] == candidate["candidate"]["request_template"]
    assert listed_candidate["baseline_request_ref"] == "captures/login-baseline.json"
    assert listed_candidate["auth_context_ref"] == "captures/auth-context.md"
    assert "objective_id is assigned" in await tool.run({
        "action": "record_candidate", "candidate_class": "xss",
        "objective_id": "some-other-objective",
    }, None, AlwaysAllow())
    assert "must match the active whole-target origin" in await tool.run({
        "action": "record_candidate", "candidate_class": "xss",
        "target": "https://other.test",
    }, None, AlwaysAllow())
    assert "assigned by the runtime" in await tool.run({
        **input_args, "objective_id": "some-other-objective",
    }, None, AlwaysAllow())
    old_candidate, _ = state.add_candidate(Candidate(
        candidate_class="xss", target="https://target.test", endpoint="/old",
        objective_id="objective-old",
    ))
    assert "active objective" in await tool.run({
        "action": "link_input_candidate", "input_id": input_id,
        "candidate_id": old_candidate.id,
    }, None, AlwaysAllow())


@pytest.mark.asyncio
async def test_workflow_result_and_list_use_redacted_form_context():
    state = whole_target_tool_state()
    tool = WorkflowTool(state, Target("https://target.test"))
    body = "username=alice&password=demo-pass&q={INJECTION_POINT}"
    recorded = json.loads(await tool.run({
        "action": "record_input",
        "method": "POST",
        "endpoint": "/search",
        "parameter": "q",
        "location": "body",
        "input_type": "string",
        "content_type": "application/x-www-form-urlencoded",
        "sample_payload": body,
    }, None, AlwaysAllow()))

    assert "demo-pass" not in json.dumps(recorded)
    assert "username=alice" in recorded["input"]["sample_payload"]
    assert "password=[REDACTED]" in recorded["input"]["sample_payload"]
    assert "q={INJECTION_POINT}" in recorded["input"]["sample_payload"]

    candidate = json.loads(await tool.run({
        "action": "record_candidate",
        "candidate_class": "xss",
        "input_id": recorded["input"]["id"],
        "request_template": body,
    }, None, AlwaysAllow()))
    listed = json.loads(await tool.run({"action": "list"}, None, AlwaysAllow()))
    assert "demo-pass" not in json.dumps(candidate)
    assert "demo-pass" not in json.dumps(listed)
    assert "q={INJECTION_POINT}" in candidate["candidate"]["request_template"]
    assert "password=[REDACTED]" in listed["candidates"][0]["request_template"]


@pytest.mark.asyncio
async def test_workflow_request_context_fields_require_strings():
    state = whole_target_tool_state()
    tool = WorkflowTool(state, Target("https://target.test"))
    bad_input = await tool.run({
        "action": "record_input", "method": "POST", "endpoint": "/login",
        "content_type": 17,
    }, None, AlwaysAllow())
    assert isinstance(bad_input, ToolOutput) and bad_input.status == "error"
    assert state.attack_surface_inputs == {}

    bad_candidate = await tool.run({
        "action": "record_candidate", "candidate_class": "xss",
        "endpoint": "/login", "request_template": {"email": "{INJECTION_POINT}"},
    }, None, AlwaysAllow())
    assert isinstance(bad_candidate, ToolOutput) and bad_candidate.status == "error"
    assert state.candidates == {}


@pytest.mark.asyncio
async def test_selecting_candidate_returns_full_bounded_request_template():
    state = whole_target_tool_state()
    request_template = '{"query":"' + ("x" * 1200) + '{INJECTION_POINT}"}'
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test",
        endpoint="/api/search", method="POST", parameter="query", location="body",
        content_type="application/json", request_template=request_template,
        objective_id="objective-active",
    ))
    tool = WorkflowTool(state, Target("https://target.test"))

    listed = json.loads(await tool.run({
        "action": "list", "candidate_id": candidate.id,
    }, None, AlwaysAllow()))

    assert listed["returned"] == 1
    assert listed["candidates"][0]["request_template"] == request_template
    assert listed["candidates"][0]["request_template_truncated"] is False


@pytest.mark.asyncio
async def test_whole_target_phase_completion_checks_order_and_inventory(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = whole_target_tool_state()
    target = Target("https://target.test")
    tool = WorkflowTool(state, target, skills=skills, evidence_root=tmp_path)

    def create_artifact(relative: str) -> None:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("bounded work completed", encoding="utf-8")

    enum_ref = "artifacts/web-enumeration/target-test/inventory.md"
    create_artifact(enum_ref)
    assert "recon must complete" in await tool.run({
        "action": "complete_skill", "skill_name": "web-enumeration",
    }, None, AlwaysAllow())

    recon_ref = "artifacts/recon/target-test/summary.md"
    create_artifact(recon_ref)
    await record_phase_coverage_for_test(tool, "recon")
    recon = json.loads(await tool.run({
        "action": "complete_skill", "skill_name": "recon",
    }, None, AlwaysAllow()))
    assert recon["phase"] == "recon"
    await record_phase_coverage_for_test(tool, "enumeration")
    enumeration = json.loads(await tool.run({
        "action": "complete_skill", "skill_name": "web-enumeration",
    }, None, AlwaysAllow()))
    assert enumeration["phase"] == "enumeration"

    analysis_ref = "artifacts/web-input-analysis/target-test/candidates.md"
    create_artifact(analysis_ref)
    assert "requires at least one recorded input" in await tool.run({
        "action": "complete_skill", "skill_name": "web-input-analysis",
    }, None, AlwaysAllow())

    input_result = json.loads(await tool.run({
        "action": "record_input", "method": "GET", "endpoint": "/search",
        "parameter": "q", "location": "query",
    }, None, AlwaysAllow()))
    assert "pending or blocked" in await tool.run({
        "action": "complete_skill", "skill_name": "web-input-analysis",
    }, None, AlwaysAllow())
    disposition = await tool.run({
        "action": "set_input_disposition", "input_id": input_result["input"]["id"],
        "disposition": "analyzed",
    }, None, AlwaysAllow())
    assert json.loads(disposition)["input"]["disposition"] == "analyzed"
    analysis = json.loads(await tool.run({
        "action": "complete_skill", "skill_name": "web-input-analysis",
    }, None, AlwaysAllow()))
    assert analysis["phase"] == "input_analysis"
    assert state.completed_phases() == frozenset({"recon", "enumeration", "input_analysis"})


@pytest.mark.asyncio
async def test_whole_target_recon_completion_requires_explicit_resolved_coverage(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = whole_target_tool_state()
    tool = WorkflowTool(
        state,
        Target("https://target.test"),
        skills=skills,
        evidence_root=tmp_path,
    )
    artifact = tmp_path / "artifacts/recon/target-test/summary.md"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("recon summary", encoding="utf-8")

    missing = await tool.run(
        {"action": "complete_skill", "skill_name": "recon"}, None, AlwaysAllow()
    )
    assert "requires explicit coverage" in missing
    assert state.completed_phases() == frozenset()

    no_reason = await tool.run({
        "action": "record_phase_coverage", "phase": "recon",
        "coverage_dimension": "service_discovery", "coverage_status": "skipped",
    }, None, AlwaysAllow())
    assert isinstance(no_reason, ToolOutput) and no_reason.status == "error"
    assert "requires a reason" in no_reason

    await record_phase_coverage_for_test(tool, "recon")
    await tool.run({
        "action": "record_phase_coverage", "phase": "recon",
        "coverage_dimension": "reachability", "coverage_status": "failed",
        "coverage_reason": "temporary DNS failure",
    }, None, AlwaysAllow())
    unresolved = await tool.run(
        {"action": "complete_skill", "skill_name": "recon"}, None, AlwaysAllow()
    )
    assert "unresolved failed/cancelled coverage" in unresolved
    assert state.completed_phases() == frozenset()

    await tool.run({
        "action": "record_phase_coverage", "phase": "recon",
        "coverage_dimension": "reachability", "coverage_status": "skipped",
        "coverage_reason": "target unavailable after bounded retry",
    }, None, AlwaysAllow())
    completed = json.loads(await tool.run(
        {"action": "complete_skill", "skill_name": "recon"}, None, AlwaysAllow()
    ))
    assert completed["phase"] == "recon"
    marker = state.phase_completions["objective-active:recon"]
    assert marker.coverage["reachability"].status == "skipped"
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.phase_completions["objective-active:recon"].coverage == marker.coverage


@pytest.mark.asyncio
async def test_whole_target_explicit_no_input_completion_is_persisted(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = whole_target_tool_state()
    tool = WorkflowTool(
        state,
        Target("https://target.test"),
        skills=skills,
        evidence_root=tmp_path,
    )
    for relative in (
        "artifacts/recon/target-test/summary.md",
        "artifacts/web-enumeration/target-test/inventory.md",
        "artifacts/web-input-analysis/target-test/candidates.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("bounded work completed", encoding="utf-8")

    for skill_name in ("recon", "web-enumeration"):
        await record_phase_coverage_for_test(tool, "recon" if skill_name == "recon" else "enumeration")
        output = await tool.run(
            {"action": "complete_skill", "skill_name": skill_name},
            None,
            AlwaysAllow(),
        )
        assert json.loads(output)["ok"] is True
    analysis = await tool.run(
        {
            "action": "complete_skill",
            "skill_name": "web-input-analysis",
            "no_inputs_discovered": True,
        },
        None,
        AlwaysAllow(),
    )

    assert json.loads(analysis)["phase"] == "input_analysis"
    marker = state.phase_completions["objective-active:input_analysis"]
    assert marker.no_inputs_discovered is True
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.phase_completions[
        "objective-active:input_analysis"
    ].no_inputs_discovered is True


@pytest.mark.asyncio
async def test_whole_target_cannot_mark_unavailable_phase_complete():
    state = whole_target_tool_state()
    output = await WorkflowTool(state, Target("https://target.test")).run({
        "action": "complete_skill", "skill_name": "recon",
        "artifact_ref": "artifacts/recon/target-test/summary.md",
    }, None, AlwaysAllow())
    assert "unavailable for whole-target phase completion" in output
    assert state.completed_phases() == frozenset()


@pytest.mark.asyncio
async def test_candidate_validation_objective_scopes_validation_mutations(tmp_path):
    state = WorkflowState()
    candidate_a, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test", endpoint="/a",
    ))
    candidate_b, _ = state.add_candidate(Candidate(
        candidate_class="sql-injection", target="https://target.test", endpoint="/b",
    ))
    state.objective = WorkflowObjective(
        id="objective-candidate-a", mode="candidate_validation",
        target_origin="https://target.test", candidate_id=candidate_a.id,
    )
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    tool = WorkflowTool(
        state, Target("https://target.test"), coverage=coverage,
        evidence_root=tmp_path,
    )

    started = json.loads(await tool.run({
        "action": "start_validation", "candidate_id": candidate_a.id,
    }, None, AlwaysAllow()))
    assert started["ok"] is True
    assert "candidate does not match the active candidate-validation objective" in await tool.run({
        "action": "start_validation", "candidate_id": candidate_b.id,
    }, None, AlwaysAllow())

    (tmp_path / "proof.txt").write_text("Observed request and response", encoding="utf-8")
    evidence = json.loads(await tool.run({
        "action": "record_evidence", "candidate_id": candidate_a.id,
        "evidence_path": "proof.txt",
    }, None, AlwaysAllow()))
    assert evidence["ok"] is True
    assert "candidate does not match the active candidate-validation objective" in await tool.run({
        "action": "record_evidence", "candidate_id": candidate_b.id,
        "evidence_path": "proof.txt",
    }, None, AlwaysAllow())

    result = json.loads(await tool.run({
        "action": "record_result", "candidate_id": candidate_a.id,
        "skill_name": "sql-injection", "outcome": "not-confirmed",
    }, None, AlwaysAllow()))
    assert result["ok"] is True
    assert "candidate does not match the active candidate-validation objective" in await tool.run({
        "action": "record_result", "candidate_id": candidate_b.id,
        "skill_name": "sql-injection", "outcome": "not-confirmed",
    }, None, AlwaysAllow())

    state.add_validation_result(ValidationResult(
        candidate_a.id, "sql-injection", "not-confirmed", coverage_synced=False,
    ), force=True)
    synced = json.loads(await tool.run({
        "action": "sync_coverage", "candidate_id": candidate_a.id,
    }, None, AlwaysAllow()))
    assert synced["coverage_sync"] == "synced"
    state.add_validation_result(ValidationResult(
        candidate_b.id, "sql-injection", "not-confirmed", coverage_synced=False,
    ))
    assert "candidate does not match the active candidate-validation objective" in await tool.run({
        "action": "sync_coverage", "candidate_id": candidate_b.id,
    }, None, AlwaysAllow())


@pytest.mark.asyncio
async def test_candidate_validation_objective_rejects_missing_candidate(tmp_path):
    state = WorkflowState(objective=WorkflowObjective(
        id="objective-missing", mode="candidate_validation",
        target_origin="https://target.test", candidate_id="candidate-missing",
    ))
    output = await WorkflowTool(
        state, Target("https://target.test"), evidence_root=tmp_path,
    ).run({
        "action": "start_validation", "candidate_id": "candidate-missing",
    }, None, AlwaysAllow())
    assert "active candidate-validation objective references an unknown candidate" in output


@pytest.mark.asyncio
async def test_capture_context_handoff_survives_workflow_resume(tmp_path):
    state = whole_target_tool_state()
    tool = WorkflowTool(state, Target("https://target.test"), evidence_root=tmp_path)
    recorded = json.loads(await tool.run({
        "action": "record_input", "method": "POST", "endpoint": "/api/search",
        "parameter": "q", "location": "body", "input_type": "string",
        "content_type": "application/json",
        "sample_payload": '{"q":"{INJECTION_POINT}","csrf":"secret-value"}',
        "baseline_request_ref": "wr:captured-1", "auth_context_ref": "user-identity",
        "source_ref": "browser:tab-1",
    }, None, AlwaysAllow()))["input"]
    candidate = json.loads(await tool.run({
        "action": "record_candidate", "candidate_class": "sql-injection",
        "input_id": recorded["id"],
    }, None, AlwaysAllow()))["candidate"]
    assert candidate["baseline_request_ref"] == "wr:captured-1"
    assert candidate["auth_context_ref"] == "user-identity"
    assert candidate["source_ref"] == "browser:tab-1"
    assert candidate["request_template"] == recorded["sample_payload"]
    assert "secret-value" not in candidate["request_template"]
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.candidates[candidate["id"]].baseline_request_ref == "wr:captured-1"
    assert restored.attack_surface_inputs[recorded["id"]].source_ref == "browser:tab-1"
