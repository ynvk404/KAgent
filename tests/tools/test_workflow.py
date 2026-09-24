from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.coverage.store import CoverageStore
from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.workflow import DEFAULT_LIST_LIMIT, WorkflowTool
from src.workflow.state import Candidate, WorkflowState


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
        assert response["recommended_skills"] == [validator]
        assert response["candidate"]["status"] == "queued"

    unsupported = json.loads(await tool.run(
        {"action": "record_candidate", "candidate_class": "open-redirect", "endpoint": "/redirect"},
        None, AlwaysAllow(),
    ))
    assert unsupported["supported"] is False
    assert unsupported["recommended_skills"] == []
    assert unsupported["candidate"]["status"] == "deferred"
    forced = json.loads(await tool.run(
        {"action": "record_candidate", "candidate_class": "open-redirect",
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
    (tmp_path / "proof.txt").write_text("Changed proof", encoding="utf-8")
    assert "changed or is unavailable" in await tool.run(
        {**base, "candidate_id": first.id, "evidence_refs": [evidence]}, None, AlwaysAllow(),
    )
    assert state.validation_results == []


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
    assert "record_result needs candidate_id, skill_name, and outcome" in (
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
                "repeatable": True,
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
async def test_skill_without_completion_artifact_is_unchanged(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    state = WorkflowState()

    output = json.loads(await WorkflowTool(
        state, Target("https://target.test"), skills=skills, evidence_root=tmp_path,
    ).run(
        {"action": "complete_skill", "skill_name": "web-input-analysis"},
        None,
        AlwaysAllow(),
    ))

    assert output["ok"] is True
    assert state.completed_skills == {"web-input-analysis"}


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
