import json
from pathlib import Path

import pytest

from src.agent.decision_planner import build_decision_plan
from src.coverage.store import CoverageStore
from src.findings.store import Store as FindingsStore
from src.llm.types import Message
from src.permission.permission import AlwaysAllow
from src.session.store import Store
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry
from src.target.target import Target
from src.tools.workflow import WorkflowTool
from src.tools.finding import ConfirmFindingTool
from src.workflow.state import WorkflowState


SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills"


def shipped_skills() -> Registry:
    registry = Registry()
    registry.load_dir(SKILLS_ROOT)
    return registry


async def register_proof(workflow, candidate_id, tmp_path, name):
    path = tmp_path / name
    path.write_text("Observed request and response differential", encoding="utf-8")
    response = json.loads(await workflow.run({
        "action": "record_evidence", "candidate_id": candidate_id,
        "evidence_path": name,
    }, None, AlwaysAllow()))
    return response["evidence"]["id"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("user_text", "skill_name", "candidate_class", "endpoint", "parameter"),
    [
        ("Test POST /product parameter id for SQL injection", "sql-injection", "sqli", "/product", "id"),
        ("Check GET /search parameter q for XSS", "cross-site-scripting", "xss", "/search", "q"),
    ],
)
async def test_offline_request_to_confirmed_workflow_handoff(
    user_text,
    skill_name,
    candidate_class,
    endpoint,
    parameter,
    tmp_path,
):
    skills = shipped_skills()
    plan = build_decision_plan(user_text, skills.list_enabled(), Target())
    assert plan is not None and plan.recommended_skill == skill_name

    body = await LoadSkillTool(skills).run({"name": skill_name})
    assert f"# Skill: {skill_name}" in body

    state = WorkflowState()
    workflow = WorkflowTool(state, Target("https://target.test"), evidence_root=tmp_path)
    candidate_args = {
        "action": "record_candidate",
        "candidate_class": candidate_class,
        "method": user_text.split()[1],
        "endpoint": endpoint,
        "parameter": parameter,
        "source_skill": "web-input-analysis",
        "signals": ["offline deterministic signal"],
    }
    recorded = json.loads(
        await workflow.run(
            candidate_args,
            None,
            AlwaysAllow(),
        )
    )
    candidate_id = recorded["candidate"]["id"]
    duplicate_candidate = json.loads(
        await workflow.run(candidate_args, None, AlwaysAllow())
    )
    assert duplicate_candidate["created"] is False
    assert duplicate_candidate["candidate"]["id"] == candidate_id
    await workflow.run(
        {"action": "start_validation", "candidate_id": candidate_id},
        None,
        AlwaysAllow(),
    )
    evidence_id = await register_proof(
        workflow, candidate_id, tmp_path, f"{skill_name}-proof.txt",
    )
    result = json.loads(
        await workflow.run(
            {
                "action": "record_result",
                "candidate_id": candidate_id,
                "skill_name": skill_name,
                "outcome": "confirmed",
                "evidence_refs": [evidence_id],
                "repeatable": True,
            },
            None,
            AlwaysAllow(),
        )
    )

    assert result["eligible_for_confirm_finding"] is True
    assert state.eligible_for_finding(candidate_id) is True

    duplicate = json.loads(
        await workflow.run(
            {
                "action": "record_result",
                "candidate_id": candidate_id,
                "skill_name": skill_name,
                "outcome": "confirmed",
                "evidence_refs": [evidence_id],
                "repeatable": True,
                "notes": "same result, different prose",
            },
            None,
            AlwaysAllow(),
        )
    )
    retest = json.loads(
        await workflow.run(
            {
                "action": "record_result",
                "candidate_id": candidate_id,
                "skill_name": skill_name,
                "outcome": "confirmed",
                "evidence_refs": [evidence_id],
                "repeatable": True,
                "force": True,
            },
            None,
            AlwaysAllow(),
        )
    )
    assert duplicate["created"] is False
    assert retest["created"] is True


def test_offline_direct_validation_and_informational_control():
    skills = shipped_skills().list_enabled()
    direct = build_decision_plan(
        "POST /login parameter username test SQL injection",
        skills,
        Target(),
    )
    informational = build_decision_plan("What is SQL injection?", skills, Target())

    assert direct is not None and direct.recommended_skill == "sql-injection"
    assert informational is None or informational.recommended_skill is None


@pytest.mark.asyncio
async def test_offline_resume_preserves_existing_candidate_and_result(tmp_path):
    state = WorkflowState()
    workflow = WorkflowTool(state, Target("https://target.test"))
    recorded = json.loads(
        await workflow.run(
            {"action": "record_candidate", "candidate_class": "idor", "endpoint": "/orders/1"},
            None,
            AlwaysAllow(),
        )
    )
    candidate_id = recorded["candidate"]["id"]
    await workflow.run(
        {
            "action": "record_result",
            "candidate_id": candidate_id,
            "skill_name": "access-control",
            "outcome": "not-confirmed",
        },
        None,
        AlwaysAllow(),
    )

    store = Store.new_with_id(tmp_path, "offline-resume")
    await store.save([Message(role="user", content="continue")], workflow=state)
    loaded = store.load().workflow

    assert candidate_id in loaded.candidates
    assert loaded.latest_result(candidate_id) is not None
    assert loaded.eligible_for_finding(candidate_id) is False


@pytest.mark.asyncio
async def test_offline_sqli_pipeline_confirms_one_canonical_redacted_finding(tmp_path):
    """Exercise the real handoff without a network, LLM, or browser."""
    registry = shipped_skills()
    skills = registry.list_enabled()
    target = Target("https://target.test:8443")
    plan = build_decision_plan(
        "Validate the login id database error candidate for SQL injection",
        skills,
        target,
    )
    assert plan is not None and plan.recommended_skill == "sql-injection"

    state = WorkflowState()
    coverage_path = tmp_path / ".kagent/coverage/e2e-session.json"
    workflow = WorkflowTool(
        state,
        target,
        coverage=CoverageStore(str(coverage_path)),
        skills=registry,
        evidence_root=tmp_path,
        session_id="e2e-session",
    )
    recorded = json.loads(
        await workflow.run(
            {
                "action": "record_candidate",
                "candidate_class": "sqli",
                "method": "POST",
                "endpoint": "/login",
                "parameter": "id",
                "source_skill": "web-input-analysis",
                "signals": ["repeatable boolean differential"],
            },
            None,
            AlwaysAllow(),
        )
    )
    candidate_id = recorded["candidate"]["id"]

    started = json.loads(
        await workflow.run(
            {"action": "start_validation", "candidate_id": candidate_id},
            None,
            AlwaysAllow(),
        )
    )
    assert started["candidate"]["status"] == "validating"

    result_path = tmp_path / "sql-injection/target-test-8443/results.md"
    result_path.parent.mkdir(parents=True)
    result_path.write_text(
        "Confirmed repeatable boolean differential for POST /login id.\n",
        encoding="utf-8",
    )
    evidence_id = await register_proof(
        workflow,
        candidate_id,
        tmp_path,
        "sql-injection/target-test-8443/results.md",
    )
    repeated_evidence_id = json.loads(await workflow.run(
        {
            "action": "record_evidence",
            "candidate_id": candidate_id,
            "evidence_path": "sql-injection/target-test-8443/results.md",
        },
        None,
        AlwaysAllow(),
    ))["evidence"]["id"]
    assert repeated_evidence_id == evidence_id

    result = json.loads(
        await workflow.run(
            {
                "action": "record_result",
                "candidate_id": candidate_id,
                "skill_name": "sql-injection",
                "outcome": "confirmed",
                "evidence_refs": [evidence_id],
                "techniques": ["boolean differential"],
                "repeatable": True,
            },
            None,
            AlwaysAllow(),
        )
    )
    assert result["created"] is True
    assert result["coverage_sync"] == "synced"
    assert result["eligible_for_confirm_finding"] is True
    assert state.relevant_candidate_classes() == frozenset()
    assert not (tmp_path / "findings").exists()

    finding = ConfirmFindingTool(
        FindingsStore(str(tmp_path / "findings")), workflow=state
    )
    await finding.run(
        {
            "candidate_id": candidate_id,
            "title": "SQL injection in login",
            "severity": "high",
            "url": "https://target.test:8443/login",
            "parameter": "id",
            "impact": "Database query manipulation only; no account takeover proven.",
            "response_excerpt": "authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.signature",
            "vuln_class": "sqli",
        },
        None,
        AlwaysAllow(),
    )

    reports = list((tmp_path / "findings").glob("*.md"))
    assert len(reports) == 1
    report = reports[0].read_text(encoding="utf-8")
    assert f"- **Candidate ID:** {candidate_id}" in report
    assert "SQL Injection" in report
    assert "CWE-89" in report
    assert "eyJhbGciOiJIUzI1NiJ9" not in report
    assert "[REDACTED" in report
    assert len(state.validation_results) == 1
    completed = json.loads(await workflow.run(
        {"action": "complete_skill", "skill_name": "sql-injection"},
        None,
        AlwaysAllow(),
    ))
    assert completed["artifact_ref"] == (
        "sql-injection/target-test-8443/results.md"
    )
    assert not (tmp_path / "findings/evidence").exists()
    assert coverage_path.exists()

    session = Store.new_with_id(tmp_path / "sessions", "e2e-session")
    await session.save(
        [Message(role="user", content="resume SQLi workflow")],
        target=target,
        workflow=state,
    )
    resumed = session.load().workflow
    assert resumed.evidence[evidence_id].is_resolvable(tmp_path)
    assert resumed.completed_artifacts["sql-injection"] == completed["artifact_ref"]
    resumed_coverage = CoverageStore(str(coverage_path))
    assert len(await resumed_coverage.list()) == 1
