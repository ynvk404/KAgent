"""Simulated single-agent skill handoff with no network or model calls."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.agent.decision_planner import (
    PlannerCandidate, PlannerContext, build_decision_plan,
)
from src.coverage.store import CoverageStore
from src.findings.store import Store
from src.permission.permission import AlwaysAllow
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.finding import ConfirmFindingTool
from src.tools.workflow import WorkflowTool
from src.workflow.state import WorkflowState


def _plan(state: WorkflowState, skills: SkillRegistry, text: str):
    candidates = tuple(
        PlannerCandidate(
            id=item.id, candidate_class=item.candidate_class,
            status=item.status, endpoint=item.endpoint, priority=item.priority,
            latest_outcome=(result.outcome if result else None),
            deferred_reason=(result.deferred_reason if result else None),
        )
        for item in state.candidates.values()
        for result in [state.latest_result(item.id)]
    )
    return build_decision_plan(
        text, skills.list_enabled(), Target("https://target.test"),
        PlannerContext(
            candidate_classes=state.relevant_candidate_classes(),
            completed_skills=frozenset(state.completed_skills),
            candidates=candidates,
        ),
    )


@pytest.mark.asyncio
async def test_inventory_to_finding_and_next_candidate_across_resume(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    state = WorkflowState()
    tool = WorkflowTool(
        state, Target("https://target.test"), coverage, skills,
        evidence_root=tmp_path, session_id="session-fixture",
    )
    allow = AlwaysAllow()

    inventory = tmp_path / "artifacts/web-enumeration/target-test/inventory.md"
    inventory.parent.mkdir(parents=True)
    inventory.write_text("GET /search?q; GET /product?id; POST /fetch?url", encoding="utf-8")
    await tool.run({
        "action": "complete_skill", "skill_name": "web-enumeration",
        "artifact_ref": inventory.relative_to(tmp_path).as_posix(),
        "current_phase": "analysis",
    }, None, allow)
    ids = {}
    for candidate_class, endpoint, parameter, priority in (
        ("cross-site-scripting", "/search", "q", "high"),
        ("sql-injection", "/product", "id", "medium"),
        ("ssrf", "/fetch", "url", "low"),
    ):
        response = json.loads(await tool.run({
            "action": "record_candidate", "candidate_class": candidate_class,
            "method": "GET", "endpoint": endpoint, "parameter": parameter,
            "priority": priority, "signals": ["inventory observation"],
        }, None, allow))
        assert response["supported"] is True
        ids[candidate_class] = response["candidate"]["id"]

    first = _plan(state, skills, "next validation")
    assert first is not None
    assert first.candidate_id == ids["cross-site-scripting"]
    assert first.candidate_id is not None
    assert first.recommended_skill == "cross-site-scripting"
    loaded = await LoadSkillTool(skills).run({"name": first.recommended_skill}, None, allow)
    assert "# Skill: cross-site-scripting" in loaded

    xss_proof = tmp_path / "artifacts/cross-site-scripting/target-test/proof.txt"
    xss_proof.parent.mkdir(parents=True)
    xss_proof.write_text(
        "GET /search?q=marker => executable marker in HTML body", encoding="utf-8",
    )
    proof = json.loads(await tool.run({
        "action": "record_evidence", "candidate_id": first.candidate_id,
        "evidence_path": xss_proof.relative_to(tmp_path).as_posix(),
    }, None, allow))["evidence"]["id"]
    confirmed = json.loads(await tool.run({
        "action": "record_result", "candidate_id": first.candidate_id,
        "skill_name": first.recommended_skill, "outcome": "confirmed",
        "evidence_refs": [proof], "repeatable": True,
    }, None, allow))
    assert confirmed["coverage_sync"] == "synced"
    assert confirmed["eligible_for_confirm_finding"] is True

    finder = ConfirmFindingTool(Store(project_directory=tmp_path), workflow=state)
    finding_args = {
        "candidate_id": first.candidate_id, "title": "Reflected XSS in search",
        "severity": "medium", "url": "https://target.test/search",
        "method": "GET", "vuln_class": "xss", "impact": "Script execution",
    }
    await finder.run(finding_args, None, allow)
    assert len(list((tmp_path / "artifacts/findings").glob("*.md"))) == 1

    second = _plan(state, skills, "next validation")
    assert second is not None and second.candidate_id == ids["sql-injection"]
    negative = json.loads(await tool.run({
        "action": "record_result", "candidate_id": second.candidate_id,
        "skill_name": "sql-injection", "outcome": "not-confirmed",
        "techniques": ["bounded differential"],
    }, None, allow))
    assert negative["coverage_sync"] == "synced"

    third = _plan(state, skills, "next validation")
    assert third is not None and third.candidate_id == ids["ssrf"]
    waiting = json.loads(await tool.run({
        "action": "record_result", "candidate_id": third.candidate_id,
        "skill_name": "ssrf", "outcome": "authorization-required",
        "deferred_reason": "internal destination not approved",
    }, None, allow))
    assert waiting["coverage_sync"] == "not-applicable"

    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.completed_artifacts["web-enumeration"] == (
        "artifacts/web-enumeration/target-test/inventory.md"
    )
    assert restored.eligible_for_finding(first.candidate_id)
    assert len(await CoverageStore(str(tmp_path / "coverage.json")).list()) == 2
    next_plan = _plan(restored, skills, "next validation")
    assert next_plan is not None and next_plan.candidate_id is None
    assert "internal destination not approved" in next_plan.guidance
    await ConfirmFindingTool(
        Store(project_directory=tmp_path), workflow=restored,
    ).run(finding_args, None, allow)
    assert len(list((tmp_path / "artifacts/findings").glob("*.md"))) == 1


def test_empty_workflow_guides_targeted_discovery():
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    plan = _plan(WorkflowState(), skills, "next")
    assert plan is not None
    assert plan.candidate_id is None
    assert "targeted inventory" in plan.guidance
