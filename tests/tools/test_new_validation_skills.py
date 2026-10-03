from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowState


REPO_ROOT = Path(__file__).resolve().parents[2]
NEW_VALIDATION_SKILLS = (
    ("nosql-injection", "nosql-injection"),
    ("path-traversal", "path-traversal"),
    ("cors-misconfiguration", "cors-misconfiguration"),
    ("open-redirect", "open-redirect"),
    ("jwt-misconfiguration", "jwt-misconfiguration"),
    ("file-upload", "file-upload"),
    ("command-injection", "command-injection"),
    ("xxe", "xxe"),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(("skill_name", "candidate_class"), NEW_VALIDATION_SKILLS)
async def test_new_skill_accepts_candidate_and_records_validation(
    skill_name: str,
    candidate_class: str,
):
    skills = SkillRegistry()
    skills.load_dir(REPO_ROOT / "skills")
    state = WorkflowState()
    tool = WorkflowTool(state, Target("https://target.test"), skills=skills)

    candidate_output = await tool.run(
        {
            "action": "record_candidate",
            "candidate_class": candidate_class,
            "target": "https://target.test",
            "method": "GET",
            "endpoint": "/safe-read",
            "parameter": "probe",
            "location": "query",
            "source_skill": "web-input-analysis",
        },
        None,
        AlwaysAllow(),
    )
    candidate_result = json.loads(candidate_output)
    candidate_id = candidate_result["candidate"]["id"]

    assert candidate_result["supported"] is True
    assert candidate_result["recommended_skills"] == [skill_name]
    assert candidate_result["candidate"]["candidate_class"] == candidate_class

    started = json.loads(await tool.run(
        {"action": "start_validation", "candidate_id": candidate_id},
        None,
        AlwaysAllow(),
    ))
    assert started["candidate"]["status"] == "validating"

    recorded = json.loads(await tool.run(
        {
            "action": "record_result",
            "candidate_id": candidate_id,
            "skill_name": skill_name,
            "outcome": "not-confirmed",
            "techniques": ["bounded-runtime-regression"],
            "notes": "Regression test only; no target request was sent.",
        },
        None,
        AlwaysAllow(),
    ))

    stored = state.latest_result(candidate_id)
    assert recorded["ok"] is True
    assert recorded["result"]["outcome"] == "not-confirmed"
    assert stored is not None
    assert stored.skill_name == skill_name
    assert stored.outcome == "not-confirmed"
    assert state.candidates[candidate_id].status == "validated"
