"""Offline input-analysis dependency gates; no target or provider calls."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from src.coverage.store import CoverageStore
from src.permission.permission import AlwaysAllow
from src.skills.artifacts import completion_artifact_path
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.outcome import ToolOutput
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowObjective, WorkflowPhase, WorkflowState
from tests.helpers.workflow import record_completed_phase


ORIGIN = "https://target.test"


@pytest.fixture
def analysis(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KAGENT_PROJECT_ROOT", str(tmp_path))
    state = WorkflowState(objective=WorkflowObjective("input-dependencies", "whole_target", ORIGIN))
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    tool = WorkflowTool(state, Target(ORIGIN), skills=skills, coverage=coverage, evidence_root=tmp_path)
    phases: tuple[tuple[WorkflowPhase, str], ...] = (
        ("recon", "recon"), ("enumeration", "web-enumeration"), ("input_analysis", "web-input-analysis"))
    for phase, name in phases:
        skill = skills.get(name)
        assert skill is not None and skill.completion_artifact
        relative = completion_artifact_path(skill.completion_artifact, ORIGIN)
        artifact = tmp_path / relative
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("Synthetic offline analysis fixture, not a target assessment.")
        if phase != "input_analysis":
            record_completed_phase(state, phase, objective_id="input-dependencies",
                                   target_origin=ORIGIN, artifact_ref=relative)
    return tool, coverage


async def record_input(tool, parameter="cid", endpoint="/orders"):
    output = await tool.run({"action": "record_input", "method": "POST", "endpoint": endpoint,
                             "parameter": parameter, "location": "json",
                             "content_type": "application/json"}, None, AlwaysAllow())
    return json.loads(output)["input"]["id"]


@pytest.mark.parametrize("declaration", [
    {}, {"analysis_complete": False}, {"analysis_complete": None},
    {"analysis_complete": "true"}, {"analysis_complete": 1},
])
@pytest.mark.parametrize("initial", ["pending", "blocked"])
async def test_inaccessible_input_cannot_be_closed_without_completed_analysis(analysis, declaration, initial):
    tool, coverage = analysis
    iid = await record_input(tool)
    reason = "Required bearer JWT is unavailable; the order handler could not be analyzed."
    if initial == "blocked":
        await tool.run({"action": "set_input_disposition", "input_id": iid,
                        "disposition": "blocked", "disposition_reason": reason}, None, AlwaysAllow())
    before = deepcopy(tool.state.to_dict())
    output = await tool.run({"action": "set_input_disposition", "input_id": iid,
                             "disposition": "analyzed", "disposition_reason": reason,
                             **declaration}, None, AlwaysAllow())
    assert isinstance(output, ToolOutput) and output.status == "error"
    assert "analysis_complete" in output
    assert tool.state.to_dict() == before
    assert tool.state.attack_surface_inputs[iid].disposition == initial
    assert not tool.phase_completion_readiness("web-input-analysis")["ready"]
    assert await coverage.list() == []


@pytest.mark.parametrize("resolution", ["provided", "excluded"])
async def test_jwt_blockers_prevent_completion_and_resolve_without_false_coverage(analysis, resolution):
    tool, coverage = analysis
    public = await record_input(tool, "q", "/search")
    output = await tool.run({"action": "set_input_disposition", "input_id": public,
                             "disposition": "analyzed", "analysis_complete": True,
                             "disposition_reason": "Completed passive triage from observed input behavior."},
                            None, AlwaysAllow())
    assert json.loads(output)["ok"]
    blocked = [await record_input(tool, parameter) for parameter in ("cid", "orderLines", "orderLinesData")]
    for iid in blocked:
        output = await tool.run({"action": "set_input_disposition", "input_id": iid,
                                 "disposition": "blocked", "disposition_reason":
                                 "Required bearer JWT is unavailable; handler analysis cannot proceed."},
                                None, AlwaysAllow())
        assert json.loads(output)["input"]["disposition"] == "blocked"
    page = json.loads(await tool.run({"action": "list", "view": "inputs"}, None, AlwaysAllow()))
    assert page["input_counts"] == {"total": 4, "pending": 0, "blocked": 3, "analyzed": 1, "dropped": 0}
    before = deepcopy(tool.state.to_dict())
    completion = {"action": "complete_skill", "skill_name": "web-input-analysis"}
    assert "pending or blocked" in await tool.run(completion, None, AlwaysAllow())
    assert tool.state.to_dict() == before
    assert "input_analysis" not in tool.state.completed_phases()
    status, actionable, blockers = tool.state.whole_target_status(
        target_origin=ORIGIN, available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset({"sql-injection"}), coverage_sync_available=True)
    assert status == "blocked" and not actionable and blockers
    restored = WorkflowState.from_dict(tool.state.to_dict())
    assert all(restored.attack_surface_inputs[iid].disposition == "blocked" for iid in blocked)
    assert await coverage.list() == []
    tool = WorkflowTool(restored, tool.target, skills=tool.skills,
                        coverage=coverage, evidence_root=tool.evidence_root)

    for iid in blocked:
        if resolution == "provided":
            assert json.loads(await tool.run({"action": "set_input_disposition", "input_id": iid,
                                               "disposition": "pending"}, None, AlwaysAllow()))["ok"]
            assert "pending or blocked" in await tool.run(completion, None, AlwaysAllow())
            args = {"disposition": "analyzed", "analysis_complete": True,
                    "disposition_reason": "Completed remaining passive triage from operator-supplied request context."}
        else:
            args = {"disposition": "dropped", "disposition_reason":
                    "Operator explicitly excluded this input from this assessment; remains untested."}
        assert json.loads(await tool.run({"action": "set_input_disposition", "input_id": iid,
                                          **args}, None, AlwaysAllow()))["ok"]
    assert tool.phase_completion_readiness("web-input-analysis")["ready"]
    assert json.loads(await tool.run(completion, None, AlwaysAllow()))["phase"] == "input_analysis"
    assert all(tool.state.attack_surface_inputs[iid].id == iid for iid in blocked)
    assert await coverage.list() == [] and (await coverage.summary()).total == 0
    assert not tool.state.attempts and not tool.state.validation_results
    assert not tool.state.evidence and not tool.state.persisted_findings
    assert tool.state.whole_target_status(
        target_origin=ORIGIN, available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset({"sql-injection"}), coverage_sync_available=True)[0] == "completed"


async def test_completed_passive_triage_does_not_infer_credentials_from_field_or_401(analysis):
    tool, coverage = analysis
    iid = await record_input(tool, "email", "/login")
    output = await tool.run({"action": "set_input_disposition", "input_id": iid,
                             "disposition": "analyzed", "analysis_complete": True,
                             "disposition_reason": "Completed passive triage; a 401 alone does not establish missing credentials."},
                            None, AlwaysAllow())
    assert json.loads(output)["input"]["disposition"] == "analyzed"
    assert tool.phase_completion_readiness("web-input-analysis")["ready"]
    assert await coverage.list() == []


def test_analysis_completion_declaration_is_exposed_only_for_input_disposition(analysis):
    tool, _ = analysis
    schema = tool.schema()["properties"]
    assert schema["analysis_complete"]["type"] == "boolean"
    assert "disposition=analyzed" in schema["analysis_complete"]["description"]
    assert "blocked" in schema["disposition"]["description"]
    assert "Action use: set_input_disposition." in schema["analysis_complete"]["description"]
