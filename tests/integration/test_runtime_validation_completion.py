"""Runtime completion through production tools with offline native HTTP dispatch."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from src.agent.agent import Agent, AgentOptions
from src.findings.store import Store
from src.llm.core.types import ChatResponse, Message
from src.permission.permission import AlwaysAllow
from src.skills.artifacts import completion_artifact_path
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.assessment import accepted_result
from src.workflow.state import Candidate, WorkflowMode, WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect
from tests.helpers.workflow import record_phase_coverage_for_test
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import ORIGIN, runtime  # noqa: F401


async def validated(runtime, tmp_path, *, candidate_class="sqli", outcome="confirmed", mode: WorkflowMode="direct"):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path, candidate_class=candidate_class)
    assert state.objective is not None
    state.objective.mode = mode
    state.objective.add_requested_goal(candidate.candidate_class)
    output = await runtime[0].execute("workflow", {**args, "outcome": outcome}, None, runtime[1])
    assert json.loads(output)["ok"], output
    return state, candidate, tool, {**args, "outcome": outcome}


def agent_for(runtime, state, tool):
    return Agent(AgentOptions(
        client=FakeClient([ChatResponse(Message("assistant", "Assigned validation is complete."), finish_reason="stop")]),
        tools=runtime[0], skills=tool.skills, prompter=runtime[1], store=None,
        target=runtime[6], workflow=state, engagement_state=runtime[2].engagement,
        streaming_enabled=False,
    ))


async def persist(runtime, tmp_path, state, candidate, *, finder=None):
    finder = finder or runtime[0].get("confirm_finding") or ConfirmFindingTool(Store(project_directory=tmp_path), workflow=state)
    if runtime[0].get("confirm_finding") is None:
        runtime[0].register(finder)
    output = await runtime[0].execute("confirm_finding", {
        "candidate_id": candidate.id, "title": "Bounded fixture validation",
        "severity": "low", "url": ORIGIN + "/fixture", "method": "GET",
        "vuln_class": candidate.candidate_class,
        "observed_impact": "Fixture response observed.",
        "potential_impact": "Further impact was not assessed.",
    }, None, runtime[1])
    assert state.finding_is_persisted(candidate.id), output
    return output


@pytest.mark.parametrize("candidate_class", ["sqli", "xss"])
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_direct_terminal_without_expert_receipt_or_results_report(runtime, tmp_path, candidate_class, outcome):
    state, candidate, tool, _ = await validated(runtime, tmp_path, candidate_class=candidate_class, outcome=outcome)
    if outcome == "confirmed":
        assert tool.validation_completion_error(candidate.id, runtime[2]) == "confirmed finding persistence pending"
        await persist(runtime, tmp_path, state, candidate)
    agent = agent_for(runtime, state, tool)
    expected = "tested_confirmed" if outcome == "confirmed" else "tested_not_confirmed"
    assert list(agent._reconcile_requested_goals().values()) == [expected]
    assert not agent._validation_completion_blockers()
    assert candidate.candidate_class in agent._planner_context().completed_skills
    assert not list(tmp_path.rglob("results.md"))
    assert not state.completed_skills
    collector = collect()
    await agent.run("continue", FakeSignal(), collector["sink"])
    assert collector["events"][-1]["stop_reason"] == "final_response"
    assert len(state.validation_results) == 1
    assert len(list((tmp_path / "artifacts/findings").glob("*.md"))) == (outcome == "confirmed")
    assert not any(message.tool_calls for message in agent.history)


async def test_confirmed_assessment_requires_finding_before_goal_and_skill_completion(runtime, tmp_path):
    state, candidate, tool, _ = await validated(runtime, tmp_path)
    agent = agent_for(runtime, state, tool)
    assert accepted_result(state, candidate, state.latest_result(candidate.id), runtime[2])
    assert list(agent._reconcile_requested_goals().values()) == ["in_progress"]
    assert "persistence pending" in agent._validation_completion_blockers()[0]
    assert "sql-injection" not in tool.completed_skills(runtime[2])
    # A model-issued receipt cannot manufacture completion.
    before = deepcopy(state.to_dict())
    output = await tool.run({"action": "complete_skill", "skill_name": "sql-injection"}, None, runtime[1])
    assert output.startswith("error:")
    assert state.to_dict() == before


@pytest.mark.parametrize("second_class", ["sqli", "xss"])
async def test_second_candidate_and_multiple_goals_remain_independent(runtime, tmp_path, second_class):
    state, first, tool, _ = await validated(runtime, tmp_path)
    await persist(runtime, tmp_path, state, first)
    agent = agent_for(runtime, state, tool)
    assert not agent._validation_completion_blockers()
    assert state.objective is not None
    state.objective.add_requested_goal(second_class)
    second, _ = state.add_candidate(Candidate(
        candidate_class=second_class, target=ORIGIN, endpoint="/second", method="GET",
        parameter="q", location="query", objective_id=state.objective.id,
    ))
    statuses = list(agent._reconcile_requested_goals().values())
    assert statuses == (["in_progress"] if second_class == "sqli" else ["tested_confirmed", "in_progress"])
    assert any(second.id in blocker for blocker in agent._validation_completion_blockers())
    assert second.candidate_class not in tool.completed_skills(runtime[2])
    assert state.finding_is_persisted(first.id)


async def test_satisfied_goal_does_not_complete_unrelated_pending_expert_work(runtime, tmp_path):
    state, first, tool, _ = await validated(runtime, tmp_path, outcome="not-confirmed")
    assert state.objective is not None
    other, _ = state.add_candidate(Candidate(
        candidate_class="xss", target=ORIGIN, endpoint="/other", objective_id=state.objective.id,
    ))
    agent = agent_for(runtime, state, tool)
    assert list(agent._reconcile_requested_goals().values()) == ["tested_not_confirmed"]
    collector = collect()
    await agent.run("continue", FakeSignal(), collector["sink"])
    assert collector["events"][-1]["stop_reason"] == "workflow_blocked"
    displayed = " ".join(e.get("text", "") for e in collector["events"] if e["type"] == "assistant-text")
    assert other.id in displayed and "incomplete" in displayed
    assert not state.completed_skills


@pytest.mark.parametrize("outcome", ["blocked", "deferred", "insufficient-evidence", "browser-required", "authorization-required"])
async def test_unresolved_outcomes_remain_explicit(runtime, tmp_path, outcome):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    assert state.objective is not None
    state.objective.mode = "direct"
    state.objective.add_requested_goal("xss")
    output = await runtime[0].execute("workflow", {
        **args, "outcome": outcome, "deferred_reason": "Fixture dependency remains unresolved",
    }, None, runtime[1])
    assert json.loads(output)["ok"], output
    agent = agent_for(runtime, state, tool)
    assert list(agent._reconcile_requested_goals().values()) == ["deferred"]
    result = state.latest_result(candidate.id)
    assert result is not None and result.outcome == outcome
    assert candidate.id in agent._validation_completion_blockers()[0]
    assert not tool.completed_skills(runtime[2])
    state.objective.mode = "whole_target"
    status, _, blockers = agent._whole_target_state()
    assert status != "completed"
    assert any(candidate.id in blocker for blocker in blockers)


@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_whole_target_discovery_artifacts_and_phase_gates_remain_mandatory(runtime, tmp_path, outcome):
    state, candidate, tool, _ = await validated(runtime, tmp_path, outcome=outcome, mode="whole_target")
    if outcome == "confirmed":
        await persist(runtime, tmp_path, state, candidate)
    agent = agent_for(runtime, state, tool)
    assert tool.validation_completion_error(candidate.id, runtime[2]) is None
    assert agent._whole_target_state()[0] == "actionable"
    assert agent._whole_target_state()[1][0] == "phase:recon"
    for phase, name in (("recon", "recon"), ("enumeration", "web-enumeration"), ("input_analysis", "web-input-analysis")):
        await record_phase_coverage_for_test(tool, phase)
        args = {"action": "complete_skill", "skill_name": name, "no_inputs_discovered": phase == "input_analysis"}
        absent = await tool.run(args, None, AlwaysAllow())
        assert absent.startswith("error:") and "requires artifacts/" in absent
        assert phase not in state.completed_phases()
        assert tool.skills is not None
        skill = tool.skills.get(name)
        assert skill is not None and skill.completion_artifact
        expected = completion_artifact_path(skill.completion_artifact, ORIGIN)
        path = tmp_path / expected
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Explicit bounded discovery fixture record.")
        wrong = await tool.run({**args, "artifact_ref": "artifacts/alternate.md"}, None, AlwaysAllow())
        assert wrong.startswith("error:")
        output = await tool.run(args, None, AlwaysAllow())
        assert json.loads(output)["ok"], output
    assert agent._whole_target_state() == ("completed", (), ())
    assert not list(tmp_path.rglob("results.md"))
    assert candidate.candidate_class not in state.completed_skills
    assert candidate.candidate_class in tool.completed_skills(runtime[2])
    # Completed validation cannot close another recorded obligation.
    assert state.objective is not None
    other, _ = state.add_candidate(Candidate(
        candidate_class="sqli", target=ORIGIN, endpoint="/second", objective_id=state.objective.id,
    ))
    status, actionable, _ = agent._whole_target_state()
    assert status == "actionable" and f"candidate:{other.id}" in actionable


async def test_custom_validator_operational_dependency_keeps_canonical_gate(runtime, tmp_path):
    state, candidate, tool, _ = await validated(runtime, tmp_path, outcome="not-confirmed")
    assert tool.skills is not None
    skill = tool.skills.get("sql-injection")
    assert skill is not None
    skill.completion_artifact = "artifacts/custom/{target}/fixture-state.json"
    expected = completion_artifact_path(skill.completion_artifact, ORIGIN)
    assert tool.validation_completion_error(candidate.id, runtime[2]) == f"operational artifact unavailable:{expected}"
    alternate = tmp_path / "artifacts/alternate.json"
    alternate.parent.mkdir(parents=True, exist_ok=True)
    alternate.write_text("fixture state")
    assert tool.validation_completion_error(candidate.id, runtime[2])
    canonical = tmp_path / expected
    canonical.parent.mkdir(parents=True, exist_ok=True)
    canonical.write_text("fixture state")
    assert tool.validation_completion_error(candidate.id, runtime[2]) is None
    # A canonical path symlink escaping the root must not satisfy the dependency.
    canonical.unlink()
    canonical.symlink_to(tmp_path.parent / "outside-fixture.json")
    assert tool.validation_completion_error(candidate.id, runtime[2])


async def test_missing_validator_registry_cannot_reopen_accepted_terminal_work(runtime, tmp_path):
    state, candidate, tool, _ = await validated(runtime, tmp_path, outcome="not-confirmed", mode="whole_target")
    agent = agent_for(runtime, state, tool)
    tool.skills = None
    status, actionable, blockers = agent._whole_target_state()
    assert status != "completed"
    assert f"revalidate:{candidate.id}" not in actionable
    assert any(candidate.id in blocker for blocker in blockers)
    assert agent._terminal_candidate_probe_blocker("http", {
        "method": "GET", "url": "/fixture?q=fixture",
    }) is not None
    assert len(runtime[4]) == 1


async def test_reporting_failure_does_not_revoke_accepted_result_or_completion(runtime, tmp_path, monkeypatch):
    state, candidate, tool, _ = await validated(runtime, tmp_path)
    result = state.latest_result(candidate.id)
    assert result is not None
    result_before = deepcopy(result.to_dict())
    finder = ConfirmFindingTool(Store(project_directory=tmp_path), workflow=state)
    async def fail(_):
        raise OSError("offline report failure")
    monkeypatch.setattr(finder, "write_summary", fail)
    output = await persist(runtime, tmp_path, state, candidate, finder=finder)
    assert "compact report export failed" in output
    assert result.to_dict() == result_before
    assert tool.validation_completion_error(candidate.id, runtime[2]) is None
    assert accepted_result(state, candidate, state.latest_result(candidate.id), runtime[2])


async def test_retries_resume_and_legacy_receipts_are_read_only_and_idempotent(runtime, tmp_path):
    state, candidate, tool, args = await validated(runtime, tmp_path)
    await persist(runtime, tmp_path, state, candidate)
    repeated = await runtime[0].execute("workflow", args, None, runtime[1])
    assert json.loads(repeated)["ok"], repeated
    await persist(runtime, tmp_path, state, candidate)
    state.completed_skills.add("sql-injection")
    state.completed_artifacts["sql-injection"] = "artifacts/sql-injection/legacy/results.md"
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.completed_artifacts == state.completed_artifacts
    assert restored.completed_skills == {"sql-injection"}
    tool.state = restored
    policy = runtime[2]
    policy.bind_validation_context(restored, tool.skills, tool.target)
    agent = agent_for(runtime, restored, tool)
    agent._reconcile_requested_goals()
    before = deepcopy(restored.to_dict())
    for _ in range(3):
        assert agent._validation_completion_blockers() == ()
        assert "sql-injection" in agent._planner_context().completed_skills
        assert list(agent._reconcile_requested_goals().values()) == ["tested_confirmed"]
        receipt = await tool.run({"action": "complete_skill", "skill_name": "sql-injection"}, None, runtime[1])
        assert json.loads(receipt)["ok"], receipt
    assert restored.to_dict() == before
    assert len(restored.validation_results) == len(restored.persisted_findings) == 1
    assert tool.coverage is not None
    assert len(await tool.coverage.list()) == 1
    assert len(list((tmp_path / "artifacts/findings").glob("*.md"))) == 1
    # A historical receipt cannot bypass new assigned work.
    restored.set_candidate_status(candidate.id, "validating")
    assert "sql-injection" not in tool.completed_skills(policy)
    assert agent._validation_completion_blockers()


@pytest.mark.parametrize("change", ["target", "objective", "candidate-target", "result-objective", "proof", "seal", "attempt", "active-retest", "coverage", "cleanup"])
async def test_stale_or_incomplete_state_never_authorizes_completion(runtime, tmp_path, change):
    state, candidate, tool, _ = await validated(runtime, tmp_path, outcome="not-confirmed")
    result = state.latest_result(candidate.id)
    assert result is not None and state.objective is not None
    if change == "target":
        assert tool.target is not None
        tool.target.set_base_url("https://other.test")
    elif change == "objective":
        state.objective.id = "different-objective"
    elif change == "candidate-target":
        candidate.target = "https://other.test"
    elif change == "result-objective":
        result.objective_id = "different-objective"
    elif change == "proof":
        proof = tmp_path / state.evidence[result.evidence_refs[0]].path
        proof.chmod(0o600)
        proof.write_text("tampered proof")
    elif change == "seal":
        result.assessment["criteria"] = "substituted"
    elif change == "attempt":
        assert result.attempt_id is not None
        state.attempts[result.attempt_id]["status"] = "active"
    elif change == "active-retest":
        assert result.attempt_id is not None
        attempt = deepcopy(state.attempts[result.attempt_id])
        attempt.update(id="new-active-attempt", status="active")
        state.attempts[attempt["id"]] = attempt
    elif change == "coverage":
        result.coverage_synced = False
    else:
        result.cleanup_state = "pending"
    agent = agent_for(runtime, state, tool)
    assert tool.validation_completion_error(candidate.id, runtime[2])
    assert not tool.completed_skills(runtime[2])
    assert all(s not in {"tested_confirmed", "tested_not_confirmed"} for s in agent._reconcile_requested_goals().values())
    state.objective.mode = "whole_target"
    assert agent._whole_target_state()[0] != "completed"
