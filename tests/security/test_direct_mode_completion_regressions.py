"""Direct completion through production gates; transports and models are offline."""
from copy import deepcopy
import json

import pytest

from src.agent.agent import AgentRunOptions
from src.agent.decision_planner import build_decision_plan
from src.findings.store import Store as FindingStore
from src.llm.core.client import StreamingClient
from src.llm.core.reasoning import ReasoningLevel
from src.llm.core.types import ChatResponse, Message
from src.session.store import Store
from src.skills.artifacts import completion_artifact_path
from src.tools.workflow.finding import ConfirmFindingTool
from src.workflow.assessment import accepted_result
from src.workflow.state import Candidate
from tests.helpers.agent_fakes import FakeSignal, collect
from tests.helpers.workflow import prepare_validation_prerequisites, record_phase_coverage_for_test
from tests.integration.test_runtime_validation_completion import agent_for, persist, validated
from tests.security.test_agent_assessment import ASSESSMENT, setup
from tests.security.test_execution_policy import ORIGIN, runtime  # noqa: F401
from tests.security.test_terminal_goal_checkpoint import TerminalClient, assert_closed, prepared


class SummaryClient(TerminalClient, StreamingClient):
    summary_text = "All work is complete; every class is confirmed."

    async def chat(self, request, signal=None):
        response = await super().chat(request, signal)
        if request.tools is None:
            response.message.content = self.summary_text
        return response

    async def chat_stream(self, request, on_delta, signal=None):
        response = await self.chat(request, signal)
        if response.message.content:
            on_delta(response.message.content)
        return response


def synthesis_instruction(client):
    return next(m.content for m in reversed(client.requests[-1].messages)
                if m.role == "system" and "Requested-goal runtime summary" in m.content)


@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_direct_completed_last_step_has_consistent_instruction(runtime, tmp_path, outcome):
    state, candidate, tool, _ = await validated(runtime, tmp_path, outcome=outcome)
    if outcome == "confirmed":
        await persist(runtime, tmp_path, state, candidate)
    agent = agent_for(runtime, state, tool)
    client = TerminalClient(("workflow", {"action": "list", "candidate_id": candidate.id}))
    agent.client = client
    events = collect()
    before = deepcopy(state.to_dict())
    sent_before = len(runtime[4])
    await agent.run("continue", FakeSignal(), events["sink"], AgentRunOptions(max_steps=1))
    assert events["events"][-1]["stop_reason"] == "final_response"
    assert not agent._validation_completion_blockers()
    assert "The objective is incomplete/partial" not in synthesis_instruction(client)
    assert len(client.requests) == 2 and len(runtime[4]) == sent_before
    assert state.validation_results[0].to_dict() == before["validation_results"][0]


@pytest.mark.parametrize("cleanup", ["requires-user-action", "failed", "unknown"])
async def test_direct_operator_cleanup_blocks_first_batch_and_survives_reload(runtime, tmp_path, cleanup):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path, mode="direct")
    assert state.objective is not None
    state.objective.add_requested_goal(candidate.candidate_class)
    payload = json.loads(await runtime[0].execute("workflow", {
        **args, "outcome": "not-confirmed", "mutation_performed": None if cleanup == "unknown" else True,
        "cleanup_state": cleanup, "cleanup_status": "Operator action required in fixture",
    }, None, runtime[1]))
    assert payload["ok"], payload
    agent = agent_for(runtime, state, tool)
    agent.store = Store.new_with_id(tmp_path / "sessions", tool.session_id)
    client = TerminalClient(("workflow", {"action": "list", "candidate_id": candidate.id}))
    agent.client = client
    result = state.latest_result(candidate.id)
    assert result is not None and accepted_result(state, candidate, result, runtime[2])
    original = deepcopy(result.to_dict())
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"], AgentRunOptions(max_steps=20))
    assert events["events"][-1]["stop_reason"] == "workflow_blocked"
    assert len(client.requests) == 2 and len(runtime[4]) == 1
    assert result.to_dict() == original
    assert agent.store.load().workflow.to_dict() == state.to_dict()


async def assessed_sibling(runtime, tmp_path, state, tool, *, cleanup=None, candidate_class="sqli"):
    assert state.objective is not None
    sibling, _ = state.add_candidate(Candidate(
        candidate_class, target=ORIGIN, endpoint="/second", method="GET", parameter="q",
        location="query", objective_id=state.objective.id,
    ))
    await prepare_validation_prerequisites(tool, sibling.id)
    started = json.loads(await runtime[0].execute("workflow", {
        "action": "start_validation", "candidate_id": sibling.id,
    }, None, runtime[1]))
    assert started["ok"], started
    await runtime[0].execute("http", {"url": "/second?q=fixture", "phase": "validation"}, None, runtime[1])
    observation = next(reversed(runtime[2].observations._items))
    (tmp_path / "second-proof.md").write_text("Controlled offline sibling observation.")
    evidence = json.loads(await runtime[0].execute("workflow", {
        "action": "record_evidence", "candidate_id": sibling.id, "evidence_path": "second-proof.md",
    }, None, runtime[1]))["evidence"]["id"]
    args = {"action": "record_result", "candidate_id": sibling.id,
            "attempt_id": started["validation_context"]["attempt_id"],
            "skill_name": "sql-injection" if candidate_class == "sqli" else "cross-site-scripting",
            "outcome": "confirmed", "evidence_refs": [evidence], "observation_ids": [observation],
            "mutation_performed": None if cleanup == "unknown" else bool(cleanup),
            "assessment": ASSESSMENT.copy()}
    if cleanup:
        args.update(cleanup_state=cleanup, cleanup_status="Exact cleanup still requires authority")
    output = json.loads(await runtime[0].execute("workflow", args, None, runtime[1]))
    assert output["ok"], output
    return sibling


async def persist_sibling(runtime, tmp_path, state, candidate):
    if runtime[0].get("confirm_finding") is None:
        runtime[0].register(ConfirmFindingTool(FindingStore(project_directory=tmp_path), workflow=state))
    await runtime[0].execute("confirm_finding", {
        "candidate_id": candidate.id, "title": "Bounded sibling fixture", "severity": "low",
        "url": ORIGIN + "/second", "method": "GET", "vuln_class": candidate.candidate_class,
        "observed_impact": "Fixture response observed.", "potential_impact": "No further impact assessed.",
    }, None, runtime[1])
    assert state.finding_is_persisted(candidate.id)


@pytest.mark.parametrize("obligation", ["finding", "coverage", "cleanup"])
async def test_direct_planner_selects_unfinished_sibling_local_obligation(runtime, tmp_path, obligation):
    state, first, tool, _ = await validated(runtime, tmp_path, outcome="not-confirmed")
    second = await assessed_sibling(runtime, tmp_path, state, tool,
                                    cleanup="pending" if obligation == "cleanup" else None)
    if obligation in {"cleanup", "coverage"}:
        await persist_sibling(runtime, tmp_path, state, second)
    if obligation == "coverage":
        result = state.latest_result(second.id)
        assert result is not None
        result.coverage_synced = False
    agent = agent_for(runtime, state, tool)
    context = agent._planner_context()
    before = deepcopy(state.to_dict())
    sent_before = len(runtime[4])
    assert agent._validation_completion_error(first, runtime[2]) is None
    plan = build_decision_plan("continue", agent.skills.list_enabled(), agent.target, context)
    assert plan is not None and plan.candidate_id == second.id
    assert plan.recommended_skill is None
    expected = {"finding": "confirm_finding", "coverage": "sync_coverage", "cleanup": "cleanup"}[obligation]
    assert expected in plan.guidance
    assert state.to_dict() == before and len(runtime[4]) == sent_before


async def test_direct_local_finding_executes_without_retesting_completed_sibling(runtime, tmp_path):
    state, first, tool, _ = await validated(runtime, tmp_path, outcome="not-confirmed")
    second = await assessed_sibling(runtime, tmp_path, state, tool)
    runtime[0].register(ConfirmFindingTool(FindingStore(project_directory=tmp_path), workflow=state))
    agent = agent_for(runtime, state, tool)
    client = SummaryClient(("confirm_finding", {
        "candidate_id": second.id, "title": "Bounded sibling fixture", "severity": "low",
        "url": ORIGIN + "/second", "method": "GET", "vuln_class": second.candidate_class,
        "observed_impact": "Fixture response observed.", "potential_impact": "No further impact assessed.",
    }))
    agent.client = client
    results = [deepcopy(r.to_dict()) for r in state.validation_results]
    attempts = deepcopy(state.attempts)
    sent_before = len(runtime[4])
    plan = build_decision_plan("continue", agent.skills.list_enabled(), agent.target, agent._planner_context())
    assert plan is not None and plan.candidate_id == second.id and plan.recommended_skill is None
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"], AgentRunOptions(max_steps=1))
    assert events["events"][-1]["stop_reason"] == "final_response"
    assert state.finding_is_persisted(second.id) and not state.finding_is_persisted(first.id)
    assert [r.to_dict() for r in state.validation_results] == results and state.attempts == attempts
    assert build_decision_plan("continue", agent.skills.list_enabled(), agent.target, agent._planner_context()) is None
    assert len(runtime[4]) == sent_before and len(client.requests) == 2


async def test_direct_completed_sibling_does_not_keep_operator_cleanup_actionable(runtime, tmp_path):
    state, _, tool, _ = await validated(runtime, tmp_path, outcome="not-confirmed")
    second = await assessed_sibling(runtime, tmp_path, state, tool, cleanup="requires-user-action")
    await persist_sibling(runtime, tmp_path, state, second)
    agent = agent_for(runtime, state, tool)
    agent.client = SummaryClient(("workflow", {"action": "list", "candidate_id": second.id}))
    agent._reconcile_requested_goals()
    assert not agent._has_actionable_requested_goal()
    events = collect()
    sent_before = len(runtime[4])
    await agent.run("continue", FakeSignal(), events["sink"], AgentRunOptions(max_steps=20))
    assert events["events"][-1]["stop_reason"] == "workflow_blocked"
    assert len(agent.client.requests) == 2 and len(runtime[4]) == sent_before


async def test_direct_operator_cleanup_outside_completed_goal_keeps_assigned_work(runtime, tmp_path):
    state, _, tool, _ = await validated(runtime, tmp_path, outcome="not-confirmed")
    extra = await assessed_sibling(runtime, tmp_path, state, tool,
                                   cleanup="requires-user-action", candidate_class="xss")
    await persist_sibling(runtime, tmp_path, state, extra)
    agent = agent_for(runtime, state, tool)
    agent.client = SummaryClient(("workflow", {"action": "list", "candidate_id": extra.id}))
    agent._reconcile_requested_goals()
    assert state.objective is not None
    assert [g.status for g in state.objective.requested_goals] == ["tested_not_confirmed"]
    assert not agent._has_actionable_requested_goal()
    events = collect()
    sent_before = len(runtime[4])
    await agent.run("continue", FakeSignal(), events["sink"], AgentRunOptions(max_steps=20))
    assert events["events"][-1]["stop_reason"] == "workflow_blocked"
    assert len(agent.client.requests) == 2 and len(runtime[4]) == sent_before
    state.add_candidate(Candidate("xss", target=ORIGIN, endpoint="/independent",
                                  objective_id=state.objective.id))
    assert agent._has_actionable_requested_goal()


@pytest.mark.parametrize("streaming", [False, True])
async def test_direct_partial_final_keeps_completed_goal_bindings_and_cleanup(runtime, tmp_path, streaming):
    agent, _, sql, xss, attempt = await prepared(runtime, tmp_path, mode="direct", steps=1)
    client = SummaryClient(("workflow", {"action": "list", "candidate_id": xss.id}))
    agent.client = client
    agent.streaming_enabled = streaming
    sql_result = agent.workflow.latest_result(sql.id)
    assert sql_result is not None and sql_result.result_id is not None
    original = deepcopy(sql_result.to_dict())
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"])
    text = agent.history[-1].content
    assert "sql-injection" in text and "tested_confirmed" in text
    assert "cross-site-scripting" in text and "deferred" in text
    assert sql_result.result_id in text and sql_result.evidence_refs[0] in text
    assert agent.workflow.persisted_findings[sql.id] in text
    assert "unknown" in text and "cleanup" in text
    assert "All work is complete" not in text
    assert not any("All work is complete" in e.get("text", "") for e in events["events"])
    assert sql_result.to_dict() == original
    assert_closed(agent, sql, xss, attempt)


async def synthesize(agent, *, reason="final_response"):
    return await agent._whole_target_synthesis(
        agent.history.copy(), FakeSignal(), collect()["sink"],
        thinking_enabled=False, reasoning_level=ReasoningLevel.OFF,
        requested_reasoning_level=ReasoningLevel.OFF, stop_reason=reason,
        instruction="Summarize recorded state.", max_steps=1,
    )


@pytest.mark.parametrize("reason", ["final_response", "max_steps", "max_steps"])
async def test_direct_pending_work_stays_incomplete_even_with_final_response(runtime, tmp_path, reason):
    state, sql, tool, _ = await validated(runtime, tmp_path, outcome="not-confirmed")
    assert state.objective is not None
    extra, _ = state.add_candidate(Candidate(
        "xss", target=ORIGIN, endpoint="/assigned-extra", objective_id=state.objective.id,
    ))
    agent = agent_for(runtime, state, tool)
    client = SummaryClient(("workflow", {"action": "list"}))
    agent.client = client
    sent_before = len(runtime[4])
    stop = await synthesize(agent, reason=reason)
    assert stop == ("workflow_blocked" if reason == "final_response" else reason)
    assert "incomplete/partial" in synthesis_instruction(client)
    assert "sql-injection" in agent.history[-1].content and extra.id in agent.history[-1].content
    assert "tested_not_confirmed" in agent.history[-1].content
    assert agent._validation_completion_error(sql, runtime[2]) is None
    assert len(state.validation_results) == 1 and len(runtime[4]) == sent_before


@pytest.mark.parametrize("damage", ["proof", "seal", "foreign-result"])
async def test_direct_fallback_does_not_claim_invalid_confirmed_bindings(runtime, tmp_path, damage):
    agent, _, sql, xss, _ = await prepared(runtime, tmp_path, mode="direct", steps=1)
    result = agent.workflow.latest_result(sql.id)
    assert result is not None
    fingerprint = agent.workflow.persisted_findings[sql.id]
    if damage == "proof":
        artifact = agent.workflow.evidence[result.evidence_refs[0]]
        path = tmp_path / artifact.path
        path.chmod(0o600)
        path.write_text("controlled invalid proof")
    elif damage == "seal":
        result.assessment["criteria"] = "controlled altered criteria"
    else:
        result.objective_id = "foreign-objective"
    agent.client = SummaryClient(("workflow", {"action": "list", "candidate_id": xss.id}))
    await agent.run("continue", FakeSignal(), collect()["sink"])
    text = agent.history[-1].content
    assert "status=tested_confirmed" not in text and fingerprint not in text
    assert "incomplete" in text and sql.id in text
    assert agent.workflow.persisted_findings[sql.id] == fingerprint


async def test_direct_planner_excludes_foreign_candidates_and_keeps_cancelled_goal(runtime, tmp_path):
    agent, _, sql, xss, _ = await prepared(runtime, tmp_path, mode="direct")
    objective = agent.workflow.objective
    assert objective is not None
    agent.workflow.set_requested_goal_status(objective.requested_goals[1], "cancelled", reason="Operator cancelled")
    foreign, _ = agent.workflow.add_candidate(Candidate(
        "sqli", target=ORIGIN, endpoint="/foreign", objective_id="foreign-objective",
    ))
    before = deepcopy(foreign.to_dict())
    context = agent._planner_context()
    assert foreign.id not in {c.id for c in context.candidates}
    assert build_decision_plan("continue", agent.skills.list_enabled(), agent.target, context) is None
    assert objective.requested_goals[1].status == "cancelled"
    assert foreign.to_dict() == before and agent.workflow.finding_is_persisted(sql.id)
    assert agent.workflow.latest_result(xss.id) is None


async def complete_input_analysis(tool):
    if 'input_analysis' in tool.state.completed_phases():
        readiness = tool.phase_completion_readiness('web-input-analysis')
        assert readiness['historically_completed'] and readiness['artifact_valid']
        assert readiness['prerequisites_valid'] and readiness['reason'] == 'input_analysis phase is already completed'
        return
    assert tool.skills is not None
    skill = tool.skills.get("web-input-analysis")
    assert skill is not None and skill.completion_artifact
    path = tool.evidence_root / completion_artifact_path(skill.completion_artifact, ORIGIN)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Offline analyzed input inventory; existing candidates retain their obligations.")
    await record_phase_coverage_for_test(tool, "input_analysis")
    output = json.loads(await tool.run({"action": "complete_skill", "skill_name": "web-input-analysis"}, None, None))
    assert output["ok"], output


@pytest.mark.parametrize("reason,steps", [("max_steps", 1), ("max_steps", 20), ("workflow_blocked", 20)])
@pytest.mark.parametrize("streaming", [False, True])
async def test_whole_target_partial_synthesis_retains_results_blockers_and_checkpoint(runtime, tmp_path, reason, steps, streaming):
    agent, _, sql, xss, attempt = await prepared(runtime, tmp_path, mode="whole_target", steps=steps)
    tool = agent.tools.get("workflow")
    assert tool is not None
    await complete_input_analysis(tool)
    if reason == "workflow_blocked":
        await agent._close_terminal_attempt("max_steps", FakeSignal(), collect()["sink"], agent.history.copy())
        # This case tests blocked synthesis after a deliberate stop. An
        # automatic inconclusive closure alone leaves retry consideration open.
        decision = await runtime[0].execute('workflow', {
            'action': 'record_retry_decision', 'candidate_id': xss.id,
            'retry_decision': {'decision': 'decline',
                'reason': 'The fixture has no usable proof or meaningful remaining validation strategy.'},
        }, FakeSignal(), runtime[1])
        assert json.loads(decision)['ok']
    sql_result = agent.workflow.latest_result(sql.id)
    assert sql_result is not None
    before_sql = deepcopy(sql_result.to_dict())
    findings = deepcopy(agent.workflow.persisted_findings)
    sent = len(runtime[4])
    rights = runtime[2].engagement.http_permissions
    grants, epoch = dict(rights.grants), rights.epoch
    client = SummaryClient(("workflow", {"action": "list", "candidate_id": xss.id}))
    client.summary_text = "SQLi has a persisted confirmed Finding; XSS is unresolved with unknown cleanup."
    def check_summary(request):
        assert_closed(agent, sql, xss, attempt)

    client.check_summary = check_summary
    agent.client = client
    agent.streaming_enabled = streaming
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"])
    assert events["events"][-1]["stop_reason"] == reason
    assert agent.history[-1].content == client.summary_text
    assert sql_result.to_dict() == before_sql
    assert agent.workflow.persisted_findings == findings
    assert len(runtime[4]) == sent and rights.grants == grants and rights.epoch == epoch
    assert synthesis_instruction(client).count("Requested-goal runtime summary") == 1
    assert "cross-site-scripting status=deferred" in synthesis_instruction(client)
    assert_closed(agent, sql, xss, attempt)


async def test_whole_target_completed_multiple_results_and_findings_keep_phase_semantics(runtime, tmp_path):
    state, first, tool, _ = await validated(runtime, tmp_path, mode="whole_target")
    await persist(runtime, tmp_path, state, first)
    second = await assessed_sibling(runtime, tmp_path, state, tool)
    await complete_input_analysis(tool)
    agent = agent_for(runtime, state, tool)
    agent.store = Store.new_with_id(tmp_path / "sessions", tool.session_id)
    agent._reconcile_requested_goals()
    assert agent._whole_target_state()[0] == "actionable"
    before = deepcopy(state.to_dict())
    client = SummaryClient(("confirm_finding", {
        "candidate_id": second.id, "title": "Bounded sibling fixture", "severity": "low",
        "url": ORIGIN + "/second", "method": "GET", "vuln_class": second.candidate_class,
        "observed_impact": "Fixture response observed.", "potential_impact": "No further impact assessed.",
    }))
    client.summary_text = "Both SQLi candidates have persisted confirmed Findings; required phases are complete."
    agent.client = client
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"], AgentRunOptions(max_steps=2))
    assert events["events"][-1]["stop_reason"] == "workflow_completed"
    assert agent.history[-1].content == client.summary_text
    assert "incomplete/partial" not in synthesis_instruction(client)
    assert len(state.validation_results) == len(state.persisted_findings) == 2
    assert len(client.requests) == 2 and len(runtime[4]) == 2
    assert state.validation_results[0].to_dict() == before["validation_results"][0]
    assert state.validation_results[1].to_dict() == before["validation_results"][1]
    assert state.attempts == before["attempts"]
    assert agent._whole_target_state() == ("completed", (), ())
    assert agent.store.load().workflow.to_dict() == state.to_dict()


@pytest.mark.parametrize("cleanup,expected", [("pending", "actionable"), ("unknown", "blocked"),
                                             ("requires-user-action", "blocked"), ("failed", "blocked"),
                                             ("not-attempted", "blocked")])
async def test_whole_target_cleanup_planner_and_summary_keep_existing_obligations(runtime, tmp_path, cleanup, expected):
    state, first, tool, _ = await validated(runtime, tmp_path, mode="whole_target")
    await persist(runtime, tmp_path, state, first)
    second = await assessed_sibling(runtime, tmp_path, state, tool, cleanup=cleanup)
    await persist_sibling(runtime, tmp_path, state, second)
    await complete_input_analysis(tool)
    agent = agent_for(runtime, state, tool)
    context = agent._planner_context()
    assert context.workflow_status == expected
    assert all(c.validation_action == "preserve_result" for c in context.candidates)
    assert context.requested_goals[0].status == "in_progress"
    before = deepcopy(state.to_dict())
    plan = build_decision_plan("continue", agent.skills.list_enabled(), agent.target, context)
    if cleanup == "pending":
        assert plan is not None and plan.candidate_id == second.id and "cleanup" in plan.guidance.lower()
    else:
        assert plan is None
    assert state.to_dict() == before and len(runtime[4]) == 2
    assert all(c.validation_complete is None and c.completion_action is None for c in context.candidates)
    client = SummaryClient(("workflow", {"action": "list"}))
    client.summary_text = f"SQLi Findings persist; second candidate cleanup remains {cleanup}; objective is incomplete."
    agent.client = client
    assert await synthesize(agent, reason="workflow_blocked") == "workflow_blocked"
    assert agent.history[-1].content == client.summary_text
    assert state.to_dict() == before and len(runtime[4]) == 2
