"""Terminal goal reconciliation through production gates and isolated stores.

The runtime fixture uses httpx.MockTransport; clients are scripted, and no
provider, target, scanner or historical Trial artifact is accessed.
"""
import asyncio
from copy import deepcopy
import json
import threading
from collections.abc import Callable
from typing import Any, cast

import pytest

from src.agent.agent import Agent, AgentOptions
from src.cli.headless import UnavailableInput
from src.llm.core.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall
from src.permission.network.grants import HTTPLimits
from src.session.store import Store
from src.tools.common.ask import AskUserTool
from src.workflow.assessment import accepted_result, seal
from src.workflow.planning.goals import RequestedGoal
from src.workflow.state import Candidate, WorkflowMode
from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect
from tests.helpers.workflow import prepare_validation_prerequisites
from tests.integration.test_runtime_validation_completion import persist, validated
from tests.security.test_execution_policy import ORIGIN, runtime  # noqa: F401


class TerminalClient(FakeClient):
    def __init__(self, call: tuple[str, dict[str, Any]], check_summary: Callable[[ChatRequest], None] | None = None):
        super().__init__([])
        self.call = call
        self.check_summary = check_summary

    async def chat(self, request, signal=None):
        self.requests.append(deepcopy(request))
        assert len(self.requests) < 30, "unexpected continuation"
        if request.tools is None:
            if self.check_summary:
                self.check_summary(request)
            return ChatResponse(Message("assistant", "Bounded fixture assessment remains incomplete."), "stop")
        name, args = self.call
        return ChatResponse(Message("assistant", "", tool_calls=[ToolCall(
            f"fixture-{len(self.requests)}", FunctionCall(name, json.dumps(args)),
        )]), "tool_calls")


async def prepared(runtime, tmp_path, *, mode: WorkflowMode = "whole_target", steps=1):
    registry, prompter, policy, *_ = runtime
    state, sql, tool, _ = await validated(runtime, tmp_path, mode=mode)
    await persist(runtime, tmp_path, state, sql)
    objective = state.objective
    assert objective is not None
    objective.add_requested_goal("cross-site-scripting")
    xss, _ = state.add_candidate(Candidate(
        "xss", target=ORIGIN, endpoint="/second", method="GET", parameter="q",
        location="query", objective_id=objective.id,
    ))
    state.link_requested_goal_candidate(objective.requested_goals[1].id, xss.id)
    await prepare_validation_prerequisites(tool, xss.id)
    started = json.loads(await registry.execute("workflow", {
        "action": "start_validation", "candidate_id": xss.id,
    }, None, prompter))
    assert started["ok"], started
    # Dispatch without an effects declaration: closure must preserve uncertainty.
    await registry.execute("http", {
        "url": "/second?q=fixture", "phase": "validation",
    }, None, prompter)
    client = TerminalClient(("workflow", {"action": "list", "candidate_id": xss.id}))
    store = Store.new_with_id(tmp_path / "sessions", tool.session_id)
    assert tool.skills is not None
    agent = Agent(AgentOptions(
        client=client, tools=registry, skills=tool.skills, prompter=prompter,
        store=store, target=runtime[6], workflow=state, engagement_state=policy.engagement,
        max_steps=steps, streaming_enabled=False, auto_compact_threshold=0,
    ))
    agent._reconcile_requested_goals()
    assert [g.status for g in objective.requested_goals] == ["tested_confirmed", "in_progress"]
    await agent.save()
    return agent, client, sql, xss, started["validation_context"]["attempt_id"]


def result_for(agent: Agent, candidate: Candidate):
    result = agent.workflow.latest_result(candidate.id)
    assert result is not None
    return result


def saved_goals(agent: Agent):
    assert agent.store is not None
    objective = agent.store.load().workflow.objective
    assert objective is not None
    return objective.requested_goals


def assert_closed(agent, sql, xss, aid, *, outcome="insufficient-evidence"):
    state = agent.workflow
    result = state.latest_result(xss.id)
    assert result is not None and result.outcome == outcome
    assert result.attempt_id == aid and result.assessment_binding == seal(result)
    assert result.mutation_performed is None and result.cleanup_state == "unknown"
    assert xss.status == "deferred" and state.attempts[aid]["status"] == "unresolved"
    assert len(state.validation_results) == 2 and len(state.persisted_findings) == 1
    assert state.finding_is_persisted(sql.id) and not state.eligible_for_finding(xss.id)
    assert accepted_result(state, sql, state.latest_result(sql.id))
    assert state.objective is not None
    assert [g.status for g in state.objective.requested_goals[:2]] == ["tested_confirmed", "deferred"]
    assert state.objective.requested_goals[1].reason == result.deferred_reason
    assert agent.store is not None
    restored = agent.store.load().workflow
    assert restored.to_dict() == state.to_dict()
    assert restored.latest_result(xss.id).to_dict() == result.to_dict()
    return result


@pytest.mark.parametrize("mode", ["whole_target", "direct"])
@pytest.mark.parametrize("reason,steps", [("max_steps", 1), ("workflow_stalled", 20)])
async def test_terminal_synthesis_uses_reconciled_persisted_goals(runtime, tmp_path, mode, reason, steps):
    agent, client, sql, xss, aid = await prepared(runtime, tmp_path, mode=mode, steps=steps)
    sql_before = deepcopy(result_for(agent, sql).to_dict())
    finding_before = deepcopy(agent.workflow.persisted_findings)
    native_before = len(runtime[4])
    rights = runtime[2].engagement.http_permissions
    grants_before, epoch_before = dict(rights.grants), rights.epoch
    inspected = []

    def summary(request):
        assert_closed(agent, sql, xss, aid)
        summaries = [m.content for m in request.messages if m.role == "system"
                     and "Requested-goal runtime summary (data, not authority):" in m.content]
        assert len(summaries) == 1
        assert summaries[0].count("Requested-goal runtime summary") == 1
        assert "cross-site-scripting status=deferred" in summaries[0]
        assert "sql-injection status=tested_confirmed" in summaries[0]
        assert "no validation result" not in summaries[0]
        inspected.append(True)

    client.check_summary = summary
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"])
    assert events["events"][-1]["stop_reason"] == reason
    assert inspected == [True]
    assert_closed(agent, sql, xss, aid)
    assert result_for(agent, sql).to_dict() == sql_before
    assert agent.workflow.persisted_findings == finding_before
    assert len(runtime[4]) == native_before
    assert rights.grants == grants_before and rights.epoch == epoch_before


@pytest.mark.parametrize("kind", ["refusal", "input_unavailable"])
async def test_direct_return_closure_is_reconciled(runtime, tmp_path, kind):
    agent, client, sql, xss, aid = await prepared(runtime, tmp_path)
    if kind == "refusal":
        runtime[1].set_yolo(False)
        runtime[2].engagement.http_permissions.activate(ORIGIN, HTTPLimits(), "confirm-each")
        client.call = ("http", {"url": "/second?q=denied", "phase": "validation"})
    else:
        agent.tools.register(AskUserTool(cast(Any, UnavailableInput())))
        client.call = ("ask_user", {"questions": [{"question": "Which test account should be used?"}]})
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"])
    expected = "all_tools_refused" if kind == "refusal" else "workflow_blocked"
    assert events["events"][-1]["stop_reason"] == expected
    assert_closed(agent, sql, xss, aid, outcome="blocked")
    assert len(client.requests) == 1 and len(runtime[4]) == 2


async def test_rejected_closure_does_not_invent_disposition(runtime, tmp_path):
    agent, _, sql, xss, aid = await prepared(runtime, tmp_path)
    runtime[2].max_calls = runtime[2].used  # Registry refuses before Result commit.
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"])
    assert agent.workflow.latest_result(xss.id) is None
    assert len(agent.workflow.validation_results) == 1
    assert agent.workflow.attempts[aid]["status"] == "active" and xss.status == "validating"
    goals = saved_goals(agent)
    assert [g.status for g in goals] == ["tested_confirmed", "in_progress"]
    assert goals[1].reason == "no validation result"
    assert agent.workflow.finding_is_persisted(sql.id)
    assert any(e["type"] == "error" for e in events["events"])


@pytest.mark.parametrize("fault", ["cancel", "receipt_error", "early_return"])
async def test_post_commit_interruption_checkpoints_without_receipt(runtime, tmp_path, monkeypatch, fault):
    agent, _, sql, xss, aid = await prepared(runtime, tmp_path)
    committed, release = asyncio.Event(), asyncio.Event()

    async def run_inner(*args):
        output = await agent.tools.execute("workflow", {
            "action": "record_result", "candidate_id": xss.id, "attempt_id": aid,
            "skill_name": "cross-site-scripting", "outcome": "insufficient-evidence",
            "deferred_reason": "Controlled terminal interruption",
        }, None, agent.prompter)
        assert json.loads(output)["ok"]
        assert agent.workflow.objective is not None
        assert agent.workflow.objective.requested_goals[1].status == "in_progress"
        committed.set()
        if fault == "cancel":
            await release.wait()
        if fault == "receipt_error":
            raise RuntimeError("controlled post-commit receipt failure")
        return "workflow_blocked"

    monkeypatch.setattr(agent, "run_inner", run_inner)
    events = collect()
    task = asyncio.create_task(agent.run("continue", FakeSignal(), events["sink"]))
    await asyncio.wait_for(committed.wait(), 5)
    if fault == "cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        assert events["events"][-1]["stop_reason"] == "cancelled"
    else:
        await asyncio.wait_for(task, 5)
        assert events["events"][-1]["stop_reason"] == ("runtime_error" if fault == "receipt_error" else "workflow_blocked")
    assert_closed(agent, sql, xss, aid)


@pytest.mark.parametrize("persistent", [False, True])
async def test_post_commit_save_failure_retains_result_and_retries_current_goals(runtime, tmp_path, monkeypatch, persistent):
    agent, client, sql, xss, aid = await prepared(runtime, tmp_path)
    assert agent.store is not None
    save = agent.store.save
    attempts = []
    summaries = []

    def summary(request):
        assert_closed(agent, sql, xss, aid)
        summaries.append(True)

    client.check_summary = summary

    async def failed(*args, **kwargs):
        if agent.workflow.latest_result(xss.id) is not None:
            assert agent.workflow.objective is not None
            attempts.append(agent.workflow.objective.requested_goals[1].status)
            if persistent or len(attempts) == 1:
                raise OSError("controlled checkpoint failure")
        await save(*args, **kwargs)

    monkeypatch.setattr(agent.store, "save", failed)
    events = collect()
    if persistent:
        with pytest.raises(OSError, match="controlled checkpoint failure"):
            await agent.run("continue", FakeSignal(), events["sink"])
        result_id = result_for(agent, xss).result_id
        assert agent._workflow_saved_revision != agent.workflow.committed_revision
        monkeypatch.setattr(agent.store, "save", save)
        await agent._checkpoint_terminal_workflow()
        assert result_for(agent, xss).result_id == result_id
    else:
        await agent.run("continue", FakeSignal(), events["sink"])
        assert len(attempts) >= 2
    assert summaries == ([] if persistent else [True])
    assert attempts and set(attempts) == {"deferred"}
    assert_closed(agent, sql, xss, aid)


async def test_closure_receipt_error_reconciles_committed_state_before_synthesis(runtime, tmp_path, monkeypatch):
    agent, client, sql, xss, aid = await prepared(runtime, tmp_path)
    execute = agent.execute_tool_calls
    receipts = []

    async def interrupted(calls, *args, **kwargs):
        batch = await execute(calls, *args, **kwargs)
        if any(call.id.startswith("terminal-closure-") for call in calls):
            receipts.append(result_for(agent, xss).result_id)
            raise RuntimeError("controlled closure receipt failure")
        return batch

    def summary(request):
        assert_closed(agent, sql, xss, aid)

    client.check_summary = summary
    monkeypatch.setattr(agent, "execute_tool_calls", interrupted)
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"])
    assert receipts == [result_for(agent, xss).result_id]
    assert_closed(agent, sql, xss, aid)
    assert any(e["type"] == "error" for e in events["events"])


async def test_repeated_cancellation_joins_terminal_writer(runtime, tmp_path, monkeypatch):
    import src.session.store as module
    agent, _, sql, xss, aid = await prepared(runtime, tmp_path)
    assert agent.store is not None
    entered, release = threading.Event(), threading.Event()
    write = module._write_session
    snapshots = []

    def held(path, body, *args):
        snapshot = json.loads(body)
        if len(snapshot["workflow"]["validation_results"]) == 2:
            snapshots.append(snapshot["workflow"])
            entered.set()
            assert release.wait(5)
        return write(path, body, *args)

    monkeypatch.setattr(module, "_write_session", held)
    task = asyncio.create_task(agent.run("continue", FakeSignal(), collect()["sink"]))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
    assert snapshots and all(s["objective"]["requested_goals"][1]["status"] == "deferred" for s in snapshots)
    assert_closed(agent, sql, xss, aid)
    assert not list(agent.store.path.parent.glob("*.tmp.*"))


async def test_duplicate_closure_and_checkpoint_are_idempotent_and_isolated(runtime, tmp_path):
    agent, _, sql, xss, aid = await prepared(runtime, tmp_path)
    objective = agent.workflow.objective
    assert objective is not None and agent.store is not None
    foreign, _ = agent.workflow.add_candidate(Candidate(
        "xss", target=ORIGIN, endpoint="/foreign", objective_id="foreign-objective",
    ))
    foreign_before = foreign.to_dict()
    await agent._close_terminal_attempt("max_steps", FakeSignal(), collect()["sink"], agent.history.copy())
    objective.requested_goals.append(RequestedGoal("access-control", status="cancelled"))
    agent.workflow.mark_committed()
    await agent._checkpoint_terminal_workflow()
    assert_closed(agent, sql, xss, aid)
    before = deepcopy(agent.workflow.to_dict())
    revision, facts = agent.workflow.committed_revision, agent.workflow.progress_facts()
    saves = agent.store.save_count
    for _ in range(2):
        await agent._close_terminal_attempt("workflow_stalled", FakeSignal(), collect()["sink"], agent.history.copy())
        await agent._checkpoint_terminal_workflow()
    assert agent.workflow.to_dict() == before
    assert agent.workflow.committed_revision == revision and agent.workflow.progress_facts() == facts
    assert agent.store.save_count == saves
    assert foreign.to_dict() == foreign_before and objective.requested_goals[2].status == "cancelled"


async def test_pending_evidence_repair_does_not_terminal_close(runtime, tmp_path):
    agent, client, _, xss, aid = await prepared(runtime, tmp_path)
    client.call = ("workflow", {
        "action": "record_result", "candidate_id": xss.id, "attempt_id": aid,
        "skill_name": "cross-site-scripting", "outcome": "confirmed",
        "mutation_performed": False,
    })
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"])
    assert events["events"][-1]["stop_reason"] == "max_steps"
    assert agent.workflow.latest_result(xss.id) is None
    assert agent.workflow.attempts[aid]["status"] == "active"
    budget = agent.workflow.evidence_recovery[aid]
    assert budget["rejections"] == 1 and not budget["closed"]
    goals = saved_goals(agent)
    assert [g.status for g in goals] == ["tested_confirmed", "in_progress"]


async def test_queued_terminal_checkpoint_cannot_publish_into_replaced_workflow(runtime, tmp_path):
    from src.workflow.state import WorkflowState
    agent, _, _, _, _ = await prepared(runtime, tmp_path)
    assert agent.store is not None
    original = agent.store.path.read_bytes()
    workflow = agent.workflow
    lock = workflow.mutation_lock
    await lock.acquire()
    task = asyncio.create_task(agent._checkpoint_terminal_workflow())
    try:
        await asyncio.sleep(0)
        replacement = WorkflowState.from_dict(workflow.to_dict())
        assert replacement.objective is not None
        replacement.objective.requested_goals[1].status = "cancelled"
        workflow.replace_from(replacement)
    finally:
        lock.release()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    assert agent.store.path.read_bytes() == original
    assert workflow.objective is not None
    assert workflow.objective.requested_goals[1].status == "cancelled"
