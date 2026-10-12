"""Committed workflow durability and current discovery readiness, offline only."""
import asyncio
from copy import deepcopy
import json

import pytest

from src.session.store import Store as SessionStore
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.skills.artifacts import completion_artifact_path
from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect
from tests.helpers.workflow import record_phase_coverage_for_test
from tests.integration.test_runtime_validation_completion import agent_for, persist, validated
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import ORIGIN, runtime  # noqa: F401


PHASES = (("recon", "recon"), ("enumeration", "web-enumeration"),
          ("input_analysis", "web-input-analysis"))


@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
@pytest.mark.parametrize("boundary", ["before_commit", "coverage_flush", "after_flush", "before_receipt"])
async def test_cancelled_result_checkpoint_and_resume(runtime, tmp_path, monkeypatch, outcome, boundary):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    agent = agent_for(runtime, state, tool)
    agent.store = SessionStore(tmp_path / "session.json", "assessment-session")
    await agent.save()
    assert tool.coverage is not None
    coverage = tool.coverage
    reached = asyncio.Event()

    async def pause(*unused, **kwargs):
        reached.set()
        await asyncio.Future()

    if boundary == "before_commit":
        monkeypatch.setattr("src.tools.workflow.workflow_tool.verify_evidence_reads", pause)
    elif boundary == "coverage_flush":
        monkeypatch.setattr(coverage, "_persist", pause)
    elif boundary == "after_flush":
        original = coverage.flush

        async def flushed():
            await original()
            await pause()

        monkeypatch.setattr(coverage, "flush", flushed)
    else:
        original_run = tool.run

        async def no_receipt(*a, **kw):
            await original_run(*a, **kw)
            await pause()

        monkeypatch.setattr(tool, "run", no_receipt)

    # Exercise production Agent cancellation/finalization around real registry
    # execution. No receipt is processed and no receipt-owned dirty flag is set.
    async def run_inner(*unused):
        await runtime[0].execute("workflow", {**args, "outcome": outcome}, None, runtime[1])
        return "final_response"

    monkeypatch.setattr(agent, "run_inner", run_inner)
    task = asyncio.create_task(agent.run("continue", FakeSignal(), collect()["sink"]))
    await asyncio.wait_for(reached.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    assert not agent.running and not state.mutation_lock.locked()
    assert coverage.saving is None or coverage.saving.done()
    assert not agent._tool_results_unsaved
    monkeypatch.undo()

    committed = boundary != "before_commit"
    assert bool(state.validation_results) == committed
    agent.resume_saved()
    restored = state.latest_result(candidate.id)
    assert (restored is not None) == committed
    if not committed:
        assert not coverage.entries
        assert all(attempt["status"] != "completed" for attempt in state.attempts.values())
        return
    assert restored is not None and restored.outcome == outcome
    assert state.candidates[candidate.id].status == "validated"
    assert restored.attempt_id is not None
    assert state.attempts[restored.attempt_id]["status"] == "completed"
    assert all(state.evidence[ref].is_available_for_resume(tmp_path) for ref in restored.evidence_refs)
    assert len(state.validation_results) == 1
    for _ in range(3):
        output = await runtime[0].execute("workflow", {
            "action": "sync_coverage", "candidate_id": candidate.id,
        }, None, runtime[1])
        assert json.loads(output)["ok"], output
        await agent._finish_tool_results()
    assert restored.coverage_synced
    reloaded_coverage = type(coverage)(str(coverage.path))
    rows = await reloaded_coverage.list()
    assert len(rows) == 1 and rows[0].count == 1
    if outcome == "confirmed":
        await persist(runtime, tmp_path, state, state.candidates[candidate.id])
        await agent.save()
        agent.resume_saved()
        assert state.finding_is_persisted(candidate.id)
        assert len(list((tmp_path / "artifacts/findings").glob("*.md"))) == 1
    saved = json.loads(agent.store.path.read_text())
    assert "grants" not in saved["engagement_state"]
    assert not any(key in saved["workflow"] for key in (
        "permission_receipts", "execution_receipts", "committed_revision"))


async def completed_discovery(runtime, tmp_path, outcome):
    state, candidate, tool, _ = await validated(runtime, tmp_path, outcome=outcome, mode="whole_target")
    if outcome == "confirmed":
        await persist(runtime, tmp_path, state, candidate)
    paths = {}
    for phase, name in PHASES:
        await record_phase_coverage_for_test(tool, phase)
        assert tool.skills is not None
        skill = tool.skills.get(name)
        assert skill is not None and skill.completion_artifact
        ref = completion_artifact_path(skill.completion_artifact, ORIGIN)
        path = tmp_path / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Explicit offline discovery fixture record.")
        output = await runtime[0].execute("workflow", {
            "action": "complete_skill", "skill_name": name,
            "no_inputs_discovered": phase == "input_analysis",
        }, None, runtime[1])
        assert json.loads(output)["ok"], output
        paths[phase] = path
    agent = agent_for(runtime, state, tool)
    agent.store = SessionStore(tmp_path / "session.json", "assessment-session")
    assert agent._whole_target_state() == ("completed", (), ())
    await agent.save()
    return agent, state, candidate, tool, paths


@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
@pytest.mark.parametrize("phase,name", PHASES)
@pytest.mark.parametrize("damage", ["missing", "empty"])
async def test_discovery_artifact_loss_and_authorized_repair(runtime, tmp_path, phase, name, damage, outcome):
    agent, state, candidate, tool, paths = await completed_discovery(runtime, tmp_path, outcome)
    agent.resume_saved()
    assert agent._whole_target_state() == ("completed", (), ())
    history = deepcopy(state.to_dict())
    content = paths[phase].read_text()
    if damage == "missing":
        paths[phase].unlink()
    else:
        paths[phase].write_text("")
    for _ in range(2):
        agent.resume_saved()
        readiness = tool.phase_completion_readiness(name)
        assert not readiness["ready"] and "requires artifacts/" in readiness["reason"]
        assert "already completed" not in readiness["reason"]
        status, actions, blockers = agent._whole_target_state()
        assert status != "completed" and not any(item.startswith("phase:") for item in actions)
        assert any("repair" in item and phase in item for item in blockers)
        planner_readiness = agent._planner_context().phase_completion_readiness
        assert planner_readiness is not None and planner_readiness["phase"] == phase
        from src.ui.core.outcomes import runtime_facts
        facts = runtime_facts(agent, None, ())
        assert not facts.completion_supported
        assert any("repair" in item and phase in item for item in facts.blockers)
        rejected = await runtime[0].execute("workflow", {
            "action": "complete_skill", "skill_name": name,
        }, None, runtime[1])
        assert "requires artifacts/" in rejected
        assert state.to_dict() == history
    # A downstream historical receipt must also check its operational inputs.
    if phase != "input_analysis":
        downstream = tool.phase_completion_readiness("web-input-analysis")
        assert downstream["artifact_valid"] and not downstream["prerequisites_valid"]
        assert "repair required" in downstream["reason"]
    # Restore an actual retained fixture copy through the real authorized tool;
    # production does not synthesize missing observations or rerun probes.
    await runtime[0].execute("file_write", {
        "path": str(paths[phase]), "content": content,
    }, None, runtime[1])
    assert agent._whole_target_state() == ("completed", (), ())
    assert state.to_dict() == history
    assert len(runtime[4]) == 1
    assert tool.coverage is not None
    assert len(await tool.coverage.list()) == 1
    assert not list(tmp_path.rglob("results.md"))
    assert tool.validation_completion_error(candidate.id, runtime[2]) is None


@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_real_agent_dispatch_joins_checkpoint_under_repeated_cancellation(runtime, tmp_path, monkeypatch, outcome):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    assert state.objective is not None and tool.coverage is not None
    state.objective.mode = "direct"
    state.objective.add_requested_goal(candidate.candidate_class)
    agent = agent_for(runtime, state, tool)
    agent.store = SessionStore(tmp_path / "session.json", "assessment-session")
    await agent.save()
    agent.client = FakeClient([ChatResponse(Message("assistant", "", tool_calls=[ToolCall(
        id="terminal-result", function=FunctionCall("workflow", json.dumps({**args, "outcome": outcome})),
    )]), finish_reason="tool_calls")])
    flush_started, save_started, release_save = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def held_flush():
        flush_started.set()
        await asyncio.Future()

    original_save = agent.store.save

    async def delayed_checkpoint(*a, **kw):
        # Let normal run startup checkpoints finish before dispatch.
        if state.latest_result(candidate.id) is not None:
            save_started.set()
            await release_save.wait()
        await original_save(*a, **kw)

    monkeypatch.setattr(tool.coverage, "_persist", held_flush)
    monkeypatch.setattr(agent.store, "save", delayed_checkpoint)
    collector = collect()
    task = asyncio.create_task(agent.run("continue", FakeSignal(), collector["sink"]))
    await asyncio.wait_for(flush_started.wait(), 2)
    task.cancel()
    await asyncio.wait_for(save_started.wait(), 2)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done() and agent.running
    release_save.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    assert not agent.running and not state.mutation_lock.locked()
    assert agent._workflow_saved_revision == state.committed_revision
    saved_result = agent.store.load().workflow.latest_result(candidate.id)
    assert saved_result is not None and saved_result.outcome == outcome
    saves = agent.store.save_count
    await agent._finish_tool_results()
    assert agent.store.save_count == saves
    assert tool.coverage.saving is None or tool.coverage.saving.done()
    assert not agent.result_retention.pending
    assert not any(event["type"] == "tool-result" for event in collector["events"])


@pytest.mark.parametrize("phase,name", PHASES)
async def test_resolving_coverage_after_resume_cannot_bypass_artifact_repair(runtime, tmp_path, phase, name):
    agent, state, candidate, tool, paths = await completed_discovery(runtime, tmp_path, "not-confirmed")
    result = state.latest_result(candidate.id)
    assert result is not None
    result.coverage_synced = False
    await agent.save()
    paths[phase].unlink()
    agent.resume_saved()
    assert f"coverage-sync:{candidate.id}" in agent._whole_target_state()[1]
    synced = await runtime[0].execute("workflow", {
        "action": "sync_coverage", "candidate_id": candidate.id,
    }, None, runtime[1])
    assert json.loads(synced)["ok"], synced
    assert agent._whole_target_state()[0] == "blocked"
    collector = collect()
    agent.client = FakeClient([ChatResponse(Message("assistant", "Artifact repair remains pending."), finish_reason="stop")
                              for _ in range(2)])
    await agent.run("continue", FakeSignal(), collector["sink"])
    assert collector["events"][-1]["stop_reason"] == "workflow_blocked"
    assert not any(e.get("stop_reason") == "workflow_completed" for e in collector["events"])
    assert state.completed_phases() == frozenset(phase for phase, _ in PHASES)


async def test_finding_commit_survives_cancellation_during_optional_export(runtime, tmp_path, monkeypatch):
    from src.findings.store import Store as FindingStore
    from src.tools.workflow.finding import ConfirmFindingTool

    state, candidate, tool, _ = await validated(runtime, tmp_path)
    finder = ConfirmFindingTool(FindingStore(project_directory=tmp_path), workflow=state)
    runtime[0].register(finder)
    agent = agent_for(runtime, state, tool)
    agent.store = SessionStore(tmp_path / "session.json", "assessment-session")
    await agent.save()
    exporting = asyncio.Event()

    async def pause_export(*unused):
        exporting.set()
        await asyncio.Future()

    async def run_inner(*unused):
        await persist(runtime, tmp_path, state, candidate, finder=finder)
        return "final_response"

    monkeypatch.setattr(finder, "write_summary", pause_export)
    monkeypatch.setattr(agent, "run_inner", run_inner)
    task = asyncio.create_task(agent.run("continue", FakeSignal(), collect()["sink"]))
    await asyncio.wait_for(exporting.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    agent.resume_saved()
    assert state.finding_is_persisted(candidate.id)
    assert len(list((tmp_path / "artifacts/findings").glob("*.md"))) == 1


async def test_artifact_repair_does_not_bypass_candidate_proof_loss(runtime, tmp_path):
    agent, state, candidate, tool, paths = await completed_discovery(runtime, tmp_path, "not-confirmed")
    retained_recon = paths["recon"].read_text()
    paths["recon"].unlink()
    result = state.latest_result(candidate.id)
    assert result is not None
    proof = tmp_path / state.evidence[result.evidence_refs[0]].path
    proof.chmod(0o600)
    proof.write_text("Altered proof cannot attest the old result.")
    agent.resume_saved()
    assert any("repair" in reason for reason in agent._whole_target_state()[2])
    await runtime[0].execute("file_write", {
        "path": str(paths["recon"]), "content": retained_recon,
    }, None, runtime[1])
    assert not tool.discovery_artifact_errors()
    assert tool.validation_completion_error(candidate.id, runtime[2])
    assert agent._whole_target_state()[0] != "completed"
    assert state.latest_result(candidate.id) is not None
    assert len(state.validation_results) == 1


async def test_completed_discovery_checks_artifacts_without_requiring_new_probes(runtime, tmp_path):
    agent, state, _, tool, paths = await completed_discovery(runtime, tmp_path, "not-confirmed")
    assert tool.skills is not None
    for _, name in PHASES:
        tool.skills.set_disabled(name, True)
    assert agent._whole_target_state() == ("completed", (), ())
    paths["recon"].unlink()
    assert agent._whole_target_state()[0] == "blocked"
    assert tool.discovery_artifact_errors().keys() == {"recon"}
    assert len(state.phase_completions) == 3


@pytest.mark.parametrize("failure", ["io_error", "timeout"])
async def test_failed_cancellation_checkpoint_is_bounded_and_retryable(runtime, tmp_path, monkeypatch, failure):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    agent = agent_for(runtime, state, tool)
    agent.store = SessionStore(tmp_path / "session.json", "assessment-session")
    await agent.save()
    original_save = agent.store.save
    from src.agent.agent import TOOL_CHECKPOINT_TIMEOUT_SECONDS as normal_checkpoint_timeout
    committed = asyncio.Event()

    async def failed_checkpoint(*unused, **kwargs):
        if failure == "io_error":
            raise OSError("offline session write failure")
        await asyncio.Future()

    async def run_inner(*unused):
        output = await runtime[0].execute("workflow", {**args, "outcome": "not-confirmed"}, None, runtime[1])
        assert json.loads(output)["ok"]
        committed.set()
        await asyncio.Future()

    monkeypatch.setattr(agent, "run_inner", run_inner)
    monkeypatch.setattr(agent.store, "save", failed_checkpoint)
    monkeypatch.setattr("src.agent.agent.TOOL_CHECKPOINT_TIMEOUT_SECONDS", 0.02)
    task = asyncio.create_task(agent.run("continue", FakeSignal(), collect()["sink"]))
    await asyncio.wait_for(committed.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    assert not state.mutation_lock.locked() and not agent.running
    assert state.latest_result(candidate.id) is not None
    assert agent._workflow_saved_revision != state.committed_revision
    monkeypatch.setattr(agent.store, "save", original_save)
    # The 20 ms deadline injects the failed checkpoint. The real async retry
    # must use the runtime deadline; synchronous saves previously hid this timer.
    monkeypatch.setattr("src.agent.agent.TOOL_CHECKPOINT_TIMEOUT_SECONDS", normal_checkpoint_timeout)
    await agent._finish_tool_results()
    saved_result = agent.store.load().workflow.latest_result(candidate.id)
    assert saved_result is not None and saved_result.outcome == "not-confirmed"
    assert agent._workflow_saved_revision == state.committed_revision
