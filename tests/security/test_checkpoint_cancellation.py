"""Offline cancellation/failure races at the checkpoint and closure boundaries."""
import asyncio
from pathlib import Path
import threading

import pytest

import src.agent.agent as agent_module
import src.session.store as session_module
from tests.helpers.agent_fakes import FakeSignal, collect
from tests.security.test_execution_policy import runtime  # noqa: F401
from tests.security.test_terminal_goal_checkpoint import assert_closed, prepared, result_for


@pytest.mark.parametrize("boundary", ["checkpoint", "closure"])
@pytest.mark.parametrize("fail,cancellations", [
    (False, 0), (True, 0), (False, 1), (False, 2), (True, 1), (True, 2),
])
async def test_checkpoint_writer_outcomes(runtime, tmp_path, monkeypatch, boundary, fail, cancellations):
    agent, _, sql, xss, aid = await prepared(runtime, tmp_path)
    assert agent.store is not None
    store = agent.store
    before = store.path.read_bytes()
    if boundary == "checkpoint":
        await agent.tools.execute("workflow", {
            "action": "record_result", "candidate_id": xss.id, "attempt_id": aid,
            "skill_name": "cross-site-scripting", "outcome": "insufficient-evidence",
            "deferred_reason": "Controlled checkpoint interruption",
        }, None, agent.prompter)

    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    replace = session_module.os.replace
    failure = OSError("controlled checkpoint writer failure")
    writes, logs = [], []

    def held_replace(source, destination):
        if Path(destination) != store.path:
            return replace(source, destination)
        writes.append(Path(source))
        entered.set()
        try:
            assert release.wait(5), "controller did not release writer"
            if fail:
                raise failure
            return replace(source, destination)
        finally:
            finished.set()

    monkeypatch.setattr(session_module.os, "replace", held_replace)
    monkeypatch.setattr(agent_module, "log_error", lambda *args: logs.append(args))
    events = collect()
    operation = (agent._checkpoint_terminal_workflow() if boundary == "checkpoint" else
                 agent._close_terminal_attempt("max_steps", FakeSignal(), events["sink"], agent.history.copy()))
    task = asyncio.create_task(operation)
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        for _ in range(cancellations):
            task.cancel()
            await asyncio.sleep(0)
        assert not task.done() and not finished.is_set()
        assert agent.workflow.mutation_lock.locked()
    finally:
        release.set()
        # Retrieve failures even if a synchronization assertion above fails.
        outcome = (await asyncio.gather(task, return_exceptions=True))[0]

    assert finished.is_set() and len(writes) == 1
    assert not agent.workflow.mutation_lock.locked()
    assert not list(store.path.parent.glob("*.tmp.*"))
    errors = [e for e in events["events"] if e["type"] == "error"]
    if cancellations:
        assert isinstance(outcome, asyncio.CancelledError), repr(outcome)
        assert task.cancelled()
        # Await directly: gather() replaces a cancelled task's exception and
        # would discard its diagnostic cause.
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        assert caught.value.__cause__ is (failure if fail else None)
        assert not errors, "cancellation must not become a closure error receipt"
    elif fail and boundary == "checkpoint":
        assert outcome is failure
    else:
        assert outcome is None
        assert bool(errors) is fail
    assert len(logs) == int(bool(cancellations and fail))
    if logs:
        assert logs[0][0] == "agent: cancellation checkpoint failed"
        assert "controlled checkpoint writer failure" in logs[0][1]["err"]

    result_id = result_for(agent, xss).result_id
    if fail:
        assert store.path.read_bytes() == before
        assert agent._workflow_saved_revision != agent.workflow.committed_revision
        # Explicit recovery retries persistence, without repeating the closure.
        monkeypatch.setattr(session_module.os, "replace", replace)
        await agent._checkpoint_terminal_workflow()
    assert agent._workflow_saved_revision == agent.workflow.committed_revision
    assert not agent._tool_results_unsaved
    assert result_for(agent, xss).result_id == result_id
    assert_closed(agent, sql, xss, aid)
