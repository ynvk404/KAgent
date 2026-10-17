"""Offline entry failures must release the existing UI turn owner."""
import asyncio
import threading
from copy import deepcopy

import pytest

from src.ui.core.app import KAgent
from tests.agent.test_token_accounting_independent_verify import make_agent
from tests.ui.test_overview import _make_app
from src.session.store import Store


@pytest.mark.parametrize("lock_state", ["idle", "held", "waiter"])
async def test_workflow_snapshot_does_not_copy_runtime_waiters(lock_state):
    agent = make_agent()
    state = agent.workflow
    waiter = None
    if lock_state != "idle":
        await state.mutation_lock.acquire()
    if lock_state == "waiter":
        waiter = asyncio.create_task(state.mutation_lock.acquire())
        await asyncio.sleep(0)
    try:
        snapshot = deepcopy(state)
        assert snapshot.mutation_lock is not state.mutation_lock
        assert not snapshot.mutation_lock.locked()
        assert snapshot.retired is not state.retired
        assert snapshot.lifecycle_lock is not state.lifecycle_lock
        assert snapshot.generation == state.generation
        snapshot.selected_sources["snapshot-only"] = {"mutable": []}
        assert not state.selected_sources
        agent.idle_request_estimate()
    finally:
        if waiter is not None:
            waiter.cancel()
            await asyncio.gather(waiter, return_exceptions=True)
        if state.mutation_lock.locked():
            state.mutation_lock.release()


@pytest.mark.parametrize("operation", ["run", "compact"])
@pytest.mark.parametrize("failure", [RuntimeError, asyncio.CancelledError])
async def test_prepare_failure_always_releases_ui_owner(monkeypatch, operation, failure):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = _make_app()
    app.agent = make_agent()
    async with app.run_test() as pilot:
        original = app._sync_status_bar
        for _ in range(2):
            def fail_when_busy():
                if app.state.busy:
                    raise failure("synthetic prepare failure")
                original()
            monkeypatch.setattr(app, "_sync_status_bar", fail_when_busy)
            try:
                if operation == "run":
                    await app.run_agent_turn("offline fixture")
                else:
                    await app._run_agent_compact()
            except (RuntimeError, asyncio.CancelledError):
                pass
            assert not app.state.busy
            assert not app.agent.is_running()
            assert app.run_abort_event is None
            assert app.run_task is None
            assert not app._elapsed_active and app._elapsed_timer is None
            assert app.state.pending_perm is None and app.state.pending_ask is None
            monkeypatch.setattr(app, "_sync_status_bar", original)
            await pilot.press("escape", "x")
            assert app.input.value.endswith("x")
            await app.agent.reset()


async def test_unmount_joins_initial_snapshot_worker(tmp_path, monkeypatch):
    import src.session.store as store_module
    entered, release = threading.Event(), threading.Event()
    original = store_module._write_context_snapshot
    def write(*args):
        entered.set()
        assert release.wait(2)
        return original(*args)
    monkeypatch.setattr(store_module, "_write_context_snapshot", write)
    app = _make_app()
    app.agent = make_agent(store=Store.new_with_id(tmp_path / "sessions", "snapshot"))
    async with app.run_test():
        assert await asyncio.to_thread(entered.wait, 1)
        closing = asyncio.create_task(app.on_unmount())
        try:
            for _ in range(3):
                await asyncio.sleep(0.01)
                assert not closing.done()
        finally:
            release.set()
        await asyncio.wait_for(closing, 1)
        assert not app.snapshot_saving
        assert app.snapshot_task is not None and app.snapshot_task.done()
