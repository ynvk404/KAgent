import asyncio
import threading
from types import SimpleNamespace

import pytest

from src.async_io import run_sync, publication
from src.agent.ownership import owned_turn
from src.workflow.state import WorkflowState


@pytest.mark.parametrize("ending", ["cancel", "retire", "failure"])
async def test_worker_is_joined_and_cannot_publish_after_cancellation_or_retirement(ending):
    entered, release = threading.Event(), threading.Event()
    published = []
    agent = SimpleNamespace(running=False, _active_turn=None, workflow=WorkflowState())

    def worker():
        entered.set()
        assert release.wait(2)
        if ending == "failure":
            raise OSError("synthetic worker failure")
        with publication():
            published.append(True)

    @owned_turn
    async def execute(agent):
        return await run_sync(worker)

    task = asyncio.create_task(execute(agent))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        if ending == "cancel":
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
        elif ending == "retire":
            agent.workflow.retire_generation()
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(OSError if ending == "failure" else asyncio.CancelledError):
        await asyncio.wait_for(task, 1)
    assert not published and agent._active_turn is None
