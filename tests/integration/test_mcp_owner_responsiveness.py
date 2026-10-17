"""Fake-only MCP owner failure, queue and cancellation regressions."""
import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from src.tools.mcp import integration as module


@pytest.mark.parametrize("ending", ["rpc_cancel", "owner_cancel", "close", "timeout"])
async def test_owner_termination_settles_current_and_queued_calls(monkeypatch, ending):
    entered, release = asyncio.Event(), asyncio.Event()
    closed = asyncio.Event()
    owner_tasks = []

    class Session:
        async def call_tool(self, *args):
            owner_tasks.append(asyncio.current_task())
            entered.set()
            await release.wait()
            raise asyncio.CancelledError("offline RPC cancelled")

        async def close(self):
            owner_tasks.append(asyncio.current_task())
            closed.set()

    async def open_session(*args, **kwargs):
        return Session()

    monkeypatch.setattr(module.MCPSession, "_open", open_session)
    if ending == "timeout":
        monkeypatch.setattr(module, "MCP_CALL_TIMEOUT_S", 0.05)
    if ending == "close":
        monkeypatch.setattr(module, "CLOSE_DEADLINE_S", 0.05)
    proxy = await module.OwnedMCPSession.open(SimpleNamespace(name="offline"), worker=object(), broker=None)
    assert proxy.task is not None
    first = asyncio.create_task(proxy.call_tool("wait", {}))
    await asyncio.wait_for(entered.wait(), 1)
    second = asyncio.create_task(proxy.call_tool("queued", {}))
    await asyncio.sleep(0)
    try:
        if ending == "rpc_cancel":
            release.set()
        elif ending == "owner_cancel":
            proxy.task.cancel()
        elif ending == "close":
            await asyncio.gather(proxy.close(), proxy.close())
        results = await asyncio.wait_for(asyncio.gather(first, second, return_exceptions=True), 0.5)
        assert all(isinstance(value, BaseException) for value in results)
        await proxy.close()
        assert closed.is_set() and proxy.task.done() and proxy.is_closed()
        assert all(task is proxy.task for task in owner_tasks)
    finally:
        release.set()
        for task in (first, second):
            if not task.done():
                task.cancel()
        await asyncio.gather(first, second, return_exceptions=True)
        await proxy.close()


async def test_caller_cancel_waits_for_owner_teardown(monkeypatch):
    entered, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    class Session:
        async def list_tools(self):
            entered.set()
            await asyncio.Future()

        async def close(self):
            cleaning.set()
            await release.wait()

    async def open_session(*args, **kwargs):
        return Session()

    monkeypatch.setattr(module.MCPSession, "_open", open_session)
    proxy = await module.OwnedMCPSession.open(SimpleNamespace(name="offline"), worker=object(), broker=None)
    assert proxy.task is not None
    call = asyncio.create_task(proxy.list_tools())
    await entered.wait()
    call.cancel()
    try:
        await asyncio.wait_for(cleaning.wait(), 1)
        assert not call.done()
        call.cancel()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(call, 1)
    await proxy.close()
    assert proxy.task.done()


async def test_cancel_is_preserved_when_owner_teardown_fails(monkeypatch):
    entered = asyncio.Event()
    class Session:
        async def list_tools(self):
            entered.set()
            await asyncio.Future()
        async def close(self):
            raise OSError("synthetic teardown failure")
    async def open_session(*args, **kwargs):
        return Session()
    monkeypatch.setattr(module.MCPSession, "_open", open_session)
    proxy = await module.OwnedMCPSession.open(SimpleNamespace(name="offline"), worker=object(), broker=None)
    task = asyncio.create_task(proxy.list_tools())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)
    await proxy.close()


@pytest.mark.parametrize("explicit_cancel", [False, True])
async def test_policy_mcp_forwards_operator_abort_to_rpc(monkeypatch, explicit_cancel):
    from src.config.config import MCPServerConfig
    from src.permission.runtime import execution
    from src.permission.worker import broker
    seen = []
    class Session:
        server_name = "offline"
        async def call_tool(self, name, args, cancel_event=None):
            seen.append(cancel_event)
            return {"isError": False, "content": []}
        async def close(self):
            pass
    async def open_session(*args, **kwargs):
        return Session()
    @asynccontextmanager
    async def directory(*args, **kwargs):
        yield None
    policy = SimpleNamespace(worker=object(), nested_allowed=lambda: True,
        observations=SimpleNamespace(owner_provider=lambda: {}), revalidate_active=lambda *args: None)
    monkeypatch.setattr(execution, "policy_for", lambda _: policy)
    monkeypatch.setattr(module.MCPSession, "open", open_session)
    monkeypatch.setattr(broker, "broker_directory", directory)
    tool = module.MCPTool(Session(), "mcp_offline", "fixture", "", {})
    tool._execution_policy = policy
    tool._server = MCPServerConfig("offline", "unused")
    monkeypatch.setattr(tool, "_render_policy_result", lambda *args: "fixture")
    signal, cancel = asyncio.Event(), asyncio.Event()
    assert await tool.run({}, signal, object(), cancel if explicit_cancel else None) == "fixture"
    assert seen == [cancel if explicit_cancel else signal]
