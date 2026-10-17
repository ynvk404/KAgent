"""Real registry/policy/TUI and owned MCP RPC, with only the peer replaced."""
import asyncio
from contextlib import asynccontextmanager
import json
import time
from types import SimpleNamespace

import pytest
from textual import events

from src.config.config import MCPServerConfig
from src.llm.core.types import ChatResponse, Message
from src.tools.mcp import integration as mcp
from tests.helpers.agent_fakes import FakeClient
from tests.helpers.system_runtime import assert_idle, drain, heartbeat, make_system_app, wait_until
from tests.system.test_local_boundaries import runtime_for
from tests.system.test_ui_lifecycle import tool_response


@pytest.mark.parametrize("ending", ["success", "escape", "timeout"])
async def test_mcp_rpc_lifecycle_through_agent_ui(tmp_path, monkeypatch, local_lab, ending, record_property):
    from src.permission.worker import broker
    entered, stopped, closed = asyncio.Event(), asyncio.Event(), asyncio.Event()
    owner_tasks = []
    proxies = []
    class Session:
        server_name = "system-fixture"
        async def call_tool(self, name, args, cancel_event=None):
            owner_tasks.append(asyncio.current_task())
            assert name == "read_fixture" and args == {} and cancel_event is not None
            entered.set()
            try:
                if ending == "success":
                    return {"isError": False, "content": [{"type": "text", "text": "offline MCP success"}]}
                await cancel_event.wait()
                raise asyncio.CancelledError("operator cancelled offline RPC")
            finally:
                stopped.set()
        async def close(self):
            owner_tasks.append(asyncio.current_task())
            closed.set()
    async def open_peer(*args, **kwargs):
        return Session()
    @asynccontextmanager
    async def no_broker_process(*args, **kwargs):
        yield None
    original_open = mcp.OwnedMCPSession.open
    async def track(*args, **kwargs):
        proxy = await original_open(*args, **kwargs)
        proxies.append(proxy)
        return proxy
    monkeypatch.setattr(mcp.MCPSession, "_open", open_peer)
    monkeypatch.setattr(mcp.MCPSession, "open", track)
    monkeypatch.setattr(broker, "broker_directory", no_broker_process)
    if ending == "timeout":
        monkeypatch.setattr(mcp, "MCP_CALL_TIMEOUT_S", 0.12)
    rt = runtime_for(tmp_path, local_lab)
    rt.policy.worker = SimpleNamespace(summary=lambda: "offline peer transport")
    tool = mcp.MCPTool(Session(), "mcp_fixture_read", "read_fixture", "Read synthetic data", {"type": "object", "properties": {}})
    tool._execution_policy = rt.policy
    tool._server = MCPServerConfig("system-fixture", "unused-offline-peer")
    rt.registry.register(tool)
    rt.agent.set_client(FakeClient([tool_response(tool.name(), "{}"),
                                   ChatResponse(Message("assistant", "Synthetic RPC settled."), "stop")]))
    app = make_system_app(rt)
    metrics = {}
    def diagnostic():
        rows = []
        for pending in asyncio.all_tasks():
            chain, coroutine = [], pending.get_coro()
            while coroutine is not None:
                frame = getattr(coroutine, "cr_frame", None)
                if frame is not None:
                    chain.append(f"{frame.f_code.co_filename}:{frame.f_lineno}:{frame.f_code.co_name}")
                coroutine = getattr(coroutine, "cr_await", None)
            rows.append({"name": pending.get_name(), "stack": chain})
        (tmp_path / "mcp-task-diagnostics.json").write_text(json.dumps(rows, indent=2))
    diagnostic_timer = asyncio.get_running_loop().call_later(1, diagnostic)
    async with app.run_test(size=(70, 24)):
        async def operator():
            while True:
                if app.state.pending_perm:
                    await app._process_key(events.Key("y", "y"))
                await asyncio.sleep(0.002)
        controller = asyncio.create_task(operator())
        app.submit("Read the synthetic MCP fixture once, with reviewed permission.")
        task = app.run_task
        assert task is not None
        try:
            async with heartbeat(metrics):
                await asyncio.wait_for(entered.wait(), 3)
                if ending == "escape":
                    start = time.monotonic()
                    abort = app.run_abort_event
                    await app._process_key(events.Key("escape", None))
                    metrics["esc_delivery_ms"] = (time.monotonic() - start) * 1000
                    assert abort is not None and abort.is_set()
                settled = await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
                assert settled[0] is None or ending != "success" and isinstance(settled[0], asyncio.CancelledError)
            assert stopped.is_set() and closed.is_set() and proxies
            assert all(proxy.task.done() and not proxy.pending and proxy.queue.empty() for proxy in proxies)
            assert len(set(owner_tasks)) == 1, "peer teardown must run in its owning task"
            assert_idle(app)
            assert not local_lab.wire and not rt.workflow.evidence and rt.policy.active == 0
            assert not rt.bridge._busy and not rt.bridge._waiters
            if ending == "success":
                assert any(message.role == "tool" and "offline MCP success" in message.content for message in rt.agent.history)
                assert any("Synthetic RPC settled." in entry.text for entry in app.state.transcript)
            record_property("mcp_lifecycle", json.dumps({"ending": ending, "closed": True, "pending": 0, **metrics}))
        finally:
            diagnostic_timer.cancel()
            controller.cancel()
            task.cancel()
            await asyncio.gather(controller, task, return_exceptions=True)
            for proxy in proxies:
                await proxy.close()
            await drain(rt)
