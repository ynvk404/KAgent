import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import create_autospec

import pytest
from mcp import ClientSession

from src.tools.mcp.integration import (
    MCPTool,
    MCPSession,
    sanitize,
)
from src.config.config import MCPServerConfig
from src.tools.common.registry import Registry
import src.tools.mcp.integration as mcp_integration


class FakeSession:
    def __init__(self, result: dict[str, Any]) -> None:
        self.server_name = "browser"
        self.result = result

    async def call_tool(
        self, name: str, args: dict[str, Any],
        cancel_event: asyncio.Event | None = None,
    ) -> dict[str, Any]:
        return self.result


class DummyPrompter:
    pass


@pytest.mark.asyncio
async def test_direct_mcp_cancellation_awaits_inner_call_cleanup():
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def blocking_call(name: str, arguments: dict[str, Any]) -> None:
        started.set()
        try:
            await asyncio.Future()
        finally:
            stopped.set()

    client_session = create_autospec(ClientSession, instance=True)
    client_session.call_tool.side_effect = blocking_call
    session = MCPSession("test", client_session, AsyncExitStack())
    task = asyncio.create_task(session.call_tool("wait", {}, asyncio.Event()))
    await asyncio.wait_for(started.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    assert stopped.is_set()


def test_sanitized_mcp_name_collision_is_rejected():
    registry = Registry()
    session = FakeSession({"isError": False, "content": []})
    first = MCPTool(session, f"mcp_{sanitize('a-b')}_scan", "scan", "", {})
    second = MCPTool(session, f"mcp_{sanitize('a_b')}_scan", "scan", "", {})
    registry.register(first)
    with pytest.raises(ValueError, match="duplicate tool registration: mcp_a_b_scan"):
        registry.register(second)
    assert registry.get("mcp_a_b_scan") is first


def test_mcp_actions_require_fresh_high_impact_approval():
    tool = MCPTool(
        FakeSession({"isError": False, "content": []}),
        "mcp_browser_click",
        "click",
        "Click in browser",
        {"type": "object"},
    )

    assert tool.permission_hints({"button": "submit"}) == {
        "noSessionCache": True,
        "riskTier": "high-impact",
    }


@pytest.mark.asyncio
async def test_cwe_mcp_rejects_non_designated_launch_before_worker_dispatch():
    class Worker:
        cwe_mcp_deployment_path = Path('/operator/configured/cwe-mcp-deployment')
        calls = []

        async def prepare(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return '/usr/bin/true', []

    worker = Worker()
    server = MCPServerConfig('cwe_catalog', '/usr/bin/python3',
                             ['-I', '-B', '/tmp/untrusted/launch.py'])

    with pytest.raises(ValueError, match='invalid designated CWE MCP launch configuration'):
        await MCPSession._open(server, worker=worker)

    assert worker.calls == []


@pytest.mark.asyncio
async def test_designated_cwe_mcp_never_falls_back_to_unisolated_launch(monkeypatch):
    server = MCPServerConfig('cwe_catalog', '/usr/bin/python3',
                             ['-I', '-B', '/opt/kagent-cwe-mcp/launch.py'])
    called = []

    def forbidden_spawn(*args, **kwargs):
        called.append(True)
        raise AssertionError('unisolated CWE MCP launch attempted')

    monkeypatch.setattr(mcp_integration, 'stdio_client', forbidden_spawn)
    with pytest.raises(ValueError, match='requires an isolated worker'):
        await MCPSession._open(server)

    assert called == []


@pytest.mark.asyncio
async def test_discovery_deployment_mismatch_blocks_before_launch(monkeypatch):
    from types import SimpleNamespace
    from src.permission.runtime.execution import ExecutionBlocked
    policy = SimpleNamespace(cwe_mcp_deployment_path=Path('/configured/deployment'),
                             worker=SimpleNamespace(cwe_mcp_deployment_path=Path('/other/deployment')))
    calls = []
    async def forbidden_open(*args, **kwargs):
        calls.append(True)
        raise AssertionError('mismatched deployment launched')
    monkeypatch.setattr(MCPSession, 'open', forbidden_open)
    server = MCPServerConfig('cwe_catalog', '/usr/bin/python3', ['-I', '-B', '/opt/kagent-cwe-mcp/launch.py'])
    with pytest.raises(ExecutionBlocked, match='policy-worker-mismatch'):
        await mcp_integration.discover_mcp_tools(server, execution_policy=policy)
    assert not calls


@pytest.mark.asyncio
async def test_discovery_path_change_during_initialize_closes_before_listing(monkeypatch):
    from types import SimpleNamespace
    from src.permission.runtime.execution import ExecutionBlocked
    policy = SimpleNamespace(cwe_mcp_deployment_path=Path('/configured/deployment'),
                             worker=SimpleNamespace(cwe_mcp_deployment_path=Path('/configured/deployment')))
    closed = []
    class Session:
        async def list_tools(self):
            raise AssertionError('stale deployment discovery accepted')
        async def close(self):
            closed.append(True)
    async def changed_open(*args, **kwargs):
        policy.cwe_mcp_deployment_path = Path('/replacement/deployment')
        policy.worker.cwe_mcp_deployment_path = policy.cwe_mcp_deployment_path
        return Session()
    monkeypatch.setattr(MCPSession, 'open', changed_open)
    server = MCPServerConfig('cwe_catalog', '/usr/bin/python3', ['-I', '-B', '/opt/kagent-cwe-mcp/launch.py'])
    with pytest.raises(ExecutionBlocked, match='changed during discovery'):
        await mcp_integration.discover_mcp_tools(server, execution_policy=policy)
    assert closed == [True]


@pytest.mark.asyncio
@pytest.mark.parametrize('interruption', ['cancel', 'repeat-cancel', 'timeout'])
async def test_real_initialization_interruption_closes_transport_in_owner_task(tmp_path, monkeypatch, interruption):
    from src.permission.worker.worker import OfflineWorker
    from tests.security.test_worker_responsiveness import MCP_SERVER
    import shutil
    if not shutil.which('bwrap') or not shutil.which('prlimit'):
        pytest.skip('existing Linux worker required')
    worker = await OfflineWorker.available(tmp_path, ())
    assert worker is not None
    entered, closed = asyncio.Event(), asyncio.Event()
    cleanup_entered, release_cleanup = asyncio.Event(), asyncio.Event()
    owners = []
    original_transport = mcp_integration.stdio_client
    loop = asyncio.get_running_loop()
    errors = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: errors.append(context))

    @asynccontextmanager
    async def transport(*args, **kwargs):
        owner = asyncio.current_task()
        try:
            async with original_transport(*args, **kwargs) as streams:
                try:
                    yield streams
                finally:
                    if interruption == 'repeat-cancel':
                        cleanup_entered.set()
                        await release_cleanup.wait()
        finally:
            owners.append((owner, asyncio.current_task()))
            closed.set()

    async def stalled_initialize(self, *args, **kwargs):
        entered.set()
        await asyncio.Future()

    monkeypatch.setattr(mcp_integration, 'stdio_client', transport)
    monkeypatch.setattr(ClientSession, 'initialize', stalled_initialize)
    server = MCPServerConfig('initialization_fixture', '/usr/bin/python3', ['-I', '-B', '-u', '-c', MCP_SERVER])
    task = asyncio.create_task(MCPSession.open(server, worker=worker))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        if interruption in {'cancel', 'repeat-cancel'}:
            task.cancel()
        if interruption == 'repeat-cancel':
            await asyncio.wait_for(cleanup_entered.wait(), 5)
            task.cancel()
            await asyncio.sleep(0)
            assert not closed.is_set() and not task.done()
            release_cleanup.set()
        with pytest.raises(TimeoutError if interruption == 'timeout' else asyncio.CancelledError):
            await task
        assert closed.is_set() and owners and all(a is b for a, b in owners)
        await asyncio.sleep(0)
        assert not errors
    finally:
        release_cleanup.set()
        loop.set_exception_handler(previous_handler)
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_formats_text_mcp_errors_without_raw_content_json():

    session = FakeSession(
        {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": "Error: WebSocket response timeout after 30000ms",
                }
            ],
        }
    )

    tool = MCPTool(
        session,
        "mcp_browser_browser_click",
        "browser_click",
        "Click in browser",
        {"type": "object"},
    )

    with pytest.raises(
        RuntimeError,
        match="Browser Click failed: WebSocket response timeout after 30000ms",
    ):
        await tool.run(
            {},
            None,
            DummyPrompter(),
        )

    try:
        await tool.run({}, None, DummyPrompter())
    except RuntimeError as err:
        assert "isError" not in str(err)

@pytest.mark.asyncio
async def test_truncates_large_successful_mcp_results():

    session = FakeSession(
        {
            "isError": False,
            "content": [
                {
                    "type": "text",
                    "text": "a" * 200_000,
                }
            ],
        }
    )

    tool = MCPTool(
        session,
        "mcp_browser_big",
        "big",
        "Big output",
        {"type": "object"},
    )

    out = await tool.run(
        {},
        None,
        DummyPrompter(),
    )

    assert "truncated" in out
    assert len(out) < 140_000


@pytest.mark.asyncio
async def test_bounds_deeply_nested_content():

    deep = {"leaf": "x"}

    for _ in range(100):
        deep = {"nested": deep}

    session = FakeSession(
        {
            "isError": False,
            "content": deep,
        }
    )
    tool = MCPTool(
        session,
        "mcp_browser_deep",
        "deep",
        "Deep output",
        {"type": "object"},
    )
    out = await tool.run(
        {},
        None,
        DummyPrompter(),
    )
    assert "max depth exceeded" in out
