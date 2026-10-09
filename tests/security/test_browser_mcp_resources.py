"""Browser MCP's larger virtual-memory budget must not grant other rights."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
import json
import os
import shutil
import sys
from types import SimpleNamespace

import pytest

from src.config.config import MCPServerConfig
from src.engagement.state import EngagementState
from src.permission.permission import Decision, UserControlledRefusal, YoloPrompter
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy
from src.permission.worker.worker import OfflineWorker
from src.tools.common.registry import Registry
from src.tools.mcp.integration import MCPSession, discover_mcp_tools
from src.tools.mcp.session_servers import BROWSER_MCP_SERVER
import src.tools.mcp.integration as integration


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux worker resource profiles")


@pytest.mark.parametrize("brokered", [False, True])
def test_browser_budget_changes_only_address_space(tmp_path, brokered):
    worker = OfflineWorker(tmp_path, (), "/usr/bin/bwrap", "/usr/bin/prlimit")
    broker = tmp_path / "broker" if brokered else None
    if broker is not None:
        broker.mkdir()
    command, ordinary = worker.wrap("npx", BROWSER_MCP_SERVER.args, broker=broker)
    browser_command, browser = worker.wrap("npx", BROWSER_MCP_SERVER.args, broker=broker, browser_mcp=True)
    assert command == browser_command == "/usr/bin/prlimit"
    assert ordinary[0] == "--as=536870912"
    assert browser[0] == "--as=1073741824"
    assert browser[1:] == ordinary[1:]
    _, scanner = worker.wrap("/usr/bin/ffuf", [], scanner=True)
    assert scanner[0] == "--as=4294967296"


@pytest.mark.asyncio
@pytest.mark.parametrize("server,expected_limit", [
    (deepcopy(BROWSER_MCP_SERVER), "--as=1073741824"),
    (MCPServerConfig("browser-mcp", "npx", list(BROWSER_MCP_SERVER.args)), "--as=1073741824"),
    (MCPServerConfig("other", "npx", list(BROWSER_MCP_SERVER.args)), "--as=536870912"),
    (MCPServerConfig("browser", "/bin/sh", ["-c", "true"]), "--as=536870912"),
    (MCPServerConfig("browser", "npx", ["-y", "unrelated-mcp"]), "--as=536870912"),
    (MCPServerConfig("browser", "npx", [*BROWSER_MCP_SERVER.args, "--extra"]), "--as=536870912"),
])
async def test_discovery_and_dispatch_select_only_designated_browser_profile(tmp_path, monkeypatch, server, expected_limit):
    worker = OfflineWorker(tmp_path, (), "/usr/bin/bwrap", "/usr/bin/prlimit")
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    policy.worker = worker
    launches = []
    calls = []
    approvals = []

    @asynccontextmanager
    async def transport(params, **kwargs):
        launches.append(params)
        yield None, None

    class Client:
        def __init__(self, *args):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def initialize(self):
            pass

        async def list_tools(self):
            return SimpleNamespace(tools=[SimpleNamespace(name="echo", description="fixture", inputSchema={"type": "object"})])

        async def call_tool(self, name, arguments):
            calls.append(name)
            return SimpleNamespace(isError=False, content=[{"type": "text", "text": "FIXTURE_OK"}])

    class Operator:
        decision = Decision.DENY

        async def ask(self, request, signal=None):
            approvals.append(request)
            return self.decision

    monkeypatch.setattr(integration, "stdio_client", transport)
    monkeypatch.setattr(integration, "ClientSession", Client)
    operator = Operator()
    prompter = YoloPrompter(operator, False)
    prompter.bind_execution_policy(policy)
    discovered = await discover_mcp_tools(server, execution_policy=policy)
    registry = Registry()
    tool = discovered["tools"][0]
    registry.register(tool)
    try:
        assert len(launches) == 1 and not calls
        with pytest.raises(UserControlledRefusal):
            await registry.execute(tool.name(), {}, None, prompter)
        assert len(launches) == 1 and not calls
        operator.decision = Decision.ALLOW_ONCE
        # A different invocation avoids reusing the declined action's receipt.
        for value in (1, 2):
            assert "FIXTURE_OK" in await registry.execute(tool.name(), {"value": value}, None, prompter)
        assert len(launches) == 3 and calls == ["echo", "echo"]
        assert len(approvals) == 3
        assert all(request.no_session_cache and request.risk_tier == "high-impact" for request in approvals)
        assert policy.active == 0
        for params in launches:
            assert params.command == "/usr/bin/prlimit" and params.args[0] == expected_limit
            assert params.env == {}
            assert "--unshare-all" in params.args and "--clearenv" in params.args
        assert "/run/kagent" not in launches[0].args
        assert all("/run/kagent" in params.args and "/relay.py" in params.args for params in launches[1:])
    finally:
        await discovered["session"].close()


@pytest.mark.asyncio
async def test_browser_profile_keeps_environment_and_worker_gates(tmp_path):
    with pytest.raises(ExecutionBlocked, match="isolated worker required"):
        await discover_mcp_tools(BROWSER_MCP_SERVER, execution_policy=SimpleNamespace(worker=None))
    worker = OfflineWorker(tmp_path, (), "/usr/bin/bwrap", "/usr/bin/prlimit")
    server = deepcopy(BROWSER_MCP_SERVER)
    server.env = {"NODE_OPTIONS": "fixture"}
    with pytest.raises(ValueError, match="environment export adapter unavailable"):
        await MCPSession._open(server, worker=worker)
    os.mkfifo(tmp_path / "host-fifo")
    with pytest.raises(ExecutionBlocked, match="host-ipc"):
        await worker.prepare("npx", BROWSER_MCP_SERVER.args, browser_mcp=True)


@pytest.mark.asyncio
async def test_real_browser_profile_keeps_memory_filesystem_environment_and_network_isolation(tmp_path, monkeypatch):
    if not shutil.which("bwrap") or not shutil.which("prlimit"):
        pytest.skip("existing Linux bwrap/prlimit required")
    root = tmp_path / "project"
    root.mkdir()
    (root / "source.txt").write_text("ORIGINAL")
    outside = tmp_path / "host-secret"
    outside.write_text("FAKE_HOST_SECRET")
    monkeypatch.setenv("KAGENT_RESOURCE_TEST_SECRET", "FAKE_ENV_SECRET")
    worker = await OfflineWorker.available(root, ())
    assert worker is not None
    accepted = []

    async def accept(reader, writer):
        accepted.append(True)
        writer.close()
        await writer.wait_closed()

    listener = await asyncio.start_server(accept, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    script = f"""
import json, os, resource, socket
checks = {{'as': resource.getrlimit(resource.RLIMIT_AS), 'secret': os.getenv('KAGENT_RESOURCE_TEST_SECRET')}}
for label, path, mode in [('host_hidden', {str(outside)!r}, 'r'), ('source_readonly', 'source.txt', 'w')]:
    try:
        with open(path, mode): pass
        checks[label] = False
    except OSError:
        checks[label] = True
try:
    with socket.create_connection(('127.0.0.1', {port}), timeout=1): pass
    checks['network_isolated'] = False
except OSError:
    checks['network_isolated'] = True
print(json.dumps(checks))
"""
    try:
        command, argv = await worker.prepare("/usr/bin/python3", ["-I", "-B", "-c", script], browser_mcp=True)
        process = await asyncio.create_subprocess_exec(command, *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 5)
        assert process.returncode == 0, stderr.decode()
        assert json.loads(stdout) == {"as": [1024**3, 1024**3], "secret": None,
                                     "host_hidden": True, "source_readonly": True, "network_isolated": True}
        assert not accepted and (root / "source.txt").read_text() == "ORIGINAL"
    finally:
        listener.close()
        await listener.wait_closed()


@pytest.mark.asyncio
async def test_real_browser_budget_initializes_installed_node(tmp_path):
    if not all(shutil.which(name) for name in ("bwrap", "prlimit", "node")):
        pytest.skip("existing Linux bwrap/prlimit/Node required")
    worker = await OfflineWorker.available(tmp_path, ())
    assert worker is not None
    command, argv = await worker.prepare("/usr/bin/node", ["-e", 'console.log("NODE_INIT_OK")'], browser_mcp=True)
    process = await asyncio.create_subprocess_exec(command, *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await asyncio.wait_for(process.communicate(), 5)
    assert process.returncode == 0, stderr.decode()
    assert stdout.strip() == b"NODE_INIT_OK"
