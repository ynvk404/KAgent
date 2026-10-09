"""Pinned closure, closed deployment failures and actual isolated MCP discovery."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
from typing import cast

import pytest

from src.config.config import MCPServerConfig
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy
from src.permission.worker.worker import OfflineWorker
from src.engagement.state import EngagementState
from src.tools.mcp.integration import MCPSession, discover_mcp_tools
from src.tools.mcp.session_servers import BROWSER_MCP_SERVER
import src.tools.mcp.browser_deployment as deployment

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux pinned deployment')


@pytest.fixture
def installed(tmp_path, monkeypatch):
    root = tmp_path / 'deployment'
    entry = root / 'node_modules/@browsermcp/mcp/dist/index.js'
    entry.parent.mkdir(parents=True)
    entry.write_text('fixture')
    (root / 'package-lock.json').write_text('fixture lock')
    entries = {path.relative_to(root).as_posix(): (
        None if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()
    ) for path in root.rglob('*')}
    manifest = json.dumps({'schema': 1, 'package': '@browsermcp/mcp', 'version': '0.1.3',
                           'entries': entries}).encode()
    (root / 'manifest.json').write_bytes(manifest)
    monkeypatch.setattr(deployment, 'BROWSER_MCP_ROOT', root)
    monkeypatch.setattr(deployment, 'BROWSER_MCP_MANIFEST_SHA256', hashlib.sha256(manifest).hexdigest())
    # Ownership is separately tested below; test files are owned by the test UID.
    # All production file-type, link, completeness and digest checks stay active.
    monkeypatch.setattr(deployment, '_has_immutable_owner', lambda info: True)
    return root


def test_complete_deployment_verified(installed):
    deployment.verify_browser_deployment()


@pytest.mark.parametrize('change', ['missing', 'modified', 'extra', 'self-signed', 'hardlink', 'symlink', 'fifo'])
def test_closure_change_fails_closed(installed, change):
    lock = installed / 'package-lock.json'
    if change == 'missing':
        lock.unlink()
    elif change == 'modified':
        lock.write_text('modified')
    elif change == 'extra':
        (installed / 'unreviewed.js').write_text('extra')
    elif change == 'self-signed':
        lock.write_text('modified')
        path = installed / 'manifest.json'
        manifest = json.loads(path.read_bytes())
        manifest['entries']['package-lock.json'] = hashlib.sha256(lock.read_bytes()).hexdigest()
        path.write_text(json.dumps(manifest))
    elif change == 'hardlink':
        (installed.parent / 'outside-link').hardlink_to(lock)
    elif change == 'symlink':
        outside = installed.parent / 'outside'
        outside.write_bytes(lock.read_bytes())
        lock.unlink()
        lock.symlink_to(outside)
    else:
        lock.unlink()
        os.mkfifo(lock)
    with pytest.raises(ExecutionBlocked, match='missing/stale/unsafe'):
        deployment.verify_browser_deployment()


def test_verification_checkpoint_cancellation_propagates(installed):
    def cancelled():
        raise ExecutionBlocked('cancelled fixture')
    with pytest.raises(ExecutionBlocked, match='cancelled fixture'):
        deployment.verify_browser_deployment(cancelled)


@pytest.mark.parametrize('uid,mode,expected', [(0, 0o100644, True), (1000, 0o100644, False),
                                             (0, 0o100664, False), (0, 0o40777, False)])
def test_root_owned_nonmutable_identity(uid, mode, expected):
    assert deployment._has_immutable_owner(cast(os.stat_result, SimpleNamespace(st_uid=uid, st_mode=mode))) is expected


@pytest.mark.asyncio
async def test_missing_deployment_blocks_before_any_child(tmp_path, monkeypatch):
    monkeypatch.setattr(deployment, 'BROWSER_MCP_ROOT', tmp_path / 'missing')
    worker = OfflineWorker(tmp_path, (), '/usr/bin/bwrap', '/usr/bin/prlimit')
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    policy.worker = worker
    async def forbidden(*args, **kwargs):
        raise AssertionError('missing deployment launched a process')
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', forbidden)
    with pytest.raises(ExecutionBlocked, match='missing/stale/unsafe'):
        await discover_mcp_tools(BROWSER_MCP_SERVER, execution_policy=policy)


@pytest.mark.asyncio
async def test_designated_browser_never_runs_on_host():
    with pytest.raises(ValueError, match='requires an isolated worker'):
        await MCPSession._open(BROWSER_MCP_SERVER)
    # Generic user MCP commands remain generic, including a similar name.
    assert not deployment.is_designated_browser_server(MCPServerConfig('browser', '/bin/sh', ['-c', 'true']))


@pytest.mark.asyncio
async def test_actual_pinned_discovery_and_offline_dispatch(tmp_path):
    if not deployment.BROWSER_MCP_ROOT.exists() or not all(shutil.which(x) for x in ('bwrap', 'prlimit', 'node')):
        pytest.skip('explicitly prepared pinned Browser MCP and Linux worker required')
    worker = await OfflineWorker.available(tmp_path, ())
    assert worker is not None
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    policy.worker = worker
    for _ in range(3):
        discovered = await discover_mcp_tools(BROWSER_MCP_SERVER, execution_policy=policy)
        session = discovered['session']
        try:
            names = {tool.name() for tool in discovered['tools']}
            assert 'mcp_browser_browser_navigate' in names
            assert 'mcp_browser_browser_snapshot' in names
            assert len(names) == 12
            # Snapshot uses no host browser here: transport is still isolated.
            result = await session.call_tool('browser_snapshot', {})
            assert result['isError']
            assert 'No connection to browser extension' in str(result['content'])
        finally:
            await session.close()
        assert session.task.done()


@pytest.mark.asyncio
async def test_actual_browser_registry_dispatch_obeys_permission_and_revocation(tmp_path, monkeypatch):
    from src.permission.permission import Decision, UserControlledRefusal, YoloPrompter
    from src.tools.common.registry import Registry

    if not deployment.BROWSER_MCP_ROOT.exists() or not shutil.which('bwrap'):
        pytest.skip('explicit pinned deployment and Linux worker required')
    worker = await OfflineWorker.available(tmp_path, ())
    assert worker is not None
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    policy.worker = worker

    class Operator:
        decision = Decision.DENY
        approvals = []

        async def ask(self, request, signal=None):
            self.approvals.append(request)
            return self.decision

    operator = Operator()
    prompter = YoloPrompter(operator, False)
    prompter.bind_execution_policy(policy)
    discovered = await discover_mcp_tools(BROWSER_MCP_SERVER, execution_policy=policy)
    registry = Registry()
    tool = next(t for t in discovered['tools'] if t.name() == 'mcp_browser_browser_snapshot')
    registry.register(tool)
    launches = []
    original_open = MCPSession.open

    async def tracked_open(*args, **kwargs):
        session = await original_open(*args, **kwargs)
        launches.append(session)
        return session

    monkeypatch.setattr(MCPSession, 'open', tracked_open)
    try:
        with pytest.raises(UserControlledRefusal):
            await registry.execute(tool.name(), {}, None, prompter)
        assert not launches
        operator.decision = Decision.ALLOW_ONCE
        with pytest.raises(RuntimeError, match='No connection to browser extension'):
            await registry.execute(tool.name(), {'fixture': 1}, None, prompter)
        assert len(launches) == 1
        assert launches[0] is not discovered['session'] and launches[0].task.done()
        assert policy.active == 0
        assert all(req.no_session_cache and req.risk_tier == 'high-impact' for req in operator.approvals)
        policy.revoke(tool.name())
        with pytest.raises(ExecutionBlocked, match='revoked'):
            await registry.execute(tool.name(), {}, None, prompter)
        assert len(launches) == 1
    finally:
        await discovered['session'].close()


def test_browser_tools_keep_active_skill_gate():
    from src.agent.agent import Agent, AgentOptions
    from src.permission.permission import AlwaysAllow
    from src.skills.registry import Registry as SkillRegistry, Skill
    from src.tools.common.registry import Registry
    from src.tools.mcp.integration import MCPTool
    from tests.helpers.agent_fakes import FakeClient
    from src.target.target import Target

    class Session:
        server_name = 'browser'

        async def call_tool(self, name, args, cancel_event=None):
            raise AssertionError('skill gate dispatched')

    tools = Registry()
    tool = MCPTool(Session(), 'mcp_browser_browser_snapshot', 'browser_snapshot', '', {})
    tools.register(tool)
    skills = SkillRegistry()
    skill = Skill(name='fixture', description='fixture', tools=['http'],
                  disable_model_invocation=False, path='/virtual/fixture/SKILL.md', body='')
    skills.add(skill)
    agent = Agent(AgentOptions(client=FakeClient([]), tools=tools, skills=skills,
                               prompter=AlwaysAllow(), store=None, target=Target()))
    agent.active_skills.add('fixture')
    assert not agent.is_tool_allowed(tool.name(), {}).ok
    skill.tools.append(tool.name())
    assert agent.is_tool_allowed(tool.name(), {}).ok
    assert tool.requires_permission()


@pytest.mark.asyncio
async def test_existing_broker_rejects_browser_upgrade_connect_and_cleans_sessions(monkeypatch):
    import src.permission.worker.broker as broker_module

    class Policy:
        concurrency = 2

        def nested_allowed(self):
            return True

        def require_network(self, url):
            assert url == 'http://127.0.0.1:9009/'

    monkeypatch.setattr(broker_module, 'current_policy', lambda: Policy())
    directories = []
    for message in (b'CONNECT 127.0.0.1:9009 HTTP/1.1\r\n\r\n',
                    b'GET http://127.0.0.1:9009/ HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'):
        async with broker_module.broker_directory() as directory:
            directories.append(directory)
            reader, writer = await asyncio.open_unix_connection(str(directory / 'broker.sock'))
            writer.write(message)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), 2)
            assert response.startswith(b'HTTP/1.1 403') and b'101 Switching' not in response
            writer.close()
            await writer.wait_closed()
        assert not directory.exists()
        with pytest.raises(FileNotFoundError):
            await asyncio.open_unix_connection(str(directory / 'broker.sock'))
    assert directories[0] != directories[1]


@pytest.mark.asyncio
async def test_cancelled_browser_initialization_never_spawns(tmp_path, monkeypatch):
    import src.tools.mcp.integration as integration

    signal = asyncio.Event()
    signal.set()
    worker = OfflineWorker(tmp_path, (), '/usr/bin/bwrap', '/usr/bin/prlimit')
    def forbidden(*args, **kwargs):
        raise AssertionError('cancelled Browser initialization spawned')
    monkeypatch.setattr(integration, 'stdio_client', forbidden)
    with pytest.raises(asyncio.CancelledError):
        await MCPSession.open(BROWSER_MCP_SERVER, worker=worker, signal=signal)
