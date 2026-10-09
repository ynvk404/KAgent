"""Trusted-local controller/lifecycle tests; fakes never pair with real Chrome."""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.cli.runtime import FlagParseError, parse_flags
from src.config.config import MCPServerConfig
from src.engagement.state import EngagementState
from src.permission.permission import Decision, UserControlledRefusal, YoloPrompter
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy, current_policy
from src.tools.common.registry import Registry
from src.tools.mcp.integration import MCPSession, MCPTool, discover_mcp_tools
from src.tools.mcp.session_servers import BROWSER_LOCAL_SERVER, BROWSER_MCP_SERVER, session_mcp_servers
from src.tools.mcp import browser_local as local
from src.tools.mcp import browser_deployment as deployment

ORIGIN = 'http://juice.lab:8081'
MARKER = ContextVar('browser_test_invocation', default='neutral')
TOOLS = [{'name': 'browser_' + name, 'description': name, 'inputSchema': {'type': 'object'}}
         for name in ('navigate', 'snapshot', 'click', 'type', 'hover', 'select_option', 'press_key',
                      'go_back', 'go_forward', 'wait', 'screenshot', 'get_console_logs')]


class Operator:
    def __init__(self, policy):
        self.execution_policy = policy
        self.decision = Decision.ALLOW_ONCE
        self.asks = []

    async def ask(self, request, signal=None):
        self.asks.append(request)
        return self.decision


@pytest.fixture
async def rig(tmp_path, monkeypatch):
    engagement = EngagementState()
    engagement.add_origin(ORIGIN)
    policy = ExecutionPolicy(engagement, tmp_path)
    policy.session_id = 'first-cli'
    binding = local.BrowserLocalBinding(policy, BROWSER_LOCAL_SERVER, lab_origin=ORIGIN)
    policy.browser_local = binding
    operator = Operator(policy)
    sessions = []
    starts, finishes, calls = [], [], []
    gate = asyncio.Event()
    started = asyncio.Event()
    block = [False]
    connected = [True]
    generation = [1]
    fail = [False]
    mcp_error = [None]

    class Session:
        snapshot = 0

        def __init__(self):
            self.owner_task = asyncio.current_task()
            self.closed = False

        async def list_tools(self):
            assert asyncio.current_task() is self.owner_task
            assert current_policy() is None and MARKER.get() == 'neutral'
            return TOOLS

        async def browser_status(self):
            assert current_policy() is None and MARKER.get() == 'neutral'
            return {'pid': 123, 'listening': True, 'connected': connected[0],
                    'generation': generation[0], 'snapshotGeneration': self.snapshot}

        async def call_tool(self, name, args, **kwargs):
            assert current_policy() is None and MARKER.get() == 'neutral'
            assert asyncio.current_task() is self.owner_task
            starts.append(name)
            calls.append((self, name, args, kwargs))
            started.set()
            if block[0]:
                await gate.wait()
            if fail[0]:
                raise RuntimeError('process died after send')
            if mcp_error[0] is not None:
                return {'isError': True, 'content': [{'type': 'text', 'text': mcp_error[0]}],
                        '_meta': {'kagentBrowser': {'generation': generation[0], 'snapshotGeneration': self.snapshot}}}
            self.snapshot += 1
            finishes.append(name)
            return {'isError': False, 'content': [{'type': 'text', 'text': '- Page URL: ' + ORIGIN + '\nbutton [ref=s1e1]'}],
                    '_meta': {'kagentBrowser': {'generation': generation[0], 'snapshotGeneration': self.snapshot}}}

        async def close(self):
            assert asyncio.current_task() is self.owner_task
            assert current_policy() is None
            self.closed = True

    async def open_session(server, **kwargs):
        assert kwargs['browser_local'] is True
        assert current_policy() is None and MARKER.get() == 'neutral'
        session = Session()
        sessions.append(session)
        return session

    monkeypatch.setattr(MCPSession, '_open', open_session)
    monkeypatch.setattr(local, 'verify_listener_owner', lambda status: None)
    discovered = await discover_mcp_tools(BROWSER_LOCAL_SERVER, execution_policy=policy, browser_local=binding)
    registry = Registry()
    for tool in discovered['tools']:
        registry.register(tool)
    value = SimpleNamespace(policy=policy, binding=binding, operator=operator, registry=registry, sessions=sessions,
                            calls=calls, gate=gate, started=started, block=block, connected=connected,
                            generation=generation, fail=fail, mcp_error=mcp_error, starts=starts, finishes=finishes)
    try:
        yield value
    finally:
        await binding.close()
        assert all(session.closed for session in sessions)
        assert policy.active == 0


async def execute(rig, name, args=None, signal=None):
    return await rig.registry.execute('mcp_browser_browser_' + name, args or {}, signal, rig.operator)


def test_browser_flag_selects_local_without_profile_attestation():
    flags = parse_flags(['--browser', '--target', ORIGIN])
    assert flags.browser and flags.target_url == ORIGIN and not flags.yolo
    assert parse_flags(['--browser', '--list-tools']).browser
    assert session_mcp_servers([], True)[0] is BROWSER_LOCAL_SERVER
    assert session_mcp_servers([BROWSER_LOCAL_SERVER, BROWSER_MCP_SERVER], False) == []


@pytest.mark.parametrize('flag', ['--browser-local', '--browser-lab-ready'])
def test_removed_browser_flags_are_unknown(flag, capsys):
    from src.cli.help import print_help
    with pytest.raises(FlagParseError, match='unknown option'):
        parse_flags(['--browser', flag, '--target', ORIGIN])
    print_help()
    assert flag not in capsys.readouterr().out


@pytest.mark.asyncio
@pytest.mark.parametrize('server', [MCPServerConfig('browser', '/bin/sh', ['-c', 'true']),
                                  MCPServerConfig('browser-mcp', BROWSER_LOCAL_SERVER.command, BROWSER_LOCAL_SERVER.args),
                                  MCPServerConfig('browser', BROWSER_LOCAL_SERVER.command, [*BROWSER_LOCAL_SERVER.args, '--extra']),
                                  MCPServerConfig('browser', BROWSER_LOCAL_SERVER.command, BROWSER_LOCAL_SERVER.args, {'NODE_OPTIONS': '-e'})])
async def test_forged_config_never_selects_host(server, tmp_path):
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    with pytest.raises(ExecutionBlocked, match='invalid controller'):
        await discover_mcp_tools(server, execution_policy=policy, browser_local=object())
    assert not deployment.is_designated_browser_local(server)


@pytest.mark.asyncio
async def test_local_configuration_alone_does_not_escape_worker():
    with pytest.raises(ValueError, match='controller opt-in'):
        await MCPSession._open(BROWSER_LOCAL_SERVER)


@pytest.mark.asyncio
async def test_reuse_serialization_neutral_owner_and_fresh_approvals(rig):
    token = MARKER.set('first-receipt')
    try:
        await execute(rig, 'navigate', {'url': ORIGIN})
        await execute(rig, 'snapshot')
        rig.block[0] = True
        rig.started.clear()
        first = asyncio.create_task(execute(rig, 'click', {'ref': 's1e1', 'element': 'first'}))
        await rig.started.wait()
        second = asyncio.create_task(execute(rig, 'type', {'ref': 's1e1', 'element': 'search', 'text': 'test', 'submit': False}))
        await asyncio.sleep(0.08)
        assert rig.starts == ['browser_navigate', 'browser_snapshot', 'browser_click']
        rig.gate.set()
        await asyncio.gather(first, second)
        assert rig.starts == rig.finishes
        assert len({id(row[0]) for row in rig.calls}) == 1
        assert len(rig.sessions) == 2 and rig.sessions[0].closed
        assert len(rig.operator.asks) == 4
        assert all(req.no_session_cache and req.risk_tier == 'high-impact' for req in rig.operator.asks)
    finally:
        MARKER.reset(token)


@pytest.mark.asyncio
async def test_deny_and_missing_target_never_start_host(rig):
    rig.operator.decision = Decision.DENY
    with pytest.raises(UserControlledRefusal):
        await execute(rig, 'snapshot')
    assert not rig.calls and len(rig.sessions) == 1
    rig.binding.lab_origin = ''
    rig.operator.decision = Decision.ALLOW_ONCE
    with pytest.raises(ExecutionBlocked, match='explicit --target'):
        await execute(rig, 'snapshot')
    assert len(rig.sessions) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('enabled', [False, True])
async def test_browser_asks_each_call_with_yolo_on_or_off_and_honors_deny(rig, enabled):
    prompter = YoloPrompter(rig.operator, enabled)
    prompter.bind_execution_policy(rig.policy)
    for _ in range(2):
        await rig.registry.execute('mcp_browser_browser_snapshot', {}, None, prompter)
    assert len(rig.calls) == 2 and len(rig.operator.asks) == 2
    assert all(request.force_operator and request.no_session_cache for request in rig.operator.asks)
    rig.operator.decision = Decision.DENY
    with pytest.raises(UserControlledRefusal):
        await rig.registry.execute('mcp_browser_browser_snapshot', {}, None, prompter)
    assert len(rig.calls) == 2 and len(rig.operator.asks) == 3
    assert rig.policy.yolo is enabled and rig.policy.active == 0


@pytest.mark.asyncio
async def test_missing_scope_never_asks_or_starts_browser(rig):
    rig.policy.engagement.reset_to_origin('http://different.lab:8081')
    with pytest.raises(ExecutionBlocked, match='no longer in engagement scope'):
        await execute(rig, 'snapshot')
    assert not rig.calls and len(rig.sessions) == 1 and not rig.operator.asks


@pytest.mark.asyncio
async def test_extra_engagement_origin_does_not_expand_browser_target(rig):
    rig.policy.engagement.add_origin('http://different.lab:8081')
    with pytest.raises(ExecutionBlocked, match='outside operator lab binding'):
        await execute(rig, 'navigate', {'url': 'http://different.lab:8081'})
    assert not rig.calls and len(rig.sessions) == 1 and not rig.operator.asks


@pytest.mark.asyncio
async def test_timing_separates_lock_wait_and_never_contains_arguments(rig):
    await rig.binding.lock.acquire()
    pending = asyncio.create_task(execute(rig, 'snapshot', {'fixture': 'private-page-text'}))
    try:
        await asyncio.sleep(0.04)
        assert not rig.calls
    finally:
        rig.binding.lock.release()
    await pending
    timing = rig.binding.last_timing
    assert timing['lockAcquiredMs'] - timing['receiptValidatedMs'] >= 30
    assert timing['ownerDispatchMs'] >= timing['readyMs'] >= timing['lockAcquiredMs']
    assert timing['mcpResponseMs'] >= timing['ownerDispatchMs']
    assert timing['traceId'] == rig.calls[0][3]['meta']['kagentBrowser']['traceId']
    assert 'private-page-text' not in json.dumps(timing)


@pytest.mark.asyncio
@pytest.mark.parametrize('url', ['file:///tmp/data', 'javascript:alert(1)', 'http://juice.lab:8082',
                                'https://juice.lab:8081', 'http://other.lab:8081',
                                'http://user:pass@juice.lab:8081', 'http://juice.lab:8081\\@other.lab',
                                'http://juice.lab:8081/\npath'])
async def test_navigation_origin_and_url_fail_before_dispatch(rig, url):
    with pytest.raises((ExecutionBlocked, PermissionError)):
        await execute(rig, 'navigate', {'url': url})
    assert not rig.calls and len(rig.sessions) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('cause', ['revoke', 'reset', 'scope', 'cancel'])
async def test_queued_operations_never_dispatch_after_authority_loss(rig, cause):
    rig.block[0] = True
    first = asyncio.create_task(execute(rig, 'snapshot', {'fixture': 1}))
    await rig.started.wait()
    signal = asyncio.Event()
    second = asyncio.create_task(execute(rig, 'snapshot', {'fixture': 2}, signal))
    await asyncio.sleep(0.06)
    if cause == 'revoke':
        rig.policy.revoke('mcp_browser_browser_snapshot')
    elif cause == 'reset':
        rig.binding.invalidate()
    elif cause == 'scope':
        rig.policy.engagement.reset_to_origin('http://other.lab:8081')
    else:
        signal.set()
    rig.gate.set()
    await asyncio.gather(first, second, return_exceptions=True)
    assert len(rig.calls) == 1 and not rig.binding.lock.locked()
    if cause == 'revoke':
        with pytest.raises(ExecutionBlocked, match='revoked'):
            await execute(rig, 'snapshot')


@pytest.mark.asyncio
async def test_readiness_deadline_does_not_read_any_tab(rig, monkeypatch):
    rig.connected[0] = False
    monkeypatch.setattr(local, 'READINESS_TIMEOUT_S', 0.05)
    with pytest.raises(ExecutionBlocked, match='readiness deadline'):
        await execute(rig, 'navigate', {'url': ORIGIN})
    assert not rig.calls and all(session.closed for session in rig.sessions)


@pytest.mark.asyncio
async def test_reconnect_invalidates_refs_until_new_snapshot(rig):
    await execute(rig, 'snapshot')
    rig.generation[0] += 1
    with pytest.raises(ExecutionBlocked, match='fresh browser_snapshot'):
        await execute(rig, 'click', {'ref': 's1e1', 'element': 'search'})
    assert len(rig.calls) == 1
    await execute(rig, 'snapshot')
    await execute(rig, 'click', {'ref': 's1e1', 'element': 'search'})
    assert len(rig.calls) == 3


@pytest.mark.asyncio
async def test_mutating_loss_is_unknown_and_never_replayed(rig):
    await execute(rig, 'snapshot')
    rig.fail[0] = True
    with pytest.raises(RuntimeError, match='outcome unknown'):
        await execute(rig, 'click', {'ref': 's1e1', 'element': 'search'})
    assert len(rig.calls) == 2
    with pytest.raises(ExecutionBlocked, match='explicit reset'):
        await execute(rig, 'snapshot')
    assert len(rig.calls) == 2 and all(s.closed for s in rig.sessions)


@pytest.mark.asyncio
async def test_mutating_mcp_failure_preserves_bounded_redacted_cause_without_replay(rig):
    await execute(rig, 'snapshot')
    secret = 'fixture-password-not-for-output'
    rig.mcp_error[0] = 'Error: WebSocket response timeout after 30000ms; ' + json.dumps({'password': secret}) + ' ' + 'x' * 10000
    with pytest.raises(RuntimeError, match='outcome unknown') as failure:
        await execute(rig, 'click', {'ref': 's1e1', 'element': 'search'})
    diagnosis = str(failure.value)
    assert 'WebSocket response timeout after 30000ms' in diagnosis
    assert secret not in diagnosis and len(diagnosis) < 4300
    assert failure.value.__cause__ is not None and secret not in str(failure.value.__cause__)
    assert len(rig.calls) == 2 and all(session.closed for session in rig.sessions)
    with pytest.raises(ExecutionBlocked, match='explicit reset'):
        await execute(rig, 'snapshot')
    assert len(rig.calls) == 2


@pytest.mark.asyncio
async def test_cross_controller_binding_is_rejected(rig, tmp_path):
    other = ExecutionPolicy(rig.policy.engagement, tmp_path)
    other.browser_local = rig.binding
    operator = Operator(other)
    with pytest.raises(ExecutionBlocked, match='binding mismatch'):
        await rig.registry.execute('mcp_browser_browser_snapshot', {}, None, operator)
    assert not rig.calls


@pytest.mark.asyncio
async def test_epoch_change_and_exit_close_owned_process(rig):
    await execute(rig, 'snapshot')
    old = rig.binding.owner
    rig.policy.engagement.http_permissions.reset(preserve_denial=True)
    await execute(rig, 'snapshot', {'new': True})
    assert old.task.done() and len({id(row[0]) for row in rig.calls}) == 2
    await rig.binding.close()
    assert all(session.closed for session in rig.sessions)
    with pytest.raises(ExecutionBlocked, match='binding mismatch'):
        await execute(rig, 'snapshot')


@pytest.mark.asyncio
async def test_local_missing_modified_or_stale_deployment_blocks_before_spawn(tmp_path, monkeypatch):
    root = tmp_path / 'local'
    root.mkdir()
    (root / 'manifest.json').write_text('{}')
    monkeypatch.setattr(deployment, 'BROWSER_LOCAL_ROOT', root)
    monkeypatch.setattr(deployment, '_has_immutable_owner', lambda info: True)
    with pytest.raises(ExecutionBlocked, match='missing/stale/unsafe'):
        await local.local_launch_parameters(BROWSER_LOCAL_SERVER, discovery_only=True)


@pytest.mark.asyncio
async def test_loopback_port_conflict_fails_without_killing(monkeypatch):
    monkeypatch.setattr(local, 'linux_listeners', lambda: [('00000000', '42')])
    with pytest.raises(ExecutionBlocked, match='already owned; no kill/adoption'):
        await local.check_ports_free()


@pytest.mark.asyncio
async def test_minimal_env_and_fixed_limits_no_ambient_exports(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY', 'must-not-pass')
    monkeypatch.setenv('NODE_OPTIONS', '--require=/tmp/unsafe.js')
    monkeypatch.setenv('HOME', '/private/operator-home')
    monkeypatch.setattr(deployment, 'verify_browser_local_deployment', lambda: None)
    params = await local.local_launch_parameters(BROWSER_LOCAL_SERVER, discovery_only=True)
    assert params.env is not None
    assert params.command == '/usr/bin/prlimit'
    assert '--as=1610612736' in params.args and '--cpu=120' in params.args
    assert params.env['HOME'] == '/tmp' and params.env['KAGENT_BROWSER_DISCOVERY'] == '1'
    assert not {'OPENAI_API_KEY', 'NODE_OPTIONS', 'NPM_TOKEN', 'HTTP_PROXY'} & set(params.env)


@pytest.mark.asyncio
async def test_actual_patched_discovery_has_no_host_listener(tmp_path):
    if not deployment.BROWSER_LOCAL_ROOT.exists():
        pytest.skip('explicitly prepared Linux patched closure required')
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    binding = local.BrowserLocalBinding(policy, BROWSER_LOCAL_SERVER, lab_origin='')
    policy.browser_local = binding
    before = local.linux_listeners()
    try:
        result = await discover_mcp_tools(BROWSER_LOCAL_SERVER, execution_policy=policy, browser_local=binding)
        assert len(result['tools']) == 12 and binding.owner is None
        assert local.linux_listeners() == before
    finally:
        await binding.close()


@pytest.mark.asyncio
async def test_approval_before_reset_cannot_be_reused(rig):
    asking, approve = asyncio.Event(), asyncio.Event()
    async def ask(request, signal=None):
        asking.set()
        await approve.wait()
        return Decision.ALLOW_ONCE
    rig.operator.ask = ask
    invocation = asyncio.create_task(execute(rig, 'snapshot'))
    await asking.wait()
    rig.policy.engagement.http_permissions.reset()
    approve.set()
    with pytest.raises(ExecutionBlocked, match='stale/replayed'):
        await invocation
    assert not rig.calls and len(rig.sessions) == 1


@pytest.mark.asyncio
async def test_agent_reset_resume_and_target_hooks_invalidate_binding(rig, tmp_path):
    from src.agent.agent import Agent, AgentOptions
    from src.session.store import Store
    from src.skills.registry import Registry as SkillRegistry
    from src.target.target import Target
    from tests.helpers.agent_fakes import FakeClient
    target = Target()
    target.set_base_url(ORIGIN)
    store = Store.new_with_id(tmp_path, 'browser-hooks')
    agent = Agent(AgentOptions(client=FakeClient([]), tools=rig.registry, skills=SkillRegistry(),
                              prompter=rig.operator, store=store, target=target,
                              engagement_state=rig.policy.engagement))
    epoch = rig.binding.epoch
    await agent.reset()
    assert rig.binding.epoch > epoch
    epoch = rig.binding.epoch
    agent.resume_saved()
    assert rig.binding.epoch > epoch
    epoch = rig.binding.epoch
    agent.apply_target_base_url('http://other.lab:8081')
    assert rig.binding.epoch > epoch
    with pytest.raises(ExecutionBlocked, match='no longer in engagement'):
        await execute(rig, 'snapshot')


@pytest.fixture
def local_tree(tmp_path, monkeypatch):
    root = tmp_path / 'patched'
    root.mkdir()
    (root / 'bundle.js').write_text('patched fixture')
    (root / 'patch.json').write_text(deployment.BROWSER_LOCAL_PATCH)
    manifest = {'schema': 2, 'package': '@browsermcp/mcp', 'version': '0.1.3',
                'patch': deployment.BROWSER_LOCAL_PATCH,
                'entries': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in root.iterdir()}}
    raw = json.dumps(manifest).encode()
    (root / 'manifest.json').write_bytes(raw)
    monkeypatch.setattr(deployment, 'BROWSER_LOCAL_ROOT', root)
    monkeypatch.setattr(deployment, 'BROWSER_LOCAL_MANIFEST_SHA256', hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(deployment, '_has_immutable_owner', lambda info: True)
    return root


@pytest.mark.parametrize('change', ['missing', 'modified', 'extra', 'self-signed', 'wrong-patch'])
def test_patched_inventory_changes_fail_closed(local_tree, change):
    deployment.verify_browser_local_deployment()
    if change == 'missing':
        (local_tree / 'bundle.js').unlink()
    elif change == 'modified':
        (local_tree / 'bundle.js').write_text('modified')
    elif change == 'extra':
        (local_tree / 'extra.js').write_text('unreviewed')
    else:
        manifest = json.loads((local_tree / 'manifest.json').read_bytes())
        if change == 'self-signed':
            (local_tree / 'bundle.js').write_text('modified')
            manifest['entries']['bundle.js'] = hashlib.sha256(b'modified').hexdigest()
        else:
            manifest['patch'] = 'other-patch'
        (local_tree / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ExecutionBlocked, match='missing/stale/unsafe'):
        deployment.verify_browser_local_deployment()


def test_node_identity_change_is_not_trusted(local_tree, monkeypatch):
    monkeypatch.setattr(deployment, 'BROWSER_NODE_SHA256', '0' * 64)
    with pytest.raises(ExecutionBlocked, match='unverified Browser Node'):
        deployment.verify_browser_local_deployment()
