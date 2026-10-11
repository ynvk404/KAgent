"""C2: controlled clocks, captured owners, synthetic traffic and fake RPC."""
import asyncio
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from typing import Any, cast

from src.config.config import MCPServerConfig, PluginConfig

from src.engagement.state import EngagementState
from src.permission.network.grants import CaptureSource, HTTPBlocked, HTTPReviewTicket, HTTPLimits
from src.permission.permission import Decision, PermissionRequest, UserControlledRefusal, YoloPrompter
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy, ExecutionReview
from src.permission.runtime.invocations import review_turn
from src.target.origin import HTTPOrigin
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.execution.file import FileReadTool, FileWriteTool, FileWriteToolAlias, FileEditTool, FileEditToolAlias
from src.tools.execution.shell import ShellTool
from src.tools.execution.plugin import CommandPluginTool
from src.tools.mcp.integration import MCPTool, MCPSession
from src.tools.http.http_tool import HTTPTool
from src.tools.http.private_host import gate_private_request
from src.ui.bridges.perm_bridge import BridgedPrompter
from tests.security.test_browser_local import rig
from tests.security.test_browser_yolo import call

ORIGIN = 'http://127.0.0.1:3000'
ARGS = {'url': '/fixture', 'phase': 'recon'}


async def modal(shown, tool=None):
    async with asyncio.timeout(2):
        while not shown or shown[-1] is None or (tool is not None and shown[-1].tool != tool):
            await asyncio.sleep(0)
    return shown[-1]


def file_runtime(tmp_path, now, *, timeout=900):
    policy = ExecutionPolicy(EngagementState(), tmp_path, clock=lambda: now[0], review_timeout=timeout)
    shown = []
    bridge = BridgedPrompter(shown.append)
    prompter = YoloPrompter(bridge)
    prompter.bind_execution_policy(policy)
    registry = Registry()
    return registry, prompter, policy, bridge, shown


@pytest.mark.parametrize('delay', [59, 60, 61, 158])
@pytest.mark.parametrize('factory', [FileWriteTool, FileWriteToolAlias])
async def test_valid_queued_and_visible_review_has_no_early_dispatch_clock(tmp_path, delay, factory):
    now = [0.0]
    registry, prompter, policy, bridge, shown = file_runtime(tmp_path, now)
    tool = factory()
    registry.register(tool)
    path = tmp_path / 'approved.txt'
    first = asyncio.create_task(bridge.ask(PermissionRequest(tool='fixture', summary='queue owner', detail='fixture')))
    first_modal = await modal(shown)
    queued = asyncio.create_task(registry.execute(tool.name(), {'path': str(path), 'content': 'exact'}, None, prompter))
    await asyncio.sleep(0)
    ticket = next(iter(policy._receipts.values()))
    assert isinstance(ticket, ExecutionReview)
    now[0] += delay
    assert not path.exists() and shown[-1] is first_modal
    first_modal.resolve(Decision.ALLOW_ONCE)
    await first
    review = await modal(shown, tool.name())
    now[0] += delay
    assert review.is_current() and policy.review_is_current(ticket)
    review.resolve(Decision.ALLOW_ONCE)
    await queued
    assert path.read_text() == 'exact'
    assert policy.used == 1 and policy.active == 0
    assert not policy._receipts and not policy._pending and not policy._review_cleanups
    assert not bridge._busy and not bridge._waiters


@pytest.mark.parametrize('elapsed,allowed', [(59, True), (60, False), (61, False)])
def test_review_and_dispatch_expiration_are_distinct(tmp_path, elapsed, allowed):
    now = [0.0]
    policy = ExecutionPolicy(EngagementState(), tmp_path, clock=lambda: now[0])
    path = tmp_path / 'fixture.txt'
    path.write_text('unchanged')
    tool, args = FileReadTool(), {'path': str(path)}
    with review_turn():
        review = policy.prepare(tool, args, reviewing=True)
        now[0] = 61
        assert policy.review_is_current(review)
        with pytest.raises(ExecutionBlocked, match='review-ticket-is-not'):
            policy.start(review, tool, args, None)
        receipt = policy.dispatch_receipt(review, tool, args, None)
        assert receipt.expires == 121 and not policy.review_is_current(review)
        now[0] += elapsed
        if allowed:
            token = policy.start(receipt, tool, args, None)
            policy.stop(token)
            with pytest.raises(ExecutionBlocked, match='stale/replayed'):
                policy.start(receipt, tool, args, None)
        else:
            with pytest.raises(ExecutionBlocked, match='stale/replayed'):
                policy.start(receipt, tool, args, None)
        policy.finish_review(review)
    assert not policy._receipts and not policy._pending


def test_old_cleanup_cannot_retire_fresh_same_shape_ticket(tmp_path):
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    path = tmp_path / 'fixture.txt'
    path.write_text('unchanged')
    tool, args = FileReadTool(), {'path': str(path)}
    with review_turn():
        old = policy.prepare(tool, args, reviewing=True)
        token = policy.start(policy.dispatch_receipt(old, tool, args, None), tool, args, None)
        policy.stop(token)
        fresh = policy.prepare(tool, args, reviewing=True)
        policy.finish_review(old)
        assert fresh.digest in policy._pending and policy.review_is_current(fresh)
    assert not policy._receipts and not policy._pending and not policy._review_cleanups


@pytest.mark.parametrize('queued', [False, True])
async def test_expired_review_is_retired_without_touching_other_modal(tmp_path, queued):
    now = [0.0]
    registry, prompter, policy, bridge, shown = file_runtime(tmp_path, now, timeout=5)
    tool = FileWriteTool()
    registry.register(tool)
    first = None
    if queued:
        first = asyncio.create_task(bridge.ask(PermissionRequest(tool='fixture', summary='still current', detail='fixture')))
        first_modal = await modal(shown)
    path = tmp_path / 'must-not-write.txt'
    pending = asyncio.create_task(registry.execute(tool.name(), {'path': str(path), 'content': 'x'}, None, prompter))
    await asyncio.sleep(0)
    stale = None if queued else await modal(shown, tool.name())
    now[0] = 5
    with pytest.raises(UserControlledRefusal, match='stale'):
        await asyncio.wait_for(pending, 1)
    assert not path.exists() and not policy._receipts and not policy._pending
    if queued:
        assert first is not None
        assert shown[-1] is first_modal and first_modal.is_current()
        first_modal.resolve(Decision.ALLOW_ONCE)
        await first
    else:
        assert stale is not None
        assert shown[-1] is None and not stale.is_current()
    fresh = asyncio.create_task(registry.execute(tool.name(), {'path': str(path), 'content': 'fresh'}, None, prompter))
    current = await modal(shown, tool.name())
    if stale is not None:
        stale.resolve(Decision.ALLOW_SESSION)
        stale.reject(RuntimeError('late'))
        assert shown[-1] is current and current.is_current()
    current.resolve(Decision.ALLOW_ONCE)
    await fresh
    assert path.read_text() == 'fresh' and not bridge._session_allowed


async def test_closed_parent_orphan_cannot_commit_file_cache(tmp_path, monkeypatch):
    monkeypatch.setenv('KAGENT_PROJECT_ROOT', str(tmp_path))
    registry, prompter, policy, bridge, shown = file_runtime(tmp_path, [0.0])
    registry.register(FileWriteTool())
    path = tmp_path / 'artifacts' / 'proof.txt'
    args = {'path': str(path), 'content': 'exact'}
    with review_turn() as owner:
        child = asyncio.create_task(registry.execute('file_write', args, None, prompter))
        stale = await modal(shown)
        assert stale.supports_session and not owner.closed
    assert owner.closed and child.cancelling() == 0 and not stale.is_current()
    # Resolve outside the owning ContextVar, as the real UI does.
    stale.resolve(Decision.ALLOW_SESSION)
    with pytest.raises(UserControlledRefusal):
        await child
    assert not path.exists() and not bridge._session_allowed
    assert not policy._receipts and not policy._pending
    fresh = asyncio.create_task(registry.execute('file_write', args, None, prompter))
    current = await modal(shown)
    stale.reject(RuntimeError('late reject'))
    assert shown[-1] is current
    current.resolve(Decision.ALLOW_ONCE)
    await fresh
    assert path.read_text() == 'exact' and not bridge._session_allowed


@pytest.mark.parametrize('factory', [FileWriteTool, FileWriteToolAlias, FileEditTool, FileEditToolAlias])
async def test_nested_sensitive_review_rejects_replaced_file(factory, tmp_path):
    path = tmp_path / '.env'
    path.write_bytes(b'ORIGINAL\r\n')
    tool = factory()
    args = {'path': str(path), 'content': 'OVERWRITE', 'old_string': 'ORIGINAL', 'new_string': 'OVERWRITE'}
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    reviews = []
    class Operator:
        async def ask(self, request, signal=None):
            reviews.append(request)
            if request.tool == 'file':
                replacement = tmp_path / 'replacement.txt'
                replacement.write_bytes(b'REPLACEMENT MUST SURVIVE\r\n')
                replacement.replace(path)
            return Decision.ALLOW_ONCE
    prompter = YoloPrompter(Operator())
    prompter.bind_execution_policy(policy)
    registry = Registry()
    registry.register(tool)
    with pytest.raises(UserControlledRefusal, match='stale|changed'):
        await registry.execute(tool.name(), args, None, prompter)
    assert len(reviews) == 2 and path.read_bytes() == b'REPLACEMENT MUST SURVIVE\r\n'
    assert policy.active == 0 and not policy._receipts and not policy._pending


async def test_delayed_nested_review_keeps_unchanged_sensitive_file_valid(tmp_path):
    now = [0.0]
    policy = ExecutionPolicy(EngagementState(), tmp_path, clock=lambda: now[0])
    path = tmp_path / '.env'
    path.write_text('original')
    class Operator:
        async def ask(self, request, signal=None):
            now[0] += 61
            assert request.is_current()
            return Decision.ALLOW_ONCE
    prompter = YoloPrompter(Operator())
    prompter.bind_execution_policy(policy)
    registry = Registry()
    registry.register(FileWriteTool())
    await registry.execute('file_write', {'path': str(path), 'content': 'reviewed'}, None, prompter)
    assert now[0] == 122 and path.read_text() == 'reviewed'


@pytest.fixture
def native(tmp_path, monkeypatch):
    now = [0.0]
    state = EngagementState()
    state.initialize_target(ORIGIN)
    target = Target(ORIGIN)
    tool = HTTPTool(target, state)
    tool.permissions.clock = lambda: now[0]
    policy = ExecutionPolicy(state, tmp_path, clock=lambda: now[0])
    shown, sent = [], []
    bridge = BridgedPrompter(shown.append)
    prompter = YoloPrompter(bridge)
    prompter.bind_execution_policy(policy)
    registry = Registry()
    registry.register(tool)
    real_client = httpx.AsyncClient
    def handler(request):
        sent.append(request)
        return httpx.Response(200, content=b'synthetic response', request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr('src.tools.http.http_tool.gate_private_request', AsyncMock(return_value=''))
    return SimpleNamespace(now=now, tool=tool, policy=policy, bridge=bridge, prompter=prompter,
                           registry=registry, shown=shown, sent=sent, target=target)


@pytest.mark.parametrize('decision', [Decision.ALLOW_SESSION, Decision.GRANT_LAB])
async def test_closed_parent_orphan_cannot_create_http_grant(native, decision):
    with review_turn() as owner:
        child = asyncio.create_task(native.registry.execute('http', ARGS, None, native.prompter))
        stale = await modal(native.shown, 'http')
        if decision == Decision.GRANT_LAB:
            stale.resolve(decision)
            stale = await modal(native.shown, 'http_lab_grant')
    assert owner.closed and child.cancelling() == 0
    stale.resolve(Decision.ALLOW_ONCE if decision == Decision.GRANT_LAB else decision)
    with pytest.raises(UserControlledRefusal):
        await child
    rights = native.tool.permissions
    assert not native.sent and not rights.grants and not rights._receipts and not rights._pending
    assert not native.bridge._session_allowed and not rights._suppressed
    fresh = asyncio.create_task(native.registry.execute('http', ARGS, None, native.prompter))
    current = await modal(native.shown, 'http')
    stale.resolve(Decision.ALLOW_SESSION)
    assert native.shown[-1] is current
    current.resolve(Decision.ALLOW_ONCE)
    await fresh
    assert len(native.sent) == 1 and not rights.grants


@pytest.mark.parametrize('decision', [Decision.ALLOW_SESSION, Decision.GRANT_LAB])
async def test_closed_parent_orphan_cannot_create_browser_grant(rig, decision):
    shown = []
    bridge = BridgedPrompter(shown.append)
    prompter = YoloPrompter(bridge, True)
    prompter.bind_execution_policy(rig.policy)
    with review_turn() as owner:
        child = asyncio.create_task(call(rig, prompter))
        stale = await modal(shown)
        if decision == Decision.GRANT_LAB:
            stale.resolve(decision)
            stale = await modal(shown, 'browser_lab_grant')
    assert owner.closed and child.cancelling() == 0
    stale.resolve(Decision.ALLOW_ONCE if decision == Decision.GRANT_LAB else decision)
    with pytest.raises(UserControlledRefusal):
        await child
    assert rig.binding.grant is None and not rig.calls and not bridge._session_allowed
    assert not rig.policy._receipts and not rig.policy._pending and rig.policy.active == 0


@pytest.mark.parametrize('delay', [59, 60, 61, 158])
async def test_native_http_dispatch_clock_starts_after_private_review(native, monkeypatch, delay):
    async def private(*_args, **kwargs):
        ticket = next(iter(native.tool.permissions._receipts.values()))
        assert isinstance(ticket, HTTPReviewTicket)
        native.now[0] += delay
        assert kwargs['is_current']()
        return ''
    monkeypatch.setattr('src.tools.http.http_tool.gate_private_request', private)
    pending = asyncio.create_task(native.registry.execute('http', ARGS, None, native.prompter))
    review = await modal(native.shown, 'http')
    native.now[0] += delay
    review.resolve(Decision.ALLOW_ONCE)
    await pending
    assert len(native.sent) == 1 and not native.tool.permissions._receipts
    assert not native.tool.permissions._review_cleanups and native.policy.active == 0


@pytest.mark.parametrize('change', ['target', 'scope', 'policy', 'grant', 'signal', 'owner'])
async def test_private_review_change_still_prevents_send(native, monkeypatch, change):
    signal = asyncio.Event()
    with review_turn() as owner:
        async def private(*_args, **_kwargs):
            native.now[0] += 61
            if change == 'target': native.target.set_base_url('http://other.test:3000')
            elif change == 'scope': native.tool.engagement.revision += 1
            elif change == 'policy': native.policy.revoke('http')
            elif change == 'grant': native.tool.permissions.activate(ORIGIN, HTTPLimits.session())
            elif change == 'signal': signal.set()
            else: owner.closed = True
            return ''
        monkeypatch.setattr('src.tools.http.http_tool.gate_private_request', private)
        pending = asyncio.create_task(native.registry.execute('http', ARGS, signal, native.prompter))
        review = await modal(native.shown, 'http')
        review.resolve(Decision.ALLOW_ONCE)
        with pytest.raises((UserControlledRefusal, asyncio.CancelledError)):
            await pending
    assert not native.sent and not native.tool.permissions._receipts and native.policy.active == 0


async def test_independent_private_modal_cannot_cache_after_parent_closes(native, monkeypatch):
    monkeypatch.setattr('src.tools.http.http_tool.gate_private_request', gate_private_request)
    with review_turn():
        child = asyncio.create_task(native.registry.execute('http', ARGS, None, native.prompter))
        exact = await modal(native.shown, 'http')
        exact.resolve(Decision.ALLOW_ONCE)
        private = await modal(native.shown, 'http')
        assert private is not exact and private.cache_key.startswith('private-declared://')
    private.resolve(Decision.ALLOW_SESSION)
    with pytest.raises(UserControlledRefusal):
        await child
    assert not native.sent and not native.bridge._session_allowed and not native.tool.permissions._receipts


async def test_capture_credentials_cannot_commit_after_parent_closes(native):
    rights = native.tool.permissions
    grant = rights.activate(ORIGIN, HTTPLimits.session())
    action, _ = native.tool.prepare(ARGS)
    source = CaptureSource('synthetic-ref', 'burp', 'synthetic-row', HTTPOrigin.from_url(ORIGIN),
                           None, None, 'synthetic-credential-digest')
    action = replace(action, capture_source=source)
    with review_turn():
        child = asyncio.create_task(rights.authorize(action, native.prompter, None, lambda: native.target.revision))
        review = await modal(native.shown, 'http_capture_credentials')
    review.resolve(Decision.ALLOW_ONCE)
    with pytest.raises(UserControlledRefusal):
        await child
    assert rights.grants[action.origin] == grant
    assert not rights._capture_grants and not rights._capture_pending and not rights._receipts


async def test_closed_owner_cannot_dispatch_shell_without_policy(tmp_path, monkeypatch):
    opened, reply = asyncio.Event(), asyncio.Future()
    class Operator:
        async def ask(self, request, signal=None):
            opened.set()
            return await reply
    run_capture = AsyncMock(return_value='must not run')
    monkeypatch.setattr('src.tools.execution.shell.run_with_capture', run_capture)
    registry = Registry()
    registry.register(ShellTool())
    with review_turn():
        child = asyncio.create_task(registry.execute('shell', {'command': 'printf fixture'}, None, Operator()))
        await opened.wait()
    reply.set_result(Decision.ALLOW_ONCE)
    with pytest.raises(UserControlledRefusal, match='stale'):
        await child
    run_capture.assert_not_called()


@pytest.mark.parametrize('kind', ['shell', 'plugin', 'mcp'])
@pytest.mark.parametrize('invalidate', [False, True])
async def test_process_and_mcp_recheck_after_initialization_await(tmp_path, monkeypatch, kind, invalidate):
    now = [0.0]
    policy = ExecutionPolicy(EngagementState(), tmp_path, clock=lambda: now[0])
    dispatched = AsyncMock(return_value='offline output')
    rpc = AsyncMock(return_value={'isError': False, 'content': [{'type': 'text', 'text': 'offline'}]})
    session = SimpleNamespace(server_name='fixture', call_tool=rpc, close=AsyncMock())
    tool = (ShellTool() if kind == 'shell' else CommandPluginTool(PluginConfig('fixture_plugin', 'fixture'))
            if kind == 'plugin' else MCPTool(cast(Any, session), 'fixture_mcp', 'operation', 'fixture', {}))
    args = {'command': 'printf fixture'} if kind == 'shell' else {'fixture': 'unchanged'}

    def change():
        now[0] += 61
        if invalidate:
            policy.revoke(tool.name())

    class Worker:
        def summary(self): return 'offline fake worker'
        async def prepare(self, command, argv, **kwargs):
            change()
            return command, argv
    policy.worker = Worker()
    if kind == 'mcp':
        tool = cast(MCPTool, tool)
        tool._server = MCPServerConfig('fixture', 'fixture')
        tool._execution_policy = policy
        async def open_session(*args, **kwargs):
            change()
            return session
        monkeypatch.setattr(MCPSession, 'open', open_session)
    monkeypatch.setattr('src.tools.execution.shell.run_with_capture', dispatched)
    monkeypatch.setattr('src.tools.execution.plugin.run_plugin', dispatched)
    class Operator:
        async def ask(self, request, signal=None):
            now[0] += 61
            assert request.is_current()
            return Decision.ALLOW_ONCE
    prompter = YoloPrompter(Operator())
    prompter.bind_execution_policy(policy)
    registry = Registry()
    registry.register(tool)
    if invalidate:
        with pytest.raises(ExecutionBlocked):
            await registry.execute(tool.name(), args, None, prompter)
        dispatched.assert_not_called()
        rpc.assert_not_called()
    else:
        await registry.execute(tool.name(), args, None, prompter)
        assert rpc.await_count == 1 if kind == 'mcp' else dispatched.await_count == 1
    assert policy.active == 0 and not policy._receipts and not policy._active_receipts


def test_review_cleanup_failure_still_drains_other_owners_and_resets_context():
    from src.permission.runtime.invocations import capture_review, review_id
    retired = []
    with pytest.raises(RuntimeError, match='fixture'):
        with review_turn():
            guard = capture_review()
            def fail(): raise RuntimeError('fixture cleanup failure')
            guard.on_close(fail)
            guard.on_close(lambda: retired.append('other cleanup'))
    assert retired == ['other cleanup'] and not guard.is_current()
    assert review_id() == 'library'
