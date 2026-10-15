"""Offline session authority and resource regressions through production gates."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from src.engagement.state import EngagementState
from src.permission.network.grants import HTTPBlocked, HTTPLimits
from src.permission.permission import Decision, YoloPrompter
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy
from src.tools.execution.file import FileReadTool
from tests.security.test_http_grants import runtime, Operator, ORIGIN, args
from tests.security.test_browser_local import rig
from tests.security.test_browser_yolo import call, yolo


@pytest.mark.asyncio
async def test_manual_session_beyond_old_request_and_time_caps_preserves_requests(runtime):
    tool, registry, sent, _ = runtime
    now = [100.0]
    tool.permissions.clock = lambda: now[0]
    operator = Operator(Decision.ALLOW_SESSION)
    request = args('/selected', method='POST', body='fixture repeated payload', headers={'X-Fixture': 'same'})
    for _ in range(510):
        now[0] += 5
        await registry.execute('http', request, None, operator)
    grant = next(iter(tool.permissions.grants.values()))
    assert grant.limits.requests is grant.limits.seconds is grant.expires_at is None
    assert len(operator.requests) == 1 and len(sent) == 510
    assert all(row.method == 'POST' and row.content == b'fixture repeated payload'
               and row.headers['X-Fixture'] == 'same' for row in sent)
    assert 'no request quota' in tool.permissions.status()
    assert tool.permissions._budgets[grant.id].used == 510
    assert not tool.permissions._inflight and not tool.permissions._receipts


@pytest.mark.asyncio
async def test_manual_session_keeps_receipt_expiry_replay_and_revoke(runtime):
    tool, _, _, _ = runtime
    rights = tool.permissions
    now = [10.0]
    rights.clock = lambda: now[0]
    action, _ = tool.prepare(args())
    receipt = await rights.authorize(action, Operator(Decision.ALLOW_SESSION), None, lambda: tool.target.revision)
    now[0] += 61
    with pytest.raises(HTTPBlocked, match='expired'):
        rights.reserve(action, receipt, None, tool.target.revision)
    fresh = await rights.authorize(action, Operator(), None, lambda: tool.target.revision)
    reservation = rights.reserve(action, fresh, None, tool.target.revision)
    reservation.release()
    with pytest.raises(HTTPBlocked, match='replayed'):
        rights.reserve(action, fresh, None, tool.target.revision)
    grant = next(iter(rights.grants.values()))
    rights.revoke(grant.id)
    with pytest.raises(HTTPBlocked, match='revoked'):
        await rights.authorize(action, Operator(Decision.ALLOW_SESSION), None, lambda: tool.target.revision)


@pytest.mark.asyncio
async def test_concurrent_session_approval_resumes_queued_invocation_and_cancels_waiter(runtime):
    tool, registry, sent, _ = runtime
    opened, release = asyncio.Event(), asyncio.Event()
    class Waiting(Operator):
        async def ask(self, request, signal=None):
            self.requests.append(request)
            opened.set()
            await release.wait()
            return Decision.ALLOW_SESSION
    operator = Waiting()
    first = asyncio.create_task(registry.execute('http', args('/first'), None, operator))
    await opened.wait()
    second = asyncio.create_task(registry.execute('http', args('/second'), None, operator))
    cancelled = asyncio.create_task(registry.execute('http', args('/cancelled'), None, operator))
    await asyncio.sleep(0)
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    release.set()
    await asyncio.wait_for(asyncio.gather(first, second), 2)
    assert len(operator.requests) == 1
    assert [row.url.path for row in sent] == ['/first', '/second']
    assert not tool.permissions._pending and not tool.permissions._inflight


def test_optional_limits_journal_requires_current_yolo_activation(tmp_path):
    state = EngagementState()
    state.initialize_target(ORIGIN)
    policy = ExecutionPolicy(state, tmp_path)
    journal = tmp_path / 'policy.json'
    policy.load_journal(journal)
    state.http_permissions.activate(ORIGIN, HTTPLimits.session())
    policy.used = 10005
    policy.persist()
    row = json.loads(journal.read_text())
    assert row['max_calls'] is None and row['http_constraints'][0]['deadline'] is None
    restored_state = EngagementState()
    restored_state.initialize_target(ORIGIN)
    restored = ExecutionPolicy(restored_state, tmp_path)
    restored.load_journal(journal)
    assert restored.used == 10005 and restored.max_calls is None
    assert not restored_state.http_permissions.grants
    restored_state.http_permissions.set_yolo(True)
    implicit = next(iter(restored_state.http_permissions.grants.values()))
    assert implicit.limits == HTTPLimits.session() and implicit.expires_at is None


@pytest.mark.parametrize('limit', [None, 10001])
def test_shared_default_ceiling_removed_but_explicit_limit_concurrency_and_freshness_remain(tmp_path, limit):
    now = [10.0]
    policy = ExecutionPolicy(EngagementState(), tmp_path, max_calls=limit, concurrency=1, clock=lambda: now[0])
    paths = [tmp_path / name for name in ('a', 'b')]
    for path in paths:
        path.write_text('fixture')
    tool = FileReadTool()
    policy.used = 10000
    first = policy.prepare(tool, {'path': str(paths[0])})
    second = policy.prepare(tool, {'path': str(paths[1])})
    token = policy.start(first, tool, {'path': str(paths[0])}, None)
    with pytest.raises(ExecutionBlocked, match='budget/concurrency'):
        policy.start(second, tool, {'path': str(paths[1])}, None)
    policy.stop(token)
    if limit is not None:
        with pytest.raises(ExecutionBlocked, match='budget'):
            policy.start(second, tool, {'path': str(paths[1])}, None)
    else:
        token = policy.start(second, tool, {'path': str(paths[1])}, None)
        policy.stop(token)
        assert policy.used == 10002 and policy.active == 0
        fresh = policy.prepare(tool, {'path': str(paths[0])})
        now[0] += 61
        with pytest.raises(ExecutionBlocked, match='stale/replayed'):
            policy.start(fresh, tool, {'path': str(paths[0])}, None)
    policy.load_journal(tmp_path / 'policy.json')
    policy.persist()
    restored = ExecutionPolicy(EngagementState(), tmp_path)
    restored.load_journal(tmp_path / 'policy.json')
    assert restored.max_calls == limit and restored.concurrency == 1


@pytest.mark.asyncio
async def test_browser_reviewed_session_beyond_old_caps_and_still_read_only(rig):
    prompter = yolo(rig)
    now = [10.0]
    rig.policy.clock = lambda: now[0]
    rig.operator.decision = Decision.ALLOW_SESSION
    for _ in range(25):
        await call(rig, prompter)
        now[0] += 20
    assert len(rig.operator.asks) == 1 and len(rig.calls) == 25
    assert rig.binding.grant.remaining is rig.binding.grant.expires is None
    rig.operator.decision = Decision.DENY
    with pytest.raises(PermissionError):
        await call(rig, prompter, 'click', {'ref': 's1e1', 'element': 'fixture'})
    assert len(rig.calls) == 25
    rig.binding.revoke_grant()
    with pytest.raises(PermissionError):
        await call(rig, prompter)


@pytest.mark.asyncio
async def test_manual_session_retains_reviewed_resource_controls_and_independent_origins(runtime):
    from src.ui.bridges.perm_bridge import BridgedPrompter
    tool, _, _, _ = runtime
    rights = tool.permissions
    action, _ = tool.prepare(args('/first'))
    # Retained operator resource restrictions are not cumulative authority.
    limits = HTTPLimits(seconds=None, requests=None, rate=0.5, burst=1, concurrency=1,
                        request_bytes=1024, response_bytes=65536)
    rights.restore_constraints([{'origin':ORIGIN,'limits':{'seconds':None,'requests':None,'rate':0.5,'burst':1,
                                'concurrency':1,'request_bytes':1024,'response_bytes':65536},'used':0,'deadline':None}])
    receipts = []
    requests = []
    def publish(request):
        if request is not None:
            requests.append(request)
            request.resolve(Decision.ALLOW_SESSION)
    bridge = BridgedPrompter(publish)
    receipts.append(await rights.authorize(action, bridge, None, lambda:tool.target.revision))
    assert rights.grants[action.origin].limits == limits
    other = 'https://juice.lab:3000'
    tool.engagement.add_origin(other)
    first_current, _ = tool.prepare(args('/first'))
    first_receipt = await rights.authorize(first_current, bridge, None, lambda:tool.target.revision)
    second_action, _ = tool.prepare(args(other+'/second'))
    await rights.authorize(second_action, bridge, None, lambda:tool.target.revision)
    # Another origin's grant must not stale this already-issued receipt.
    now = [rights.clock() + 3]
    rights.clock = lambda:now[0]
    reservation = rights.reserve(first_current, first_receipt, None, tool.target.revision)
    reservation.release()
    assert len(requests) == 2 and len(rights.grants) == 2 and not bridge._session_allowed
