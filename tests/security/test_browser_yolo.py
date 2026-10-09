"""Browser-only bounded operator grants, using the production Registry/receipts."""
from __future__ import annotations

import asyncio

import pytest

from src.permission.permission import Decision, UserControlledRefusal, YoloPrompter
from src.permission.runtime.execution import ExecutionBlocked
from src.tools.mcp.integration import MCPTool
from src.tools.mcp.session_servers import BROWSER_MCP_SERVER
from tests.security.test_browser_local import rig, ORIGIN


def yolo(rig, enabled=True):
    prompter = YoloPrompter(rig.operator, enabled)
    prompter.bind_execution_policy(rig.policy)
    return prompter


async def call(rig, prompter, name='snapshot', args=None):
    return await rig.registry.execute('mcp_browser_browser_' + name, args or {}, None, prompter)


@pytest.mark.asyncio
async def test_valid_grant_autoapproves_fresh_receipts_and_keeps_same_owner(rig):
    prompter = yolo(rig)
    grant = rig.binding.activate_grant('interaction')
    for name, args in [('navigate', {'url': ORIGIN}), ('snapshot', {}),
                       ('click', {'ref': 's1e1', 'element': 'search'}),
                       ('type', {'ref': 's1e1', 'element': 'search', 'text': 'fixture', 'submit': False})]:
        await call(rig, prompter, name, args)
    assert len(rig.calls) == rig.policy.used == 4 and rig.policy.active == 0
    assert not rig.operator.asks and grant.remaining == 16
    assert len({id(row[0]) for row in rig.calls}) == 1
    assert not rig.policy._receipts and not rig.policy._pending


@pytest.mark.asyncio
@pytest.mark.parametrize('condition', ['off', 'missing', 'read-only', 'unknown-action'])
async def test_grant_absence_or_uncovered_action_never_silently_approves(rig, condition):
    prompter = yolo(rig)
    if condition != 'missing':
        rig.binding.activate_grant('read' if condition == 'read-only' else 'interaction')
    if condition == 'off':
        prompter.set_yolo(False)
    rig.operator.decision = Decision.DENY
    name = 'hover' if condition == 'unknown-action' else 'click' if condition == 'read-only' else 'snapshot'
    args = {'ref': 's1e1', 'element': 'search'} if name != 'snapshot' else {}
    with pytest.raises(UserControlledRefusal):
        await call(rig, prompter, name, args)
    assert len(rig.operator.asks) == 1 and not rig.calls and rig.policy.active == 0


@pytest.mark.asyncio
async def test_expiry_and_quota_need_explicit_review_never_refill(rig):
    now = [100.0]
    rig.policy.clock = lambda: now[0]
    prompter = yolo(rig)
    grant = rig.binding.activate_grant('read', seconds=1, calls=1)
    await call(rig, prompter)
    assert grant.remaining == 0 and not rig.operator.asks
    rig.operator.decision = Decision.DENY
    with pytest.raises(UserControlledRefusal):
        await call(rig, prompter)
    assert rig.binding.grant is grant and grant.remaining == 0
    rig.binding.activate_grant('read', seconds=1)
    now[0] += 2
    with pytest.raises(UserControlledRefusal):
        await call(rig, prompter)
    assert len(rig.calls) == 1 and len(rig.operator.asks) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('cause', ['revoke', 'expire', 'quota', 'reset', 'scope', 'session', 'revision', 'yolo-off'])
async def test_queued_autoapproval_rechecks_grant_and_receipt_before_rpc(rig, cause):
    now = [100.0]
    rig.policy.clock = lambda: now[0]
    prompter = yolo(rig)
    grant = rig.binding.activate_grant('read', seconds=1)
    await rig.binding.lock.acquire()
    pending = asyncio.create_task(call(rig, prompter))
    try:
        async with asyncio.timeout(2):
            while rig.policy.active == 0:
                await asyncio.sleep(0.001)
        if cause == 'revoke':
            rig.binding.revoke_grant()
        elif cause == 'expire':
            now[0] += 2
        elif cause == 'quota':
            grant.remaining = 0
        elif cause == 'reset':
            rig.binding.invalidate()
        elif cause == 'scope':
            rig.policy.engagement.clear()
        elif cause == 'session':
            rig.policy.session_id = 'different-controller-session'
        elif cause == 'revision':
            rig.policy.revoke('mcp_browser_browser_snapshot')
        else:
            prompter.set_yolo(False)
        with pytest.raises(ExecutionBlocked):
            await asyncio.wait_for(pending, 2)
    finally:
        rig.binding.lock.release()
        if not pending.done():
            pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
    assert not rig.calls and not rig.operator.asks and rig.policy.active == 0


@pytest.mark.asyncio
async def test_pending_owner_rpc_cannot_spend_revoked_autoapproval(rig):
    prompter = yolo(rig)
    rig.binding.activate_grant('read')
    await call(rig, prompter)
    owner = rig.binding.owner
    original = owner.request
    waiting, release = asyncio.Event(), asyncio.Event()

    async def request(method, *args, **kwargs):
        if method == 'call_tool':
            waiting.set()
            await release.wait()
        return await original(method, *args, **kwargs)

    owner.request = request
    pending = asyncio.create_task(call(rig, prompter))
    await waiting.wait()
    rig.binding.revoke_grant()
    release.set()
    with pytest.raises(ExecutionBlocked):
        await pending
    assert len(rig.calls) == 1 and rig.policy.active == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('changed', ['scope', 'revoke', 'reset'])
async def test_separate_grant_confirmation_cannot_cross_context_change(rig, changed):
    prompter = yolo(rig)
    asking, approve = asyncio.Event(), asyncio.Event()

    async def ask(request, signal=None):
        if request.tool != 'browser_lab_grant':
            return Decision.GRANT_LAB
        asking.set()
        await approve.wait()
        return Decision.ALLOW_ONCE

    rig.operator.ask = ask
    pending = asyncio.create_task(call(rig, prompter))
    await asking.wait()
    if changed == 'scope':
        rig.policy.engagement.clear()
    elif changed == 'revoke':
        rig.binding.revoke_grant()
    else:
        rig.binding.invalidate()
    approve.set()
    with pytest.raises(ExecutionBlocked):
        await pending
    assert not rig.calls and rig.binding.grant is None


@pytest.mark.asyncio
async def test_operator_grant_flow_is_separate_from_session_trust_and_model_args(rig):
    prompter = yolo(rig)
    seen = []

    async def ask(request, signal=None):
        seen.append(request)
        return Decision.ALLOW_ONCE if request.tool == 'browser_lab_grant' else Decision.GRANT_LAB

    rig.operator.ask = ask
    await call(rig, prompter, args={'grant': 'interaction', 'calls': 100000, 'forceOperator': False})
    grant = rig.binding.grant
    assert grant.group == 'read' and grant.remaining == 19
    assert len(seen) == 2 and seen[0].offer_browser_grant == 'read'
    assert all(request.force_operator and request.no_session_cache for request in seen)
    assert 'browser_click' not in seen[1].detail and ORIGIN in seen[1].detail
    await call(rig, prompter)
    assert len(seen) == 2 and grant.remaining == 18


@pytest.mark.asyncio
async def test_interaction_grant_confirms_unknown_application_effects(rig):
    prompter = yolo(rig)
    await call(rig, prompter)  # Fresh ref, ordinary one-shot permission.
    seen = []

    async def ask(request, signal=None):
        seen.append(request)
        return Decision.ALLOW_ONCE if request.tool == 'browser_lab_grant' else Decision.GRANT_LAB

    rig.operator.ask = ask
    await call(rig, prompter, 'click', {'ref': 's1e1', 'element': 'search'})
    assert len(seen) == 2 and 'change application state' in seen[1].detail
    assert 'submit forms' in seen[1].detail and rig.binding.grant.group == 'interaction'
    assert rig.binding.grant.remaining == 19


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['outside-origin', 'missing-connection', 'unknown-outcome'])
async def test_grant_never_overrides_browser_security_or_replays(rig, monkeypatch, failure):
    prompter = yolo(rig)
    rig.binding.activate_grant('interaction')
    if failure == 'outside-origin':
        with pytest.raises(PermissionError):
            await call(rig, prompter, 'navigate', {'url': 'http://outside.lab:8081'})
        assert not rig.calls
    elif failure == 'missing-connection':
        from src.tools.mcp import browser_local as local
        rig.connected[0] = False
        monkeypatch.setattr(local, 'READINESS_TIMEOUT_S', 0.02)
        with pytest.raises(ExecutionBlocked):
            await call(rig, prompter)
        assert not rig.calls
    else:
        await call(rig, prompter)
        rig.fail[0] = True
        with pytest.raises(RuntimeError, match='outcome unknown'):
            await call(rig, prompter, 'click', {'ref': 's1e1', 'element': 'search'})
        assert len(rig.calls) == 2 and rig.binding.grant is None
        with pytest.raises(ExecutionBlocked, match='explicit reset'):
            await call(rig, prompter)
        assert len(rig.calls) == 2


def test_general_mcp_never_selects_browser_grant_hints():
    tool = MCPTool(None, 'mcp_browser_browser_snapshot', 'browser_snapshot', '', {})  # type: ignore[arg-type]
    tool._server = BROWSER_MCP_SERVER
    assert tool.permission_hints({}) == {'noSessionCache': True, 'riskTier': 'high-impact'}


@pytest.mark.asyncio
async def test_reconnect_with_grant_still_rejects_stale_refs(rig):
    prompter = yolo(rig)
    rig.binding.activate_grant('interaction')
    await call(rig, prompter)
    rig.generation[0] += 1
    with pytest.raises(ExecutionBlocked, match='fresh browser_snapshot'):
        await call(rig, prompter, 'click', {'ref': 's1e1', 'element': 'search'})
    assert len(rig.calls) == 1 and rig.binding.grant is None


@pytest.mark.asyncio
async def test_real_permission_modal_grants_then_status_and_operator_revoke(rig):
    from src.ui.bridges.perm_bridge import BridgedPrompter
    from src.ui.widgets.permission_modal import PermissionModal
    from src.ui.commands.slash_handler import handle_slash
    from tests.ui.test_http_permissions import make_app

    requests = []
    bridge = BridgedPrompter(lambda request: requests.append(request) if request is not None else None)
    prompter = YoloPrompter(bridge, True)
    prompter.bind_execution_policy(rig.policy)
    task = asyncio.create_task(call(rig, prompter))
    try:
        async with asyncio.timeout(3):
            while len(requests) < 1:
                await asyncio.sleep(0.001)
            assert requests[0].offer_browser_grant == 'read' and requests[0].force_operator
            PermissionModal(requests[0]).handle_key('g')
            while len(requests) < 2:
                await asyncio.sleep(0.001)
            assert requests[1].tool == 'browser_lab_grant'
            assert rig.binding.grant is None and not rig.calls
            assert '300s' in requests[1].detail and '20 dispatched calls' in requests[1].detail
            PermissionModal(requests[1]).handle_key('y')
            await task
        granted = rig.binding.grant
        assert granted is not None and granted.remaining == 19
        app = make_app()
        app.agent.prompter = prompter
        app.agent.engagement_state = rig.policy.engagement
        assert handle_slash(app, '/permissions browser')
        text = app.state.transcript[-1].text
        assert ORIGIN in text and 'calls remaining 19' in text and '/permissions browser revoke' in text
        assert handle_slash(app, '/permissions browser revoke')
        assert rig.binding.grant is None
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize('decision', [Decision.DENY, Decision.ALLOW_SESSION])
async def test_grant_review_requires_explicit_allow_once(rig, decision):
    prompter = yolo(rig)
    async def ask(request, signal=None):
        return decision if request.tool == 'browser_lab_grant' else Decision.GRANT_LAB
    rig.operator.ask = ask
    with pytest.raises(UserControlledRefusal):
        await call(rig, prompter)
    assert rig.binding.grant is None and not rig.calls and rig.policy.active == 0
