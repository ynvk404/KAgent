from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest

from src.agent.agent import Agent
from src.engagement.state import EngagementState
from src.permission.http_grants import HTTPLimits
from src.permission.permission import Decision, Prompter, YoloPrompter
from src.target.target import Target
from src.tools.http import HTTPTool
from src.ui.bridges.perm_bridge import BridgedPrompter
from src.ui.commands.slash_handler import handle_slash
from src.ui.core.app import KAgent
from src.ui.core.state import SetPerm
from tests.ui.test_app import make_app

ORIGIN = "http://juice.lab:3000"
SPEC = ORIGIN + ",autonomous,1200,500,3,3,2,131072,65536"


@pytest.mark.asyncio
async def test_slash_yolo_activates_http_without_manual_grant_and_honors_revoke(monkeypatch):
    import httpx
    from src.permission.http_grants import HTTPBlocked

    app = make_app()
    engagement = EngagementState()
    engagement.initialize_target(ORIGIN)
    tool = HTTPTool(Target(ORIGIN), engagement)
    inner = SimpleNamespace(ask=AsyncMock(return_value=Decision.DENY))
    prompter = YoloPrompter(cast(Prompter, inner))
    prompter.bind_http_permissions(tool.permissions)
    app.set_yolo = prompter.set_yolo
    app.agent = cast(Agent, SimpleNamespace(engagement_state=engagement, prompter=prompter))
    sent = []

    def transport(request):
        sent.append(request)
        return httpx.Response(200, content=b"ok")

    original = httpx.AsyncClient
    monkeypatch.setattr("src.tools.http.httpx.AsyncClient", lambda **kw: original(transport=httpx.MockTransport(transport), **kw))
    monkeypatch.setattr("src.tools.http.gate_private_request", AsyncMock(return_value=""))
    assert handle_slash(app, "/yolo on")
    assert "unknown server effects" in app.state.transcript[-1].text
    await tool.run({"url": "/new", "method": "DELETE", "phase": "recon"}, None, prompter)
    grant = next(iter(tool.permissions.grants.values()))
    assert handle_slash(app, "/permissions revoke " + grant.id)
    assert handle_slash(app, "/yolo on")
    with pytest.raises(HTTPBlocked, match="revoked"):
        await tool.run({"url": "/again"}, None, prompter)
    assert len(sent) == 1 and inner.ask.await_count == 0
    assert handle_slash(app, "/permissions retry " + ORIGIN)
    await tool.run({"url": "/retry"}, None, prompter)
    assert len(sent) == 2 and inner.ask.await_count == 0
    assert handle_slash(app, "/yolo off")
    assert not tool.permissions.grants


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", [Decision.ALLOW_ONCE, Decision.DENY])
async def test_slash_grant_requires_operator_review(decision):
    app = make_app()
    engagement = EngagementState()
    engagement.initialize_target(ORIGIN)
    prompter = SimpleNamespace(ask=AsyncMock(return_value=decision))
    app.agent = cast(Agent, SimpleNamespace(engagement_state=engagement, prompter=prompter))
    assert handle_slash(app, "/permissions grant " + SPEC)
    await asyncio.sleep(0)
    assert prompter.ask.await_count == 1
    request = prompter.ask.call_args.args[0]
    assert request.tool == "http_lab_grant" and not request.yolo_auto_approve
    assert "bulk delete" in request.detail and "500" in request.detail
    assert bool(engagement.http_permissions.grants) is (decision == Decision.ALLOW_ONCE)


def test_operator_show_revoke_deny_retry_commands():
    app = make_app()
    engagement = EngagementState()
    engagement.initialize_target(ORIGIN)
    app.agent = cast(Agent, SimpleNamespace(engagement_state=engagement))
    rights = engagement.http_permissions
    grant = rights.activate(ORIGIN, HTTPLimits())
    assert handle_slash(app, "/permissions show")
    assert grant.id in app.state.transcript[-1].text
    assert handle_slash(app, "/permissions revoke " + grant.id)
    assert not rights.grants
    assert handle_slash(app, "/permissions deny")
    assert rights.denied
    assert handle_slash(app, "/permissions retry " + ORIGIN)
    assert not rights.denied and not rights.grants


@pytest.mark.asyncio
async def test_real_modal_g_reviews_then_y_activates_grant(monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    engagement = EngagementState()
    engagement.initialize_target(ORIGIN)
    tool = HTTPTool(Target(ORIGIN), engagement)
    bridge = BridgedPrompter(lambda request: app.dispatch(SetPerm(request)))
    action, _ = tool.prepare({"url": "/new", "phase": "recon"})
    async with app.run_test(size=(100, 40)) as pilot:
        task = asyncio.create_task(tool.permissions.authorize(action, bridge, None, lambda: tool.target.revision))
        try:
            await pilot.pause()
            assert app.state.pending_perm and app.state.pending_perm.offer_http_lab
            assert not tool.permissions.grants
            await pilot.press("g")
            await pilot.pause()
            assert app.state.pending_perm and app.state.pending_perm.tool == "http_lab_grant"
            assert not tool.permissions.grants
            await pilot.press("v", "end", "y")
            await pilot.pause()
            receipt = await task
            assert receipt.grant_id and tool.permissions.grants
            assert app.state.pending_perm is None
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
