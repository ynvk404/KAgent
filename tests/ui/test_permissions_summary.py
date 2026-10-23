"""Compact operator state, without changing permission decisions or budgets."""
from __future__ import annotations

from dataclasses import asdict
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from rich.cells import cell_len

from src.engagement.state import EngagementState
from src.permission.network.grants import EffectiveHTTP, HTTPBlocked, HTTPLimits, WARNING
from src.permission.permission import Decision, Prompter
from src.permission.runtime.execution import ExecutionPolicy
from src.ui.commands.slash_handler import handle_slash
from src.ui.core.app import KAgent
from src.ui.render.permissions import permissions_summary
from tests.ui.test_app import make_app
from tests.ui.test_input_rendering import app  # Offline mounted TUI fixture.

ORIGIN = "http://juice.lab:3000"
VIEWPORTS = [(160, 40), (100, 30), (48, 20)]


def bind_permissions(app: KAgent, tmp_path):
    engagement = EngagementState()
    engagement.initialize_target(ORIGIN)
    policy = ExecutionPolicy(engagement, tmp_path)
    app.agent.engagement_state = engagement
    app.agent.prompter = cast(Prompter, SimpleNamespace(execution_policy=policy))
    return engagement.http_permissions, policy


def test_default_summary_is_short_and_never_requests_runtime_diagnostics(tmp_path, monkeypatch):
    app = make_app()
    rights, policy = bind_permissions(app, tmp_path)
    policy.used = 1
    monkeypatch.setattr(policy, "status", Mock(side_effect=AssertionError("verbose policy status")))
    monkeypatch.setattr(rights, "status", Mock(side_effect=AssertionError("verbose HTTP status")))
    assert handle_slash(app, "/permissions")
    text = app.state.transcript[-1].text
    assert "YOLO: off" in text and "HTTP session deny: off" in text
    assert "HTTP grants: none" in text and "Revoked tools: none" in text
    assert "1 used · no session quota" in text and "0/16 running" in text
    assert len(text.splitlines()) <= 6
    for internal in (str(tmp_path), rights.session_id, "Worker", "broker", "MiB", "Grant format", "REQUEST_BYTES"):
        assert internal not in text


def test_summary_shows_yolo_denials_revokes_and_finite_tool_limits(tmp_path):
    app = make_app()
    rights, policy = bind_permissions(app, tmp_path)
    policy.set_yolo(True)
    rights.set_yolo(True)
    rights.deny_session()
    policy.revoke("Shell")
    policy.max_calls, policy.used, policy.active = 5, 3, 1
    assert handle_slash(app, "/permissions show")
    text = app.state.transcript[-1].text
    assert "YOLO: on" in text and "HTTP session deny: on" in text
    assert "HTTP grants: none" in text and "Revoked tools: Shell" in text
    assert "3/5 used" in text and "1/16 running" in text
    assert "HTTP retry needed: " + ORIGIN in text
    assert rights.denied and not rights.grants and policy.revoked == {"Shell"}


@pytest.mark.parametrize("mode", ["autonomous", "confirm-each"])
@pytest.mark.parametrize("state", ["active", "expired", "exhausted", "blocked"])
def test_grant_summary_reports_actual_state_and_never_refills_or_replaces_grants(tmp_path, mode, state):
    app = make_app()
    rights, policy = bind_permissions(app, tmp_path)
    now = [100.0]
    rights.clock = lambda: now[0]
    grant = rights.activate(ORIGIN, HTTPLimits(seconds=60, requests=2), mode)
    budget = rights._budgets[grant.id]
    if state == "expired":
        now[0] += 61
    elif state == "exhausted":
        budget.used = 2
    elif state == "blocked":
        rights.pause_private(grant.origin)
    rights._inflight[grant.origin] = 1
    before = (rights.revision, rights.epoch, dict(rights.grants), asdict(budget))
    text = permissions_summary(rights, policy)
    assert f"HTTP grants: {1 if state == 'active' else 0} active" in text
    assert f"{ORIGIN}: {state} · {mode}" in text and grant.id in text
    assert f"{0 if state == 'exhausted' else 2} requests left" in text
    assert "1/2 running" in text
    if state == "blocked":
        assert "Private-host review blocked: " + ORIGIN in text
    assert before == (rights.revision, rights.epoch, dict(rights.grants), asdict(budget))
    # The diagnostics API and approval warning remain available unchanged.
    assert WARNING in rights.status() and rights.session_id in rights.status()


def test_session_grants_show_no_artificial_expiry_or_quota(tmp_path):
    app = make_app()
    rights, policy = bind_permissions(app, tmp_path)
    rights.activate(ORIGIN, HTTPLimits.session())
    text = permissions_summary(rights, policy)
    assert "no request quota · session lifetime" in text
    assert "HTTP grants do not approve scanner jobs." in text


@pytest.mark.parametrize("mode", ["autonomous", "confirm-each"])
@pytest.mark.parametrize("yolo", [False, True])
async def test_declined_review_summary_matches_the_existing_authorize_path(tmp_path, mode, yolo):
    app = make_app()
    rights, policy = bind_permissions(app, tmp_path)
    grant = rights.activate(ORIGIN, HTTPLimits(), mode)
    rights.set_yolo(yolo)
    operator = cast(Prompter, SimpleNamespace(ask=AsyncMock(return_value=Decision.DENY)))
    assert await rights.review_grant(ORIGIN, HTTPLimits(), "autonomous", operator) is None
    blocked = mode == "confirm-each" and not yolo
    text = permissions_summary(rights, policy)
    assert f"{ORIGIN}: {'blocked' if blocked else 'active'} · {mode}" in text
    assert f"HTTP grants: {0 if blocked else 1} active" in text
    action = EffectiveHTTP("GET", ORIGIN, (), b"", 1024, 0, policy.engagement.revision, rights.epoch)
    if blocked:
        with pytest.raises(HTTPBlocked, match="Lab grant review was previously declined"):
            await rights.authorize(action, operator, None, lambda: 0)
    else:
        receipt = await rights.authorize(action, operator, None, lambda: 0)
        assert receipt.grant_id == grant.id




def test_limits_result_is_compact_and_details_does_not_expand_the_command_surface(tmp_path):
    app = make_app()
    rights, policy = bind_permissions(app, tmp_path)
    assert handle_slash(app, "/permissions limits 7 2")
    assert policy.max_calls == 7 and policy.concurrency == 2
    assert "0/7 used · 0/2 running" in app.state.transcript[-1].text
    assert "Worker" not in app.state.transcript[-1].text
    assert handle_slash(app, "/permissions details")
    assert app.state.transcript[-1].kind == "error"
    assert "usage: /permissions" in app.state.transcript[-1].text
    assert not rights.grants


@pytest.mark.parametrize("size", VIEWPORTS)
async def test_summary_wraps_in_real_transcript_and_reflows_on_resize(app: KAgent, tmp_path, size):
    # Keep the offline Agent fixture's other methods for the full render path.
    rights, policy = bind_permissions(app, tmp_path)
    grant = rights.activate(ORIGIN, HTTPLimits.session())
    policy.revoke("mcp_configured_server_tool_with_a_long_identifier")
    async with app.run_test(size=size) as pilot:
        assert handle_slash(app, "/permissions")
        await pilot.pause()
        entry = app.state.transcript[-1]
        for width, height in [size, *VIEWPORTS]:
            await pilot.resize_terminal(width, height)
            await pilot.pause()
            log = app.transcript_log
            compact = "".join("".join(line.text.split()) for line in log.lines)
            assert "".join(entry.text.split()) in compact
            assert grant.id in compact and ORIGIN in compact
            assert max(cell_len(line.text) for line in log.lines) <= log.transcript_content_width
            assert log.scroll_x == log.max_scroll_x == 0
            log.scroll_home(animate=False, immediate=True)
            await pilot.pause()
            compositor = app.screen._compositor.render_strips()
            assert any("Permissions" in compositor[y].text for y in range(log.region.y, log.region.bottom))
            log.scroll_end(animate=False, immediate=True, x_axis=False)
            await pilot.pause()
            assert log.is_vertical_scroll_end
            assert any("Revoked tools" in log.render_line(y).text for y in range(log.size.height))
            assert (app.size.width, app.size.height) == (width, height)
