"""Command/render regressions with real permission state; no Agent, TUI or network."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest

from src.engagement.state import EngagementState
from src.permission.network.grants import EffectiveHTTP, HTTPLimits
from src.permission.permission import Prompter, YoloPrompter
from src.permission.runtime.execution import ExecutionPolicy
from src.target.target import Target
from src.ui.commands.slash_handler import handle_slash
from src.ui.core.app import KAgent

ORIGIN = "http://127.0.0.1:3000"


@pytest.fixture
def rig(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Status must not probe adapters, spawn processes or use the network")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    state = EngagementState()
    state.add_origin(ORIGIN)
    policy = ExecutionPolicy(state, tmp_path)
    policy.status = Mock(side_effect=forbidden)
    state.http_permissions.status = Mock(side_effect=forbidden)
    operator = SimpleNamespace(ask=AsyncMock(side_effect=forbidden))
    prompter = YoloPrompter(cast(Prompter, operator))
    prompter.bind_execution_policy(policy)
    actions = []
    app = SimpleNamespace(
        agent=SimpleNamespace(target=Target(ORIGIN), engagement_state=state, prompter=prompter),
        state=SimpleNamespace(yolo=False), dispatch=actions.append,
    )

    def apply_yolo(enabled):
        prompter.set_yolo(enabled)
        app.state.yolo = enabled

    app.apply_yolo = apply_yolo
    return SimpleNamespace(app=app, actions=actions, policy=policy, rights=state.http_permissions,
                           state=state, prompter=prompter, operator=operator)


def status(rig, command):
    assert handle_slash(cast(KAgent, rig.app), command)
    return rig.actions[-1].entry.text


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("has_target", [False, True])
def test_target_query_stays_separate_while_yolo_keeps_compact_permission_status(rig, enabled, has_target):
    if not has_target:
        rig.app.agent.target.clear()
        rig.state.clear()
    rig.app.apply_yolo(enabled)
    before = (rig.policy.revision, rig.policy.used, rig.policy.active, rig.rights.revision,
              rig.rights.epoch, dict(rig.rights.grants),
              {key: asdict(value) for key, value in rig.rights._budgets.items()})
    target_text = status(rig, "/target")
    assert target_text == (f"target currently: {ORIGIN}" if has_target else "no target configured")
    text = status(rig, "/yolo")
    assert f"YOLO {'ON' if enabled else 'OFF'}" in text
    assert "Target: " + (ORIGIN if has_target else "(not set)") in text
    assert ("/target <url>" in text) is (not has_target)
    assert ("Auto-approve supported actions within declared scope" in text) is enabled
    assert ("change/delete data" in text) is enabled
    if not enabled:
        assert "Normal permission review" in text and "explicit HTTP grants are retained" in text
    assert "/permissions show" in text and "/help" not in text
    assert all(detail not in text for detail in ("Raw TCP/nmap", "broker", "KiB", "/s", "adapter"))
    assert len(text.splitlines()) <= 5
    assert before == (rig.policy.revision, rig.policy.used, rig.policy.active, rig.rights.revision,
                      rig.rights.epoch, dict(rig.rights.grants),
                      {key: asdict(value) for key, value in rig.rights._budgets.items()})


def test_status_uses_bound_runtime_mode_even_if_ui_state_is_stale(rig):
    rig.prompter.set_yolo(True)
    assert not rig.app.state.yolo
    assert "YOLO ON" in status(rig, "/yolo")


@pytest.mark.parametrize("command", ["/yolo off", "/yolo default"])
async def test_off_and_default_keep_manual_autonomous_grant_usable_and_remove_yolo_grants(rig, command):
    manual = rig.rights.activate(ORIGIN, HTTPLimits.session())
    other = rig.state.add_origin("http://127.0.0.1:3001")[0]
    assert "YOLO ON" in status(rig, "/yolo on")
    assert rig.rights.grants[other].activation == "yolo"
    budget_before = asdict(rig.rights._budgets[manual.id])
    text = status(rig, command)
    assert "YOLO OFF" in text and "existing explicit HTTP grants are retained" in text
    assert not rig.policy.yolo and not rig.prompter.is_yolo() and not rig.app.state.yolo
    assert rig.rights.grants == {manual.origin: manual}
    assert asdict(rig.rights._budgets[manual.id]) == budget_before
    action = EffectiveHTTP("GET", ORIGIN, (), b"", 1024, 0, rig.state.revision, rig.rights.epoch)
    # Exercise the HTTP grant itself; no execution/worker fingerprint is needed.
    receipt = await rig.rights.authorize(action, cast(Prompter, rig.operator), None, lambda: 0)
    assert receipt.grant_id == manual.id
    rig.operator.ask.assert_not_called()


def test_extended_scope_is_not_presented_as_only_the_active_target(rig):
    rig.state.add_origin("http://127.0.0.1:3001")
    rig.state.add_tcp("127.0.0.1", "3000,3001")
    text = status(rig, "/yolo on")
    assert "Target: " + ORIGIN in text
    assert "HTTP origins 2" in text and "TCP entries 1" in text and "/scope" in text


@pytest.mark.parametrize("blocked", ["session", "origin", "tool"])
def test_yolo_status_keeps_active_denials_and_revocations_visible(rig, blocked):
    rig.app.apply_yolo(True)
    if blocked == "session":
        rig.rights.deny_session()
    elif blocked == "origin":
        rig.rights.revoke(next(iter(rig.rights.grants.values())).id)
    else:
        rig.policy.revoke("shell")
    text = status(rig, "/yolo")
    assert "YOLO ON" in text and "Blocked:" in text
    expected = {"session": "HTTP denied", "origin": "HTTP origins revoked", "tool": "tools revoked"}
    assert expected[blocked] in text




def test_permissions_show_explains_actual_transport_and_scanner_paths_without_probes(rig):
    text = status(rig, "/permissions show")
    assert "Native Service/Content Discovery" in text
    assert "direct subprocess" in text and "no OS isolation" in text
    assert "unavailable" in text and "no automatic host fallback" in text
    assert "http tool for HTTP or HTTPS" in text
    limits = HTTPLimits.session()
    assert limits.display() in text
    assert "/permissions details" not in text and "/help" not in text


def test_permissions_default_stays_compact_and_show_reports_configured_limits_without_changes(rig):
    grant = rig.rights.activate(ORIGIN, HTTPLimits(rate=7, burst=5, concurrency=4))
    before = (rig.rights.revision, dict(rig.rights.grants), asdict(rig.rights._budgets[grant.id]))
    summary = status(rig, "/permissions")
    details = status(rig, "/permissions show")
    assert details.startswith(summary)
    assert "Execution details" not in summary and "broker" not in summary
    assert f"Configured HTTP limits {ORIGIN}: {grant.limits.display()}" in details
    assert before == (rig.rights.revision, dict(rig.rights.grants), asdict(rig.rights._budgets[grant.id]))


def test_permissions_details_is_still_not_an_advertised_or_supported_subcommand(rig):
    assert "/permissions details" not in status(rig, "/yolo")
    assert "usage: /permissions" in status(rig, "/permissions details")
    assert rig.actions[-1].entry.kind == "error"
