"""Actual transport, admission, revocation, stale reviews and bounded failures."""
from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
from textual import events

from src.permission.network.grants import HTTPLimits, HTTPBlocked
from src.permission.permission import Decision, UserControlledRefusal
from src.permission.runtime.execution import ExecutionBlocked
from tests.helpers.burp_selection import make_runtime
from tests.helpers.system_runtime import assert_idle, drain, heartbeat, make_system_app, wait_until


def runtime_for(root, lab, *, grant=True):
    rt = make_runtime(root, origin=lab.origin, yolo=False)
    if grant:
        rt.engagement.http_permissions.activate(lab.origin, HTTPLimits(requests=30, rate=1000, burst=30))
    return rt


@pytest.mark.parametrize("path,status,marker,extra", [
    ("/public", 200, "public lab page", {}),
    ("/hidden", 200, "synthetic hidden route", {}),
    ("/reflect?q=inert-marker", 200, "Reflected: inert-marker", {}),
    ("/filter?category=Gifts%27", 400, "fixture syntax error", {}),
    ("/objects/2", 200, "owned by bob", {}),
    ("/auth", 401, "auth required", {}),
    ("/auth", 200, "synthetic user", {"headers": {"X-Lab-User": "alice"}}),
    ("/redirect", 200, "public lab page", {"max_redirects": 1}),
    ("/error", 503, "controlled service error", {}),
    ("/absent", 404, "not found", {}),
])
async def test_direct_route_oracles(tmp_path, local_lab, path, status, marker, extra, record_property):
    rt = runtime_for(tmp_path, local_lab)
    metrics = {}
    try:
        async with heartbeat(metrics):
            output = await rt.registry.execute("http", {"url": path, "phase": "recon", **extra}, None, rt.prompter)
        assert marker in output and str(status) in output
        assert local_lab.wire[-1]["status"] == status
        assert local_lab.wire[-1]["response"].decode() == marker or marker.encode() in local_lab.wire[-1]["response"]
        assert not rt.workflow.candidates and not rt.workflow.validation_results
        assert not rt.engagement.http_permissions._inflight and rt.policy.active == 0
        record_property("fault_case", json.dumps({"pre": "idle, exact-origin lab grant", "injected": path,
            "expected": "bounded response only; no finding", "post": {"status": status, **metrics}}))
    finally:
        await drain(rt)


async def test_real_error_retry_and_timeout_release_receipts(tmp_path, monkeypatch, local_lab, record_property):
    import src.tools.http.http_tool as http_module
    rt = runtime_for(tmp_path, local_lab)
    local_lab.failures_left = 1
    metrics = {}
    try:
        first = await rt.registry.execute("http", {"url": "/flaky", "phase": "recon"}, None, rt.prompter)
        second = await rt.registry.execute("http", {"url": "/flaky", "phase": "recon"}, None, rt.prompter)
        assert "503" in first and "recovered" in second
        monkeypatch.setattr(http_module, "REQUEST_TIMEOUT", 0.08)
        async with heartbeat(metrics):
            with pytest.raises(httpx.ReadTimeout):
                await rt.registry.execute("http", {"url": "/slow", "phase": "recon"}, None, rt.prompter)
        assert not rt.engagement.http_permissions._inflight and rt.policy.active == 0
        assert not rt.workflow.validation_results and not rt.workflow.persisted_findings
        record_property("fault_case", json.dumps({"pre": "grant active", "injected": "503 then retry; held response timeout",
            "expected": "receipts released; no fabricated proof", "post": metrics}))
    finally:
        local_lab.release.set()
        await drain(rt)


async def test_denial_exact_request_and_session_retry(tmp_path, local_lab):
    rt = runtime_for(tmp_path, local_lab, grant=False)
    args = {"url": "/public", "phase": "recon"}
    try:
        rt.operator.decision = Decision.DENY
        with pytest.raises(UserControlledRefusal):
            await rt.registry.execute("http", args, None, rt.prompter)
        assert not local_lab.wire
        rt.engagement.http_permissions.retry(local_lab.origin)
        rt.operator.decision = Decision.ALLOW_ONCE
        await rt.registry.execute("http", args, None, rt.prompter)
        assert len(local_lab.wire) == 1 and not rt.engagement.http_permissions.grants
        reviews = len(rt.operator.requests)
        await rt.registry.execute("http", {"url": "/hidden", "phase": "recon"}, None, rt.prompter)
        assert len(rt.operator.requests) > reviews and len(local_lab.wire) == 2
        rt.engagement.http_permissions.deny_session()
        with pytest.raises((HTTPBlocked, UserControlledRefusal)):
            await rt.registry.execute("http", args, None, rt.prompter)
        assert len(local_lab.wire) == 2
        rt.engagement.http_permissions.retry(local_lab.origin)
        await rt.registry.execute("http", args, None, rt.prompter)
        assert len(local_lab.wire) == 3 and rt.policy.active == 0
    finally:
        await drain(rt)


async def test_target_supplied_after_missing_origin(tmp_path, local_lab):
    rt = runtime_for(tmp_path, local_lab, grant=False)
    try:
        await rt.agent.clear_target()
        with pytest.raises((ValueError, ExecutionBlocked)):
            await rt.registry.execute("http", {"url": "/public", "phase": "recon"}, None, rt.prompter)
        assert not local_lab.wire
        await rt.agent.set_target_base_url(local_lab.origin)
        output = await rt.registry.execute("http", {"url": "/public", "phase": "recon"}, None, rt.prompter)
        assert "public lab page" in output and len(local_lab.wire) == 1
        assert not rt.engagement.http_permissions.grants
    finally:
        await drain(rt)


@pytest.mark.parametrize("change", ["target", "revoke", "session_deny"])
@pytest.mark.parametrize("stage", ["headers", "body"])
async def test_scope_change_during_real_network_wait_cannot_publish_old_observations(tmp_path, local_lab, change, stage, record_property):
    rt = runtime_for(tmp_path, local_lab)
    task = asyncio.create_task(rt.registry.execute("http", {"url": "/slow" if stage == "headers" else "/slow-body", "phase": "recon"}, None, rt.prompter))
    metrics = {}
    try:
        await asyncio.wait_for(local_lab.entered.wait(), 2)
        before = rt.workflow.generation
        if change == "target":
            await rt.agent.set_target_base_url(local_lab.origin + "/replacement")
        elif change == "revoke":
            rt.engagement.http_permissions.revoke(next(iter(rt.engagement.http_permissions.grants.values())).id)
        else:
            rt.engagement.http_permissions.deny_session()
        async with heartbeat(metrics):
            await asyncio.sleep(0.05)
            local_lab.release.set()
            result = await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 1)
        assert isinstance(result[0], (UserControlledRefusal, ExecutionBlocked)), result
        assert not rt.policy.observations._items
        assert not rt.workflow.validation_results and not rt.workflow.evidence
        assert not rt.engagement.http_permissions._inflight and rt.policy.active == 0
        record_property("fault_case", json.dumps({"pre": {"generation": before}, "injected": change,
            "expected": "no old observation publication", "post": {"observations": 0, **metrics}}))
    finally:
        local_lab.release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await drain(rt)


async def test_old_permission_callback_cannot_clear_or_approve_new_modal(tmp_path, local_lab):
    rt = runtime_for(tmp_path, local_lab, grant=False)
    app = make_system_app(rt)
    async with app.run_test(size=(48, 20)) as pilot:
        task = asyncio.create_task(rt.registry.execute("http", {"url": "/public", "phase": "recon"}, None, rt.prompter))
        try:
            await wait_until(lambda: app.state.pending_perm is not None)
            old = app.state.pending_perm
            assert old is not None
            await rt.agent.set_target_base_url(local_lab.origin + "/replacement")
            old.resolve(Decision.ALLOW_ONCE)
            results = await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 1)
            assert isinstance(results[0], BaseException) and not local_lab.wire
            task = asyncio.create_task(rt.registry.execute("http", {"url": local_lab.origin + "/hidden", "phase": "recon"}, None, rt.prompter))
            await wait_until(lambda: app.state.pending_perm is not None)
            current = app.state.pending_perm
            assert current is not None and current is not old
            old.resolve(Decision.ALLOW_ONCE)
            assert app.state.pending_perm is current and not local_lab.wire
            while not task.done():
                if app.state.pending_perm:
                    await app._process_key(events.Key("y", "y"))
                await asyncio.sleep(0.002)
            assert "synthetic hidden route" in await task
            assert len(local_lab.wire) == 1 and not rt.bridge._busy and not rt.bridge._waiters
            assert_idle(app)
            await pilot.press("x")
            assert app.input.value.endswith("x")
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await drain(rt)
