from __future__ import annotations

import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock

import httpx
import pytest

from src.engagement.state import EngagementState, OutOfScopeError
from src.permission.http_grants import HTTPLimits, HTTPBlocked
from src.permission.http_control import parse_lab_spec
from src.permission.permission import Decision, PermissionRequest, YoloPrompter
from src.cli.main import parse_flags, FlagParseError, apply_startup_http_grants
from src.target.target import Target
from src.tools.http import HTTPTool
from src.tools.registry import Registry

ORIGIN = "http://juice.lab:3000"
REAL_ASYNC_CLIENT = httpx.AsyncClient


class Operator:
    def __init__(self, decision=Decision.DENY):
        self.decision = decision
        self.requests: list[PermissionRequest] = []

    async def ask(self, request: PermissionRequest, signal=None):
        self.requests.append(request)
        return self.decision


@pytest.fixture
def runtime(monkeypatch):
    target = Target(ORIGIN)
    engagement = EngagementState()
    engagement.initialize_target(ORIGIN)
    tool = HTTPTool(target, engagement)
    registry = Registry()
    registry.register(tool)
    sent: list[httpx.Request] = []
    responses: list[httpx.Response] = []

    def transport(request):
        sent.append(request)
        response = httpx.Response(200, content=b"ok", request=request)
        responses.append(response)
        return response

    original = httpx.AsyncClient
    monkeypatch.setattr("src.tools.http.httpx.AsyncClient", lambda **kw: original(transport=httpx.MockTransport(transport), **kw))
    monkeypatch.setattr("src.tools.http.gate_private_request", AsyncMock(return_value=""))
    return tool, registry, sent, responses


def args(path="/new", phase="recon", **extra):
    return {"url": path, "phase": phase, **extra}


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["recon", "validation", "impact"])
async def test_phase_and_scope_without_yolo_do_not_create_http_rights(runtime, phase):
    tool, registry, sent, _ = runtime
    operator = Operator()
    with pytest.raises(HTTPBlocked, match="denied"):
        await registry.execute("http", args(phase=phase, method="DELETE"), None, YoloPrompter(operator, False))
    assert not sent and len(operator.requests) == 1 and not tool.permissions.grants
    assert operator.requests[0].no_session_cache and not operator.requests[0].yolo_auto_approve


@pytest.mark.asyncio
@pytest.mark.parametrize("phase,method,path,body", [
    ("validation", "GET", "/rest/products/search?q=' OR 1=1--", ""),
    ("validation", "POST", "/feedback", "<script>alert('x')</script>"),
    ("recon", "POST", "/rest/user/login", '{"email":"test","password":"fake"}'),
    ("impact", "DELETE", "/new-endpoint/test-object", ""),
    ("impact", "PATCH", "/new-endpoint/another", '{"field":"new"}'),
])
@pytest.mark.parametrize("activation", ["manual", "yolo"])
async def test_payloads_new_endpoints_and_mutations_run_without_dialog(runtime, phase, method, path, body, activation):
    tool, registry, sent, responses = runtime
    if activation == "manual":
        tool.permissions.activate(ORIGIN, HTTPLimits())
    operator = Operator()
    prompter = YoloPrompter(operator, activation == "yolo")
    result = await registry.execute("http", args(path, phase, method=method, body=body), None, prompter)
    assert result.http_status == 200 and len(sent) == 1
    assert sent[0].method == method and sent[0].content == body.encode()
    assert not operator.requests and responses[0].is_closed


@pytest.mark.asyncio
async def test_yolo_toggle_removes_only_implicit_rights(runtime):
    tool, registry, sent, _ = runtime
    operator = Operator()
    prompter = YoloPrompter(operator, False)
    prompter.bind_http_permissions(tool.permissions)
    assert not tool.permissions.grants
    prompter.set_yolo(True)
    implicit = next(iter(tool.permissions.grants.values()))
    assert implicit.activation == "yolo" and implicit.limits == HTTPLimits()
    await registry.execute("http", args(), None, prompter)
    prompter.set_yolo(False)
    assert not tool.permissions.grants
    with pytest.raises(HTTPBlocked, match="denied"):
        await registry.execute("http", args("/another"), None, prompter)
    manual = tool.permissions.activate(ORIGIN, HTTPLimits(requests=7))
    prompter.set_yolo(True)
    prompter.set_yolo(False)
    await registry.execute("http", args("/manual"), None, prompter)
    assert next(iter(tool.permissions.grants.values())).id == manual.id
    assert len(sent) == 2 and len(operator.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("restriction", ["expired", "budget", "revoke", "session-deny"])
async def test_yolo_binding_does_not_reset_limits_or_revocation(runtime, restriction):
    tool, registry, sent, _ = runtime
    operator = Operator()
    prompter = YoloPrompter(operator, True)
    prompter.bind_http_permissions(tool.permissions)
    grant = next(iter(tool.permissions.grants.values()))
    budget = tool.permissions._budgets[grant.id]
    if restriction == "expired":
        tool.permissions.clock = lambda: grant.expires_at + 1
    elif restriction == "budget":
        budget.used = grant.limits.requests
    elif restriction == "revoke":
        tool.permissions.revoke(grant.id)
    else:
        tool.permissions.deny_session()
    for phase in ["recon", "validation", "impact"]:
        with pytest.raises(HTTPBlocked):
            await registry.execute("http", args("/" + phase, phase), None, prompter)
    assert not sent and not operator.requests
    if restriction in {"revoke", "session-deny"}:
        prompter.set_yolo(False)
        prompter.set_yolo(True)
        with pytest.raises(HTTPBlocked):
            await registry.execute("http", args(), None, prompter)
        assert not tool.permissions.grants


@pytest.mark.asyncio
async def test_yolo_scope_addition_and_removal_remain_operator_controlled(runtime):
    tool, registry, sent, _ = runtime
    operator = Operator()
    prompter = YoloPrompter(operator, True)
    prompter.bind_http_permissions(tool.permissions)
    other = "https://new.lab:8443"
    with pytest.raises(OutOfScopeError):
        await registry.execute("http", args(other + "/new"), None, prompter)
    assert not sent
    tool.engagement.add_origin(other)
    await registry.execute("http", args(other + "/new", "impact", method="POST"), None, prompter)
    tool.engagement.remove_origin(other)
    tool.engagement.add_origin(other)
    with pytest.raises(HTTPBlocked, match="revoked"):
        await registry.execute("http", args(other + "/again"), None, prompter)
    assert len(sent) == 1 and not operator.requests


@pytest.mark.asyncio
async def test_model_fields_or_duck_typed_yolo_cannot_activate_rights(runtime):
    tool, registry, sent, _ = runtime

    class FakeYolo(Operator):
        def is_yolo(self):
            return True

    operator = FakeYolo()
    with pytest.raises(HTTPBlocked, match="denied"):
        await registry.execute("http", args(yolo=True, grant="autonomous", accept_unknown_effects=True), None, operator)
    assert not tool.permissions.grants and not sent and len(operator.requests) == 1


@pytest.mark.asyncio
async def test_yolo_mode_change_invalidates_pending_exact_approval(runtime):
    tool, registry, sent, _ = runtime
    entered, finish = asyncio.Event(), asyncio.Event()

    class Waiting(Operator):
        async def ask(self, request, signal=None):
            self.requests.append(request)
            entered.set()
            await finish.wait()
            return Decision.ALLOW_ONCE

    operator = Waiting()
    prompter = YoloPrompter(operator, False)
    task = asyncio.create_task(registry.execute("http", args(), None, prompter))
    await entered.wait()
    prompter.set_yolo(True)
    finish.set()
    with pytest.raises(HTTPBlocked):
        await task
    assert not sent
    await registry.execute("http", args("/after-toggle"), None, prompter)
    assert len(sent) == 1 and len(operator.requests) == 1


@pytest.mark.asyncio
async def test_resume_uses_current_operator_mode_not_serialized_rights(runtime):
    tool, registry, sent, _ = runtime
    prompter = YoloPrompter(Operator(), True)
    await registry.execute("http", args(), None, prompter)
    old = next(iter(tool.permissions.grants.values()))
    raw = tool.engagement.to_dict()
    assert "yolo" not in raw and "http_permissions" not in raw
    restored = EngagementState.from_dict(raw)
    assert not restored.http_permissions.grants
    tool.engagement.replace_from(restored)
    assert not tool.permissions.grants
    await registry.execute("http", args("/resumed"), None, prompter)
    current = next(iter(tool.permissions.grants.values()))
    assert current.id != old.id and current.engagement_id != old.engagement_id
    assert tool.permissions._budgets[current.id].used == 1 and len(sent) == 2


@pytest.mark.asyncio
async def test_operator_target_change_with_yolo_issues_fresh_scoped_rights(runtime):
    tool, registry, sent, _ = runtime
    operator = Operator()
    prompter = YoloPrompter(operator, True)
    await registry.execute("http", args(), None, prompter)
    old = next(iter(tool.permissions.grants.values()))
    new_target = "https://second.lab:8443"
    tool.engagement.initialize_target(new_target)
    tool.target.set_base_url(new_target)
    await registry.execute("http", args("/new", "impact", method="PATCH", body="test"), None, prompter)
    current = next(iter(tool.permissions.grants.values()))
    assert current.id != old.id and current.origin.as_url() == new_target
    assert len(tool.permissions.grants) == 1
    with pytest.raises(OutOfScopeError):
        await registry.execute("http", args(ORIGIN + "/old"), None, prompter)
    assert len(sent) == 2 and not operator.requests


@pytest.mark.asyncio
async def test_reusable_grant_not_yolo_dependent(runtime):
    tool, registry, sent, _ = runtime
    tool.permissions.activate(ORIGIN, HTTPLimits())
    operator = Operator()
    for phase in ["impact", "recon", "validation"]:
        await registry.execute("http", args(phase=phase), None, YoloPrompter(operator, False))
    assert len(sent) == 3 and not operator.requests


@pytest.mark.asyncio
async def test_confirm_each_even_yolo(runtime):
    tool, registry, sent, _ = runtime
    tool.permissions.activate(ORIGIN, HTTPLimits(), "confirm-each")
    operator = Operator(Decision.ALLOW_ONCE)
    for phase in ["recon", "impact"]:
        await registry.execute("http", args(phase=phase), None, YoloPrompter(operator, True))
    assert len(operator.requests) == len(sent) == 2
    assert all(not req.offer_http_lab for req in operator.requests)


@pytest.mark.asyncio
async def test_effective_request_full_preview_and_caller_mutation(runtime):
    tool, registry, sent, _ = runtime
    original = args("/new", method="POST", body="A" * 9000 + "TAIL", headers={"X-Custom": "yes", "Authorization": "Bearer fake-secret"})

    class Mutating(Operator):
        async def ask(self, request, signal=None):
            self.requests.append(request)
            assert ORIGIN + "/new" in request.detail and "TAIL" in request.detail
            assert "Content-Length".lower() in request.detail.lower()
            assert "fake-secret" not in request.detail
            original["body"] = "changed"
            original["headers"]["X-Custom"] = "changed"
            return Decision.ALLOW_ONCE

    operator = Mutating()
    await registry.execute("http", original, None, operator)
    assert sent[0].content.endswith(b"TAIL") and sent[0].headers["X-Custom"] == "yes"
    assert sent[0].headers["Authorization"] == "Bearer fake-secret"


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["expiry", "revoke", "quota", "session-deny", "request-size", "response-size"])
async def test_limits_block_before_dispatch_without_dialog(runtime, reason):
    tool, registry, sent, _ = runtime
    now = [100.0]
    rights = tool.permissions
    rights.clock = lambda: now[0]
    limits = HTTPLimits(requests=1, request_bytes=500, response_bytes=16384)
    grant = rights.activate(ORIGIN, limits)
    request = args()
    if reason == "expiry":
        now[0] += 1200
    elif reason == "revoke":
        rights.revoke(grant.id)
    elif reason == "quota":
        await registry.execute("http", request, None, Operator())
        sent.clear()
    elif reason == "session-deny":
        rights.deny_session()
    elif reason == "request-size":
        request["body"] = "x" * 501
    elif reason == "response-size":
        request["max_response_bytes"] = 16385
    operator = Operator(Decision.ALLOW_ONCE)
    with pytest.raises(HTTPBlocked):
        await registry.execute("http", request, None, operator)
    assert not sent and not operator.requests


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["https://juice.lab:3000/a", "http://juice.lab:3001/a", "http://other.lab:3000/a"])
async def test_exact_origin_scope_and_grant(runtime, url):
    tool, registry, sent, _ = runtime
    tool.permissions.activate(ORIGIN, HTTPLimits())
    with pytest.raises(OutOfScopeError):
        await registry.execute("http", args(url), None, Operator(Decision.ALLOW_ONCE))
    tool.engagement.add_origin(url)
    operator = Operator()
    with pytest.raises(HTTPBlocked):
        await registry.execute("http", args(url), None, operator)
    assert not sent and len(operator.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["body", "headers", "expiry", "replay", "revision", "scope", "target", "resume"])
async def test_receipt_bound_one_shot_and_revision(runtime, tamper):
    tool, _, sent, _ = runtime
    now = [100.0]
    rights = tool.permissions
    rights.clock = lambda: now[0]
    action, _ = tool.prepare(args(method="POST", body="approved"))
    receipt = await rights.authorize(action, Operator(Decision.ALLOW_ONCE), None, lambda: tool.target.revision)
    if tamper == "body":
        action = replace(action, body=b"different")
    elif tamper == "headers":
        action = replace(action, headers=((b"x", b"changed"),))
    elif tamper == "expiry":
        now[0] += 60
    elif tamper == "replay":
        reservation = rights.reserve(action, receipt, None, tool.target.revision)
        reservation.start()
        reservation.release()
    elif tamper == "revision":
        rights.retry(ORIGIN)
    elif tamper == "scope":
        tool.engagement.add_origin("http://other.lab")
    elif tamper == "target":
        tool.target.set_base_url("http://other.lab")
    elif tamper == "resume":
        tool.engagement.replace_from(EngagementState.from_dict(tool.engagement.to_dict()))
    with pytest.raises(HTTPBlocked):
        rights.reserve(action, receipt, None, tool.target.revision)
    assert not sent


@pytest.mark.asyncio
async def test_concurrent_reservations_do_not_exceed_budget(runtime):
    tool, _, _, _ = runtime
    rights = tool.permissions
    rights.activate(ORIGIN, HTTPLimits(requests=2, concurrency=2, burst=10))
    action, _ = tool.prepare(args())
    receipts = [await rights.authorize(action, Operator(), None, lambda: tool.target.revision) for _ in range(10)]
    gate = asyncio.Event()

    async def worker(receipt):
        await gate.wait()
        try:
            reservation = rights.reserve(action, receipt, None, tool.target.revision)
            reservation.start()
            return reservation
        except HTTPBlocked:
            return None

    tasks = [asyncio.create_task(worker(receipt)) for receipt in receipts]
    gate.set()
    reservations = [r for r in await asyncio.gather(*tasks) if r]
    assert len(reservations) == 2
    for reservation in reservations:
        reservation.release()


@pytest.mark.asyncio
async def test_rate_concurrency_release_and_accounting(runtime):
    tool, _, _, _ = runtime
    now = [0.0]
    rights = tool.permissions
    rights.clock = lambda: now[0]
    grant = rights.activate(ORIGIN, HTTPLimits(burst=1, concurrency=1, rate=1))
    action, _ = tool.prepare(args())
    receipt = await rights.authorize(action, Operator(), None, lambda: tool.target.revision)
    reservation = rights.reserve(action, receipt, None, tool.target.revision)
    other_receipt = await rights.authorize(action, Operator(), None, lambda: tool.target.revision)
    with pytest.raises(HTTPBlocked, match="concurrency"):
        rights.reserve(action, other_receipt, None, tool.target.revision)
    reservation.release()  # Not started: refund count/rate and slot.
    assert rights._budgets[grant.id].used == 0
    receipt = await rights.authorize(action, Operator(), None, lambda: tool.target.revision)
    reservation = rights.reserve(action, receipt, None, tool.target.revision)
    reservation.start()
    reservation.release()
    other_receipt = await rights.authorize(action, Operator(), None, lambda: tool.target.revision)
    with pytest.raises(HTTPBlocked, match="rate"):
        rights.reserve(action, other_receipt, None, tool.target.revision)
    now[0] += 1
    await rights.authorize(action, Operator(), None, lambda: tool.target.revision)
    assert rights._budgets[grant.id].used == 1 and rights._budgets[grant.id].active == 0


@pytest.mark.asyncio
async def test_pending_and_deny_do_not_spam_or_create_session_deny(runtime):
    tool, registry, sent, _ = runtime
    opened = asyncio.Event()
    release = asyncio.Event()

    class Waiting(Operator):
        async def ask(self, request, signal=None):
            self.requests.append(request)
            opened.set()
            await release.wait()
            return Decision.DENY

    operator = Waiting()
    task = asyncio.create_task(registry.execute("http", args(), None, operator))
    await opened.wait()
    for _ in range(5):
        with pytest.raises(HTTPBlocked, match="already open"):
            await registry.execute("http", args("/other", phase="impact"), None, operator)
    release.set()
    with pytest.raises(HTTPBlocked):
        await task
    for _ in range(3):
        with pytest.raises(HTTPBlocked, match="previously"):
            await registry.execute("http", args(), None, operator)
    assert len(operator.requests) == 1 and not sent and not tool.permissions.denied
    tool.permissions.retry(ORIGIN)
    await registry.execute("http", args(), None, Operator(Decision.ALLOW_ONCE))
    assert len(sent) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["cancel", "revoke", "scope", "target"])
async def test_state_change_while_exact_approval_is_pending(runtime, change):
    tool, registry, sent, _ = runtime
    signal = asyncio.Event()
    grant = tool.permissions.activate(ORIGIN, HTTPLimits(), "confirm-each")

    class Changing(Operator):
        async def ask(self, request, signal=None):
            if change == "cancel":
                assert signal is not None
                signal.set()
            elif change == "revoke":
                tool.permissions.revoke(grant.id)
            elif change == "scope":
                tool.engagement.add_origin("http://other.lab")
            elif change == "target":
                tool.target.set_base_url("http://other.lab")
            return Decision.ALLOW_ONCE

    with pytest.raises((HTTPBlocked, asyncio.CancelledError)):
        await registry.execute("http", args(), signal, Changing())
    assert not sent


@pytest.mark.asyncio
async def test_private_gate_independent_and_no_repeat_after_deny(runtime, monkeypatch):
    tool, registry, sent, _ = runtime
    tool.permissions.activate(ORIGIN, HTTPLimits())
    from src.tools.private_host import gate_private_request
    monkeypatch.setattr("src.tools.http.gate_private_request", gate_private_request)
    monkeypatch.setattr("src.tools.private_host.private_host_reason", AsyncMock(return_value="loopback IPv4"))
    operator = Operator()
    with pytest.raises(PermissionError, match="private/internal URL denied"):
        await registry.execute("http", args(), None, operator)
    with pytest.raises(HTTPBlocked, match="private-host"):
        await registry.execute("http", args(), None, operator)
    assert len(operator.requests) == 1 and not sent
    assert (operator.requests[0].cache_key or "").startswith("private-declared://")


@pytest.mark.asyncio
async def test_resume_does_not_restore_grant_from_serialized_engagement(runtime):
    tool, registry, sent, _ = runtime
    tool.permissions.activate(ORIGIN, HTTPLimits())
    raw = tool.engagement.to_dict()
    assert "http_permissions" not in raw and "grants" not in raw
    tool.engagement.replace_from(EngagementState.from_dict(raw))
    assert not tool.permissions.grants
    with pytest.raises(HTTPBlocked):
        await registry.execute("http", args(), None, Operator())
    assert not sent


@pytest.mark.asyncio
async def test_scope_add_keeps_old_grant_remove_readd_does_not(runtime):
    tool, registry, sent, _ = runtime
    tool.permissions.activate(ORIGIN, HTTPLimits())
    tool.engagement.add_origin("http://other.lab")
    await registry.execute("http", args(), None, Operator())
    tool.engagement.remove_origin(ORIGIN)
    tool.engagement.add_origin(ORIGIN)
    with pytest.raises(HTTPBlocked, match="revoked"):
        await registry.execute("http", args(), None, Operator())
    assert len(sent) == 1


@pytest.mark.asyncio
async def test_lab_option_requires_separate_explicit_confirmation(runtime):
    tool, registry, sent, _ = runtime

    class Granting(Operator):
        async def ask(self, request, signal=None):
            self.requests.append(request)
            if request.tool == "http":
                assert request.offer_http_lab
                return Decision.GRANT_LAB
            assert "bulk delete" in request.detail and "500" in request.detail
            return Decision.ALLOW_ONCE

    operator = Granting()
    await registry.execute("http", args(), None, operator)
    await registry.execute("http", args("/new"), None, operator)
    assert len(operator.requests) == len(sent) == 2 and tool.permissions.grants


@pytest.mark.parametrize("field,value", [("seconds", float("inf")), ("rate", float("nan")), ("concurrency", 0), ("requests", True), ("request_bytes", -1)])
def test_limits_are_finite_and_explicit(field, value):
    with pytest.raises(ValueError):
        HTTPLimits(**{field: value})


def test_cli_spec_explicit_no_paths_and_no_payload_classification():
    origin, limits, mode = parse_lab_spec(ORIGIN + ",autonomous,1200,500,3,3,2,131072,65536")
    assert origin == ORIGIN and limits.requests == 500 and mode == "autonomous"
    with pytest.raises(ValueError):
        parse_lab_spec(ORIGIN + "/admin,autonomous,1200,500,3,3,2,131072,65536")


def test_cli_flags_require_explicit_unknown_effect_acceptance(runtime):
    tool, _, _, _ = runtime
    spec = ORIGIN + ",autonomous,1200,500,3,3,2,131072,65536"
    with pytest.raises(FlagParseError, match="accept-unknown"):
        parse_flags(["--http-lab-grant", spec])
    flags = parse_flags(["--http-lab-grant", spec, "--accept-unknown-http-effects"])
    from types import SimpleNamespace
    from typing import cast
    from src.agent.agent import Agent
    agent = cast(Agent, SimpleNamespace(engagement_state=tool.engagement))
    apply_startup_http_grants(agent, flags)
    assert tool.permissions.grants
    tool.permissions.reset()
    apply_startup_http_grants(agent, parse_flags(["--yolo"]))
    assert tool.permissions.grants
    assert all(grant.activation == "yolo" for grant in tool.permissions.grants.values())


@pytest.mark.asyncio
async def test_url_credentials_materialized_before_review(runtime):
    tool, registry, sent, _ = runtime
    operator = Operator(Decision.ALLOW_ONCE)
    await registry.execute("http", args("http://test:fake-password@juice.lab:3000/login"), None, operator)
    assert "fake-password" not in operator.requests[0].detail
    assert "authorization:" in operator.requests[0].detail.lower()
    assert sent[0].headers["authorization"].startswith("Basic ")
    assert not sent[0].url.username and not sent[0].url.password


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["cancel-after-send", "timeout", "transport-error"])
async def test_dispatch_failures_keep_count_and_release_slot(runtime, monkeypatch, failure):
    tool, registry, sent, _ = runtime
    grant = tool.permissions.activate(ORIGIN, HTTPLimits())

    async def failing_send(self, request, **kwargs):
        sent.append(request)
        if failure == "cancel-after-send":
            raise asyncio.CancelledError()
        if failure == "timeout":
            raise httpx.ReadTimeout("fake timeout")
        raise httpx.ConnectError("fake transport error")

    monkeypatch.setattr(REAL_ASYNC_CLIENT, "send", failing_send)
    with pytest.raises((asyncio.CancelledError, httpx.HTTPError)):
        await registry.execute("http", args(), None, Operator())
    budget = tool.permissions._budgets[grant.id]
    assert budget.used == 1 and budget.active == 0 and len(sent) == 1


@pytest.mark.asyncio
async def test_cancel_during_review_reopens_only_by_operator(runtime):
    tool, registry, sent, _ = runtime
    started = asyncio.Event()

    class Waiting(Operator):
        async def ask(self, request, signal=None):
            self.requests.append(request)
            started.set()
            await asyncio.Event().wait()
            return Decision.ALLOW_ONCE

    operator = Waiting()
    task = asyncio.create_task(registry.execute("http", args(), None, operator))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(HTTPBlocked, match="previously"):
        await registry.execute("http", args(), None, operator)
    assert len(operator.requests) == 1 and not sent
    assert not tool.permissions._pending


@pytest.mark.asyncio
async def test_cancellable_scheduler_rechecks_revoke_and_refunds_nothing_unsent(runtime):
    tool, _, _, _ = runtime
    rights = tool.permissions
    grant = rights.activate(ORIGIN, HTTPLimits(concurrency=1, burst=10))
    action, _ = tool.prepare(args())
    first = await rights.authorize(action, Operator(), None, lambda: tool.target.revision)
    running = rights.reserve(action, first, None, tool.target.revision)
    running.start()
    receipt = await rights.authorize(action, Operator(), None, lambda: tool.target.revision)
    task = asyncio.create_task(rights.reserve_when_ready(action, receipt, None, lambda: tool.target.revision))
    await asyncio.sleep(0)
    rights.revoke(grant.id)
    with pytest.raises(HTTPBlocked):
        await task
    assert running.budget.used == 1 and running.budget.active == 1
    running.release()
    assert running.budget.active == 0


@pytest.mark.asyncio
async def test_same_request_parallel_approvals_do_not_share_receipt(runtime):
    tool, registry, sent, _ = runtime
    opened, release = asyncio.Event(), asyncio.Event()

    class Waiting(Operator):
        async def ask(self, request, signal=None):
            self.requests.append(request)
            opened.set()
            await release.wait()
            return Decision.ALLOW_ONCE

    operator = Waiting()
    first = asyncio.create_task(registry.execute("http", args(), None, operator))
    await opened.wait()
    with pytest.raises(HTTPBlocked, match="already open"):
        await registry.execute("http", args(), None, operator)
    release.set()
    await first
    assert len(sent) == len(operator.requests) == 1


def test_session_deny_survives_target_change_until_operator_retry(runtime):
    tool, _, _, _ = runtime
    tool.permissions.activate(ORIGIN, HTTPLimits())
    tool.permissions.deny_session()
    tool.target.set_base_url(ORIGIN + "/new-base")
    tool.permissions.sync_target()
    assert tool.permissions.denied and not tool.permissions.grants
    with pytest.raises(HTTPBlocked, match="session deny"):
        tool.permissions.activate(ORIGIN, HTTPLimits())
    tool.permissions.retry(ORIGIN)
    assert not tool.permissions.denied and not tool.permissions.grants


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["shell", "mcp", "local-read"])
async def test_http_grants_do_not_authorize_other_tools(runtime, tmp_path, monkeypatch, kind):
    from src.tools.shell import ShellTool
    from src.tools.mcp_integration import MCPTool
    from src.tools.file import FileReadTool
    from tests.security.test_action_approval import Session
    tool, registry, _, _ = runtime
    tool.permissions.activate(ORIGIN, HTTPLimits())
    subprocess = AsyncMock()
    monkeypatch.setattr("src.tools.shell.run_with_capture", subprocess)
    remote = Session()
    if kind == "shell":
        other = ShellTool()
        request = {"command": "echo fake-marker"}
    elif kind == "mcp":
        other = MCPTool(remote, "mcp_fixture", "operation", "fixture", {})
        request = {"url": ORIGIN}
    else:
        other = FileReadTool()
        sensitive = tmp_path / ".env"
        sensitive.write_text("FAKE_SECRET=canary")
        request = {"path": str(sensitive)}
    registry.register(other)
    operator = Operator()
    with pytest.raises(PermissionError):
        await registry.execute(other.name(), request, None, YoloPrompter(operator, True))
    assert operator.requests and not remote.calls
    subprocess.assert_not_called()


@pytest.mark.asyncio
async def test_operator_retry_can_renew_exact_envelope_without_broad_rights(runtime):
    tool, registry, sent, _ = runtime
    now = [100.0]
    rights = tool.permissions
    rights.clock = lambda: now[0]
    operator = Operator(Decision.ALLOW_ONCE)
    await registry.execute("http", args(), None, operator)
    now[0] += 1200
    with pytest.raises(HTTPBlocked, match="expired"):
        await registry.execute("http", args(), None, operator)
    rights.retry(ORIGIN)
    await registry.execute("http", args(), None, operator)
    assert len(sent) == len(operator.requests) == 2 and not rights.grants


@pytest.mark.asyncio
async def test_retry_does_not_replenish_existing_lab_budget(runtime):
    tool, registry, _, _ = runtime
    rights = tool.permissions
    rights.activate(ORIGIN, HTTPLimits(requests=1))
    await registry.execute("http", args(), None, Operator())
    rights.retry(ORIGIN)
    operator = Operator(Decision.ALLOW_ONCE)
    with pytest.raises(HTTPBlocked, match="budget exhausted"):
        await registry.execute("http", args(), None, operator)
    assert not operator.requests


@pytest.mark.asyncio
async def test_legacy_origin_cache_and_allow_session_cannot_grant_http(runtime):
    from src.ui.bridges.perm_bridge import BridgedPrompter
    tool, registry, sent, _ = runtime
    dialogs = []

    def publish(request):
        if request is not None:
            dialogs.append(request)
            request.resolve(Decision.ALLOW_SESSION)

    bridge = BridgedPrompter(publish)
    bridge._session_allowed.add("http " + ORIGIN)
    with pytest.raises(HTTPBlocked, match="denied"):
        await registry.execute("http", args(), None, YoloPrompter(bridge, False))
    assert len(dialogs) == 1 and not sent and not tool.permissions.grants


@pytest.mark.asyncio
@pytest.mark.parametrize("activation", ["manual", "yolo"])
async def test_parallel_http_dispatch_cannot_exceed_request_budget(runtime, monkeypatch, activation):
    tool, registry, sent, _ = runtime
    operator = Operator()
    prompter = YoloPrompter(operator, activation == "yolo")
    if activation == "manual":
        grant = tool.permissions.activate(ORIGIN, HTTPLimits(requests=1, burst=10))
    else:
        prompter.bind_http_permissions(tool.permissions)
        grant = next(iter(tool.permissions.grants.values()))
        tool.permissions._budgets[grant.id].used = grant.limits.requests - 1
    used_before = tool.permissions._budgets[grant.id].used
    started, release = asyncio.Event(), asyncio.Event()

    async def waiting_send(self, request, **kwargs):
        sent.append(request)
        started.set()
        await release.wait()
        return httpx.Response(200, content=b"ok", request=request)

    monkeypatch.setattr(REAL_ASYNC_CLIENT, "send", waiting_send)
    first = asyncio.create_task(registry.execute("http", args(), None, prompter))
    await started.wait()
    results = await asyncio.gather(*[
        registry.execute("http", args("/new"), None, prompter) for _ in range(8)
    ], return_exceptions=True)
    assert all(isinstance(result, HTTPBlocked) for result in results)
    release.set()
    await first
    assert len(sent) == 1
    assert tool.permissions._budgets[grant.id].used == used_before + 1 and tool.permissions._budgets[grant.id].active == 0
    assert not operator.requests


@pytest.mark.asyncio
async def test_replacement_grant_cannot_hide_old_inflight_requests(runtime):
    tool, _, _, _ = runtime
    rights = tool.permissions
    rights.activate(ORIGIN, HTTPLimits(concurrency=1))
    action, _ = tool.prepare(args())
    receipt = await rights.authorize(action, Operator(), None, lambda: tool.target.revision)
    running = rights.reserve(action, receipt, None, tool.target.revision)
    running.start()
    rights.activate(ORIGIN, HTTPLimits(concurrency=1))
    new_receipt = await rights.authorize(action, Operator(), None, lambda: tool.target.revision)
    with pytest.raises(HTTPBlocked, match="concurrency"):
        rights.reserve(action, new_receipt, None, tool.target.revision)
    running.release()
    next_request = rights.reserve(action, new_receipt, None, tool.target.revision)
    next_request.release()
    assert not rights._inflight


@pytest.mark.asyncio
async def test_pending_cancelled_control_plane_grant_does_not_spawn_request_dialog(runtime):
    tool, registry, sent, _ = runtime
    opened = asyncio.Event()

    class Waiting(Operator):
        async def ask(self, request, signal=None):
            self.requests.append(request)
            opened.set()
            await asyncio.Event().wait()
            return Decision.ALLOW_ONCE

    operator = Waiting()
    task = asyncio.create_task(tool.permissions.review_grant(ORIGIN, HTTPLimits(), "autonomous", operator))
    await opened.wait()
    with pytest.raises(HTTPBlocked, match="already open"):
        await registry.execute("http", args(), None, operator)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(HTTPBlocked, match="previously"):
        await registry.execute("http", args(), None, operator)
    assert len(operator.requests) == 1 and not sent
