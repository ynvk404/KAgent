"""N1 through real Agent/registry/policy gates; no sockets or child processes.

Only DNS, TCP connect, HTTP transport and process launch boundaries are replaced.
The private-host classifier, receipts, permission review and budgets remain real.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
import errno
import json
import socket
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from src.engagement.state import OutOfScopeError
from src.permission.network.grants import HTTPLimits, HTTPBlocked, HTTPReviewTimeout
from src.permission.permission import Decision, UserControlledRefusal
from src.permission.runtime.execution import ExecutionBlocked, current_policy
from src.permission.runtime.invocations import review_turn
from src.tools.common.capabilities import CapabilityInventory
from src.tools.common.registry import InvalidToolArguments
from src.tools.discovery.service import ServiceDiscoveryTool
from src.workflow.state import WorkflowObjective
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.helpers.burp_selection import make_runtime


ORIGIN = "http://target.test:8080"
REAL_CLIENT = httpx.AsyncClient


@pytest.fixture
def boundary(monkeypatch):
    io = SimpleNamespace(
        connects=[], writers=[], dns=[], http=[], connect_error=None, connect_wait=None,
        connection_tasks=[], connect_started=asyncio.Event(), connect_finished=asyncio.Event())

    def resolve(host, *_args, **_kwargs):
        assert host == "target.test"
        io.dns.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0))]

    async def connect(host, port):
        policy = current_policy()
        assert policy is not None and policy.nested_allowed()
        rights = policy.engagement.http_permissions
        origin = next(iter(policy.engagement.allowed_origins))
        grant = rights.grants[origin]
        budget = rights._budgets[grant.id]
        # Observe the actual socket boundary after admission, without replacing
        # socket_budget/reserve/start or deriving TCP counts from HTTP output.
        assert budget.active == 1 and budget.used >= 1
        assert rights._inflight[grant.origin] == 1
        io.connects.append((host, port))
        io.connection_tasks.append(asyncio.current_task())
        io.connect_started.set()
        try:
            if io.connect_error is not None:
                raise io.connect_error
            if io.connect_wait is not None:
                await io.connect_wait.wait()
            writer = SimpleNamespace(close=Mock(), wait_closed=AsyncMock())
            io.writers.append(writer)
            return object(), writer
        finally:
            io.connect_finished.set()

    def respond(request):
        io.http.append(request)
        return httpx.Response(200, content=b"fixture unchanged", request=request)

    io.process = AsyncMock(side_effect=AssertionError("N1 must not launch a process"))
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", io.process)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: REAL_CLIENT(
        transport=httpx.MockTransport(respond), **kwargs))
    return io


@pytest.fixture
def runtime_factory(tmp_path, boundary):
    def factory(*, profile="full", nmap="/tools/nmap", coverage="missing", yolo=False, client=None, origin=ORIGIN):
        runtime = make_runtime(tmp_path, client, origin=origin, yolo=yolo)
        runtime.workflow.objective = WorkflowObjective(
            id="n1-service", mode="whole_target", target_origin=origin)
        if coverage == "performed":
            runtime.workflow.record_phase_coverage(
                "recon", "service_discovery", "performed",
                objective_id="n1-service", target_origin=origin)
        elif coverage == "no-workflow":
            runtime.workflow.objective = None
        runtime.inventory = CapabilityInventory(which=lambda name: nmap if name == "nmap" else None)
        runtime.service = ServiceDiscoveryTool(
            runtime.target, runtime.engagement, runtime.inventory, lambda: profile, runtime.workflow)
        runtime.registry.register(runtime.service)
        runtime.grant = runtime.engagement.http_permissions.activate(
            origin, HTTPLimits(requests=10, rate=100, burst=10))
        runtime.agent.tooling_profile = profile
        runtime.agent.rebuild_system_prompt()
        return runtime
    return factory


def assert_idle(runtime, boundary):
    assert runtime.policy.active == 0
    assert not runtime.policy._receipts and not runtime.policy._active_receipts
    assert not runtime.engagement.http_permissions._inflight
    assert not runtime.engagement.http_permissions._receipts
    assert not runtime.policy._pending and not runtime.policy._review_cleanups
    assert all(budget.active == 0 for budget in runtime.engagement.http_permissions._budgets.values())
    assert all(task.done() for task in boundary.connection_tasks)
    assert not boundary.http
    boundary.process.assert_not_awaited()


@pytest.mark.parametrize("profile", ["minimal", "full"])
@pytest.mark.parametrize("mode", ["auto", "socket"])
@pytest.mark.parametrize("nmap", [None, "/tools/nmap"])
@pytest.mark.parametrize("coverage", ["missing", "performed", "no-workflow"])
async def test_registry_selects_native_before_review_and_consumes_socket_budget(
    runtime_factory, boundary, profile, mode, nmap, coverage,
):
    runtime = runtime_factory(profile=profile, nmap=nmap, coverage=coverage)
    result = await runtime.registry.execute("service_discovery", {"mode": mode}, FakeSignal(), runtime.prompter)
    payload = json.loads(result)

    assert result.status == "observation" and payload["backend"] == "socket"
    assert payload["ports"] == [{"port": 8080, "protocol": "tcp", "state": "open"}]
    assert payload["completed_ports"] == 1 and payload["completed_port_count_exact"]
    assert boundary.dns == ["target.test"] and boundary.connects == [("127.0.0.1", 8080)]
    assert len(runtime.operator.requests) == 1
    request = runtime.operator.requests[0]
    assert request.tool == "service_discovery" and "backend: socket" in request.detail
    assert "using socket" in request.session_scope_display
    assert runtime.inventory.snapshot().nmap == nmap
    if profile == "full" and mode == "auto" and nmap:
        assert "nmap detected" in payload["backend_reason"]
        assert "execution unsupported" in payload["backend_reason"]
    budget = runtime.engagement.http_permissions._budgets[runtime.grant.id]
    assert budget.used == 1 and budget.active == 0 and runtime.policy.used == 1
    boundary.writers[0].wait_closed.assert_awaited_once()
    boundary.writers[0].close.assert_called_once()
    if coverage != "no-workflow":
        assert runtime.workflow.phase_coverage_record("recon", "service_discovery").status == "performed"
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("origin,port", [
    ("http://target.test", 80), ("http://target.test:80", 80),
    ("https://target.test", 443), ("https://target.test:8443", 8443),
])
async def test_native_uses_only_effective_active_port(runtime_factory, boundary, origin, port):
    runtime = runtime_factory(origin=origin)
    result = await runtime.registry.execute(
        "service_discovery", {"target": origin, "ports": [port]}, None, runtime.prompter)
    assert json.loads(result)["requested_ports"] == [port]
    assert boundary.connects == [("127.0.0.1", port)]
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("mode", ["auto", "socket"])
async def test_registry_denial_stops_before_resolution_or_connect(runtime_factory, boundary, mode):
    runtime = runtime_factory()
    runtime.operator.decision = Decision.DENY

    with pytest.raises(UserControlledRefusal, match="permission denied"):
        await runtime.registry.execute("service_discovery", {"mode": mode}, None, runtime.prompter)

    assert len(runtime.operator.requests) == 1
    assert not boundary.dns and not boundary.connects and runtime.policy.used == 0
    assert_idle(runtime, boundary)


async def test_direct_receipt_still_requires_private_host_permission(runtime_factory, boundary):
    runtime = runtime_factory()
    runtime.operator.decision = Decision.DENY
    with review_turn():
        token = runtime.policy.start(runtime.policy.prepare(runtime.service, {}), runtime.service, {}, None)
        try:
            with pytest.raises(UserControlledRefusal, match="private-host service discovery denied"):
                await runtime.service.run({}, None, runtime.prompter)
        finally:
            runtime.policy.stop(token)
    assert len(runtime.operator.requests) == 1
    assert "loopback IPv4" in runtime.operator.requests[0].detail
    assert boundary.dns == ["target.test"] and not boundary.connects
    assert runtime.engagement.http_permissions._budgets[runtime.grant.id].used == 0
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("yolo", [False, True])
@pytest.mark.parametrize("mode", ["auto", "socket"])
async def test_direct_bound_call_without_receipt_cannot_bypass_registry(runtime_factory, boundary, yolo, mode):
    runtime = runtime_factory(yolo=yolo)
    with pytest.raises(ExecutionBlocked, match="without-receipt"):
        await runtime.service.run({"mode": mode}, None, runtime.prompter)
    assert not runtime.operator.requests and not boundary.dns and not boundary.connects
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("args", [
    {"target": "other.test"}, {"target": "http://other.test:8080"},
    {"target": "https://target.test:8080"}, {"target": "http://target.test"},
    {"ports": [80]}, {"ports": [8080, 8081]}, {"mode": "nmap"},
])
async def test_exact_active_origin_and_port_rejected_before_review(runtime_factory, boundary, args):
    runtime = runtime_factory(yolo=True)
    with pytest.raises(InvalidToolArguments):
        await runtime.registry.execute("service_discovery", args, None, runtime.prompter)
    assert not runtime.operator.requests and not boundary.dns and not boundary.connects
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("change", ["tool-revoke", "origin-revoke", "session-deny", "scope", "target", "expired"])
async def test_review_change_cannot_dispatch_or_fallback(runtime_factory, boundary, change):
    runtime = runtime_factory()
    before = deepcopy(runtime.workflow.to_dict())
    clock = [runtime.policy.clock()]
    runtime.policy.clock = lambda: clock[0]

    async def review(request):
        assert "backend: socket" in request.detail
        if change == "tool-revoke":
            runtime.policy.revoke("service_discovery")
        elif change == "origin-revoke":
            runtime.engagement.http_permissions.revoke(runtime.grant.id)
        elif change == "session-deny":
            runtime.engagement.http_permissions.deny_session()
        elif change == "scope":
            runtime.engagement.remove_origin(ORIGIN)
        elif change == "target":
            runtime.target.set_base_url(ORIGIN + "/changed")
        else:
            clock[0] += runtime.policy.review_timeout + 1
        assert not request.is_current()

    runtime.operator.review = review
    with pytest.raises(ExecutionBlocked, match="stale") as failure:
        await runtime.registry.execute("service_discovery", {}, None, runtime.prompter)
    assert failure.value.error_kind == "policy_block" and not failure.value.explicit_denial
    assert runtime.workflow.to_dict() == before
    assert len(runtime.operator.requests) == 1
    assert not boundary.dns and not boundary.connects and runtime.policy.used == 0
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("block", ["tool-revoke", "origin-revoke", "session-deny", "call-budget", "scope"])
@pytest.mark.parametrize("yolo", [False, True])
async def test_existing_terminal_gates_remain_terminal(runtime_factory, boundary, block, yolo):
    runtime = runtime_factory(yolo=yolo)
    if block == "tool-revoke":
        runtime.policy.revoke("service_discovery")
    elif block == "origin-revoke":
        runtime.engagement.http_permissions.revoke(runtime.grant.id)
    elif block == "session-deny":
        runtime.engagement.http_permissions.deny_session()
    elif block == "call-budget":
        runtime.policy.max_calls = 1
        runtime.policy.used = 1
    else:
        runtime.engagement.remove_origin(ORIGIN)

    expected = OutOfScopeError if block == "scope" else UserControlledRefusal
    with pytest.raises(expected):
        await runtime.registry.execute("service_discovery", {}, None, runtime.prompter)
    assert not runtime.operator.requests and not boundary.dns and not boundary.connects
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("yolo", [False, True])
async def test_socket_budget_exhaustion_does_not_launch_or_retry(runtime_factory, boundary, yolo):
    runtime = runtime_factory(yolo=yolo)
    rights = runtime.engagement.http_permissions
    grant = rights.activate(ORIGIN, HTTPLimits(requests=1, rate=100, burst=1))
    first = await runtime.registry.execute("service_discovery", {}, None, runtime.prompter)
    original_result = str(first)
    original_coverage = runtime.workflow.phase_coverage_record("recon", "service_discovery")
    original_workflow = deepcopy(runtime.workflow.to_dict())

    with pytest.raises(HTTPBlocked, match="budget exhausted") as failure:
        await runtime.registry.execute("service_discovery", {}, None, runtime.prompter)
    assert failure.value.error_kind == "policy_block" and not failure.value.explicit_denial
    assert str(first) == original_result and json.loads(first)["completed_ports"] == 1
    assert runtime.workflow.phase_coverage_record("recon", "service_discovery") is original_coverage
    assert runtime.workflow.to_dict() == original_workflow
    assert boundary.connects == [("127.0.0.1", 8080)]
    assert rights._budgets[grant.id].used == 1
    assert len(runtime.operator.requests) == (0 if yolo else 2)
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("failure,state", [
    (ConnectionRefusedError(), "closed"), (asyncio.TimeoutError(), "filtered"),
    (PermissionError(errno.EACCES, "socket access denied"), "unknown"),
    (OSError(errno.ENETUNREACH, "network unreachable"), "unknown"),
])
async def test_native_connection_outcomes_keep_budget_and_coverage(runtime_factory, boundary, failure, state):
    runtime = runtime_factory()
    boundary.connect_error = failure
    result = await runtime.registry.execute("service_discovery", {}, None, runtime.prompter)
    payload = json.loads(result)
    assert result.status == "observation" and payload["ports"][0]["state"] == state
    assert payload["completed_ports"] == 1 and payload["completed_port_count_exact"]
    assert runtime.engagement.http_permissions._budgets[runtime.grant.id].used == 1
    assert runtime.workflow.phase_coverage_record("recon", "service_discovery").status == "performed"
    assert_idle(runtime, boundary)


def exhaust_budget(runtime):
    budget = runtime.engagement.http_permissions._budgets[runtime.grant.id]
    # Seed prior session consumption, not a prior service invocation/coverage.
    assert budget.limits.requests is not None
    budget.used = budget.limits.requests
    return budget


def expire_scheduler_window(runtime, monkeypatch):
    import src.permission.network.grants as grants

    rights = runtime.engagement.http_permissions
    now = rights.clock()
    rights.clock = lambda: now
    budget = rights._budgets[runtime.grant.id]
    budget.tokens = 0
    budget.updated_at = now
    # The actual scheduler sees rate pressure, then its 30s deadline. No gate
    # is replaced and no real delay or global asyncio/time monkeypatch is used.
    ticks = iter((0.0, 31.0))
    monkeypatch.setattr(grants, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    return budget


@pytest.mark.parametrize("yolo", [False, True])
@pytest.mark.parametrize("coverage", ["missing", "failed", "cancelled"])
async def test_exhausted_budget_on_first_service_call_cannot_attest_coverage(
    runtime_factory, boundary, yolo, coverage,
):
    runtime = runtime_factory(yolo=yolo)
    if coverage != "missing":
        runtime.workflow.record_phase_coverage(
            "recon", "service_discovery", coverage, objective_id="n1-service",
            target_origin=ORIGIN, reason="earlier incomplete service check")
    before = deepcopy(runtime.workflow.to_dict())
    budget = exhaust_budget(runtime)
    used = budget.used

    with pytest.raises(HTTPBlocked, match="budget exhausted") as failure:
        await runtime.registry.execute("service_discovery", {}, None, runtime.prompter)

    assert failure.value.error_kind == "policy_block" and not failure.value.explicit_denial
    assert not boundary.connects and runtime.workflow.to_dict() == before
    assert budget.used == used and budget.limits == runtime.grant.limits
    assert runtime.engagement.http_permissions.grants[runtime.grant.origin] is runtime.grant
    assert len(runtime.operator.requests) == (0 if yolo else 1)
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("yolo", [False, True])
async def test_real_scheduler_timeout_is_not_a_filtered_port(runtime_factory, boundary, monkeypatch, yolo):
    runtime = runtime_factory(yolo=yolo)
    before = deepcopy(runtime.workflow.to_dict())
    budget = expire_scheduler_window(runtime, monkeypatch)

    with pytest.raises(HTTPReviewTimeout, match="scheduling deadline") as failure:
        await runtime.registry.execute("service_discovery", {}, None, runtime.prompter)

    assert isinstance(failure.value, TimeoutError)
    assert failure.value.error_kind == "permission_timeout" and not failure.value.explicit_denial
    assert not boundary.connects and budget.used == 0
    assert runtime.workflow.to_dict() == before
    assert len(runtime.operator.requests) == (0 if yolo else 1)
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("block,kind,status,denied", [
    ("budget", "policy_block", "error", False),
    ("scheduler", "permission_timeout", "pending", False),
    ("deny", "permission_denied", "error", True),
])
async def test_agent_keeps_control_error_metadata(runtime_factory, boundary, monkeypatch, block, kind, status, denied):
    from src.llm.core.types import FunctionCall, ToolCall

    runtime = runtime_factory()
    if block == "budget":
        exhaust_budget(runtime)
    elif block == "scheduler":
        expire_scheduler_window(runtime, monkeypatch)
    else:
        runtime.operator.decision = Decision.DENY
    before = deepcopy(runtime.workflow.to_dict())
    call = ToolCall("n11-control", FunctionCall("service_discovery", "{}"))
    result = await runtime.agent.run_parsed_tool_call(call, runtime.agent.parse_tool_call(call), FakeSignal())

    assert (result.status, result.error_kind, result.terminal_user_controlled_refusal) == (status, kind, denied)
    assert str(result.result).startswith("ERROR:") and "completed_ports" not in result.result
    assert runtime.workflow.to_dict() == before and not boundary.connects
    assert len(runtime.operator.requests) == 1
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("yolo", [False, True])
@pytest.mark.parametrize("change", ["tool-revoke", "origin-revoke", "stale-profile", "scope", "session-deny"])
async def test_authority_change_during_dns_cannot_become_tcp_completion(
    runtime_factory, boundary, monkeypatch, change, yolo,
):
    runtime = runtime_factory(yolo=yolo)
    before = deepcopy(runtime.workflow.to_dict())
    budget = runtime.engagement.http_permissions._budgets[runtime.grant.id]
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    resolve = socket.getaddrinfo

    def paused_resolve(*args, **kwargs):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(2), "DNS test boundary was not released"
        return resolve(*args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", paused_resolve)
    invocation = asyncio.create_task(runtime.registry.execute("service_discovery", {}, None, runtime.prompter))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        if change == "tool-revoke":
            runtime.policy.revoke("service_discovery")
        elif change == "origin-revoke":
            runtime.engagement.http_permissions.revoke(runtime.grant.id)
        elif change == "stale-profile":
            runtime.policy.protected += (runtime.policy.root / "additional-protected",)
        elif change == "scope":
            runtime.engagement.remove_origin(ORIGIN)
        else:
            runtime.engagement.http_permissions.deny_session()
        release.set()
        expected = OutOfScopeError if change == "scope" else ExecutionBlocked
        with pytest.raises(expected) as failure:
            await asyncio.wait_for(invocation, 1)
        if isinstance(failure.value, ExecutionBlocked):
            assert failure.value.error_kind == "policy_block" and not failure.value.explicit_denial
    finally:
        release.set()
        invocation.cancel()
        await asyncio.gather(invocation, return_exceptions=True)

    assert not boundary.connects and budget.used == 0 and budget.active == 0
    assert runtime.workflow.to_dict() == before
    assert len(runtime.operator.requests) == (0 if yolo else 1)
    assert_idle(runtime, boundary)


async def test_control_failure_cleans_up_native_fanout(runtime_factory, boundary):
    runtime = runtime_factory()
    boundary.connect_wait = asyncio.Event()
    with review_turn():
        token = runtime.policy.start(runtime.policy.prepare(runtime.service, {}), runtime.service, {}, None)
        try:
            # Exercise the private helper's task cleanup under the real port
            # gate. Public args still permit only the one active URL port.
            with pytest.raises(ExecutionBlocked, match="socket-port-outside-profile") as failure:
                await runtime.service._scan_sockets("127.0.0.1", (8080, 8081), 20, None)
        finally:
            runtime.policy.stop(token)

    assert failure.value.error_kind == "policy_block" and not failure.value.explicit_denial
    assert boundary.connect_started.is_set() and boundary.connect_finished.is_set()
    assert boundary.connects == [("127.0.0.1", 8080)]
    assert runtime.engagement.http_permissions._budgets[runtime.grant.id].used == 1
    assert runtime.workflow.phase_coverage_record("recon", "service_discovery") is None
    assert_idle(runtime, boundary)


@pytest.mark.parametrize("cancel", ["signal", "task"])
async def test_cancellation_reaps_native_connect_and_reservation(runtime_factory, boundary, cancel):
    runtime = runtime_factory()
    boundary.connect_wait = asyncio.Event()
    signal = FakeSignal()
    invocation = asyncio.create_task(runtime.registry.execute("service_discovery", {}, signal, runtime.prompter))
    try:
        await asyncio.wait_for(boundary.connect_started.wait(), 1)
        if cancel == "signal":
            signal.aborted = True
            result = await asyncio.wait_for(invocation, 1)
            payload = json.loads(result)
            assert result.status == "cancelled" and result.error_kind == "cancelled"
            assert payload["completed_ports"] == 0 and payload["ports"][0]["state"] == "unknown"
            coverage = runtime.workflow.phase_coverage_record("recon", "service_discovery")
            assert coverage.status == "cancelled"
        else:
            invocation.cancel()
            with pytest.raises(asyncio.CancelledError):
                await invocation
            assert runtime.workflow.phase_coverage_record("recon", "service_discovery") is None
    finally:
        invocation.cancel()
        await asyncio.gather(invocation, return_exceptions=True)

    assert boundary.connect_finished.is_set()
    assert boundary.connects == [("127.0.0.1", 8080)]
    assert runtime.engagement.http_permissions._budgets[runtime.grant.id].used == 1
    assert_idle(runtime, boundary)


async def test_expired_dispatch_receipt_cannot_start_service(runtime_factory, boundary):
    runtime = runtime_factory()
    with review_turn():
        receipt = runtime.policy.prepare(runtime.service, {})
        runtime.policy.clock = lambda: receipt.expires + 1
        with pytest.raises(ExecutionBlocked, match="stale/replayed"):
            runtime.policy.start(receipt, runtime.service, {}, None)
    assert not boundary.connects and runtime.policy.used == 0
    assert_idle(runtime, boundary)


async def test_direct_benchmark_request_does_not_inject_service_discovery(runtime_factory, boundary):
    from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall

    def call(identifier, name, args):
        return ChatResponse(Message("assistant", "", tool_calls=[
            ToolCall(identifier, FunctionCall(name, json.dumps(args)))]), "tool_calls")

    client = FakeClient([
        call("skill", "load_skill", {"name": "sql-injection"}),
        call("request", "http", {"url": "/search?q=fixture", "phase": "validation"}),
        ChatResponse(Message("assistant", "Only the requested endpoint was inspected; no finding confirmed."), "stop"),
    ])
    runtime = runtime_factory(client=client, yolo=True)
    runtime.workflow.objective = None
    events = []
    await runtime.agent.run("Test only GET /search parameter q for SQL injection", FakeSignal(), events.append)

    assert len(boundary.http) == 1 and boundary.http[0].url.path == "/search"
    assert not boundary.connects
    assert not any(event.get("name") == "service_discovery" for event in events)
    assert not runtime.workflow.completed_phases()
    assert runtime.workflow.phase_coverage_record("recon", "service_discovery") is None
    boundary.process.assert_not_awaited()


async def test_burp_selected_request_keeps_replay_without_service_discovery(runtime_factory, boundary, tmp_path):
    from tests.integration.test_burp_selection import CaptureAwareClient, burp_ingest, slash
    from tests.helpers.burp_selection import ORIGIN as burp_origin

    runtime = runtime_factory(yolo=True, origin=burp_origin, client=CaptureAwareClient(tmp_path))
    runtime.workflow.objective = None
    selected = burp_ingest(runtime)
    slash(runtime, "/burp use " + selected["id"])
    events = []
    await runtime.agent.run("Test only the selected request for SQL injection", FakeSignal(), events.append)

    assert runtime.agent.client.finished and len(boundary.http) == 1
    assert boundary.http[0].method == "POST" and boundary.http[0].url.path == "/search"
    candidate = next(iter(runtime.workflow.candidates.values()))
    assert candidate.baseline_request_ref == selected["baseline_request_ref"]
    assert not boundary.connects
    assert not any(event.get("name") == "service_discovery" for event in events)
    assert runtime.workflow.phase_coverage_record("recon", "service_discovery") is None
    boundary.process.assert_not_awaited()
