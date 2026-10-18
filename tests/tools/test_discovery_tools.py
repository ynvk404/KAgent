from __future__ import annotations

import asyncio
import json
import socket
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlsplit

import pytest

from src.engagement.state import EngagementState, OutOfScopeError
from src.permission.permission import (
    AlwaysAllow, Decision, PermissionRequest, UserControlledRefusal, YoloPrompter,
    PermissionPolicyBlocked, PermissionReviewStale,
)
from src.permission.network.grants import HTTPBlocked, HTTPPending, HTTPReviewStale, HTTPReviewTimeout
from src.permission.runtime.execution import ExecutionBlocked
from src.target.target import Target
from src.tools.common.capabilities import CapabilityInventory
from src.tools.discovery.content import (
    ContentDiscoveryTool,
    MAX_REQUESTS,
)
from src.tools.discovery.service import ServiceDiscoveryTool
from src.tools.common.registry import Registry
from src.workflow.state import WorkflowObjective, WorkflowState
from tests.helpers.workflow import record_completed_phase


def make_workflow(*, phase: str = "recon", origin: str = "http://target.test:8080") -> WorkflowState:
    workflow = WorkflowState()
    workflow.objective = WorkflowObjective(
        id="discovery-test", mode="whole_target", target_origin=origin
    )
    if phase == "enumeration":
        record_completed_phase(
            workflow,
            "recon",
            objective_id="discovery-test",
            target_origin=origin,
            artifact_ref="artifacts/recon.md",
        )
    return workflow


@pytest.mark.parametrize('tool_type,mode,backend', [
    (ContentDiscoveryTool, 'auto', 'native'), (ServiceDiscoveryTool, 'auto', 'socket'),
])
def test_native_constructor_preserves_workflow_without_scanner_probe(tool_type, mode, backend, monkeypatch):
    import shutil
    target, engagement, workflow = Target('http://target.test:8080'), EngagementState(), make_workflow()
    def forbidden(*_args):
        pytest.fail('native discovery must not probe installed scanner binaries')
    monkeypatch.setattr(shutil, 'which', forbidden)
    tool = tool_type(target, engagement, workflow=workflow)
    assert tool.target is target and tool.engagement is engagement and tool.workflow is workflow
    assert tool._select_backend(mode) == backend


class Response:
    def __init__(self, status: int, body: bytes, headers: dict[str, str] | None = None):
        self.status_code = status
        self.headers = headers or {"content-type": "text/plain"}
        self._body = body

    async def aiter_bytes(self):
        yield self._body


class Stream:
    def __init__(self, response: Response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeHTTPClient:
    responses: dict[str, Response] = {}
    seen: list[str] = []

    def __init__(self, **_kwargs):
        self.responses = type(self).responses
        self.seen = type(self).seen

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def stream(self, method: str, url: str, **_kwargs):
        assert method == "GET"
        self.seen.append(url)
        path = url.split("?", 1)[0].rsplit("/", 1)[-1]
        response = self.responses.get(path, Response(404, b"not found"))
        return Stream(response)


class FakeWriter:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class RecordingPrompter:
    def __init__(self, decision: Decision = Decision.ALLOW_ONCE):
        self.requests: list[PermissionRequest] = []
        self.decision = decision

    async def ask(self, request: PermissionRequest, signal=None) -> Decision:
        self.requests.append(request)
        return self.decision


def make_content_tool(
    *,
    workflow: WorkflowState | None = None,
) -> ContentDiscoveryTool:
    target = Target("http://target.test:8080/app")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    return ContentDiscoveryTool(target, engagement, workflow=workflow)


def make_service_tool(
    *,
    workflow: WorkflowState | None = None,
) -> ServiceDiscoveryTool:
    target = Target("http://target.test:8080")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    tool = ServiceDiscoveryTool(target, engagement, workflow=workflow)
    setattr(
        tool,
        "_resolve_execution_addresses",
        AsyncMock(return_value=(["203.0.113.10"], None)),
    )
    return tool


@pytest.fixture(autouse=True)
def fake_content_network(monkeypatch):
    FakeHTTPClient.responses = {}
    FakeHTTPClient.seen = []
    monkeypatch.setattr("src.tools.discovery.content.httpx.AsyncClient", FakeHTTPClient)
    monkeypatch.setattr(
        "src.tools.discovery.content.gate_private_request",
        AsyncMock(return_value=""),
    )

    async def no_wait(_delay: float, _signal):
        return True

    monkeypatch.setattr("src.tools.discovery.content.sleep_or_abort", no_wait)


def test_capability_inventory_detects_once_and_missing_tools_are_supported():
    calls: list[str] = []

    def which(name: str) -> str | None:
        calls.append(name)
        return f"/tools/{name}" if name == "ffuf" else None

    inventory = CapabilityInventory(which=which)
    first = inventory.snapshot()
    second = inventory.snapshot()

    assert first is second
    assert first.ffuf == "/tools/ffuf"
    assert first.nmap is None
    assert calls == ["ffuf", "nmap"]
    assert first.prompt_summary() == "ffuf"


def test_capability_inventory_empty_does_not_raise():
    inventory = CapabilityInventory(which=lambda _name: None)
    assert inventory.snapshot().prompt_summary() == "native tools only"


def test_capability_inventory_invalidates_only_the_matching_stale_binary():
    inventory = CapabilityInventory(which=lambda name: f"/tools/{name}")
    inventory.snapshot()
    inventory.mark_unavailable("ffuf", "/tools/other-ffuf")
    assert inventory.snapshot().ffuf == "/tools/ffuf"
    inventory.mark_unavailable("ffuf", "/tools/ffuf")
    assert inventory.snapshot().ffuf is None
    assert inventory.snapshot().nmap == "/tools/nmap"


def test_content_discovery_requires_active_exact_origin_and_effective_port():
    tool = make_content_tool()
    tool.validate_args({"base_url": "/admin", "paths": ["health"]})
    with pytest.raises(ValueError, match="active target origin"):
        tool.validate_args({"base_url": "http://other.test:8080", "paths": ["health"]})
    with pytest.raises(ValueError, match="active target origin"):
        tool.validate_args({"base_url": "http://target.test/admin", "paths": ["health"]})


def test_content_discovery_rejects_path_traversal_raw_flags_and_unbounded_limits():
    tool = make_content_tool()
    for path in (
        "../admin", "%2e%2e/admin", "%252e%252e%252fadmin",
        "admin?x=1", "http://other.test/x",
    ):
        with pytest.raises(ValueError):
            tool.validate_args({"paths": [path]})
    with pytest.raises(ValueError, match="max_requests"):
        tool.validate_args({"max_requests": MAX_REQUESTS + 1})
    with pytest.raises(ValueError, match="extensions"):
        tool.validate_args({"extensions": ["json/../../etc"]})
    with pytest.raises(ValueError, match="dot segments"):
        tool.validate_args({"base_url": "/app/%2e%2e/admin", "paths": ["health"]})
    with pytest.raises(ValueError, match="encoded path delimiters"):
        tool.validate_args({"base_url": "/app%2fadmin", "paths": ["health"]})


def test_content_base_path_normalization_is_shared_by_permission_and_execution():
    tool = make_content_tool()
    encoded = tool.permission_hints({"base_url": "/app/%41", "paths": ["health"]})
    canonical = tool.permission_hints({"base_url": "/app/A", "paths": ["health"]})
    assert isinstance(encoded.get("cacheKey"), str)
    assert encoded.get("cacheKey") == canonical.get("cacheKey")
    encoded_path = tool.permission_hints({"paths": ["%41dmin"]})
    canonical_path = tool.permission_hints({"paths": ["Admin"]})
    assert encoded_path.get("cacheKey") == canonical_path.get("cacheKey")
    canonical_host = tool.permission_hints({
        "base_url": "http://TARGET.TEST:8080/app/A", "paths": ["health"]
    })
    assert canonical_host.get("cacheKey") == canonical.get("cacheKey")
    assert tool.summarize({"base_url": "/app/%41"})["summary"] == (
        "content discovery: http://target.test:8080/app/A"
    )
    default_port_tool = make_content_tool()
    default_port_tool.target = Target("http://target.test/app")
    default_port_tool.engagement = EngagementState()
    default_port_tool.engagement.initialize_target(default_port_tool.target.base_url())
    default = default_port_tool.permission_hints({"base_url": "/app/A", "paths": ["health"]})
    explicit_80 = default_port_tool.permission_hints({
        "base_url": "http://target.test:80/app/A", "paths": ["health"]
    })
    assert default.get("cacheKey") == explicit_80.get("cacheKey")


@pytest.mark.parametrize("mode", ["auto", "native"])
@pytest.mark.parametrize("coverage", ["no-workflow", "missing", "performed"])
def test_content_discovery_always_selects_native(mode, coverage, monkeypatch):
    workflow = None if coverage == "no-workflow" else make_workflow(phase="enumeration")
    if coverage == "performed":
        assert workflow is not None and workflow.objective is not None
        workflow.record_phase_coverage(
            "enumeration", "active_content_discovery", "performed",
            objective_id=workflow.objective.id,
            target_origin=workflow.objective.target_origin or "",
        )
    # Native discovery must not inspect installed scanner executables.
    monkeypatch.setattr(CapabilityInventory, "snapshot", lambda self: pytest.fail("scanner lookup"))
    tool = make_content_tool(workflow=workflow)
    assert tool._select_backend(mode, max_requests=6) == "native"
    assert "backend: native" in tool.summarize({"mode": mode})["detail"]
    with pytest.raises(ValueError, match="mode"):
        tool.validate_args({"mode": "ffuf"})


def test_content_permission_summary_and_cache_key_cover_scope_and_budget():
    tool = make_content_tool()
    first = tool.permission_hints({"paths": ["admin"], "max_requests": 8})
    second = tool.permission_hints({"paths": ["admin"], "max_requests": 9})
    detail = tool.summarize({"paths": ["admin"], "max_requests": 8})["detail"]
    first_key = first.get("cacheKey")
    second_key = second.get("cacheKey")
    display = first.get("sessionScopeDisplay")
    assert isinstance(first_key, str) and isinstance(second_key, str)
    assert first.get("yoloAutoApprove") is True
    assert first.get("riskTier") == "routine"
    assert first.get("noSessionCache", False) is False
    assert first_key != second_key
    assert isinstance(display, str) and "http://target.test:8080" in display
    assert "maximum requests: 8" in detail
    assert "raw" not in detail.lower()


@pytest.mark.asyncio
async def test_yolo_auto_approves_in_scope_content_enumeration():
    tool = make_content_tool()
    registry = Registry()
    registry.register(tool)
    inner = RecordingPrompter(Decision.DENY)

    await registry.execute(
        "content_discovery",
        {"paths": ["health"], "max_requests": 4},
        None,
        YoloPrompter(inner, True),
    )

    assert inner.requests == []


@pytest.mark.asyncio
async def test_content_discovery_filters_spa_wildcard_and_reports_bounded_structured_hits(monkeypatch):
    FakeHTTPClient.responses = {
        "kagent-missing-does-not-matter": Response(200, b"spa"),
        "admin": Response(200, b"real admin page"),
    }

    class SPAClient(FakeHTTPClient):
        def stream(self, method: str, url: str, **kwargs):
            self.seen.append(url)
            if "kagent-missing-" in url:
                return Stream(Response(200, b"same app shell"))
            path = url.rstrip("/").rsplit("/", 1)[-1]
            if path == "admin":
                return Stream(Response(200, b"admin page"))
            return Stream(Response(200, b"same app shell"))

    tool = make_content_tool()
    monkeypatch.setattr("src.tools.discovery.content.httpx.AsyncClient", SPAClient)
    output = await tool.run(
        {"paths": ["admin", "missing"], "max_requests": 4},
        None,
        AlwaysAllow(),
    )

    payload = json.loads(str(output))
    assert output.status == "observation"
    assert [item["path"] for item in payload["discovered"]] == ["admin"]
    assert payload["requested_requests"] == 4
    assert payload["completed_requests"] == 4
    assert payload["completed_request_count_exact"] is True
    assert payload["rejected"][0]["reason"] == "wildcard_or_spa_baseline"
    assert all("body" not in item for item in payload["discovered"])
    assert payload["backend_reason"] == "native HTTP discovery; external ffuf uses typed Shell scanner jobs"


@pytest.mark.asyncio
async def test_content_discovery_uses_two_random_baselines_and_normalizes_dynamic_shell(monkeypatch):
    class DynamicSPAClient(FakeHTTPClient):
        def stream(self, method: str, url: str, **kwargs):
            self.seen.append(url)
            path = urlsplit(url).path
            timestamp = "2026-09-27T12:34:56Z"
            return Stream(Response(200, f"shell:{path}:request=123456789012:{timestamp}".encode()))

    monkeypatch.setattr("src.tools.discovery.content.httpx.AsyncClient", DynamicSPAClient)
    tool = make_content_tool()
    output = await tool.run({"paths": ["admin"], "max_requests": 3}, None, AlwaysAllow())
    payload = json.loads(str(output))

    baseline = payload["wildcard_baseline"]
    assert len(baseline) == 2
    baseline_paths = {urlsplit(url).path.rsplit("/", 1)[-1] for url in DynamicSPAClient.seen[:2]}
    assert len(baseline_paths) == 2
    assert payload["discovered"] == []
    assert payload["rejected"][0]["reason"] == "wildcard_or_spa_baseline"
    assert payload["requested_requests"] == payload["completed_requests"] == 3


@pytest.mark.asyncio
async def test_content_auto_explains_native_discovery():
    tool = make_content_tool()
    output = await tool.run(
        {"paths": ["admin"], "max_requests": 3}, None, AlwaysAllow()
    )
    payload = json.loads(str(output))
    assert payload["backend"] == "native"
    assert payload["backend_reason"] == "native HTTP discovery; external ffuf uses typed Shell scanner jobs"


@pytest.mark.asyncio
async def test_content_discovery_does_not_follow_or_expose_external_redirect_query(monkeypatch):
    class RedirectClient(FakeHTTPClient):
        def stream(self, method: str, url: str, **kwargs):
            self.seen.append(url)
            if "kagent-missing-" in url:
                return Stream(Response(404, b"not found"))
            return Stream(Response(302, b"", {"location": "https://other.test/path?token=secret"}))

    tool = make_content_tool()
    monkeypatch.setattr("src.tools.discovery.content.httpx.AsyncClient", RedirectClient)
    output = await tool.run({"paths": ["redirect"], "max_requests": 3}, None, AlwaysAllow())

    payload = json.loads(str(output))
    assert len(FakeHTTPClient.seen) == 3
    assert all(url.startswith("http://target.test:8080/") for url in FakeHTTPClient.seen)
    assert payload["discovered"][0]["redirect"] == "[external redirect not followed]"
    assert "secret" not in str(payload)


@pytest.mark.asyncio
async def test_content_discovery_cancels_an_inflight_baseline(monkeypatch):
    workflow = make_workflow(phase="enumeration")
    tool = make_content_tool(workflow=workflow)
    started = asyncio.Event()

    async def blocked_probe(_client, _url: str, _timeout: float):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(tool, "_read_probe", blocked_probe)

    class AbortSignal:
        aborted = False

    signal = AbortSignal()
    task = asyncio.create_task(
        tool.run({"paths": ["admin"]}, signal, AlwaysAllow())
    )
    await asyncio.wait_for(started.wait(), timeout=1)
    signal.aborted = True
    output = await asyncio.wait_for(task, timeout=1)

    payload = json.loads(str(output))
    assert output.status == "cancelled"
    assert payload["reason"] == "cancelled during wildcard baseline"
    assert payload["phase_coverage"]["status"] == "cancelled"
    coverage_record = workflow.phase_coverage_record("enumeration", "active_content_discovery")
    assert coverage_record is not None
    assert coverage_record.status == "cancelled"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["auto", "native"])
async def test_native_content_preserves_paths_extensions_budget_and_coverage(mode, monkeypatch):
    workflow = make_workflow(phase="enumeration")
    tool = make_content_tool(workflow=workflow)
    FakeHTTPClient.responses = {
        "admin": Response(200, b"admin page"),
        "admin.json": Response(200, b"admin metadata"),
    }
    launch = AsyncMock(side_effect=AssertionError("native discovery must not spawn"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", launch)
    output = await tool.run(
        {"paths": ["admin", "settings"], "extensions": ["json"], "mode": mode, "max_requests": 6},
        None, AlwaysAllow(),
    )
    payload = json.loads(str(output))
    assert payload["backend"] == "native"
    assert payload["requested_requests"] == payload["completed_requests"] == 6
    assert payload["completed_request_count_exact"] is True
    assert {urlsplit(url).path for url in FakeHTTPClient.seen[2:]} == {
        "/app/admin", "/app/settings", "/app/admin.json", "/app/settings.json",
    }
    assert [item["path"] for item in payload["discovered"]] == ["admin", "admin.json"]
    assert all(item["verified"] for item in payload["discovered"])
    assert payload["phase_coverage"] == {
        "phase": "enumeration", "dimension": "active_content_discovery",
        "status": "performed", "changed": True, "source": "content_discovery",
    }
    launch.assert_not_awaited()


@pytest.mark.asyncio
async def test_content_discovery_reports_unscanned_paths_and_keeps_coverage_retryable():
    workflow = make_workflow(phase="enumeration")
    tool = make_content_tool(workflow=workflow)
    output = await tool.run(
        {"paths": ["one", "two", "three"], "max_requests": 3},
        None,
        AlwaysAllow(),
    )
    payload = json.loads(str(output))

    assert output.status == "observation"
    assert payload["requested_paths"] == 3 and payload["scanned_paths"] == 1
    assert "covered 1 of 3 requested paths" in payload["reason"]
    coverage = workflow.phase_coverage_record("enumeration", "active_content_discovery")
    assert coverage is not None and coverage.status == "failed"
    assert payload["phase_coverage"]["status"] == "failed"
    assert payload["phase_coverage"]["changed"] is True
    assert tool._select_backend("auto") == "native"


@pytest.mark.asyncio
async def test_content_discovery_omits_attestation_without_qualifying_phase():
    workflow = make_workflow(phase="recon")
    tool = make_content_tool(workflow=workflow)
    output = await tool.run({"paths": ["admin"], "max_requests": 3}, None, AlwaysAllow())
    payload = json.loads(str(output))
    assert "phase_coverage" not in payload
    assert workflow.phase_coverage_record("enumeration", "active_content_discovery") is None


@pytest.mark.asyncio
async def test_content_discovery_omits_attestation_when_recording_fails(monkeypatch):
    workflow = make_workflow(phase="enumeration")
    tool = make_content_tool(workflow=workflow)

    def reject_record(*args, **kwargs):
        raise ValueError("phase changed")

    monkeypatch.setattr(WorkflowState, "record_phase_coverage", reject_record)
    output = await tool.run({"paths": ["admin"], "max_requests": 3}, None, AlwaysAllow())
    assert "phase_coverage" not in json.loads(str(output))
    assert workflow.phase_coverage_record("enumeration", "active_content_discovery") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["baseline", "path"])
async def test_native_content_timeout_preserves_failure_and_coverage(stage, monkeypatch):
    tool = make_content_tool(workflow=make_workflow(phase="enumeration"))
    original = tool._probe
    async def timeout_probe(client, url, signal, deadline):
        if stage == "baseline" or ".kagent-missing-" not in url:
            return None, "timeout"
        return await original(client, url, signal, deadline)
    monkeypatch.setattr(tool, "_probe", timeout_probe)
    output = await tool.run({"paths": ["admin"], "max_requests": 3}, None, AlwaysAllow())
    payload = json.loads(str(output))
    assert output.status == "error" and output.error_kind == "timeout"
    assert payload["completed_requests"] == (0 if stage == "baseline" else 2)
    assert payload["phase_coverage"]["status"] == "failed"


def test_service_target_and_ports_are_constrained():
    tool = make_service_tool()
    tool.validate_args({"target": "target.test", "ports": [8080]})
    with pytest.raises(ValueError, match="effective port"):
        tool.validate_args({"ports": [80, 8080]})
    with pytest.raises(ValueError, match="active target"):
        tool.validate_args({"target": "other.test", "ports": [80]})
    with pytest.raises(ValueError, match="query or fragment"):
        tool.validate_args({"target": "http://target.test:8080/?token=secret", "ports": [80]})
    for target in ("10.0.0.0/24", "target.test,other.test", "*.target.test"):
        with pytest.raises(ValueError):
            tool.validate_args({"target": target, "ports": [80]})
    for target in ("-p80,443", "127.1", "target.test=127.0.0.1"):
        with pytest.raises(ValueError):
            tool.validate_args({"target": target})
    for ports in ([0], [65536], [True], list(range(1, 102))):
        with pytest.raises(ValueError):
            tool.validate_args({"ports": ports})

    target = Target("http://-oN-output.xml")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    unsafe_host = ServiceDiscoveryTool(target, engagement)
    with pytest.raises(ValueError, match="valid hostname"):
        unsafe_host.validate_args({})


@pytest.mark.parametrize("mode", ["auto", "socket"])
@pytest.mark.parametrize("coverage", ["no-workflow", "missing", "performed"])
def test_service_always_selects_native(mode, coverage, monkeypatch):
    workflow = None if coverage == "no-workflow" else make_workflow()
    if coverage == "performed":
        assert workflow is not None and workflow.objective is not None
        workflow.record_phase_coverage(
            "recon", "service_discovery", "performed",
            objective_id=workflow.objective.id,
            target_origin=workflow.objective.target_origin or "",
        )
    monkeypatch.setattr(CapabilityInventory, "snapshot", lambda self: pytest.fail("scanner lookup"))
    tool = make_service_tool(workflow=workflow)
    assert tool._select_backend(mode) == "socket"
    assert "backend: socket" in tool.summarize({"mode": mode})["detail"]
    display = tool.permission_hints({"mode": mode}).get("sessionScopeDisplay")
    assert isinstance(display, str) and "using socket" in display


def test_service_cannot_request_nmap_execution_by_mode():
    with pytest.raises(ValueError, match="mode"):
        make_service_tool().validate_args({"mode": "nmap"})


@pytest.mark.asyncio
async def test_service_socket_backend_reports_open_and_closed_without_subprocess(monkeypatch):
    tool = make_service_tool()
    monkeypatch.setattr("src.tools.discovery.service.private_host_reason", AsyncMock(return_value=""))

    async def fake_open_connection(host: str, port: int):
        assert host == "203.0.113.10"
        return object(), FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    output = await tool.run({"mode": "socket", "ports": [8080]}, None, AlwaysAllow())
    payload = json.loads(str(output))

    assert output.status == "observation"
    assert [(item["port"], item["state"]) for item in payload["ports"]] == [(8080, "open")]
    assert payload["resolved_address"] == "203.0.113.10"
    assert payload["completed_ports"] == 1
    assert payload["completed_port_count_exact"] is True
    assert payload["scan_started"] is True
    assert payload["scan_duration_seconds"] >= 0
    assert payload["permission_wait_seconds"] >= 0
    assert payload["backend_reason"] == "socket backend explicitly selected"


@pytest.mark.asyncio
async def test_service_auto_explains_native_tcp(monkeypatch):
    tool = make_service_tool()
    monkeypatch.setattr("src.tools.discovery.service.private_host_reason", AsyncMock(return_value=""))
    monkeypatch.setattr(tool, "_scan_sockets", AsyncMock(return_value=([], "success", None)))
    output = await tool.run({}, None, AlwaysAllow())
    payload = json.loads(str(output))
    assert payload["backend"] == "socket"
    assert payload["backend_reason"] == "native TCP discovery; external Nmap uses typed Shell scanner jobs"


@pytest.mark.asyncio
async def test_service_socket_backend_cancels_pending_connections_promptly(monkeypatch):
    tool = make_service_tool()
    monkeypatch.setattr("src.tools.discovery.service.private_host_reason", AsyncMock(return_value=""))
    started = asyncio.Event()

    async def blocked_connection(_host: str, _port: int):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(asyncio, "open_connection", blocked_connection)

    class AbortSignal:
        aborted = False

    signal = AbortSignal()
    task = asyncio.create_task(
        tool.run({"mode": "socket", "ports": [8080]}, signal, AlwaysAllow())
    )
    await asyncio.wait_for(started.wait(), timeout=1)
    signal.aborted = True
    output = await asyncio.wait_for(task, timeout=1)

    payload = json.loads(str(output))
    assert output.status == "cancelled"
    assert payload["reason"] == "cancelled during socket checks"
    assert payload["ports"][0]["state"] == "unknown"
    assert payload["completed_ports"] == 0
    assert payload["completed_port_count_exact"] is True


@pytest.mark.parametrize("port,scheme", [(80, "http"), (443, "https")])
def test_native_service_origin_suggestions_do_not_authorize_origins(port, scheme):
    tool = make_service_tool()
    origin = tool.target.origin()
    assert origin is not None
    entries = [{"port": port, "protocol": "tcp", "state": "open", "_completed": True}]
    output = tool._result(origin, "target.test", "socket", (port,), entries, time.monotonic(), "success", None)
    payload = json.loads(str(output))
    assert payload["http_origin_suggestions"] == [scheme + "://target.test"]
    assert payload["suggestions_authorized"] is False
    assert tool.engagement.allowed_origins == {origin}


@pytest.mark.asyncio
async def test_service_dns_checks_all_answers_and_scans_only_a_vetted_numeric_ip(monkeypatch):
    tool = make_service_tool()
    resolver = AsyncMock(return_value=( ["8.8.8.8", "127.0.0.1"], None ))
    monkeypatch.setattr(tool, "_resolve_execution_addresses", resolver)
    reasons: list[str] = []

    async def private_reason(address: str) -> str:
        reasons.append(address)
        return "loopback IPv4" if address == "127.0.0.1" else ""

    monkeypatch.setattr("src.tools.discovery.service.private_host_reason", private_reason)
    observed: list[str] = []

    async def scan(address: str, ports: tuple[int, ...], _timeout: int, _signal):
        observed.append(address)
        return ([{"port": 8080, "state": "open", "protocol": "tcp", "_completed": True}], "success", None)

    monkeypatch.setattr(tool, "_scan_sockets", scan)
    prompter = RecordingPrompter()
    output = await tool.run({}, None, prompter)
    payload = json.loads(str(output))

    assert reasons == ["8.8.8.8", "127.0.0.1"]
    assert observed == ["8.8.8.8"]
    assert payload["resolved_address"] == "8.8.8.8"
    assert len(prompter.requests) == 1 and not prompter.requests[0].no_session_cache
    assert "8.8.8.8, 127.0.0.1" in prompter.requests[0].detail
    assert "selected execution address: 8.8.8.8" in prompter.requests[0].detail


@pytest.mark.asyncio
async def test_service_dns_resolution_is_deterministic_bounded_and_fails_closed(monkeypatch):
    tool = make_service_tool()
    answers = [
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:4860:4860::8888", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 0)),
    ]
    monkeypatch.setattr("src.tools.discovery.service.socket.getaddrinfo", lambda *_args: answers)
    resolved, error = await ServiceDiscoveryTool._resolve_execution_addresses(
        tool, "target.test", 5, None
    )
    assert resolved == ["8.8.8.8", "2001:4860:4860::8888"]
    assert error is None

    many_answers = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (f"8.8.8.{index}", 0))
        for index in range(1, 18)
    ]
    monkeypatch.setattr("src.tools.discovery.service.socket.getaddrinfo", lambda *_args: many_answers)
    resolved, error = await ServiceDiscoveryTool._resolve_execution_addresses(
        tool, "target.test", 5, None
    )
    assert resolved == [] and error == "failed"


@pytest.mark.asyncio
async def test_private_service_discovery_uses_cacheable_active_target_policy(monkeypatch):
    tool = make_service_tool()
    monkeypatch.setattr(
        "src.tools.discovery.service.private_host_reason",
        AsyncMock(return_value="loopback IPv4"),
    )
    monkeypatch.setattr(
        tool,
        "_scan_sockets",
        AsyncMock(return_value=([], "success", None)),
    )
    prompter = RecordingPrompter()

    await tool.run({"mode": "socket"}, None, prompter)

    assert len(prompter.requests) == 1
    assert prompter.requests[0].no_session_cache is False
    assert prompter.requests[0].risk_tier == "routine"
    assert prompter.requests[0].yolo_auto_approve is True
    assert "8080" in prompter.requests[0].detail


@pytest.mark.asyncio
async def test_service_discovery_coalesces_private_gate_with_registry_approval(monkeypatch):
    tool = make_service_tool()
    monkeypatch.setattr(
        "src.tools.discovery.service.private_host_reason",
        AsyncMock(return_value="loopback IPv4"),
    )
    monkeypatch.setattr(
        tool,
        "_scan_sockets",
        AsyncMock(return_value=([], "success", None)),
    )
    registry = Registry()
    registry.register(tool)
    prompter = RecordingPrompter()

    await registry.execute("service_discovery", {"mode": "socket"}, None, prompter)

    assert len(prompter.requests) == 1
    assert prompter.requests[0].risk_tier == "routine"
    assert prompter.requests[0].yolo_auto_approve is True


@pytest.mark.asyncio
async def test_yolo_auto_approves_in_scope_service_discovery_once(monkeypatch):
    tool = make_service_tool()
    monkeypatch.setattr(
        "src.tools.discovery.service.private_host_reason",
        AsyncMock(return_value="loopback IPv4"),
    )
    monkeypatch.setattr(
        tool,
        "_scan_sockets",
        AsyncMock(return_value=([], "success", None)),
    )
    registry = Registry()
    registry.register(tool)
    inner = RecordingPrompter(Decision.DENY)

    await registry.execute(
        "service_discovery",
        {"mode": "socket"},
        None,
        YoloPrompter(inner, True),
    )

    assert inner.requests == []


@pytest.mark.asyncio
async def test_private_service_discovery_denial_never_starts_scan(monkeypatch):
    tool = make_service_tool()
    monkeypatch.setattr(
        "src.tools.discovery.service.private_host_reason",
        AsyncMock(return_value="loopback IPv4"),
    )
    scanner = AsyncMock(return_value=([], "success", None))
    monkeypatch.setattr(tool, "_scan_sockets", scanner)
    prompter = RecordingPrompter(Decision.DENY)

    with pytest.raises(UserControlledRefusal, match="private-host service discovery denied"):
        await tool.run({}, None, prompter)

    scanner.assert_not_awaited()
    assert len(prompter.requests) == 1
    assert prompter.requests[0].no_session_cache is False


@pytest.mark.asyncio
async def test_service_scan_timeout_excludes_permission_wait(monkeypatch):
    tool = make_service_tool()
    clock = [0.0]
    monkeypatch.setattr(
        "src.tools.discovery.service.time",
        SimpleNamespace(monotonic=lambda: clock[0]),
    )
    monkeypatch.setattr(
        "src.tools.discovery.service.private_host_reason",
        AsyncMock(return_value="private address"),
    )
    scan_timeouts: list[float] = []

    class DelayedPrompter:
        async def ask(self, request: PermissionRequest, signal=None) -> Decision:
            assert request.no_session_cache is False
            clock[0] += 8.0
            return Decision.ALLOW_ONCE

    async def scan(_address, ports, timeout, _signal):
        scan_timeouts.append(timeout)
        return ([
            {"port": port, "state": "closed", "protocol": "tcp", "_completed": True}
            for port in ports
        ], "success", None)

    monkeypatch.setattr(tool, "_scan_sockets", scan)
    output = await tool.run(
        {"mode": "socket", "timeout_seconds": 5}, None,
        DelayedPrompter(),
    )
    payload = json.loads(str(output))

    assert scan_timeouts == [5]
    assert payload["permission_wait_seconds"] == 8.0
    assert payload["scan_duration_seconds"] == 0.0
    assert payload["duration_seconds"] == 8.0
    assert payload["completed_port_count_exact"] is True


@pytest.mark.asyncio
async def test_socket_connect_timeout_is_counted_as_exact_completion(monkeypatch):
    tool = make_service_tool()

    async def connect(_host: str, _port: int):
        await asyncio.Event().wait()

    monkeypatch.setattr(asyncio, "open_connection", connect)
    entries, status, reason = await tool._scan_sockets(
        "203.0.113.10", (8080,), 0.02, None,
    )
    assert status == "success" and reason is None
    assert [(item["port"], item["state"], item["_completed"]) for item in entries] == [
        (8080, "filtered", True),
    ]

    origin = tool.target.origin()
    assert origin is not None
    output = tool._result(
        origin, "target.test", "socket", (8080,), entries,
        time.monotonic(), status, reason,
    )
    payload = json.loads(str(output))
    assert payload["completed_ports"] == 1
    assert payload["completed_port_count_exact"] is True


@pytest.mark.parametrize("stage", ["connect", "close"])
@pytest.mark.parametrize("failure", [
    UserControlledRefusal("operator denied"),
    PermissionPolicyBlocked("policy blocked"),
    PermissionReviewStale("review stale"),
    HTTPBlocked("budget exhausted"),
    HTTPBlocked("operator denied HTTP", explicit_denial=True),
    HTTPPending("scheduling pending"),
    HTTPReviewTimeout("permission scheduling timeout"),
    HTTPReviewStale("HTTP receipt stale"),
    ExecutionBlocked("execution stale"),
    OutOfScopeError("origin removed"),
])
async def test_native_socket_handlers_preserve_control_exception_identity(monkeypatch, stage, failure):
    tool = make_service_tool()
    metadata = (getattr(failure, "error_kind", None), getattr(failure, "explicit_denial", None))

    class Writer(FakeWriter):
        async def wait_closed(self):
            raise failure

    async def connect(_host, _port):
        if stage == "connect":
            raise failure
        return object(), Writer()

    # Handler-level coverage only. Production gates are exercised separately
    # through the registry/policy integration tests without replacement.
    monkeypatch.setattr(asyncio, "open_connection", connect)
    with pytest.raises(type(failure)) as raised:
        await tool._scan_sockets("203.0.113.10", (8080,), 20, None)

    assert raised.value is failure
    assert (getattr(raised.value, "error_kind", None), getattr(raised.value, "explicit_denial", None)) == metadata


def test_permission_cache_keys_are_action_specific():
    content = make_content_tool()
    content_a = content.permission_hints({"paths": ["admin"], "max_requests": 10})
    content_b = content.permission_hints({"paths": ["admin", "api"], "max_requests": 10})
    content_key_a = content_a.get("cacheKey")
    content_key_b = content_b.get("cacheKey")
    assert isinstance(content_key_a, str) and isinstance(content_key_b, str)
    assert content_key_a != content_key_b

    service = make_service_tool()
    service_a = service.permission_hints({"timeout_seconds": 20})
    service_b = service.permission_hints({"timeout_seconds": 21})
    service_key_a = service_a.get("cacheKey")
    service_key_b = service_b.get("cacheKey")
    assert isinstance(service_key_a, str) and isinstance(service_key_b, str)
    assert service_key_a != service_key_b
    assert service_a.get("yoloAutoApprove") is True
    assert service_a.get("riskTier") == "routine"
    assert service_a.get("noSessionCache", False) is False
    assert service.permission_hints({"ports": [8080, 443]}).get("noSessionCache") is True
