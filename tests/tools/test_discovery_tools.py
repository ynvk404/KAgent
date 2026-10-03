from __future__ import annotations

import asyncio
import json
import socket
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlsplit

import pytest

from src.engagement.state import EngagementState
from src.permission.permission import AlwaysAllow, Decision, PermissionRequest, UserControlledRefusal, YoloPrompter
from src.target.target import Target
from src.tools.capabilities import CapabilityInventory
from src.tools.content_discovery import (
    ContentDiscoveryTool,
    MAX_REQUESTS,
)
from src.tools.outcome import ToolOutput
from src.tools.service_discovery import ServiceDiscoveryTool
from src.tools.registry import Registry
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
    *, profile: str = "minimal", ffuf: str | None = None,
    workflow: WorkflowState | None = None,
) -> ContentDiscoveryTool:
    target = Target("http://target.test:8080/app")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    inventory = CapabilityInventory(which=lambda name: ffuf if name == "ffuf" else None)
    return ContentDiscoveryTool(target, engagement, inventory, lambda: profile, workflow)


def make_service_tool(
    *, profile: str = "minimal", nmap: str | None = None,
    workflow: WorkflowState | None = None,
) -> ServiceDiscoveryTool:
    target = Target("http://target.test:8080")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    inventory = CapabilityInventory(which=lambda name: nmap if name == "nmap" else None)
    tool = ServiceDiscoveryTool(target, engagement, inventory, lambda: profile, workflow)
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
    monkeypatch.setattr("src.tools.content_discovery.httpx.AsyncClient", FakeHTTPClient)
    monkeypatch.setattr(
        "src.tools.content_discovery.gate_private_request",
        AsyncMock(return_value=""),
    )

    async def no_wait(_delay: float, _signal):
        return True

    monkeypatch.setattr("src.tools.content_discovery.sleep_or_abort", no_wait)


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


def test_content_discovery_selects_external_backend_only_for_a_runtime_gap():
    assert make_content_tool(profile="minimal", ffuf="/tools/ffuf")._select_backend("auto") == "native"
    assert make_content_tool(profile="full", ffuf="/tools/ffuf")._select_backend("auto") == "native"
    assert make_content_tool(
        profile="full", ffuf="/tools/ffuf", workflow=make_workflow(phase="enumeration")
    )._select_backend("auto") == "ffuf"
    assert make_content_tool(
        profile="full", ffuf="/tools/ffuf", workflow=make_workflow(phase="enumeration")
    )._select_backend("auto", max_requests=3) == "native"
    with pytest.raises(ValueError, match="mode"):
        make_content_tool().validate_args({"mode": "ffuf"})


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
    monkeypatch.setattr("src.tools.content_discovery.httpx.AsyncClient", SPAClient)
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
    assert payload["backend_reason"] == "minimal profile defaults to native HTTP discovery"


@pytest.mark.asyncio
async def test_content_discovery_uses_two_random_baselines_and_normalizes_dynamic_shell(monkeypatch):
    class DynamicSPAClient(FakeHTTPClient):
        def stream(self, method: str, url: str, **kwargs):
            self.seen.append(url)
            path = urlsplit(url).path
            timestamp = "2026-09-27T12:34:56Z"
            return Stream(Response(200, f"shell:{path}:request=123456789012:{timestamp}".encode()))

    monkeypatch.setattr("src.tools.content_discovery.httpx.AsyncClient", DynamicSPAClient)
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
async def test_content_auto_fallback_explains_missing_ffuf():
    tool = make_content_tool(profile="full")
    output = await tool.run(
        {"paths": ["admin"], "max_requests": 3}, None, AlwaysAllow()
    )
    payload = json.loads(str(output))
    assert payload["backend"] == "native"
    assert payload["backend_reason"] == "ffuf unavailable; fell back to native HTTP discovery"


@pytest.mark.asyncio
async def test_content_discovery_does_not_follow_or_expose_external_redirect_query(monkeypatch):
    class RedirectClient(FakeHTTPClient):
        def stream(self, method: str, url: str, **kwargs):
            self.seen.append(url)
            if "kagent-missing-" in url:
                return Stream(Response(404, b"not found"))
            return Stream(Response(302, b"", {"location": "https://other.test/path?token=secret"}))

    tool = make_content_tool()
    monkeypatch.setattr("src.tools.content_discovery.httpx.AsyncClient", RedirectClient)
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
async def test_content_ffuf_output_is_parsed_and_every_hit_is_verified(monkeypatch):
    workflow = make_workflow(phase="enumeration")
    tool = make_content_tool(profile="full", ffuf="/tools/ffuf", workflow=workflow)
    FakeHTTPClient.responses = {"admin": Response(200, b"admin page")}
    captured: dict[str, object] = {}

    async def fake_ffuf(binary: str, argv: list[str], timeout: float, signal):
        captured["binary"] = binary
        captured["argv"] = list(argv)
        output_path = Path(argv[argv.index("-o") + 1])
        output_path.write_text(
            json.dumps({"results": [{"input": {"FUZZ": "admin"}}]}),
            encoding="utf-8",
        )
        return ToolOutput("exit: 0", status="success")

    monkeypatch.setattr("src.tools.content_discovery.run_with_capture", fake_ffuf)
    output = await tool.run(
        {"paths": ["admin", "settings"], "mode": "auto", "max_requests": 6},
        None,
        AlwaysAllow(),
    )
    payload = json.loads(str(output))

    assert captured["binary"] == "/tools/ffuf"
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert "-u" in argv and "-rate" in argv and "-maxtime" in argv
    assert "-recursion" not in argv and "-H" not in argv
    assert payload["backend"] == "ffuf"
    assert payload["backend_reason"] == (
        "full profile selected installed ffuf for a runtime-confirmed enumeration coverage gap"
    )
    assert payload["requested_requests"] == 5
    assert payload["completed_requests"] == 5
    assert payload["discovered"][0]["path"] == "admin"
    assert payload["discovered"][0]["verified"] is True
    coverage = workflow.phase_coverage_record("enumeration", "active_content_discovery")
    assert coverage is not None and coverage.status == "performed"
    assert payload["phase_coverage"] == {
        "phase": "enumeration", "dimension": "active_content_discovery",
        "status": "performed", "changed": True, "source": "content_discovery",
    }
    assert tool._select_backend("auto") == "native"


@pytest.mark.asyncio
async def test_content_discovery_reports_unscanned_paths_and_keeps_coverage_retryable():
    workflow = make_workflow(phase="enumeration")
    tool = make_content_tool(profile="minimal", workflow=workflow)
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
async def test_content_ffuf_malformed_json_returns_error_and_cleans_temp_directory(monkeypatch):
    tool = make_content_tool(
        profile="full", ffuf="/tools/ffuf", workflow=make_workflow(phase="enumeration")
    )
    observed_dir: list[Path] = []

    async def fake_ffuf(_binary: str, argv: list[str], _timeout: float, _signal):
        output_path = Path(argv[argv.index("-o") + 1])
        observed_dir.append(output_path.parent)
        output_path.write_text("{bad json", encoding="utf-8")
        return ToolOutput("exit: 0", status="success")

    monkeypatch.setattr("src.tools.content_discovery.run_with_capture", fake_ffuf)
    output = await tool.run({"paths": ["admin"], "mode": "auto"}, None, AlwaysAllow())

    assert output.status == "error"
    assert "malformed or missing ffuf JSON" in json.loads(str(output))["reason"]
    assert observed_dir and not observed_dir[0].exists()


@pytest.mark.asyncio
async def test_content_discovery_reports_missing_or_unexecutable_ffuf(monkeypatch):
    tool = make_content_tool(
        profile="full", ffuf="/tools/ffuf", workflow=make_workflow(phase="enumeration")
    )
    monkeypatch.setattr(
        "src.tools.content_discovery.run_with_capture",
        AsyncMock(side_effect=FileNotFoundError("ffuf disappeared")),
    )
    output = await tool.run(
        {"paths": ["admin"], "mode": "auto", "max_requests": 4},
        None,
        AlwaysAllow(),
    )
    payload = json.loads(str(output))
    assert output.status == "error"
    assert "could not be started" in payload["reason"]
    assert tool._select_backend("auto") == "native"


@pytest.mark.asyncio
async def test_content_discovery_preserves_ffuf_timeout_classification(monkeypatch):
    tool = make_content_tool(
        profile="full", ffuf="/tools/ffuf", workflow=make_workflow(phase="enumeration")
    )
    monkeypatch.setattr(
        "src.tools.content_discovery.run_with_capture",
        AsyncMock(return_value=ToolOutput(
            "exit: timeout after 5s", status="error", error_kind="timeout"
        )),
    )

    output = await tool.run(
        {"paths": ["admin"], "mode": "auto", "max_requests": 4},
        None,
        AlwaysAllow(),
    )

    assert output.status == "error"
    assert output.error_kind == "timeout"
    assert json.loads(str(output))["completed_request_count_exact"] is False


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
    unsafe_host = ServiceDiscoveryTool(
        target, engagement, CapabilityInventory(which=lambda _name: None), lambda: "minimal"
    )
    with pytest.raises(ValueError, match="valid hostname"):
        unsafe_host.validate_args({})


def test_service_profile_selects_external_backend_only_for_runtime_gap():
    assert make_service_tool(profile="minimal", nmap="/tools/nmap")._select_backend("auto") == "socket"
    assert make_service_tool(profile="full", nmap="/tools/nmap")._select_backend("auto") == "socket"
    assert make_service_tool(
        profile="full", nmap="/tools/nmap", workflow=make_workflow()
    )._select_backend("auto") == "nmap"
    with pytest.raises(ValueError, match="mode"):
        make_service_tool().validate_args({"mode": "nmap"})


@pytest.mark.asyncio
async def test_service_socket_backend_reports_open_and_closed_without_subprocess(monkeypatch):
    tool = make_service_tool()
    monkeypatch.setattr("src.tools.service_discovery.private_host_reason", AsyncMock(return_value=""))

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
async def test_service_auto_fallback_explains_missing_nmap(monkeypatch):
    tool = make_service_tool(profile="full")
    monkeypatch.setattr("src.tools.service_discovery.private_host_reason", AsyncMock(return_value=""))
    monkeypatch.setattr(
        tool,
        "_scan_sockets",
        AsyncMock(return_value=([], "success", None)),
    )
    output = await tool.run({}, None, AlwaysAllow())
    payload = json.loads(str(output))
    assert payload["backend"] == "socket"
    assert payload["backend_reason"] == "nmap unavailable; fell back to native TCP discovery"


@pytest.mark.asyncio
async def test_service_socket_backend_cancels_pending_connections_promptly(monkeypatch):
    tool = make_service_tool()
    monkeypatch.setattr("src.tools.service_discovery.private_host_reason", AsyncMock(return_value=""))
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


@pytest.mark.asyncio
async def test_service_nmap_argv_is_bounded_and_suggested_http_origin_is_not_authorized(monkeypatch):
    workflow = make_workflow()
    tool = make_service_tool(profile="full", nmap="/tools/nmap", workflow=workflow)
    monkeypatch.setattr("src.tools.service_discovery.private_host_reason", AsyncMock(return_value=""))
    captured: dict[str, object] = {}

    async def fake_nmap(binary: str, argv: list[str], _timeout: float, _signal):
        captured["binary"] = binary
        captured["argv"] = list(argv)
        xml_path = Path(argv[argv.index("-oX") + 1])
        xml_path.write_text(
            '<nmaprun><host><ports><port protocol="tcp" portid="8080">'
            '<state state="open"/><service name="http" product="test" version="1"/>'
            '</port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        return ToolOutput("exit: 0", status="success")

    monkeypatch.setattr("src.tools.service_discovery.run_with_capture", fake_nmap)
    output = await tool.run(
        {"mode": "auto", "ports": [8080]},
        None,
        AlwaysAllow(),
    )
    payload = json.loads(str(output))
    argv = captured["argv"]
    assert captured["binary"] == "/tools/nmap"
    assert isinstance(argv, list)
    assert argv[argv.index("-p") + 1] == "8080"
    assert "-Pn" in argv and "-n" in argv and "-sT" in argv
    assert not any(option in argv for option in ("-sV", "-sU", "-O", "--script", "-p-"))
    assert argv[-1] == "203.0.113.10"
    assert payload["ports"][0]["service"] == "http"
    assert payload["http_origin_suggestions"] == ["http://target.test:8080"]
    assert payload["suggestions_authorized"] is False
    coverage = workflow.phase_coverage_record("recon", "service_discovery")
    assert coverage is not None and coverage.status == "performed"
    assert tool._select_backend("auto") == "socket"


@pytest.mark.asyncio
async def test_service_nmap_missing_executable_returns_structured_error(monkeypatch):
    tool = make_service_tool(
        profile="full", nmap="/tools/nmap", workflow=make_workflow()
    )
    monkeypatch.setattr("src.tools.service_discovery.private_host_reason", AsyncMock(return_value=""))
    monkeypatch.setattr(
        "src.tools.service_discovery.run_with_capture",
        AsyncMock(side_effect=FileNotFoundError("nmap disappeared")),
    )

    output = await tool.run({}, None, AlwaysAllow())
    payload = json.loads(str(output))
    assert output.status == "error"
    assert payload["reason"] == "nmap could not be started"
    assert payload["completed_port_count_exact"] is False
    assert tool._select_backend("auto") == "socket"


@pytest.mark.asyncio
async def test_service_nmap_extraports_are_only_exact_when_state_mapping_is_unambiguous(monkeypatch):
    tool = make_service_tool(profile="full", nmap="/tools/nmap")

    async def aggregate_output(_binary: str, argv: list[str], _timeout: float, _signal):
        path = Path(argv[argv.index("-oX") + 1])
        path.write_text(
            '<nmaprun><host><ports><extraports state="closed" count="2"/>'
            '</ports></host></nmaprun>',
            encoding="utf-8",
        )
        return ToolOutput("exit: 0", status="success")

    monkeypatch.setattr("src.tools.service_discovery.run_with_capture", aggregate_output)
    entries, status, reason = await tool._scan_nmap(
        "203.0.113.10", (8080, 8081), 20, None
    )
    assert status == "success" and reason is None
    assert [(item["port"], item["state"]) for item in entries] == [
        (8080, "closed"), (8081, "closed")
    ]
    assert all(item["_completed"] and item["aggregate_state"] for item in entries)

    async def ambiguous_output(_binary: str, argv: list[str], _timeout: float, _signal):
        path = Path(argv[argv.index("-oX") + 1])
        path.write_text(
            '<nmaprun><host><ports><extraports state="closed" count="1"/>'
            '<extraports state="filtered" count="1"/></ports></host></nmaprun>',
            encoding="utf-8",
        )
        return ToolOutput("exit: 0", status="success")

    monkeypatch.setattr("src.tools.service_discovery.run_with_capture", ambiguous_output)
    entries, status, _reason = await tool._scan_nmap(
        "203.0.113.10", (8080, 8081), 20, None
    )
    assert status == "success"
    assert all(item["state"] == "unknown" and not item["_completed"] for item in entries)


@pytest.mark.asyncio
async def test_service_partial_nmap_output_keeps_recon_coverage_retryable(monkeypatch):
    workflow = make_workflow()
    tool = make_service_tool(profile="full", nmap="/tools/nmap", workflow=workflow)

    async def ambiguous_state(_binary: str, argv: list[str], _timeout: float, _signal):
        Path(argv[argv.index("-oX") + 1]).write_text(
            '<nmaprun><host><ports><port protocol="tcp" portid="8080">'
            '<state state="open|filtered"/></port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        return ToolOutput("exit: 0", status="success")

    monkeypatch.setattr("src.tools.service_discovery.run_with_capture", ambiguous_state)
    output = await tool.run({}, None, AlwaysAllow())
    payload = json.loads(str(output))

    assert output.status == "observation"
    assert payload["ports"][0]["state"] == "unknown"
    assert payload["completed_port_count_exact"] is False
    coverage = workflow.phase_coverage_record("recon", "service_discovery")
    assert coverage is not None and coverage.status == "failed"
    assert tool._select_backend("auto") == "nmap"


@pytest.mark.asyncio
async def test_service_nmap_timeout_and_cancel_classification_survive_partial_xml(monkeypatch):
    tool = make_service_tool(profile="full", nmap="/tools/nmap")

    async def partial_timeout(_binary: str, argv: list[str], _timeout: float, _signal):
        Path(argv[argv.index("-oX") + 1]).write_text(
            '<nmaprun><host><ports><port protocol="tcp" portid="8080">'
            '<state state="open"/></port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        return ToolOutput("partial", status="error", error_kind="timeout")

    monkeypatch.setattr("src.tools.service_discovery.run_with_capture", partial_timeout)
    entries, status, reason = await tool._scan_nmap("203.0.113.10", (8080,), 20, None)
    assert entries == [] and status == "error" and reason == "timeout"

    async def partial_cancel(_binary: str, argv: list[str], _timeout: float, _signal):
        Path(argv[argv.index("-oX") + 1]).write_text("<nmaprun>", encoding="utf-8")
        return ToolOutput("partial", status="cancelled", error_kind="cancelled")

    monkeypatch.setattr("src.tools.service_discovery.run_with_capture", partial_cancel)
    entries, status, reason = await tool._scan_nmap("203.0.113.10", (8080,), 20, None)
    assert entries == [] and status == "cancelled" and reason == "cancelled during nmap scan"


@pytest.mark.asyncio
async def test_service_dns_checks_all_answers_and_scans_only_a_vetted_numeric_ip(monkeypatch):
    tool = make_service_tool()
    resolver = AsyncMock(return_value=( ["8.8.8.8", "127.0.0.1"], None ))
    monkeypatch.setattr(tool, "_resolve_execution_addresses", resolver)
    reasons: list[str] = []

    async def private_reason(address: str) -> str:
        reasons.append(address)
        return "loopback IPv4" if address == "127.0.0.1" else ""

    monkeypatch.setattr("src.tools.service_discovery.private_host_reason", private_reason)
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
    monkeypatch.setattr("src.tools.service_discovery.socket.getaddrinfo", lambda *_args: answers)
    resolved, error = await ServiceDiscoveryTool._resolve_execution_addresses(
        tool, "target.test", 5, None
    )
    assert resolved == ["8.8.8.8", "2001:4860:4860::8888"]
    assert error is None

    many_answers = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (f"8.8.8.{index}", 0))
        for index in range(1, 18)
    ]
    monkeypatch.setattr("src.tools.service_discovery.socket.getaddrinfo", lambda *_args: many_answers)
    resolved, error = await ServiceDiscoveryTool._resolve_execution_addresses(
        tool, "target.test", 5, None
    )
    assert resolved == [] and error == "failed"


@pytest.mark.asyncio
async def test_private_service_discovery_uses_cacheable_active_target_policy(monkeypatch):
    tool = make_service_tool()
    monkeypatch.setattr(
        "src.tools.service_discovery.private_host_reason",
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
        "src.tools.service_discovery.private_host_reason",
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
        "src.tools.service_discovery.private_host_reason",
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
        "src.tools.service_discovery.private_host_reason",
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
        "src.tools.service_discovery.time",
        SimpleNamespace(monotonic=lambda: clock[0]),
    )
    monkeypatch.setattr(
        "src.tools.service_discovery.private_host_reason",
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
