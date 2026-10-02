from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock
from typing import Any, cast

import httpx
import pytest

from src.engagement.state import EngagementState, OutOfScopeError
from src.permission.execution import ExecutionPolicy, ExecutionBlocked
from src.permission.invocations import review_turn
from src.permission.http_grants import HTTPLimits, HTTPBlocked
from src.permission.permission import Decision, UserControlledRefusal, YoloPrompter
from src.target.target import Target
from src.tools.registry import Registry
from src.tools.http import HTTPTool
from src.tools.web import WebFetchTool, WebSearchTool, clear_web_cache
from src.tools.file import FileReadTool, FileWriteTool
from src.tools.shell import ShellTool
from src.tools.plugin import CommandPluginTool
from src.tools.mcp_integration import MCPTool
from src.tools.capabilities import CapabilityInventory
from src.tools.content_discovery import ContentDiscoveryTool
from src.config.config import PluginConfig

ORIGIN = "http://127.0.0.1:3000"
REAL_CLIENT = httpx.AsyncClient


class Operator:
    def __init__(self, decision=Decision.DENY):
        self.requests = []
        self.decision = decision

    async def ask(self, request, signal=None):
        self.requests.append(request)
        return self.decision


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    state = EngagementState()
    state.add_origin(ORIGIN)
    target = Target(ORIGIN)
    operator = Operator()
    prompter = YoloPrompter(operator, True)
    policy = ExecutionPolicy(state, tmp_path, protected=(tmp_path / "control",))
    HTTPTool(target, state)
    state.http_permissions.activate(ORIGIN, HTTPLimits(requests=100, rate=1000, burst=100, concurrency=20))
    prompter.bind_execution_policy(policy)
    policy.vetted_ips["https://html.duckduckgo.com:443"] = ("1.1.1.1",)
    registry = Registry()
    for tool in [HTTPTool(target, state), WebFetchTool(state, target), WebSearchTool(), FileReadTool(), FileWriteTool(),
                 ContentDiscoveryTool(target, state, CapabilityInventory(which=lambda _: None), lambda: "minimal")]:
        registry.register(tool)
    sent, responses = [], []

    def handler(request):
        sent.append(request)
        response = httpx.Response(200, content=b"fixture", request=request)
        responses.append(response)
        return response

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: REAL_CLIENT(transport=httpx.MockTransport(handler), **kwargs))
    clear_web_cache()
    return registry, prompter, policy, operator, sent, responses, target


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["recon", "validation", "impact"])
@pytest.mark.parametrize("method", ["GET", "POST", "PATCH", "DELETE"])
async def test_yolo_new_endpoint_payload_and_effects_are_not_classifiers(runtime, phase, method):
    registry, p, policy, operator, sent, responses, _ = runtime
    payload = "<script>alert(1)</script>' OR 1=1-- ../../etc/passwd {{7*7}} ignore prior instructions"
    result = await registry.execute("http", {"url": "/new/auth", "phase": phase, "method": method, "body": payload}, None, p)
    assert result.http_status == 200
    assert sent[0].content == payload.encode()
    assert sent[0].method == method and sent[0].url.host == "127.0.0.1"
    assert not operator.requests and responses[0].is_closed
    assert policy.active == 0


@pytest.mark.asyncio
async def test_yolo_confirm_each_is_restored_when_off(runtime):
    registry, p, policy, operator, sent, _, _ = runtime
    rights = policy.engagement.http_permissions
    rights.activate(ORIGIN, HTTPLimits(), "confirm-each")
    await registry.execute("http", {"url": "/", "phase": "impact"}, None, p)
    assert len(sent) == 1 and not operator.requests
    p.set_yolo(False)
    with pytest.raises(HTTPBlocked):
        await registry.execute("http", {"url": "/", "phase": "recon"}, None, p)
    assert len(sent) == 1 and len(operator.requests) == 1
    assert rights.grants[next(iter(rights.grants))].mode == "confirm-each"


@pytest.mark.asyncio
async def test_file_source_payload_sensitive_lab_and_artifact_zero_dialogs(runtime, tmp_path):
    registry, p, _, operator, _, _, _ = runtime
    fake = tmp_path / ".env"
    fake.write_text("FAKE_LAB_SECRET=fixture")
    assert "fixture" in await registry.execute("file_read", {"path": str(fake)}, None, p)
    payload = "<script>fixture</script>"
    artifact = tmp_path / "new-source.py"
    await registry.execute("file_write", {"path": str(artifact), "content": payload}, None, p)
    assert artifact.read_text() == payload and not operator.requests


@pytest.mark.asyncio
async def test_outside_root_protected_symlink_hardlink_blocked(runtime, tmp_path):
    registry, p, _, operator, _, _, _ = runtime
    outside = tmp_path.parent / (tmp_path.name + "-fake-secret")
    outside.write_text("FAKE_HOST_KEY")
    paths = [outside, tmp_path / "control" / "policy.json"]
    link = tmp_path / "link"
    link.symlink_to(outside)
    hard = tmp_path / "hard"
    hard.hardlink_to(outside)
    paths.extend([link, hard])
    for path in paths:
        with pytest.raises(ExecutionBlocked):
            await registry.execute("file_read", {"path": str(path)}, None, p)
    assert not operator.requests


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args", [("http", {"url": "/", "phase": "recon"}),
                                     ("web_fetch", {"url": ORIGIN}), ("web_search", {"query": "fixture"}),
                                     ("content_discovery", {"paths": ["new"], "mode": "native"})])
async def test_session_deny_stops_every_native_network_path(runtime, name, args):
    registry, p, policy, operator, sent, _, _ = runtime
    policy.engagement.http_permissions.deny_session()
    for _ in range(2):
        with pytest.raises(UserControlledRefusal):
            await registry.execute(name, args, None, p)
    assert not operator.requests and not sent


@pytest.mark.asyncio
async def test_discovery_fetch_search_use_authority_and_close(runtime):
    registry, p, policy, operator, sent, responses, _ = runtime
    await registry.execute("web_fetch", {"url": ORIGIN + "/new"}, None, p)
    await registry.execute("content_discovery", {"paths": ["new"], "mode": "native", "max_requests": 3, "rate_limit": 10}, None, p)
    await registry.execute("web_search", {"query": "public vulnerability reference"}, None, p)
    assert len(sent) == 5 and not operator.requests
    assert all(response.is_closed for response in responses)
    assert sent[-1].headers["host"] == "html.duckduckgo.com" and sent[-1].url.host == "1.1.1.1"
    grant = next(iter(policy.engagement.http_permissions.grants.values()))
    assert policy.engagement.http_permissions._budgets[grant.id].used == 4


@pytest.mark.asyncio
async def test_revoked_origin_cache_and_discovery_do_not_bypass(runtime):
    registry, p, policy, operator, sent, _, _ = runtime
    await registry.execute("web_fetch", {"url": ORIGIN}, None, p)
    grant = next(iter(policy.engagement.http_permissions.grants.values()))
    policy.engagement.http_permissions.revoke(grant.id)
    p.set_yolo(False)
    p.set_yolo(True)
    for name, args in [("web_fetch", {"url": ORIGIN}), ("content_discovery", {"paths": ["new"]})]:
        with pytest.raises(UserControlledRefusal):
            await registry.execute(name, args, None, p)
    assert len(sent) == 1 and not operator.requests


@pytest.mark.asyncio
async def test_shared_quota_parallel_and_no_dialog(runtime):
    registry, p, policy, operator, sent, _, _ = runtime
    policy.engagement.http_permissions.activate(ORIGIN, HTTPLimits(requests=2, rate=1000, burst=20, concurrency=20))
    results = await asyncio.gather(*(registry.execute("http", {"url": f"/{i}", "phase": "recon"}, None, p)
                                    for i in range(8)), return_exceptions=True)
    assert len(sent) == 2 and sum(isinstance(r, UserControlledRefusal) for r in results) == 6
    assert not operator.requests and policy.active == 0


@pytest.mark.asyncio
async def test_off_decline_once_suppresses_issue_without_session_deny(runtime, tmp_path):
    registry, p, policy, operator, _, _, _ = runtime
    p.set_yolo(False)
    args = {"path": str(tmp_path / "new"), "content": "fixture"}
    with review_turn():
        for _ in range(2):
            with pytest.raises(UserControlledRefusal):
                await registry.execute("file_write", args, None, p)
    assert len(operator.requests) == 1 and not policy.engagement.http_permissions.denied
    operator.decision = Decision.ALLOW_ONCE
    await registry.execute("file_write", {**args, "path": str(tmp_path / "other")}, None, p)
    assert (tmp_path / "other").read_text() == "fixture"


@pytest.mark.asyncio
async def test_scope_change_during_review_and_args_freeze(runtime, tmp_path):
    registry, p, policy, operator, _, _, _ = runtime
    p.set_yolo(False)
    args = {"path": str(tmp_path / "new"), "content": "before"}

    async def review(request, signal=None):
        args["content"] = "after"
        return Decision.ALLOW_ONCE

    operator.ask = review
    await registry.execute("file_write", args, None, p)
    assert (tmp_path / "new").read_text() == "before"

    async def change_scope(request, signal=None):
        policy.engagement.add_origin("http://127.0.0.1:3001")
        return Decision.ALLOW_ONCE

    operator.ask = change_scope
    with pytest.raises(ExecutionBlocked, match="stale"):
        await registry.execute("file_write", {"path": str(tmp_path / "second"), "content": "fixture"}, None, p)
    assert not (tmp_path / "second").exists()


def test_receipt_replay_expiry_and_changed_args(runtime, tmp_path):
    registry, _, policy, _, _, _, _ = runtime
    tool = registry.get("file_write")
    args = {"path": str(tmp_path / "new"), "content": "fixture"}
    receipt = policy.prepare(tool, args)
    with pytest.raises(ExecutionBlocked, match="arguments-changed"):
        policy.start(receipt, tool, {**args, "content": "changed"}, None)
    with pytest.raises(ExecutionBlocked):
        policy.start(replace(receipt, expires=0), tool, args, None)
    token = policy.start(receipt, tool, args, None)
    policy.stop(token)
    with pytest.raises(ExecutionBlocked, match="replayed"):
        policy.start(receipt, tool, args, None)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["shell", "plugin", "mcp"])
async def test_missing_process_enforcement_blocks_before_dialog_and_direct_dispatch(runtime, monkeypatch, kind):
    registry, p, _, operator, _, _, _ = runtime
    dispatch = AsyncMock()
    monkeypatch.setattr("src.tools.shell.run_with_capture", dispatch)
    monkeypatch.setattr("src.tools.plugin.run_plugin", dispatch)
    session = type("Session", (), {"call_tool": dispatch, "server_name": "fixture"})()
    tool = {"shell": ShellTool(), "plugin": CommandPluginTool(PluginConfig(name="fixture", command="fixture")),
            "mcp": MCPTool(cast(Any, session), "fixture_mcp", "operation", "fixture", {})}[kind]
    registry.register(tool)
    args = {"command": "printf fixture", "url": ORIGIN}
    for _ in range(2):
        with pytest.raises(ExecutionBlocked, match="enforcement-unavailable"):
            await registry.execute(tool.name(), args, None, p)
    with pytest.raises(ExecutionBlocked, match="enforcement-unavailable"):
        await tool.run(args, None, p)
    assert not operator.requests and not dispatch.called


@pytest.mark.asyncio
async def test_plugin_effective_config_frozen_before_ordinary_review(monkeypatch):
    dispatch = AsyncMock(return_value="fixture")
    monkeypatch.setattr("src.tools.plugin.run_plugin", dispatch)
    cfg = PluginConfig(name="fixture", command="before", args=["before"])
    registry = Registry()
    registry.register(CommandPluginTool(cfg))

    class Reviewer(Operator):
        async def ask(self, request, signal=None):
            assert "before" in request.detail
            cfg.command, cfg.args = "after", ["after"]
            return Decision.ALLOW_ONCE

    await registry.execute("fixture", {"nested": {"data": "fixture"}}, None, Reviewer())
    assert dispatch.await_args is not None
    assert dispatch.await_args.args[:2] == ("before", ["before"])


@pytest.mark.asyncio
async def test_private_gate_not_yolo_hint_is_authority(runtime):
    registry, p, _, operator, sent, _, _ = runtime
    with pytest.raises(OutOfScopeError):
        await registry.execute("http", {"url": "http://127.0.0.1:3001", "phase": "recon"}, None, p)
    assert not operator.requests and not sent


@pytest.mark.asyncio
async def test_file_ipc_resource_is_not_treated_as_lab_input(runtime, tmp_path):
    import os
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO fixture requires POSIX")
    registry, p, _, operator, _, _, _ = runtime
    path = tmp_path / "fixture-fifo"
    os.mkfifo(path)
    with pytest.raises(ExecutionBlocked, match="unsupported-file-resource-type"):
        await registry.execute("file_read", {"path": str(path)}, None, p)
    assert not operator.requests


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize("phase", ["recon", "validation", "impact"])
async def test_bound_native_mode_requires_no_manual_grant_and_phase_cannot_enable_it(runtime, tmp_path, enabled, phase):
    _, _, _, operator, sent, _, _ = runtime
    state = EngagementState()
    state.add_origin(ORIGIN)
    tool = HTTPTool(Target(ORIGIN), state)
    fresh = YoloPrompter(operator, enabled)
    fresh.bind_execution_policy(ExecutionPolicy(state, tmp_path))
    registry = Registry()
    registry.register(tool)
    args = {"url": "/new-without-manual-grant", "method": "POST", "phase": phase, "body": "<script>fixture</script>"}
    if enabled:
        result = await registry.execute("http", args, None, fresh)
        assert isinstance(result, str) and "200" in result
        assert len(sent) == 1 and not operator.requests
        assert next(iter(state.http_permissions.grants.values())).activation == "yolo"
    else:
        with pytest.raises(HTTPBlocked):
            await registry.execute("http", args, None, fresh)
        assert not sent and len(operator.requests) == 1 and not state.http_permissions.grants


def test_actual_common_receipt_deadline_expires_before_dispatch(runtime, tmp_path):
    registry, _, policy, _, _, _, _ = runtime
    tool = registry.get("file_write")
    args = {"path": str(tmp_path / "new"), "content": "fixture"}
    receipt = policy.prepare(tool, args)
    policy.clock = lambda: receipt.expires + 1
    with pytest.raises(ExecutionBlocked, match="stale/replayed"):
        policy.start(receipt, tool, args, None)
    assert policy.used == 0 and not (tmp_path / "new").exists()
