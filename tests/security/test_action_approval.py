from __future__ import annotations

from contextlib import asynccontextmanager
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from src.engagement.state import EngagementState
from src.permission.permission import AlwaysDeny, Decision, UserControlledRefusal, YoloPrompter
from src.permission.runtime.execution import ExecutionPolicy, ExecutionReview, current_policy, invocation_digest
from src.tools.mcp.integration import MCPTool
from src.tools.common.registry import Registry
from src.tools.execution.shell import BashTool, ShellTool
from src.tools.common.outcome import ToolOutput
from src.ui.bridges.perm_bridge import BridgedPermissionRequest
from src.ui.widgets.permission_modal import PermissionModal


class Session:
    server_name = "fixture-server"
    def __init__(self):
        self.calls = []
    async def call_tool(self, name, args, cancel_event=None):
        self.calls.append((name, args))
        return {"isError": False, "content": []}


@pytest.mark.asyncio
async def test_mcp_full_preview_redacts_and_dispatches_same_nested_arguments():
    session = Session()
    tool = MCPTool(session, "mcp_browser_navigate", "navigate", "fixture", {})
    registry = Registry()
    registry.register(tool)
    original = {"url": "https://target.test/new", "options": {"callback": "https://callback.test"},
                "password": "FAKE_SECRET", "long": "X" * 9000 + "FINAL_ARGUMENT"}
    class Approve:
        async def ask(self, request, signal=None):
            req = request
            preview = json.loads(req.detail)
            assert preview["server"] == session.server_name
            assert preview["tool"] == "navigate"
            assert preview["args"]["options"] == original["options"]
            assert preview["args"]["password"] == "[REDACTED]"
            assert "FINAL_ARGUMENT" in req.detail
            original["options"]["callback"] = "https://changed.invalid"
            return Decision.ALLOW_ONCE
    await registry.execute(tool.name(), original, None, Approve())
    assert session.calls[0][1]["options"]["callback"] == "https://callback.test"
    assert session.calls[0][1]["password"] == "FAKE_SECRET"


@pytest.mark.asyncio
async def test_mcp_deny_prevents_remote_dispatch():
    session = Session()
    tool = MCPTool(session, "mcp_fixture", "operation", "fixture", {})
    registry = Registry()
    registry.register(tool)
    with pytest.raises(UserControlledRefusal):
        await registry.execute(tool.name(), {"url": "https://target.test"}, None, AlwaysDeny())
    assert session.calls == []


@pytest.mark.asyncio
async def test_shell_preview_matches_original_dispatch_and_preserves_secrets(monkeypatch):
    command = "printf abc | grep -P 'a'; echo token=FAKE_SECRET_1234567890"
    args = {"command": command}
    calls = []
    async def run_capture(cmd, argv, timeout, signal):
        calls.append((cmd, argv))
        return "fixture output"
    monkeypatch.setattr("src.tools.execution.shell.run_with_capture", run_capture)
    class Approve:
        async def ask(self, request, signal=None):
            req = request
            assert "FAKE_SECRET_1234567890" not in req.detail
            assert "[REDACTED" in req.detail
            assert "printf abc | grep -P 'a'" in req.detail
            assert req.cache_key == command
            assert req.no_session_cache and not req.supports_session
            args["command"] = "echo changed"
            return Decision.ALLOW_ONCE
    registry = Registry()
    registry.register(ShellTool())
    await registry.execute("shell", args, None, Approve())
    assert calls == [("/bin/sh", ["-c", command])]

@pytest.mark.asyncio
@pytest.mark.parametrize("factory", [ShellTool, BashTool])
async def test_shell_review_receipt_worker_and_dispatch_keep_original_arguments(factory, tmp_path, monkeypatch):
    command = "pat=abc; printf '%s\\n' abc | grep -P \"$pat\""
    args = {"command": command, "timeout_seconds": 7}
    reviewed_args = deepcopy(args)
    tool = factory()
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    expected_digest = invocation_digest(tool, reviewed_args)
    review_ids = []
    prepared = []
    dispatched = []

    class Approve:
        async def ask(self, request, signal=None):
            assert request.detail == f"{command}\n\nTimeout: 7s"
            assert request.cache_key == command
            assert request.no_session_cache and not request.supports_session
            review, = policy._receipts.values()
            assert isinstance(review, ExecutionReview)
            assert review.digest == expected_digest
            review_ids.append(review.id)
            args["command"] = "echo caller changed during review"
            args["timeout_seconds"] = 1
            return Decision.ALLOW_ONCE

    def assert_active_receipt():
        assert current_policy() is policy
        receipt, = policy._active_receipts.values()
        assert not isinstance(receipt, ExecutionReview)
        assert receipt.digest == expected_digest
        assert receipt.id == review_ids[0]

    @asynccontextmanager
    async def broker(signal=None, *, collector=None):
        assert_active_receipt()
        yield tmp_path / "fake-broker"

    async def prepare(cmd, argv, *, broker, signal):
        assert_active_receipt()
        assert broker == tmp_path / "fake-broker"
        prepared.append((cmd, list(argv)))
        return cmd, argv

    async def capture(cmd, argv, timeout, signal):
        assert_active_receipt()
        dispatched.append((cmd, list(argv), timeout))
        return ToolOutput("fixture output")

    # Keep the real Registry and receipt lifecycle; only the worker/broker and
    # subprocess boundary are fakes. No host command or network is dispatched.
    policy.worker = SimpleNamespace(summary=lambda: "fixture-worker", prepare=prepare)
    prompter = YoloPrompter(Approve())
    prompter.bind_execution_policy(policy)
    monkeypatch.setattr("src.permission.worker.broker.broker_directory", broker)
    monkeypatch.setattr("src.tools.execution.shell.run_with_capture", capture)
    registry = Registry()
    registry.register(tool)
    assert await registry.execute(tool.name(), args, None, prompter) == "fixture output"
    assert prepared == [(tool.shell_path, ["-c", command])]
    assert dispatched == [(tool.shell_path, ["-c", command], 7)]
    assert len(review_ids) == 1
    assert not policy._receipts and not policy._active_receipts and not policy._pending
    assert policy.active == 0



def test_full_detail_is_reviewable_without_a_mode_toggle_or_secret_leak():
    req = BridgedPermissionRequest(tool="shell", summary="shell command",
        detail="echo " + "X" * 9000 + " FINAL_OPERATION token=FAKE_SECRET_1234567890",
        resolve=Mock(), reject=Mock())
    modal = PermissionModal(req)
    def frame():
        console = Console(width=120, record=True)
        console.print(modal.render())
        return console.export_text()
    preview = frame()
    assert "FINAL_OPERATION" in preview and "FAKE_SECRET_1234567890" not in preview
    modal.handle_key("v")
    full = frame()
    assert "FINAL_OPERATION" in full
    assert "FAKE_SECRET_1234567890" not in full
    req.resolve.assert_not_called()


def test_credential_flag_values_are_hidden_without_hiding_target_or_operation():
    from src.tools.common.approval_display import redact_approval
    text = "curl --password 'fake short' --token=fake-token -u testactor:fake-password -H 'Authorization: Basic ZmFrZQ==' https://target.test/operation"
    safe = redact_approval(text)
    for secret in ["fake short", "fake-token", "fake-password", "ZmFrZQ=="]:
        assert secret not in safe
    assert "testactor" in safe
    assert "https://target.test/operation" in safe
    assert "Authorization: Basic" in safe
