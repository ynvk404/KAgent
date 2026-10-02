from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from rich.console import Console

from src.permission.permission import AlwaysDeny, Decision, UserControlledRefusal
from src.tools.mcp_integration import MCPTool
from src.tools.registry import Registry
from src.tools.shell import ShellTool, rewrite_portable_command
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
async def test_shell_preview_matches_rewritten_dispatch_and_preserves_secrets(monkeypatch):
    command = "printf abc | grep -P 'a'; echo token=FAKE_SECRET_1234567890"
    args = {"command": command}
    calls = []
    async def run_capture(cmd, argv, timeout, signal):
        calls.append((cmd, argv))
        return "fixture output"
    monkeypatch.setattr("src.tools.shell.run_with_capture", run_capture)
    class Approve:
        async def ask(self, request, signal=None):
            req = request
            assert "FAKE_SECRET_1234567890" not in req.detail
            assert "[REDACTED" in req.detail
            args["command"] = "echo changed"
            return Decision.ALLOW_ONCE
    registry = Registry()
    registry.register(ShellTool())
    await registry.execute("shell", args, None, Approve())
    assert rewrite_portable_command(command) in calls[0][1]


def test_full_detail_toggle_reveals_tail_without_approving_or_secret_leak():
    req = BridgedPermissionRequest(tool="shell", summary="shell command",
        detail="echo " + "X" * 9000 + " FINAL_OPERATION token=FAKE_SECRET_1234567890",
        resolve=Mock(), reject=Mock())
    modal = PermissionModal(req)
    def frame():
        console = Console(width=120, record=True)
        console.print(modal.render())
        return console.export_text()
    assert "FINAL_OPERATION" not in frame()
    modal.handle_key("v")
    full = frame()
    assert "FINAL_OPERATION" in full
    assert "FAKE_SECRET_1234567890" not in full
    req.resolve.assert_not_called()


def test_credential_flag_values_are_hidden_without_hiding_target_or_operation():
    from src.tools.approval_display import redact_approval
    text = "curl --password 'fake short' --token=fake-token -u testactor:fake-password -H 'Authorization: Basic ZmFrZQ==' https://target.test/operation"
    safe = redact_approval(text)
    for secret in ["fake short", "fake-token", "fake-password", "ZmFrZQ=="]:
        assert secret not in safe
    assert "testactor" in safe
    assert "https://target.test/operation" in safe
    assert "Authorization: Basic" in safe
