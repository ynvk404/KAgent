from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from src.findings.store import Store as FindingsStore
from src.config.config import PluginConfig
from src.coverage.store import CoverageStore
from src.engagement.state import EngagementState
from src.permission.http_grants import HTTPLimits
from src.permission.permission import (
    Decision,
    PermissionRequest,
    Prompter,
    UserControlledRefusal,
    YoloPrompter,
)
from src.target.target import Target
from src.tools.workflow.coverage import CoverageTool
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.execution.file import FileWriteTool
from src.tools.http.http_tool import HTTPTool
from src.tools.execution.plugin import CommandPluginTool
from src.tools.common.registry import Registry
from src.tools.execution.shell import ShellTool
from src.tools.common.types import Tool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowState

class GatedTool:
    def __init__(self):
        self.ran = False

    def name(self) -> str:
        return "http"

    def description(self) -> str:
        return "gated"

    def schema(self) -> dict:
        return {
            "type": "object"
        }

    def requires_permission(self) -> bool:
        return True

    async def run(
        self,
        args,
        signal,
        prompter,
    ) -> str:
        self.ran = True
        return "ok"


class YoloEligibleTool(GatedTool):
    def permission_hints(self, _args):
        return {"yoloAutoApprove": True}


def test_duplicate_registration_rejects_and_preserves_original():
    registry = Registry()
    original = GatedTool()
    registry.register(original)
    with pytest.raises(ValueError, match="duplicate tool registration: http"):
        registry.register(GatedTool())
    assert registry.get("http") is original


def test_plugin_name_cannot_replace_builtin():
    registry = Registry()
    original = GatedTool()
    registry.register(original)
    plugin = CommandPluginTool(PluginConfig(
        name="http", command="echo", args=[], description="",
        requires_permission=False,
    ))
    with pytest.raises(ValueError, match="duplicate tool registration: http"):
        registry.register(plugin)
    assert registry.get("http") is original


def test_second_plugin_cannot_replace_first():
    registry = Registry()
    first = CommandPluginTool(PluginConfig(name="plugin", command="echo"))
    second = CommandPluginTool(PluginConfig(name="plugin", command="echo"))
    registry.register(first)
    with pytest.raises(ValueError, match="duplicate tool registration: plugin"):
        registry.register(second)
    assert registry.get("plugin") is first


class ActionAwareTool(GatedTool):
    def __init__(self, requires: bool):
        super().__init__()
        self.requires = requires
        self.legacy_checked = False

    def requires_permission(self) -> bool:
        self.legacy_checked = True
        return not self.requires

    def requires_permission_for(self, args) -> bool:
        return self.requires


class PreserveContextTool(GatedTool):
    def context_reduction_policy(self) -> str:
        return "preserve"


class InvalidContextPolicyTool(GatedTool):
    def context_reduction_policy(self) -> str:
        return "invalid"

class SpyPrompter:
    def __init__(
        self,
        decision: Decision = Decision.DENY,
    ):
        self.calls: list[PermissionRequest] = []
        self.decision = decision

    async def ask(
        self,
        request: PermissionRequest,
        signal=None,
    ) -> Decision:
        self.calls.append(request)
        return self.decision

@pytest.mark.asyncio
async def test_yolo_auto_approves_permission_tool_without_calling_prompter():
    reg = Registry()

    tool = YoloEligibleTool()
    reg.register(tool)

    inner = SpyPrompter(
        Decision.DENY
    )

    yolo = YoloPrompter(
        inner,
        True,
    )

    out = await reg.execute(
        "http",
        {
            "url": "http://example.test/"
        },
        None,
        yolo,
    )

    assert out == "ok"
    assert tool.ran is True
    assert len(inner.calls) == 0


@pytest.mark.asyncio
async def test_yolo_does_not_bypass_non_cacheable_coverage_clear(tmp_path):
    registry = Registry()
    store = CoverageStore(str(tmp_path / "coverage.json"))
    registry.register(CoverageTool(store))
    inner = SpyPrompter(Decision.DENY)
    yolo = YoloPrompter(inner, True)

    with pytest.raises(UserControlledRefusal):
        await registry.execute("coverage", {"action": "clear"}, None, yolo)

    assert len(inner.calls) == 1
    assert inner.calls[0].no_session_cache is True


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["shell", "file_write", "http", "plugin"])
async def test_unprofiled_generic_tools_and_ordinary_http_keep_review(action, tmp_path, monkeypatch):
    send = AsyncMock()
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient.send", send)
    registry = Registry()
    if action == "shell":
        registry.register(ShellTool())
        args = {"command": "printf approval-gated"}
        expected_tier = "high-impact"
    elif action == "file_write":
        path = tmp_path / "must-not-write.txt"
        registry.register(FileWriteTool())
        args = {"path": str(path), "content": "must not be written"}
        expected_tier = "high-impact"
    elif action == "plugin":
        registry.register(CommandPluginTool(PluginConfig(
            name="plugin",
            command="python",
            args=["-c", "raise SystemExit(99)"],
            description="external action",
            requires_permission=False,
        )))
        args = {}
        expected_tier = "high-impact"
    else:
        target = Target("https://target.test")
        engagement = EngagementState()
        engagement.initialize_target(target.base_url())
        engagement.http_permissions.activate(target.base_url(), HTTPLimits(), "confirm-each")
        registry.register(HTTPTool(target, engagement))
        args = {"phase": "impact", "method": "POST", "url": "/submit", "body": "marker"}
        expected_tier = "high-impact"

    inner = SpyPrompter(Decision.DENY)
    yolo = YoloPrompter(inner, action != "http")

    with pytest.raises(UserControlledRefusal):
        await registry.execute(action, args, None, yolo)

    assert len(inner.calls) == 1
    assert inner.calls[0].no_session_cache is True
    assert inner.calls[0].risk_tier == expected_tier
    send.assert_not_called()
    if action == "file_write":
        assert not path.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
async def test_ordinary_http_confirm_each_denial_stops_dispatch(method, monkeypatch):
    send = AsyncMock()
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient.send", send)
    target = Target("https://target.test")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    engagement.http_permissions.activate(target.base_url(), HTTPLimits(), "confirm-each")
    registry = Registry()
    registry.register(HTTPTool(target, engagement))
    inner = SpyPrompter(Decision.DENY)
    yolo = YoloPrompter(inner, False)

    with pytest.raises(UserControlledRefusal):
        await registry.execute(
            "http",
            {"phase": "impact", "method": method, "url": "/item/1", "body": "{}"},
            None,
            yolo,
        )

    assert len(inner.calls) == 1
    assert inner.calls[0].risk_tier == "high-impact"
    assert inner.calls[0].no_session_cache is True
    send.assert_not_called()

@pytest.mark.asyncio
async def test_prompts_and_denies_when_yolo_disabled():
    reg = Registry()

    reg.register(
        GatedTool()
    )

    inner = SpyPrompter(
        Decision.DENY
    )

    yolo = YoloPrompter(
        inner,
        False,
    )

    with pytest.raises(
        PermissionError,
        match="permission denied",
    ):
        await reg.execute(
            "http",
            {
                "url": "http://example.test/"
            },
            None,
            yolo,
        )

    assert len(inner.calls) == 1


@pytest.mark.asyncio
async def test_permission_denial_has_typed_user_controlled_refusal():
    reg = Registry()
    reg.register(GatedTool())

    with pytest.raises(UserControlledRefusal, match="permission denied"):
        await reg.execute(
            "http",
            {"url": "http://example.test/"},
            None,
            SpyPrompter(Decision.DENY),
        )


@pytest.mark.asyncio
async def test_action_aware_permission_hook_requires_permission_when_true():
    reg = Registry()
    tool = ActionAwareTool(requires=True)
    reg.register(tool)
    prompter = SpyPrompter(Decision.DENY)

    with pytest.raises(PermissionError):
        await reg.execute("http", {"action": "clear"}, None, prompter)

    assert tool.ran is False
    assert tool.legacy_checked is False
    assert len(prompter.calls) == 1


@pytest.mark.asyncio
async def test_action_aware_permission_hook_executes_without_permission_when_false():
    reg = Registry()
    tool = ActionAwareTool(requires=False)
    reg.register(tool)
    prompter = SpyPrompter(Decision.DENY)

    assert await reg.execute("http", {"action": "summary"}, None, prompter) == "ok"
    assert tool.ran is True
    assert tool.legacy_checked is False
    assert prompter.calls == []


def test_context_reduction_policy_defaults_to_adaptive_for_known_and_unknown_tools():
    reg = Registry()
    reg.register(GatedTool())

    assert reg.context_reduction_policy("http") == "adaptive"
    assert reg.context_reduction_policy("historical_tool") == "adaptive"
    assert reg.context_reduction_policy(None) == "adaptive"


def test_context_reduction_policy_uses_optional_tool_metadata():
    reg = Registry()
    reg.register(PreserveContextTool())

    assert reg.context_reduction_policy("http") == "preserve"


def test_invalid_context_reduction_metadata_falls_back_to_adaptive():
    reg = Registry()
    reg.register(InvalidContextPolicyTool())

    assert reg.context_reduction_policy("http") == "adaptive"


def test_real_tool_metadata_resolves_protected_and_adaptive_policies(tmp_path):
    """Exercise the registry path used by the context guard, not a test double."""
    reg = Registry()
    reg.register(WorkflowTool(WorkflowState()))
    reg.register(ConfirmFindingTool(FindingsStore(str(tmp_path / "findings"))))
    reg.register(CoverageTool(CoverageStore(str(tmp_path / "coverage.json"))))

    assert reg.context_reduction_policy("workflow") == "preserve"
    assert reg.context_reduction_policy("confirm_finding") == "preserve"
    assert reg.context_reduction_policy("coverage") == "adaptive"
