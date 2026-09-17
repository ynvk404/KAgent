from __future__ import annotations

import pytest

from src.permission.permission import (
    Decision,
    PermissionRequest,
    Prompter,
    YoloPrompter,
)
from src.tools.registry import Registry
from src.tools.types import Tool

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

    tool = GatedTool()
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
