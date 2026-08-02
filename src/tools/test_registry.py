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


# ============================================================
# Fake permission-required tool
# ============================================================

class GatedTool:
    """
    Tool yêu cầu permission, giả lập http/shell.
    """

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


# ============================================================
# Spy Prompter
# ============================================================

class SpyPrompter:
    """
    Ghi nhận xem có bị gọi ask() hay không.
    """

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


# ============================================================
# Tests
# ============================================================

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

    # Inner prompter không được gọi
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