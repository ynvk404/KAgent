import pytest

from src.permission.permission import (
    Decision,
    PermissionRequest,
    Prompter,
    YoloPrompter,
)


class ScriptedPrompter(Prompter):

    def __init__(
        self,
        decision: Decision,
    ):
        self._decision = decision
        self.seen: list[PermissionRequest] = []

    async def ask(
        self,
        request: PermissionRequest,
        signal=None,
    ) -> Decision:
        self.seen.append(request)
        return self._decision


@pytest.mark.asyncio
async def test_auto_approves_without_prompting():

    inner = ScriptedPrompter(
        Decision.DENY,
    )

    yolo = YoloPrompter(
        inner,
        True,
    )

    decision = await yolo.ask(
        PermissionRequest(
            tool="shell",
            summary="s",
            detail="d",
        )
    )

    assert decision == Decision.ALLOW_ONCE
    assert len(inner.seen) == 0


@pytest.mark.asyncio
async def test_yolo_defers_sensitive_requests_to_the_real_prompter():

    inner = ScriptedPrompter(
        Decision.DENY,
    )

    yolo = YoloPrompter(
        inner,
        True,
    )

    decision = await yolo.ask(
        PermissionRequest(
            tool="file",
            summary="s",
            detail="d",
            no_session_cache=True,
        )
    )

    assert decision == Decision.DENY
    assert len(inner.seen) == 1


@pytest.mark.asyncio
async def test_defers_to_real_prompter():

    inner = ScriptedPrompter(
        Decision.DENY,
    )

    yolo = YoloPrompter(
        inner,
        False,
    )

    decision = await yolo.ask(
        PermissionRequest(
            tool="shell",
            summary="s",
            detail="d",
        )
    )

    assert decision == Decision.DENY
    assert len(inner.seen) == 1
