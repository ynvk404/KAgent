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
async def test_auto_approves_only_a_tool_marked_routine_action():

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
            yolo_auto_approve=True,
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
async def test_risk_tier_does_not_force_no_session_cache_or_control_yolo():
    inner = ScriptedPrompter(Decision.DENY)
    yolo = YoloPrompter(inner, True)
    request = PermissionRequest(
        tool="shell",
        summary="run bounded impact check",
        detail="exact command",
        risk_tier="bounded-impact",
    )

    decision = await yolo.ask(request)

    assert request.no_session_cache is False
    assert decision == Decision.DENY
    assert inner.seen == [request]


@pytest.mark.asyncio
async def test_yolo_eligibility_is_independent_of_risk_tier_and_session_trust():
    inner = ScriptedPrompter(Decision.DENY)
    yolo = YoloPrompter(inner, True)
    request = PermissionRequest(
        tool="http",
        summary="bounded validation request",
        detail="POST marker probe in the active scope",
        risk_tier="bounded-impact",
        yolo_auto_approve=True,
    )

    decision = await yolo.ask(request)

    assert decision == Decision.ALLOW_ONCE
    assert request.no_session_cache is False
    assert inner.seen == []


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
