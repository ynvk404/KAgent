"""Deterministic origin review scheduling; no network or wall-clock deadlines."""
import asyncio

import pytest

from src.permission.network.grants import HTTPBlocked, HTTPReviewTimeout
from src.permission.permission import Decision
from tests.security.test_http_grants import runtime, args


class Reviews:
    def __init__(self):
        self.requests = []
        self.decisions = []

    async def ask(self, request, signal=None):
        decision = asyncio.get_running_loop().create_future()
        self.requests.append(request)
        self.decisions.append(decision)
        return await decision


async def until(predicate):
    async with asyncio.timeout(2):
        while not predicate():
            await asyncio.sleep(0)


def authorize(tool, operator, path):
    action, _ = tool.prepare(args(path))
    async def run():
        with tool.permissions.reviewed_dispatch(action):
            return await tool.permissions.authorize(action, operator, None, lambda: tool.target.revision)
    return action, asyncio.create_task(run())


@pytest.mark.parametrize('cancel_b', [False, True])
async def test_fifo_newcomer_at_release_and_cancelled_waiter(runtime, cancel_b):
    tool, _, sent, _ = runtime
    reviews = Reviews()
    a, first = authorize(tool, reviews, '/a')
    await until(lambda: len(reviews.requests) == 1)
    b, second = authorize(tool, reviews, '/b')
    await until(lambda: tool.permissions._review_locks[a.origin][1] == 2)
    if cancel_b:
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
    reviews.decisions[0].set_result(Decision.ALLOW_ONCE)
    c, third = authorize(tool, reviews, '/c')
    await first
    await until(lambda: len(reviews.requests) == 2)
    assert reviews.requests[1].summary.endswith('/c' if cancel_b else '/b')
    reviews.decisions[1].set_result(Decision.ALLOW_ONCE)
    if not cancel_b:
        await second
        await until(lambda: len(reviews.requests) == 3)
        assert reviews.requests[2].summary.endswith('/c')
        reviews.decisions[2].set_result(Decision.ALLOW_ONCE)
    await third
    assert not tool.permissions._review_locks and not tool.permissions._pending and not sent


async def test_queue_time_does_not_consume_active_review_lease(runtime):
    tool, _, sent, _ = runtime
    now = [0.0]
    rights = tool.permissions
    rights.clock = lambda: now[0]
    rights.review_timeout = 5
    reviews = Reviews()
    a, first = authorize(tool, reviews, '/a')
    await until(lambda: len(reviews.requests) == 1)
    b, second = authorize(tool, reviews, '/b')
    await until(lambda: rights._review_locks[a.origin][1] == 2)
    now[0] = 4
    reviews.decisions[0].set_result(Decision.ALLOW_ONCE)
    await first
    await until(lambda: len(reviews.requests) == 2)
    now[0] = 6
    assert reviews.requests[1].is_current()
    reviews.decisions[1].set_result(Decision.ALLOW_ONCE)
    receipt = await second
    # authorize() alone leaves a review ticket, never dispatches traffic.
    assert receipt.expires_at == 9 and receipt.invocation_id == b.invocation_id
    assert not sent and not rights._review_locks


async def test_queue_expiry_is_pending_and_never_replayed(runtime):
    tool, _, sent, _ = runtime
    rights = tool.permissions
    now = [0.0]
    rights.clock = lambda: now[0]
    rights.review_timeout = 5
    reviews = Reviews()
    a, first = authorize(tool, reviews, '/a')
    await until(lambda: len(reviews.requests) == 1)
    _, second = authorize(tool, reviews, '/b')
    await until(lambda: rights._review_locks[a.origin][1] == 2)
    now[0] = 5
    with pytest.raises(HTTPReviewTimeout) as failure:
        await second
    assert failure.value.error_kind == 'permission_timeout' and not failure.value.explicit_denial
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert len(reviews.requests) == 1 and not sent and not rights._review_locks


async def test_explicit_session_grant_coalesces_review_but_never_receipts(runtime):
    tool, _, sent, _ = runtime
    reviews = Reviews()
    a, first = authorize(tool, reviews, '/a')
    await until(lambda: len(reviews.requests) == 1)
    b, second = authorize(tool, reviews, '/b')
    await until(lambda: tool.permissions._review_locks[a.origin][1] == 2)
    reviews.decisions[0].set_result(Decision.ALLOW_SESSION)
    ra, rb = await asyncio.gather(first, second)
    assert len(reviews.requests) == 1 and ra.id != rb.id
    assert ra.invocation_id == a.invocation_id and rb.invocation_id == b.invocation_id
    with pytest.raises(HTTPBlocked):
        tool.permissions.dispatch_receipt(ra, b, None, tool.target.revision)
    assert not sent and not tool.permissions._review_locks


@pytest.mark.parametrize('owner', [True, False])
async def test_repeated_cancellation_releases_owner_or_waiter_without_poisoning_retry(runtime, owner):
    tool, _, sent, _ = runtime
    reviews = Reviews()
    action, first = authorize(tool, reviews, '/first')
    await until(lambda: len(reviews.requests) == 1)
    _, second = authorize(tool, reviews, '/second')
    await until(lambda: tool.permissions._review_locks[action.origin][1] == 2)
    cancelled, remaining = (first, second) if owner else (second, first)
    cancelled.cancel()
    asyncio.get_running_loop().call_soon(cancelled.cancel)
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    if owner:
        await until(lambda: len(reviews.requests) == 2)
        reviews.decisions[1].set_result(Decision.ALLOW_ONCE)
    else:
        reviews.decisions[0].set_result(Decision.ALLOW_ONCE)
    await remaining
    assert not sent and not tool.permissions._review_locks and not tool.permissions._pending


@pytest.mark.parametrize('failure', ['callback_timeout', 'expired_reply', 'expired_bridge'])
@pytest.mark.parametrize('reviewed', [False, True])
async def test_active_review_timeout_has_permission_metadata_and_legacy_timeout_base(runtime, failure, reviewed):
    from src.permission.permission import PermissionReviewStale
    tool, _, sent, _ = runtime
    now = [0.0]
    tool.permissions.clock = lambda: now[0]
    tool.permissions.review_timeout = 5

    class Operator:
        async def ask(self, request, signal=None):
            if failure == 'callback_timeout':
                raise TimeoutError('synthetic operator review timeout')
            now[0] = 5
            if failure == 'expired_bridge':
                raise PermissionReviewStale('blocked: stale permission review')
            return Decision.ALLOW_ONCE

    if reviewed:
        _, task = authorize(tool, Operator(), '/expired-review')
    else:
        action, _ = tool.prepare(args('/expired-review'))
        task = asyncio.create_task(tool.permissions.authorize(
            action, Operator(), None, lambda: tool.target.revision))
    with pytest.raises(HTTPReviewTimeout) as result:
        await task
    assert isinstance(result.value, TimeoutError)
    assert result.value.error_kind == 'permission_timeout' and not result.value.explicit_denial
    assert not sent and not tool.permissions._review_locks and not tool.permissions._receipts
