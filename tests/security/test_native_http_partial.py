"""Partial native streams retain forensic bytes without issuing terminal proof."""
import asyncio

import httpx
import pytest

from src.permission.runtime.observations import ObservationPersistenceError
from tests.security.test_execution_policy import runtime, REAL_CLIENT
from tests.security.test_agent_assessment import setup
from tests.helpers.agent_fakes import FakeSignal


@pytest.mark.parametrize('failure', ['transport', 'cancelled', 'empty', 'cap', 'storage', 'revoked', 'stale', 'close'])
async def test_partial_stream_publication_cleanup_and_original_error(runtime, tmp_path, monkeypatch, failure):
    registry, prompter, policy, _, _, _, target = runtime
    policy.observations.attach_storage(tmp_path / 'observations.json')
    closed = []
    original = asyncio.CancelledError() if failure == 'cancelled' else httpx.ReadError('fixture transport failed')

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            if failure != 'empty':
                yield b'x' * 800 if failure == 'cap' else b'partial fixture'
            if failure == 'revoked':
                policy.revoke('http')
            if failure == 'stale':
                target.set_base_url('http://127.0.0.1:3001')
            raise original

        async def aclose(self):
            closed.append(True)
            if failure == 'close':
                raise RuntimeError('fixture close failure')

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, headers={'Content-Type': 'text/plain', 'Set-Cookie': 'secret=fixture'},
                                   stream=Stream(), request=req)), **kw))
    if failure == 'storage':
        def fail(_items):
            raise ObservationPersistenceError('failed')
        monkeypatch.setattr(policy.observations, '_persist_snapshot', fail)
    args = {'url': '/fixture', 'phase': 'recon', 'max_response_bytes': 512}
    if failure == 'cap':
        result = await registry.execute('http', args, None, prompter)
        assert result.truncated and result.status != 'error'
    else:
        with pytest.raises(type(original)) as caught:
            await registry.execute('http', args, None, prompter)
        assert caught.value is original
    assert closed == [True] and policy.active == 0
    assert not policy._active_receipts
    assert all(budget.active == 0 for budget in policy.engagement.http_permissions._budgets.values())
    if failure in {'transport', 'cancelled', 'cap', 'close'}:
        items = list(policy.observations._items.values())
        assert len(items) == 1
        item = items[0]
        assert not item.complete and item.status == 200
        assert item.execution_status == {'transport': 'failed', 'cancelled': 'cancelled', 'cap': 'completed', 'close': 'failed'}[failure]
        assert item.truncated == (failure == 'cap')
        assert item.body == (b'x' * 512 if failure == 'cap' else b'partial fixture')
        assert ('content-type', 'text/plain') in item.response_headers
        assert not any(k == 'set-cookie' for k, _ in item.response_headers)
        assert item.elapsed_ms is not None and item.request_hash and item.response_hash
        assert policy.observations.storage.is_file()
    else:
        assert not policy.observations._items


async def test_task_cancellation_after_bytes_preserves_partial_once(runtime, monkeypatch):
    registry, prompter, policy, *_ = runtime
    waiting = asyncio.Event()
    closed = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'partial'
            waiting.set()
            await asyncio.Event().wait()

        async def aclose(self):
            closed.append(True)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, stream=Stream(), request=req)), **kw))
    task = asyncio.create_task(registry.execute('http', {'url': '/fixture', 'phase': 'recon'}, None, prompter))
    await asyncio.wait_for(waiting.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(policy.observations._items) == 1 and closed == [True]
    item = next(iter(policy.observations._items.values()))
    assert item.execution_status == 'cancelled' and not item.complete


@pytest.mark.parametrize('abort_at', ['first-bytes', 'stream-end'])
async def test_signal_revoked_receipt_cannot_publish_after_received_bytes(runtime, monkeypatch, abort_at):
    registry, prompter, policy, *_ = runtime
    signal = FakeSignal()
    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            if abort_at == 'first-bytes': signal.aborted = True
            yield b'partial'
            signal.aborted = True
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, stream=Stream(), request=req)), **kw))
    with pytest.raises(asyncio.CancelledError):
        await registry.execute('http', {'url': '/fixture', 'phase': 'recon'}, signal, prompter)
    # Signal cancellation revokes the current receipt through ReviewGuard.
    # Task cancellation above retains forensic bytes while authority is valid.
    assert not policy.observations._items and policy.active == 0


@pytest.mark.parametrize('stale_owner', [False, True])
async def test_partial_owned_observation_cannot_support_terminal_result(runtime, tmp_path, monkeypatch, stale_owner):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, prompter, policy, *_ = runtime

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'partial response'
            if stale_owner:
                state.attempts[args['attempt_id']]['status'] = 'interrupted'
            raise httpx.ReadError('fixture')

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, stream=Stream(), request=req)), **kw))
    before = set(policy.observations._items)
    with pytest.raises(httpx.ReadError):
        await registry.execute('http', {'url': '/fixture?q=partial', 'phase': 'validation'}, None, prompter)
    if stale_owner:
        assert set(policy.observations._items) == before
        return
    oid = next(reversed(policy.observations._items))
    item = policy.observations._items[oid]
    assert item.candidate_id == candidate.id and item.attempt_id == args['attempt_id']
    dispatch = state.attempts[args['attempt_id']]['effects']['dispatches'][-1]
    assert dispatch['status'] == 'failed' and dispatch['observation_id'] == oid
    result = await registry.execute('workflow', {**args, 'observation_ids': [oid]}, None, prompter)
    assert result.startswith('error:') and not state.validation_results
    assert not state.eligible_for_finding(candidate.id)
