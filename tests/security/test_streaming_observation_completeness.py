"""Real HTTPX async streams through production dispatch, without network I/O."""
import asyncio
from dataclasses import replace
import gzip

import httpx
import pytest

from src.permission.network.transport import governed_send
from src.permission.network.grants import HTTPReservation
from src.permission.runtime.observations import ObservationStore
from tests.security.test_execution_policy import runtime, REAL_CLIENT, ORIGIN  # noqa: F401


class Stream(httpx.AsyncByteStream):
    def __init__(self, chunks, failure=None):
        self.chunks = chunks
        self.failure = failure
        self.closed = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            await asyncio.sleep(0)
            yield chunk
        if self.failure:
            raise self.failure

    async def aclose(self):
        self.closed += 1


def install_stream(monkeypatch, chunks, *, encoding=None, failure=None):
    streams = []

    async def handler(request):
        stream = Stream(chunks, failure)
        streams.append(stream)
        headers = {'Content-Encoding': encoding} if encoding else {'Transfer-Encoding': 'chunked'}
        return httpx.Response(200, stream=stream, headers=headers, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))
    return streams


def released_reservations(monkeypatch):
    releases = []
    original = HTTPReservation.release

    def release(reservation):
        assert all(previous is not reservation for previous in releases)
        releases.append(reservation)
        return original(reservation)

    monkeypatch.setattr(HTTPReservation, 'release', release)
    return releases


@pytest.mark.parametrize('producer', ['http', 'content_discovery'])
@pytest.mark.parametrize('size', [0, 7, 8, 9])
@pytest.mark.parametrize('encoding', [None, 'gzip'])
async def test_stream_eof_and_cap_through_registry(runtime, tmp_path, monkeypatch, producer, size, encoding):
    registry, p, policy, _, _, _, _ = runtime
    releases = released_reservations(monkeypatch)
    rights = policy.engagement.http_permissions
    grant = next(iter(rights.grants.values()))
    rights.grants[grant.origin] = replace(grant, limits=replace(grant.limits, response_bytes=8))
    body = b'x' * size
    wire = gzip.compress(body) if encoding else body
    streams = install_stream(monkeypatch, [wire[:2], wire[2:5], wire[5:]], encoding=encoding)
    policy.observations.attach_storage(tmp_path / 'observations.json')
    args = ({'url': '/fixture', 'phase': 'recon', 'max_response_bytes': 8} if producer == 'http'
            else {'paths': ['fixture'], 'mode': 'native', 'max_requests': 3, 'rate_limit': 10})
    await registry.execute(producer, args, None, p)
    items = list(policy.observations._items.values())
    assert len(items) == len(streams) > 0
    assert len(releases) == len(streams)
    assert all(s.closed == 1 for s in streams)
    assert all(i.complete is (size <= 8) and i.truncated is (size > 8) for i in items)
    assert all(i.body == body[:8] for i in items)
    assert not rights._inflight and policy.active == 0
    restored = ObservationStore()
    restored.attach_storage(tmp_path / 'observations.json')
    assert restored._items == policy.observations._items


@pytest.mark.parametrize('ending', ['early', 'exception', 'cancel'])
async def test_governed_interruption_snapshots_once_and_releases(runtime, monkeypatch, ending):
    registry, p, policy, *_ = runtime
    releases = released_reservations(monkeypatch)
    failure = (httpx.ReadError('fixture') if ending == 'exception' else
               asyncio.CancelledError() if ending == 'cancel' else None)
    streams = install_stream(monkeypatch, [b'first', b'second'], failure=failure)
    tool = registry.get('content_discovery')
    args = {'paths': ['fixture'], 'mode': 'native', 'max_requests': 3}
    receipt = policy.prepare(tool, args)
    token = policy.start(receipt, tool, args, None)
    try:
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await governed_send(client, client.build_request('GET', ORIGIN + '/fixture'), p, None, response_cap=32)
            try:
                if ending == 'early':
                    async for _ in response.aiter_bytes():
                        break
                else:
                    with pytest.raises((httpx.ReadError, asyncio.CancelledError)):
                        await response.aread()
            finally:
                await response.aclose()
                await response.aclose()
        assert streams[0].closed == 1
        assert len(policy.observations._items) == 1
        item = next(iter(policy.observations._items.values()))
        assert not item.complete and not item.truncated
        assert item.execution_status == {'early': 'completed', 'exception': 'failed', 'cancel': 'cancelled'}[ending]
        assert len(releases) == 1
        assert not policy.engagement.http_permissions._inflight
    finally:
        policy.stop(token)


async def test_governed_decoder_flush_and_automatic_close(runtime, monkeypatch):
    registry, p, policy, *_ = runtime
    streams = install_stream(monkeypatch, [gzip.compress(b'fixture')], encoding='gzip')
    tool = registry.get('content_discovery')
    args = {'paths': ['fixture'], 'mode': 'native', 'max_requests': 3}
    token = policy.start(policy.prepare(tool, args), tool, args, None)
    try:
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await governed_send(client, client.build_request('GET', ORIGIN + '/fixture'), p, None, response_cap=32)
            assert b''.join([c async for c in response.aiter_bytes(chunk_size=32)]) == b'fixture'
            assert response.is_closed
            assert len(policy.observations._items) == 1
            item = next(iter(policy.observations._items.values()))
            assert item.complete and item.body == b'fixture'
            await response.aclose()
        assert streams[0].closed == 1 and not policy.engagement.http_permissions._inflight
    finally:
        policy.stop(token)


@pytest.mark.parametrize('producer', ['http', 'content_discovery'])
@pytest.mark.parametrize('size', [7, 8, 9])
async def test_wire_chunked_gzip_eof_through_production_dispatch(tmp_path, producer, size):
    from src.engagement.state import EngagementState
    from src.permission.runtime.execution import default_execution_policy
    from src.permission.permission import AlwaysAllow, YoloPrompter
    from src.permission.network.grants import HTTPLimits
    from src.tools.common.registry import Registry
    from src.tools.common.capabilities import CapabilityInventory
    from src.tools.discovery.content import ContentDiscoveryTool
    from src.tools.http.http_tool import HTTPTool
    from src.target.target import Target

    body = b'x' * size
    wire = gzip.compress(body)
    served = []
    writers = []

    async def serve(reader, writer):
        writers.append(writer)
        try:
            served.append(await reader.readuntil(b'\r\n\r\n'))
            writer.write(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\n')
            for chunk in [wire[:5], wire[5:]]:
                writer.write(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
                await writer.drain()
                await asyncio.sleep(0)
            writer.write(b'0\r\n\r\n')
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(serve, '127.0.0.1', 0)
    try:
        origin = f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}'
        state = EngagementState()
        state.initialize_target(origin)
        target = Target(origin)
        policy = default_execution_policy(state, tmp_path)
        state.http_permissions.activate(origin, HTTPLimits(response_bytes=8, rate=1000, burst=100))
        p = YoloPrompter(AlwaysAllow(), True)
        p.bind_execution_policy(policy)
        registry = Registry()
        registry.register(HTTPTool(target, state))
        registry.register(ContentDiscoveryTool(target, state, CapabilityInventory(which=lambda _: None), lambda: 'minimal'))
        args = ({'url': '/fixture', 'phase': 'recon', 'max_response_bytes': 8} if producer == 'http' else
                {'paths': ['fixture'], 'mode': 'native', 'max_requests': 3, 'rate_limit': 10})
        await registry.execute(producer, args, None, p)
        items = list(policy.observations._items.values())
        assert len(items) == len(served) > 0
        assert all(i.body == body[:8] and i.complete is (size <= 8) and i.truncated is (size > 8) for i in items)
        assert not state.http_permissions._inflight and policy.active == 0
    finally:
        server.close()
        await server.wait_closed()
        for writer in writers:
            writer.close()
            await writer.wait_closed()
