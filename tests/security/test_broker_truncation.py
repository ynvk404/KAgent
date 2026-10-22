"""F2: real offline wire framing, native diagnostics and worker delivery."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, contextmanager
from dataclasses import replace
import gzip
import http.client
import io
import json
import shlex
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest

from src.engagement.state import EngagementState
from src.permission.network.grants import HTTPLimits
from src.permission.runtime.execution import ExecutionPolicy
from src.permission.runtime.observations import ObservationPersistenceError, ObservationStore
from src.permission.worker.broker import BrokerCollector, broker_directory
from src.target.target import Target
from src.tools.common.runtime_metadata import BrokerHTTPMetadata, RuntimeMetadata, runtime_view
from src.tools.discovery.content import ContentDiscoveryTool
from src.session.store import Store, _message_from_dict
from tests.security.test_offline_worker import worker_runtime
from tests.security.test_streaming_observation_completeness import released_reservations
from tests.agent.test_tool_result_offloading import make, record
from src.agent.agent import bounded_history_for_compaction

CAP = 65536


@asynccontextmanager
async def upstream(body=b'fixture', *, framing='length', encoding=None, status=200,
                   headers=(), failure=False, pause=None):
    tasks = set()
    requests = []
    closed = []
    wire = gzip.compress(body) if encoding == 'gzip' else body

    async def serve(reader, writer):
        try:
            head = await reader.readuntil(b'\r\n\r\n')
            requests.append(head)
            reason = http.client.responses[status]
            rows = [f'HTTP/1.1 {status} {reason}', 'Connection: close', *headers]
            if framing == 'length':
                rows.append(f'Content-Length: {len(wire) + (10 if failure else 0)}')
            else:
                rows.append('Transfer-Encoding: chunked')
            if encoding:
                rows.append('Content-Encoding: ' + encoding)
            writer.write(('\r\n'.join(rows) + '\r\n\r\n').encode())
            if pause:
                await writer.drain()
                pause[0].set()
                await pause[1].wait()
            if not head.startswith(b'HEAD ') and status not in {204, 304}:
                for offset in range(0, len(wire), 8192):
                    chunk = wire[offset:offset + 8192]
                    writer.write((f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
                                 if framing == 'chunked' else chunk)
                    await writer.drain()
                if framing == 'chunked' and not failure:
                    writer.write(b'0\r\n\r\n')
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
            closed.append(True)

    def accepted(reader, writer):
        task = asyncio.create_task(serve(reader, writer))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    server = await asyncio.start_server(accepted, '127.0.0.1', 0)
    origin = f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}'
    try:
        yield origin, requests, closed
    finally:
        server.close()
        pending = tuple(tasks)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await server.wait_closed()


@contextmanager
def authority(tmp_path, origin):
    state = EngagementState()
    state.initialize_target(origin)
    state.http_permissions.activate(origin, HTTPLimits(requests=100, response_bytes=CAP,
                                                       rate=1000, burst=100, concurrency=20))
    policy = ExecutionPolicy(state, tmp_path)
    owner = {'session_id': 'session-fixture', 'objective_id': 'objective-fixture', 'id': 'invocation-fixture'}
    policy.observations.owner_provider = lambda: owner
    tool = ContentDiscoveryTool(Target(origin), state)
    args = {'paths': ['fixture'], 'mode': 'native', 'max_requests': 3}
    token = policy.start(policy.prepare(tool, args), tool, args, None)
    try:
        yield policy
    finally:
        policy.stop(token)


async def exchange(directory, origin, *, method='GET', headers=()):
    reader, writer = await asyncio.open_unix_connection(str(directory / 'broker.sock'))
    writer.write((f'{method} {origin}/fixture HTTP/1.1\r\nHost: fixture\r\n'
                  + '\r\n'.join(headers) + '\r\n\r\n').encode())
    await writer.drain()
    try:
        return await asyncio.wait_for(reader.read(), 5)
    finally:
        writer.close()
        await writer.wait_closed()


class WireSocket:
    def __init__(self, wire):
        self.wire = wire

    def makefile(self, *args):
        return io.BytesIO(self.wire)


def consume(wire, *, method='GET', incomplete=False):
    response = http.client.HTTPResponse(cast(Any, WireSocket(wire)), method=method)
    response.begin()
    if incomplete:
        with pytest.raises(http.client.IncompleteRead) as caught:
            response.read()
        body = caught.value.partial
    else:
        body = response.read()
    return response, body


@pytest.mark.parametrize('size', [CAP - 1, CAP, CAP + 1, CAP * 12])
@pytest.mark.parametrize('framing,encoding', [('length', None), ('chunked', None), ('length', 'gzip'), ('chunked', 'gzip')])
async def test_wire_cap_boundary_binary_gzip_and_framing(tmp_path, monkeypatch, size, framing, encoding):
    body = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    releases = released_reservations(monkeypatch)
    async with upstream(body, framing=framing, encoding=encoding) as (origin, requests, _):
        with authority(tmp_path, origin) as policy:
            collector = BrokerCollector()
            async with broker_directory(collector=collector) as directory:
                wire = await exchange(directory, origin)
            response, actual = consume(wire, incomplete=size > CAP)
            assert response.status == 200 and actual == body[:CAP]
            assert response.getheader('Content-Length') is None
            assert response.getheader('Content-Encoding') is None
            assert response.getheader('Content-Range') is None
            assert wire.count(b'HTTP/1.1 ') == 1
            totals = collector.snapshot()
            assert totals.requests == 1 and totals.truncated == int(size > CAP)
            assert totals.complete == int(size <= CAP) and totals.interrupted == 0
            assert totals.observation_memory_only == 1
            assert len(requests) == len(releases) == 1
            item, = policy.observations._items.values()
            # Invalid UTF-8 expands in the redacted textual observation. Its
            # retention is partial even when the upstream binary body fit.
            assert not item.complete and item.truncated
            assert item.session_id == 'session-fixture' and item.attempt_id == 'invocation-fixture'
            assert item.invocation_id and item.invocation_id != item.attempt_id
            assert len(item.body) <= CAP
            assert totals.observation_partial == int(not item.complete)
            assert not policy.engagement.http_permissions._inflight
            assert not directory.exists()


@pytest.mark.parametrize('method,status', [('HEAD', 200), ('GET', 204), ('GET', 304), ('GET', 206)])
async def test_no_body_and_legitimate_range_are_not_truncation(tmp_path, method, status):
    headers = ['Content-Range: bytes 0-6/90000'] if status == 206 else []
    body = b'fixture' if status == 206 else b'x' * (CAP + 1)
    async with upstream(body, status=status, headers=headers) as (origin, _, _):
        with authority(tmp_path, origin):
            collector = BrokerCollector()
            async with broker_directory(collector=collector) as directory:
                wire = await exchange(directory, origin, method=method, headers=['Range: bytes=0-6'] if status == 206 else [])
            response, actual = consume(wire, method=method)
            assert response.status == status and actual == (body if status == 206 else b'')
            if method == 'HEAD' or status == 304:
                assert response.getheader('Content-Length') == str(len(body))
            if status == 204:
                assert response.getheader('Content-Length') is None
            if status == 206:
                assert response.getheader('Content-Range') == 'bytes 0-6/90000'
            assert collector.snapshot().complete == 1 and collector.snapshot().truncated == 0


async def test_concurrent_requests_and_broker_invocations_do_not_mix(tmp_path):
    async with upstream(b'x' * (CAP + 1)) as (big, _, _), upstream(b'ok') as (small, _, _):
        async def run(origin, count):
            with authority(tmp_path, origin) as policy:
                collector = BrokerCollector()
                async with broker_directory(collector=collector) as directory:
                    wires = await asyncio.gather(*(exchange(directory, origin) for _ in range(count)))
                assert len(policy.observations._items) == count
                assert all(item.url.startswith(origin) for item in policy.observations._items.values())
                assert len({item.invocation_id for item in policy.observations._items.values()}) == count
                assert not policy.engagement.http_permissions._inflight
                return collector.snapshot(), wires
        (large, a), (short, b) = await asyncio.gather(run(big, 4), run(small, 3))
        assert large.requests == large.truncated == 4 and large.complete == 0
        assert short.requests == short.complete == 3 and short.truncated == 0
        assert all(consume(w, incomplete=True)[1] == b'x' * CAP for w in a)
        assert all(consume(w)[1] == b'ok' for w in b)


@pytest.mark.parametrize('persistence', ['failed', 'unknown'])
@pytest.mark.parametrize('transport_failure', [False, True])
async def test_persistence_and_transport_failure_are_independent(tmp_path, monkeypatch, persistence, transport_failure):
    releases = released_reservations(monkeypatch)
    async with upstream(b'bounded', failure=transport_failure) as (origin, _, _):
        with authority(tmp_path, origin) as policy:
            attempted = []
            def fail(staged):
                attempted.extend(staged)
                raise ObservationPersistenceError(persistence)
            monkeypatch.setattr(policy.observations, '_persist_snapshot', fail)
            collector = BrokerCollector()
            async with broker_directory(collector=collector) as directory:
                wire = await exchange(directory, origin)
            response, body = consume(wire, incomplete=transport_failure)
            assert response.status == 200 and wire.count(b'HTTP/1.1 ') == 1
            if not transport_failure:
                assert body == b'bounded'
            totals = collector.snapshot()
            assert totals.complete == int(not transport_failure)
            assert totals.transport_failed == int(transport_failure)
            assert totals.interrupted == int(transport_failure)
            assert getattr(totals, 'observation_' + persistence) == 1
            assert not policy.observations._items and len(attempted) == 1
            assert len(releases) == 1 and not policy.engagement.http_permissions._inflight


async def test_cleanup_cancels_inflight_before_snapshot_and_releases_once(tmp_path, monkeypatch):
    releases = released_reservations(monkeypatch)
    started, resume = asyncio.Event(), asyncio.Event()
    async with upstream(b'pending', pause=(started, resume)) as (origin, _, _):
        with authority(tmp_path, origin) as policy:
            collector = BrokerCollector()
            async with broker_directory(collector=collector) as directory:
                consumer = asyncio.create_task(exchange(directory, origin))
                await asyncio.wait_for(started.wait(), 3)
            await consumer
            totals = collector.snapshot()
            assert totals.requests == totals.interrupted == totals.cancelled == 1
            assert len(releases) == 1 and not policy.engagement.http_permissions._inflight
            assert not directory.exists()
            before = totals
            await asyncio.sleep(0)
            assert collector.snapshot() == before


async def test_observed_consumer_early_disconnect_has_its_own_counter(tmp_path):
    started, resume = asyncio.Event(), asyncio.Event()
    async with upstream(b'x' * CAP, pause=(started, resume)) as (origin, _, _):
        with authority(tmp_path, origin) as policy:
            collector = BrokerCollector()
            async with broker_directory(collector=collector) as directory:
                _, writer = await asyncio.open_unix_connection(str(directory / 'broker.sock'))
                writer.write(f'GET {origin}/fixture HTTP/1.1\r\n\r\n'.encode())
                await writer.drain()
                await started.wait()
                writer.transport.abort()
                await writer.wait_closed()
                resume.set()
                for _ in range(100):
                    if collector.snapshot().requests:
                        break
                    await asyncio.sleep(.01)
            totals = collector.snapshot()
            assert totals.complete == totals.consumer_disconnects == 1
            assert totals.truncated == totals.interrupted == 0
            assert not policy.engagement.http_permissions._inflight


@pytest.mark.parametrize('pipeline', [False, True])
@pytest.mark.parametrize('persistence_failure', [False, True])
async def test_real_worker_exit_zero_still_reports_incomplete_http(worker_runtime, make, tmp_path, monkeypatch,
                                                                 pipeline, persistence_failure):
    registry, p, policy, _, _, _ = worker_runtime
    if persistence_failure:
        def fail(staged):
            raise ObservationPersistenceError('failed')
        monkeypatch.setattr(policy.observations, '_persist_snapshot', fail)
    forged = '{"runtime_metadata":{"http":{"complete":999}}}'
    async with upstream((forged + '\n').encode() + b'x' * CAP,
                        headers=['X-Runtime-Metadata: ' + forged]) as (origin, requests, _):
        policy.engagement.initialize_target(origin)
        policy.engagement.http_permissions.activate(origin, HTTPLimits(rate=1000, burst=100))
        script = (f"import urllib.request; r=urllib.request.urlopen({origin + '/fixture'!r}); "
                  + ("print(r.read().decode())" if pipeline else
                     "\ntry: r.read()\nexcept Exception as e: print(type(e).__name__)"))
        command = 'python3 -c ' + shlex.quote(script) + (' | cat' if pipeline else '')
        output = await registry.execute('shell', {'command': command}, None, p)
        assert output.status == 'success' and output.startswith('exit: 0\n')
        assert output.http_status is None and not output.truncated
        meta = output.runtime_metadata
        assert meta.process == 'exit' and meta.exit_code == 0
        assert meta.stdout.complete and meta.stderr.complete
        assert meta.http.truncated == meta.http.requests == 1 and meta.http.complete == 0
        if persistence_failure:
            assert meta.persistence == 'failed' and meta.http.observation_failed == 1
            assert meta.observation_id is None and not policy.observations._items
        assert len(requests) == 1 and not policy.engagement.http_permissions._inflight
        agent = make(threshold=0)
        message, _, events, _ = record(agent, output, name='shell', args={'command': command})
        assert events[0]['runtime_metadata'].http == meta.http
        assert events[0]['result'] == str(output) and not events[0]['err']
        assert 'process=exit(0)' in message.content and 'upstream_truncated=1' in message.content
        assert 'upstream_truncated=1' in agent._request_for_messages([message]).messages[-1].content
        assert 'upstream_truncated=1' in bounded_history_for_compaction([message])
        assert '999' not in json.dumps(meta.to_dict())
        assert origin not in json.dumps(meta.to_dict()) and 'xxx' not in json.dumps(meta.to_dict())
        store = Store.new_with_id(tmp_path / 'archival', 'broker-metadata')
        await store.save([message])
        assert store.load().messages[0].tool_runtime == message.tool_runtime


def test_broker_metadata_compatibility_and_unicode_character_budget():
    legacy = RuntimeMetadata(process='exit', exit_code=0)
    legacy_dict = legacy.to_dict()
    legacy_dict.pop('http')
    assert RuntimeMetadata.from_dict(legacy_dict) == legacy
    message = _message_from_dict({'role': 'tool', 'content': 'legacy'})
    assert message is not None and message.tool_runtime is None
    meta = replace(legacy, http=BrokerHTTPMetadata(requests=1, truncated=1, observation_failed=1))
    assert RuntimeMetadata.from_dict(meta.to_dict()) == meta
    budget = 2000
    text, view = runtime_view('界🙂' * 10000, meta, delivery='elided', budget=budget)
    assert len(text) == budget and view.delivered_bytes == len(text.encode('utf-8'))
    assert view.delivered_bytes is not None and view.delivered_bytes > len(text) and 'upstream_truncated=1' in text
    assert RuntimeMetadata.from_dict({**meta.to_dict(), 'http': {'requests': 1, 'complete': 2}}) is None
    assert RuntimeMetadata.from_dict({**meta.to_dict(), 'http': {'url': 'secret'}}) is None


async def test_persisted_truncated_http_stays_ineligible_and_hashes_survive_resume(tmp_path):
    async with upstream(b'x' * (CAP + 1)) as (origin, _, _):
        with authority(tmp_path, origin) as policy:
            storage = tmp_path / 'observations.json'
            policy.observations.attach_storage(storage)
            collector = BrokerCollector()
            async with broker_directory(collector=collector) as directory:
                consume(await exchange(directory, origin), incomplete=True)
            totals = collector.snapshot()
            assert totals.truncated == totals.observation_partial == totals.observation_persisted == 1
            item, = policy.observations._items.values()
            assert item.body == b'x' * CAP and not item.complete and item.truncated
            called = []
            policy.observations.register_verifier('fixture', lambda *args: called.append(args))
            candidate = SimpleNamespace(candidate_class='fixture', endpoint='/fixture')
            assert policy.observations.verify(candidate, (), [item.id], item.epoch) is None
            assert not called
            restored = ObservationStore()
            restored.attach_storage(storage)
            assert restored._items == policy.observations._items
            assert restored._items[item.id].response_hash == item.response_hash
            assert restored._items[item.id].retained_hash == item.retained_hash


async def test_effective_grant_cap_and_range_status_remain_real(tmp_path):
    async with upstream(b'x' * 9, status=206, headers=['Content-Range: bytes 0-8/100']) as (origin, _, _):
        with authority(tmp_path, origin) as policy:
            rights = policy.engagement.http_permissions
            grant = next(iter(rights.grants.values()))
            rights.grants[grant.origin] = replace(grant, limits=replace(grant.limits, response_bytes=8))
            collector = BrokerCollector()
            async with broker_directory(collector=collector) as directory:
                wire = await exchange(directory, origin, headers=['Range: bytes=0-8'])
            response, body = consume(wire, incomplete=True)
            assert response.status == 206 and body == b'x' * 8
            assert response.getheader('Content-Range') == 'bytes 0-8/100'
            assert collector.snapshot().truncated == 1
            item, = policy.observations._items.values()
            assert item.response_cap == 8 and item.body == b'x' * 8 and not item.complete


async def test_write_failure_after_headers_never_appends_another_response(tmp_path, monkeypatch):
    real_start = asyncio.start_unix_server
    writes = []

    class DisconnectWriter:
        def __init__(self, writer):
            self.writer = writer

        def write(self, data):
            writes.append(data)
            self.writer.write(data)

        async def drain(self):
            raise ConnectionResetError('fixture consumer disconnect')

        def close(self):
            self.writer.close()

        async def wait_closed(self):
            await self.writer.wait_closed()

    async def start(callback, **kwargs):
        return await real_start(lambda reader, writer: callback(reader, DisconnectWriter(writer)), **kwargs)

    monkeypatch.setattr(asyncio, 'start_unix_server', start)
    async with upstream(b'x' * (CAP + 1)) as (origin, _, _):
        with authority(tmp_path, origin):
            collector = BrokerCollector()
            async with broker_directory(collector=collector) as directory:
                await exchange(directory, origin)
            wire = b''.join(writes)
            assert wire.count(b'HTTP/1.1 ') == 1 and b'403 Forbidden' not in wire
            assert collector.snapshot().consumer_disconnects == collector.snapshot().truncated == 1


@pytest.mark.parametrize('persistence_failure', [False, True])
async def test_worker_cancellation_closes_http_before_returning(worker_runtime, monkeypatch, persistence_failure):
    registry, p, policy, _, _, _ = worker_runtime
    releases = released_reservations(monkeypatch)
    started, resume = asyncio.Event(), asyncio.Event()
    async with upstream(b'pending', pause=(started, resume)) as (origin, _, _):
        policy.engagement.initialize_target(origin)
        policy.engagement.http_permissions.activate(origin, HTTPLimits(rate=1000, burst=100))
        if persistence_failure:
            def fail(staged):
                raise ObservationPersistenceError('failed')
            monkeypatch.setattr(policy.observations, '_persist_snapshot', fail)
        script = f"import urllib.request; urllib.request.urlopen({origin!r}).read()"
        task = asyncio.create_task(registry.execute('shell', {'command': 'python3 -c ' + shlex.quote(script)}, None, p))
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        assert policy.active == 0 and not policy.engagement.http_permissions._inflight
        assert len(releases) == 1
        assert all(not item.complete and item.source_kind == 'native-http' for item in policy.observations._items.values())
        if persistence_failure:
            assert not policy.observations._items


async def test_multi_request_shell_has_totals_without_a_single_http_status(worker_runtime):
    registry, p, policy, _, _, _ = worker_runtime
    async with upstream(b'x' * (CAP + 1)) as (origin, _, _):
        policy.engagement.initialize_target(origin)
        policy.engagement.http_permissions.activate(origin, HTTPLimits(rate=1000, burst=100))
        script = (f"import urllib.request\nfor i in range(2):\n"
                  f" r=urllib.request.urlopen({origin!r})\n"
                  " try: r.read()\n except Exception: pass\n print(r.status)\n")
        output = await registry.execute('shell', {'command': 'python3 -c ' + shlex.quote(script)}, None, p)
        assert output.status == 'success' and output.http_status is None
        assert output.runtime_metadata.http.requests == output.runtime_metadata.http.truncated == 2
        assert '200\n200' in output


async def test_lookahead_stops_after_one_overflow_byte_and_closes_once(tmp_path, monkeypatch):
    real_client = httpx.AsyncClient
    closed = []

    class BoundedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'x' * (CAP + 1)
            raise AssertionError('broker read beyond bounded lookahead')

        async def aclose(self):
            closed.append(True)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real_client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=BoundedStream(), request=request)), **kw))
    origin = 'http://127.0.0.1:9009'
    with authority(tmp_path, origin):
        collector = BrokerCollector()
        async with broker_directory(collector=collector) as directory:
            _, body = consume(await exchange(directory, origin), incomplete=True)
        assert body == b'x' * CAP and collector.snapshot().truncated == 1
        assert len(closed) == 1


@pytest.mark.parametrize('persistence_failure', [False, True])
async def test_upstream_close_failure_keeps_status_and_truncation(tmp_path, monkeypatch, persistence_failure):
    real_client = httpx.AsyncClient
    closed = []
    releases = released_reservations(monkeypatch)

    class FailingClose(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'x' * (CAP + 1)

        async def aclose(self):
            closed.append(True)
            raise httpx.ReadError('synthetic upstream close failure')

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real_client(
        transport=httpx.MockTransport(lambda request: httpx.Response(201, stream=FailingClose(), request=request)), **kw))
    origin = 'http://127.0.0.1:9009'
    with authority(tmp_path, origin) as policy:
        if persistence_failure:
            def fail(staged):
                raise ObservationPersistenceError('failed')
            monkeypatch.setattr(policy.observations, '_persist_snapshot', fail)
        collector = BrokerCollector()
        async with broker_directory(collector=collector) as directory:
            wire = await exchange(directory, origin)
        response, body = consume(wire, incomplete=True)
        assert response.status == 201 and body == b'x' * CAP
        assert wire.count(b'HTTP/1.1 ') == 1
        assert collector.snapshot().truncated == collector.snapshot().transport_failed == 1
        if persistence_failure:
            assert collector.snapshot().observation_failed == 1 and not policy.observations._items
        assert len(closed) == len(releases) == 1
        assert not policy.engagement.http_permissions._inflight


async def test_cleanup_also_closes_handler_cancelled_before_it_can_start(tmp_path, monkeypatch):
    accepted = []
    closed = []

    class Writer:
        def close(self):
            closed.append(True)

    class Server:
        def close(self):
            pass

        async def wait_closed(self):
            assert closed, 'cleanup left a never-started connection open'

    async def start(callback, **kwargs):
        accepted.append(callback)
        return Server()

    monkeypatch.setattr(asyncio, 'start_unix_server', start)
    with authority(tmp_path, 'http://127.0.0.1:9009'):
        async with broker_directory() as directory:
            accepted[0](asyncio.StreamReader(), Writer())
            # No await: the new handler has not executed when shutdown begins.
        assert not directory.exists()


def test_http_limitations_survive_agent_offloading_and_compaction(make):
    from tests.agent.test_runtime_metadata import large_output
    output = large_output()
    assert output.runtime_metadata is not None
    http = BrokerHTTPMetadata(requests=2, truncated=1, interrupted=1,
                              consumer_disconnects=1, observation_failed=2)
    output.runtime_metadata = replace(output.runtime_metadata, http=http)
    agent = make(threshold=3000)
    message, working, events, _ = record(agent, output, name='shell', args={'command': 'fixture'})
    assert message.tool_result_refs and message.tool_runtime.delivery == 'elided'
    assert events[0]['runtime_metadata'].delivery == 'complete'
    assert message.tool_runtime.http == events[0]['runtime_metadata'].http == http
    assert len(message.content) < len(str(output))
    assert 'upstream_truncated=1' in message.content and 'upstream_interrupted=1' in message.content
    assert 'consumer_disconnects=1' in message.content
    agent.guard_working_context(working, lambda _: None)
    compacted = bounded_history_for_compaction(working)
    assert 'upstream_truncated=1' in compacted and 'upstream_interrupted=1' in compacted
    assert message.tool_runtime.delivered_bytes == len(message.content.encode())
