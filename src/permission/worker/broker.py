"""Bounded plaintext HTTP broker across an offline namespace's UDS mount.

Proxy environment is convenience, not isolation: the worker still has no host
network. CONNECT, upgrades and raw TCP are not granted by this adapter.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from contextlib import asynccontextmanager
from pathlib import Path
import tempfile
from typing import Any
import httpx

from src.permission.runtime.execution import ExecutionBlocked, current_policy
from src.permission.network.transport import ResponseDiagnostics, governed_send
from src.permission.network.grants import check_cancelled
from src.permission.permission import UserControlledRefusal
from src.engagement.state import OutOfScopeError
from src.permission.runtime.observations import ObservationPersistenceError
from src.tools.common.runtime_metadata import BrokerHTTPMetadata


class BrokerCollector:
    """Controller-owned, fixed-size totals for exactly one broker directory."""

    def __init__(self):
        self._totals = asdict(BrokerHTTPMetadata())
        self.failure: BaseException | None = None

    def record(self, state: ResponseDiagnostics, disconnected: bool) -> None:
        totals = self._totals
        totals['requests'] += 1
        totals['truncated' if state.truncated else 'complete' if state.eof else 'interrupted'] += 1
        totals['transport_failed'] += int(state.transport_failed)
        totals['cancelled'] += int(state.cancelled)
        totals['consumer_disconnects'] += int(disconnected)
        if state.capture_attempted:
            key = {'persisted': 'observation_persisted', 'memory-only': 'observation_memory_only',
                   'failed': 'observation_failed', 'unknown': 'observation_unknown'}[state.persistence]
            totals[key] += 1
        totals['observation_partial'] += int(state.observation_partial)

    def snapshot(self) -> BrokerHTTPMetadata:
        return BrokerHTTPMetadata(**self._totals)


@asynccontextmanager
async def broker_directory(signal=None, *, collector: BrokerCollector | None = None):
    policy = current_policy()
    if policy is None or not policy.nested_allowed():
        raise ExecutionBlocked('blocked: worker-broker-without-receipt')
    # AF_UNIX has a short pathname limit; a private controller-owned directory
    # is mounted alone. No host /tmp or ambient socket directory is exposed.
    directory = Path(tempfile.mkdtemp(prefix='kgb-'))
    collector = collector if collector is not None else BrokerCollector()
    handlers: dict[asyncio.Task, Any] = {}
    client = httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=20)

    async def handle(reader, writer):
        response = None
        state = ResponseDiagnostics()
        disconnected = False
        started = False
        try:
            check_cancelled(signal)
            if not policy.nested_allowed():
                raise ExecutionBlocked('blocked: worker-receipt-revoked')
            head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 10)
            if len(head) > 32768:
                raise ExecutionBlocked('blocked: proxy-header-limit')
            line, *rows = head[:-4].split(b'\r\n')
            method, url, version = line.decode('ascii').split(' ')
            if method == 'CONNECT' or version not in {'HTTP/1.0', 'HTTP/1.1'}:
                raise ExecutionBlocked('blocked: proxy-transport-unsupported; plaintext HTTP only')
            policy.require_network(url)
            if not url.startswith('http://'):
                raise ExecutionBlocked('blocked: proxy-transport-unsupported; plaintext HTTP only')
            headers = httpx.Headers([(key, value.strip(b' \t')) for key, value in (row.split(b':', 1) for row in rows)])
            if 'transfer-encoding' in headers or 'upgrade' in headers or len(headers.get_list('content-length')) > 1:
                raise ExecutionBlocked('blocked: proxy-framing-unsupported')
            length = int(headers.get('content-length', '0'))
            if length < 0 or length > 128 * 1024:
                raise ExecutionBlocked('blocked: proxy-request-size-limit')
            body = await asyncio.wait_for(reader.readexactly(length), 10)
            for key in ('connection', 'proxy-connection', 'proxy-authorization', 'host'):
                headers.pop(key, None)
            request = client.build_request(method, url, headers=headers, content=body)
            response = await governed_send(client, request, None, signal, response_cap=64 * 1024,
                                           diagnostics=state)
            cap = response.extensions['policy_response_cap']
            data = bytearray()
            # At most cap+1 decoded bytes are buffered. The extra byte proves
            # overflow; EOF at exactly cap remains a complete response.
            iterator = response.aiter_bytes(chunk_size=cap + 1)
            try:
                try:
                    async for chunk in iterator:
                        data.extend(chunk[:max(0, cap + 1 - len(data))])
                        if len(data) > cap:
                            break
                except ObservationPersistenceError:
                    # A storage outage does not change the target response.
                    pass
                except httpx.HTTPError:
                    state.transport_failed = True
            finally:
                close_iterator = getattr(iterator, 'aclose', None)
                if close_iterator is not None:
                    await close_iterator()
                try:
                    await response.aclose()
                except ObservationPersistenceError:
                    pass
                except httpx.HTTPError:
                    state.transport_failed = True
            payload = bytes(data[:cap])
            body_allowed = method != 'HEAD' and response.status_code not in {204, 304} and response.status_code >= 200
            # HEAD/304 Content-Length describes the selected representation,
            # not a body sent here. 204 has no body or Content-Length.
            removed = {'connection', 'transfer-encoding'}
            if body_allowed or response.status_code == 204:
                removed |= {'content-encoding', 'content-length'}
            outgoing = [(k, v) for k, v in response.headers.multi_items()
                        if k.lower() not in removed]
            if body_allowed:
                outgoing.append(('transfer-encoding', 'chunked'))
            outgoing.append(('connection', 'close'))
            started = True
            writer.write(f'HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n'.encode())
            for key, value in outgoing:
                writer.write(f'{key}: {value}\r\n'.encode('latin1'))
            writer.write(b'\r\n')
            if body_allowed:
                if payload:
                    writer.write(f'{len(payload):x}\r\n'.encode() + payload + b'\r\n')
                # Never forge a complete document after truncation/read failure.
                if state.eof and not state.truncated and not state.transport_failed:
                    writer.write(b'0\r\n\r\n')
            await writer.drain()
        except asyncio.CancelledError:
            state.cancelled = True
            raise
        except (BrokenPipeError, ConnectionResetError):
            disconnected = True
        except Exception as exc:
            # Only controller-generated reason is exposed; request/body/error
            # text from third-party libraries is not an operator-safe message.
            expected = isinstance(exc, (OutOfScopeError, UserControlledRefusal, ValueError,
                                       asyncio.TimeoutError, asyncio.IncompleteReadError,
                                       asyncio.LimitOverrunError, httpx.HTTPError))
            if not expected and collector.failure is None:
                # Integrity/programming failures are not storage outages.
                collector.failure = exc
            message = ('blocked: network-origin-outside-profile' if isinstance(exc, OutOfScopeError)
                       else str(exc) if isinstance(exc, UserControlledRefusal)
                       else 'blocked: broker-request-invalid-or-failed')
            payload = message.encode()
            if not started:
                writer.write(f'HTTP/1.1 403 Forbidden\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n'.encode() + payload)
                try:
                    await writer.drain()
                except (BrokenPipeError, ConnectionResetError):
                    disconnected = True
        finally:
            try:
                if response is not None:
                    try:
                        await response.aclose()
                    except ObservationPersistenceError:
                        pass
                    except httpx.HTTPError:
                        state.transport_failed = True
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (BrokenPipeError, ConnectionResetError):
                    disconnected = True
                finally:
                    collector.record(state, disconnected)

    def accepted(reader, writer):
        # Register synchronously so shutdown cannot miss a not-yet-started task.
        if len(handlers) >= policy.concurrency:
            writer.write(b'HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            writer.close()
            return
        task = asyncio.create_task(handle(reader, writer))
        handlers[task] = writer
        def finished(task):
            handlers.pop(task, None)
            if not task.cancelled():
                error = task.exception()
                if error is not None and collector.failure is None:
                    collector.failure = error
        task.add_done_callback(finished)

    server = None
    try:
        server = await asyncio.start_unix_server(accepted, path=str(directory / 'broker.sock'), limit=32768)
        yield directory
    finally:
        try:
            if server is not None:
                server.close()
                pending = tuple(handlers)
                for task in pending:
                    # Also close connections whose task has not started yet.
                    handlers[task].close()
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                await server.wait_closed()
        finally:
            try:
                await client.aclose()
            finally:
                (directory / 'broker.sock').unlink(missing_ok=True)
                directory.rmdir()
    if collector.failure is not None:
        raise collector.failure
