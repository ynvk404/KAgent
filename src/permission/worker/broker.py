"""Bounded plaintext HTTP broker across an offline namespace's UDS mount.

Proxy environment is convenience, not isolation: the worker still has no host
network. CONNECT, upgrades and raw TCP are not granted by this adapter.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import tempfile
import httpx

from src.permission.runtime.execution import ExecutionBlocked, current_policy
from src.permission.network.transport import governed_send
from src.permission.network.grants import check_cancelled
from src.permission.permission import UserControlledRefusal
from src.engagement.state import OutOfScopeError


@asynccontextmanager
async def broker_directory(signal=None):
    policy = current_policy()
    if policy is None or not policy.nested_allowed():
        raise ExecutionBlocked('blocked: worker-broker-without-receipt')
    # AF_UNIX has a short pathname limit; a private controller-owned directory
    # is mounted alone. No host /tmp or ambient socket directory is exposed.
    directory = Path(tempfile.mkdtemp(prefix='kgb-'))
    handlers: set[asyncio.Task] = set()
    client = httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=20)

    async def handle(reader, writer):
        if len(handlers) >= policy.concurrency:
            writer.write(b'HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            writer.close()
            return
        task = asyncio.current_task()
        if task is not None:
            handlers.add(task)
        response = None
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
            response = await governed_send(client, request, None, signal, response_cap=64 * 1024)
            cap = response.extensions['policy_response_cap']
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk[:max(0, cap + 1 - len(data))])
                if len(data) > cap:
                    break
            payload = bytes(data[:cap])
            # Decoded response body: remove transfer/compression framing.
            outgoing = [(k, v) for k, v in response.headers.multi_items()
                        if k.lower() not in {'connection', 'transfer-encoding', 'content-encoding', 'content-length'}]
            outgoing += [('content-length', str(len(payload))), ('connection', 'close')]
            writer.write(f'HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n'.encode())
            for key, value in outgoing:
                writer.write(f'{key}: {value}\r\n'.encode('latin1'))
            writer.write(b'\r\n' + payload)
            await writer.drain()
        except Exception as exc:
            # Only controller-generated reason is exposed; request/body/error
            # text from third-party libraries is not an operator-safe message.
            message = ('blocked: network-origin-outside-profile' if isinstance(exc, OutOfScopeError)
                       else str(exc) if isinstance(exc, UserControlledRefusal)
                       else 'blocked: broker-request-invalid-or-failed')
            payload = message.encode()
            writer.write(f'HTTP/1.1 403 Forbidden\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n'.encode() + payload)
            try:
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
        finally:
            if response is not None:
                await response.aclose()
            writer.close()
            if task is not None:
                handlers.discard(task)

    server = await asyncio.start_unix_server(handle, path=str(directory / 'broker.sock'), limit=32768)
    try:
        yield directory
    finally:
        server.close()
        await server.wait_closed()
        for task in tuple(handlers):
            task.cancel()
        await asyncio.gather(*handlers, return_exceptions=True)
        await client.aclose()
        (directory / 'broker.sock').unlink(missing_ok=True)
        directory.rmdir()
