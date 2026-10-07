"""Scoped native transport: shared accounting and numeric socket destination.

No environment proxy and no automatic redirect can silently expand a role.
The vetted address set is retained until an explicit controller refresh.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
from contextlib import asynccontextmanager
import ipaddress
import socket
import time
from typing import Any
import httpx

from src.permission.runtime.execution import ExecutionPolicy, ExecutionBlocked, policy_for, current_policy
from src.permission.network.grants import EffectiveHTTP, check_cancelled


async def pin_request(policy: ExecutionPolicy, request: httpx.Request, *, research: bool = False) -> tuple[httpx.Request, str]:
    original = str(request.url)
    policy.require_network(original, research=research)
    origin = f"{request.url.scheme}://{request.url.host}:{request.url.port or (443 if request.url.scheme == 'https' else 80)}"
    if origin not in policy.vetted_ips:
        try:
            address = str(ipaddress.ip_address(request.url.host))
            addresses = (address,)
        except ValueError:
            rows = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, request.url.host, request.url.port,
                                                           socket.AF_UNSPEC, socket.SOCK_STREAM), 10)
            addresses = tuple(sorted({str(ipaddress.ip_address(row[4][0])) for row in rows}))
        if not addresses or len(addresses) > 16:
            raise ExecutionBlocked("blocked: invalid-dns-destination")
        if research and any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            raise ExecutionBlocked("blocked: private-research-destination")
        policy.vetted_ips[origin] = addresses
    address = policy.vetted_ips[origin][0]
    # Keep original Host and certificate/SNI identity while dialing numeric IP.
    pinned = httpx.Request(request.method, request.url.copy_with(host=address),
                           headers=request.headers, content=request.content,
                           extensions={**request.extensions, "sni_hostname": request.url.host})
    return pinned, address


async def governed_send(client: httpx.AsyncClient, request: httpx.Request, prompter: Any,
                        signal: Any, *, response_cap: int, research: bool = False) -> httpx.Response:
    policy = policy_for(prompter) or current_policy()
    if policy is None:
        return await client.send(request, stream=True)
    if not policy.nested_allowed():
        raise ExecutionBlocked("blocked: network-executor-without-receipt")
    policy.require_network(str(request.url), research=research)
    manager = policy.research_permissions if research else policy.engagement.http_permissions
    grant = manager.grants.get(manager.engagement.require_in_scope(str(request.url)))
    cap = min(response_cap, grant.limits.response_bytes if grant is not None else 64 * 1024)
    action = EffectiveHTTP(request.method, str(request.url), tuple(request.headers.raw), request.content,
                           cap, manager.target_revision, manager.engagement.revision, manager.epoch)
    pinned, address = await pin_request(policy, request, research=research)
    action = replace(action, transport_address=address)
    receipt = manager.authorize_adapter(action)
    reservation = await manager.reserve_when_ready(action, receipt, signal, lambda: manager.target_revision)
    try:
        check_cancelled(signal)
        if not policy.nested_allowed():
            raise ExecutionBlocked("blocked: policy-changed-before-network-send")
        policy.require_network(action.url, research=research)
        reservation.start()
        source_owner = policy.observations.owner_provider() or {}
        sent_at = time.monotonic()
        response = await client.send(pinned, stream=True)
    except BaseException:
        reservation.release()
        raise
    close = response.aclose
    response.extensions["policy_response_cap"] = cap
    released = False
    original_iterator = response.aiter_bytes
    chunks: list[bytes] = []
    observed = 0
    complete = False

    async def capture_bytes(chunk_size=None):
        nonlocal observed, complete
        async for chunk in original_iterator(chunk_size):
            room = max(0, cap - observed)
            chunks.append(chunk[:room])
            observed += len(chunk)
            yield chunk
        complete = observed <= cap

    response.aiter_bytes = capture_bytes

    async def release_response():
        nonlocal released
        try:
            await close()
        finally:
            if not released:
                released = True
                response.extensions["runtime_observation_id"] = policy.observations.capture(
                    action, response.status_code, b"".join(chunks), complete=complete,
                    owner=source_owner, response_headers=response.headers.items(),
                    elapsed_ms=(time.monotonic() - sent_at) * 1000,
                )
                reservation.release()

    response.aclose = release_response
    return response


@asynccontextmanager
async def governed_stream(client: httpx.AsyncClient, url: str, timeout: float, *, response_cap: int):
    if current_policy() is None:
        async with client.stream("GET", url, timeout=timeout) as response:
            yield response
        return
    request = client.build_request("GET", url, timeout=timeout)
    response = await governed_send(client, request, None, None, response_cap=response_cap)
    try:
        yield response
    finally:
        await response.aclose()


@asynccontextmanager
async def socket_budget(host: str, port: int, signal: Any, origin_url: str):
    policy = current_policy()
    if policy is None:
        yield
        return
    manager = policy.engagement.http_permissions
    # Existing service adapter verifies active origin and exact target port.
    origin = policy.engagement.require_in_scope(origin_url)
    if origin.port != port:
        raise ExecutionBlocked("blocked: socket-port-outside-profile")
    policy.require_network(origin.as_url())
    key = f"{origin.scheme}://{origin.hostname}:{origin.port}"
    if key in policy.vetted_ips and host not in policy.vetted_ips[key]:
        raise ExecutionBlocked("blocked: socket-address-changed; operator network refresh required")
    policy.vetted_ips.setdefault(key, (host,))
    action = EffectiveHTTP("CONNECT", origin.as_url(), (), b"", 0, manager.target_revision,
                           policy.engagement.revision, manager.epoch, f"{host}:{port}")
    receipt = manager.authorize_adapter(action)
    reservation = await manager.reserve_when_ready(action, receipt, signal, lambda: manager.target_revision)
    try:
        if not policy.nested_allowed():
            raise ExecutionBlocked("blocked: policy-changed-before-socket")
        policy.require_network(action.url)
        reservation.start()
        yield
    finally:
        reservation.release()
