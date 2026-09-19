"""Shared HTTP/cancellation helpers used by every LLM provider client."""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import AsyncIterator, Awaitable, Mapping
from typing import Any, TypeVar

import httpx
import requests

from .errors import BackendError, parse_retry_after

T = TypeVar("T")

CHAT_TIMEOUT_MS = 10 * 60 * 1000
CHAT_TIMEOUT_SEC = CHAT_TIMEOUT_MS / 1000.0
ABORT_POLL_INTERVAL_SEC = 0.1
PING_TIMEOUT_SEC = 10.0


def new_provider_async_client(timeout: float = CHAT_TIMEOUT_SEC) -> httpx.AsyncClient:
    """Build an HTTP client for control-plane traffic to an LLM provider.

    Provider requests must not inherit target/interception proxy variables from
    the process environment.  Target-facing tools own their proxy policy
    separately and intentionally do not use this factory.
    """
    return httpx.AsyncClient(timeout=timeout, trust_env=False)


def new_provider_session() -> requests.Session:
    """Build the synchronous equivalent used by provider model discovery."""
    session = requests.Session()
    session.trust_env = False
    return session


def aborted(signal: Any) -> bool:
    return getattr(signal, "aborted", False)


async def run_cancellable(coro: Awaitable[T], signal: Any = None) -> T:
    """Run `coro` as a task, polling `signal.aborted` so an in-flight request can be interrupted."""
    task: asyncio.Task[T] = asyncio.ensure_future(coro)
    if signal is None:
        return await task
    while not task.done():
        if aborted(signal):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            raise RuntimeError("aborted")
        await asyncio.wait({task}, timeout=ABORT_POLL_INTERVAL_SEC)
    return task.result()


def attach_retry_after(err: BackendError, resp: httpx.Response) -> BackendError:
    """Fill in `err.retry_after_ms` from the response's `retry-after` header."""
    if err.retry_after_ms is None:
        ms = parse_retry_after(resp.headers.get("retry-after"))
        if ms is not None:
            err.retry_after_ms = ms
    return err


def resolve_max_tokens(gen_opts: Mapping[str, Any] | None) -> int | None:
    """Read a max-token budget written as either `maxTokens` or `max_tokens`."""
    if not gen_opts:
        return None
    value = gen_opts.get("maxTokens")
    return gen_opts.get("max_tokens") if value is None else value


def new_call_id(hex_len: int | None = None) -> str:
    digest = uuid.uuid4().hex
    return f"call_{digest[:hex_len] if hex_len else digest}"


async def ping_models_endpoint(
    base_url: str,
    headers: Mapping[str, str],
    provider: str,
) -> None:
    """GET `<base_url>/models` and treat any 5xx as the backend being unavailable."""
    async with new_provider_async_client(PING_TIMEOUT_SEC) as client:
        resp = await client.get(f"{base_url}/models", headers=dict(headers))
        if resp.status_code >= 500:
            raise RuntimeError(f"{provider} status {resp.status_code}")


async def iter_sse_lines(resp: httpx.Response) -> AsyncIterator[str]:
    async for line in resp.aiter_lines():
        if line:
            yield line.rstrip("\r")
