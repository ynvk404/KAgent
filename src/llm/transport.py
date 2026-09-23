"""Shared HTTP/cancellation helpers used by every LLM provider client."""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import ssl
import uuid
from collections.abc import AsyncIterator, Awaitable, Mapping
from typing import Any, TypeVar

import httpx
import requests

from .errors import (
    BackendError,
    ProviderControlError,
    exception_has_type_name,
    parse_retry_after,
    provider_http_error,
    provider_transport_error,
)

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


def parse_openai_model_ids(body: Any) -> list[str]:
    """Validate the OpenAI-compatible ``/models`` envelope and extract IDs."""
    if not isinstance(body, dict) or not isinstance(body.get("data"), list):
        raise ProviderControlError(
            "malformed-response",
            "provider returned an invalid OpenAI-compatible models response",
        )
    model_ids: list[str] = []
    for item in body["data"]:
        if not isinstance(item, dict):
            raise ProviderControlError(
                "malformed-response",
                "provider returned an invalid OpenAI-compatible models response",
            )
        model_id = item.get("id")
        if not isinstance(model_id, str) or not model_id.strip():
            raise ProviderControlError(
                "malformed-response",
                "provider returned an invalid OpenAI-compatible models response",
            )
        model_ids.append(model_id)
    return model_ids


def classify_provider_transport_exception(error: BaseException) -> ProviderControlError:
    """Map transport failures to safe, typed messages without exposing details."""
    if exception_has_type_name(error, {"SSLError", "SSLCertVerificationError"}):
        return provider_transport_error("tls-failure")
    if isinstance(error, (httpx.TimeoutException, TimeoutError)):
        return provider_transport_error("timeout")
    if isinstance(error, socket.gaierror) or exception_has_type_name(
        error, {"gaierror", "NameResolutionError"}
    ):
        return provider_transport_error("dns-failure")
    return provider_transport_error("connection-failure")


def new_call_id(hex_len: int | None = None) -> str:
    digest = uuid.uuid4().hex
    return f"call_{digest[:hex_len] if hex_len else digest}"


async def ping_models_endpoint(
    base_url: str,
    headers: Mapping[str, str],
    provider: str,
) -> None:
    """Check the provider models endpoint and its protocol response envelope."""
    try:
        async with new_provider_async_client(PING_TIMEOUT_SEC) as client:
            resp = await client.get(
                f"{base_url.rstrip('/')}/models",
                headers=dict(headers),
            )
    except (httpx.TimeoutException, httpx.TransportError, ssl.SSLError) as error:
        raise classify_provider_transport_exception(error) from None
    if resp.status_code != 200:
        raise provider_http_error(resp.status_code)
    try:
        body = resp.json()
    except (ValueError, json.JSONDecodeError):
        raise ProviderControlError(
            "malformed-json",
            "provider returned invalid JSON from the models endpoint",
        ) from None
    if provider == "gemini":
        models = body.get("models") if isinstance(body, dict) else None
        if not isinstance(models, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("name"), str)
            for item in models
        ):
            raise ProviderControlError(
                "malformed-response",
                "Gemini returned an invalid models response",
            )
        return
    if provider == "anthropic":
        models = body.get("data") if isinstance(body, dict) else None
        if not isinstance(models, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("id"), str)
            for item in models
        ):
            raise ProviderControlError(
                "malformed-response",
                "Anthropic returned an invalid models response",
            )
        return
    parse_openai_model_ids(body)


async def iter_sse_lines(resp: httpx.Response) -> AsyncIterator[str]:
    async for line in resp.aiter_lines():
        if line:
            yield line.rstrip("\r")
