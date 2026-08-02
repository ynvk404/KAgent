from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypedDict, TypeVar

from .errors import BackendError, is_transient

T = TypeVar("T")

# Ceiling for server-advised Retry-After waits. A misbehaving proxy can echo
# an absurd Retry-After (minutes/hours); clamp it so one bad response can't
# stall the agent for far longer than our own backoff ever would.
MAX_RETRY_AFTER_MS = 30_000

_ABORT_POLL_INTERVAL_MS = 100.0


class RetryInfo(TypedDict):
    attempt: int
    delay_ms: float
    err: BaseException


@dataclass(slots=True)
class RetryOptions:
    """Mirrors retry.ts's RetryOptions."""

    # Max additional attempts after the first try (default 2 -> up to 3 calls).
    retries: int = 2
    # First backoff step in ms; doubles each attempt.
    base_delay_ms: float = 500
    # Upper bound on a single backoff wait.
    max_delay_ms: float = 8_000
    # Injectable sleep so tests don't wait real time.
    sleep: Callable[[float], Awaitable[None]] | None = None
    # Cancels pending waits and stops further attempts. Duck-typed: any
    # object exposing a truthy `.aborted` attribute (mirrors AbortSignal).
    signal: Any = None
    # Observability hook fired before each retry wait.
    on_retry: Callable[[RetryInfo], None] | None = None


def _aborted(signal: Any) -> bool:
    return signal is not None and getattr(signal, "aborted", False)


async def _default_sleep(ms: float, signal: Any = None) -> None:
    """Polling sleep so an aborted signal interrupts the wait promptly,
    without requiring a real addEventListener-style API in Python."""
    if _aborted(signal):
        raise RuntimeError("aborted")
    remaining = ms
    while remaining > 0:
        step = min(_ABORT_POLL_INTERVAL_MS, remaining)
        await asyncio.sleep(step / 1000)
        remaining -= step
        if _aborted(signal):
            raise RuntimeError("aborted")


async def with_retry(
    fn: Callable[[], Awaitable[T]],
    opts: RetryOptions | None = None,
) -> T:
    """
    Run `fn`, retrying on transient backend errors with exponential backoff.
    Returns fn's result, or re-raises the last error once attempts are
    exhausted or the error is non-transient.

    Contract: `fn` must raise an already-classified `BackendError` on
    failure (via classify_backend at the call site) — with_retry does not
    classify errors itself, only decides whether to retry them.
    """
    opts = opts or RetryOptions()
    sleep = opts.sleep or (lambda ms: _default_sleep(ms, opts.signal))

    attempt = 0
    while True:
        try:
            return await fn()
        except Exception as err:
            if _aborted(opts.signal):
                raise
            if attempt >= opts.retries or not is_transient(err):
                raise

            # Exponential backoff plus a little jitter so concurrent callers
            # hitting the same rate limit don't all wake and re-fire in lockstep.
            backoff = min(opts.max_delay_ms, opts.base_delay_ms * (2**attempt))
            jittered = backoff + random.random() * opts.base_delay_ms
            advised = err.retry_after_ms if isinstance(err, BackendError) else None
            delay_ms = max(jittered, min(advised or 0, MAX_RETRY_AFTER_MS))

            if opts.on_retry is not None:
                opts.on_retry({"attempt": attempt + 1, "delay_ms": delay_ms, "err": err})

            await sleep(delay_ms)
            attempt += 1