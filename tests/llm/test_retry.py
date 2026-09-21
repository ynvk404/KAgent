from __future__ import annotations

from typing import Any

import pytest

from src.llm.errors import (
    BackendError,
    is_transient,
    parse_retry_after,
)
from src.llm.retry import (
    RetryOptions,
    with_retry,
)

from src.llm.retry import (
    RetryInfo,
    RetryOptions,
    with_retry,
)
def transient(status: int) -> BackendError:
    return BackendError(
        "test",
        "unknown",
        status,
        "rate limited",
    )


def down() -> BackendError:
    return BackendError(
        "test",
        "backend-down",
        0,
        "socket hang up",
    )


class TestIsTransient:

    def test_flags_transient_errors(self) -> None:
        assert is_transient(transient(429))
        assert is_transient(transient(503))
        assert is_transient(down())

    def test_does_not_flag_non_transient(self) -> None:
        assert not is_transient(transient(400))
        assert not is_transient(transient(401))
        assert not is_transient(transient(500))
        assert not is_transient(Exception("boom"))


class TestParseRetryAfter:

    def test_parses_delta_seconds(self) -> None:
        assert parse_retry_after("2") == 2000

    def test_parses_http_date(self) -> None:
        now = 1767225600.0  # 2026-01-01T00:00:00Z

        assert (
            parse_retry_after(
                "Thu, 01 Jan 2026 00:00:05 GMT",
                now,
            )
            == 5000
        )

    def test_returns_none(self) -> None:
        assert parse_retry_after(None) is None
        assert parse_retry_after("soon") is None

class TestWithRetry:

    @pytest.mark.asyncio
    async def test_returns_immediately(self) -> None:

        calls = 0

        async def fn() -> str:
            nonlocal calls
            calls += 1
            return "ok"

        async def sleep(_: float) -> None:
            pass

        out = await with_retry(
            fn,
            RetryOptions(
                sleep=sleep,
            ),
        )

        assert out == "ok"
        assert calls == 1

    @pytest.mark.asyncio
    async def test_retries_then_succeeds(self) -> None:

        calls = 0
        retries: list[RetryInfo] = []
        async def fn() -> str:
            nonlocal calls
            calls += 1

            if calls == 1:
                raise transient(429)

            if calls == 2:
                raise transient(503)

            return "done"

        async def sleep(_: float) -> None:
            pass

        out = await with_retry(
            fn,
            RetryOptions(
                sleep=sleep,
                on_retry=retries.append,
            ),
        )

        assert out == "done"
        assert calls == 3
        assert len(retries) == 2

    @pytest.mark.asyncio
    async def test_exhausts_retries(self) -> None:

        calls = 0

        async def fn() -> str:
            nonlocal calls
            calls += 1
            raise transient(429)

        async def sleep(_: float) -> None:
            pass

        with pytest.raises(BackendError):
            await with_retry(
                fn,
                RetryOptions(
                    retries=2,
                    sleep=sleep,
                ),
            )

        assert calls == 3

    @pytest.mark.asyncio
    async def test_does_not_retry_non_transient(self) -> None:

        calls = 0

        async def fn() -> str:
            nonlocal calls
            calls += 1
            raise transient(400)

        async def sleep(_: float) -> None:
            pass

        with pytest.raises(BackendError):
            await with_retry(
                fn,
                RetryOptions(
                    sleep=sleep,
                ),
            )

        assert calls == 1

    @pytest.mark.asyncio
    async def test_retry_after_wins(self) -> None:

        delays: list[float] = []
        calls = 0

        async def sleep(ms: float) -> None:
            delays.append(ms)

        with_ra = transient(429)
        with_ra.retry_after_ms = 9000

        async def fn() -> str:
            nonlocal calls
            calls += 1

            if calls == 1:
                raise transient(429)

            if calls == 2:
                raise with_ra

            return "ok"

        await with_retry(
            fn,
            RetryOptions(
                sleep=sleep,
                base_delay_ms=500,
                max_delay_ms=8000,
            ),
        )

        assert 500 <= delays[0] < 1000
        assert delays[1] == 9000

    @pytest.mark.asyncio
    async def test_retry_after_is_clamped(self) -> None:

        delays: list[float] = []
        calls = 0

        async def sleep(ms: float) -> None:
            delays.append(ms)

        err = transient(429)
        err.retry_after_ms = 3_600_000

        async def fn() -> str:
            nonlocal calls
            calls += 1

            if calls == 1:
                raise err

            return "ok"

        await with_retry(
            fn,
            RetryOptions(
                sleep=sleep,
            ),
        )

        assert len(delays) == 1
        assert delays[0] == 30_000

    @pytest.mark.asyncio
    async def test_aborted_signal(self) -> None:

        class Signal:
            aborted = True

        calls = 0

        async def fn() -> str:
            nonlocal calls
            calls += 1
            raise transient(429)

        async def sleep(_: float) -> None:
            pass

        with pytest.raises(BackendError):
            await with_retry(
                fn,
                RetryOptions(
                    sleep=sleep,
                    signal=Signal(),
                ),
            )

        assert calls == 1