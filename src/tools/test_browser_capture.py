"""Output-cap tests for the browser_capture_* tools."""

from typing import cast

import pytest

from src.browser.store import (
    BurpTask,
    CaptureStore,
    CapturedRequest,
)
from src.permission.permission import Prompter
from src.tools.browser_capture import (
    BrowserCaptureBurpTasksTool,
    BrowserCaptureEndpointsTool,
    BrowserCaptureRequestsTool,
)

signal = None
prompter = cast(Prompter, object())


class TestBrowserCaptureRequestsToolLimitClamp:
    @pytest.mark.asyncio
    async def test_clamps_oversized_limit_to_500(self):
        seen_limit = -1

        class FakeStore:
            def list_requests(self, url_substr=None, method=None, limit=None):
                nonlocal seen_limit
                seen_limit = limit if limit is not None else -1
                return []

        store = cast(CaptureStore, FakeStore())
        await BrowserCaptureRequestsTool(store).run(
            {"limit": 99999},
            signal,
            prompter,
        )

        assert seen_limit == 500

    @pytest.mark.asyncio
    async def test_uses_default_50_when_no_limit_provided(self):
        seen_limit = -1

        class FakeStore:
            def list_requests(self, url_substr=None, method=None, limit=None):
                nonlocal seen_limit
                seen_limit = limit if limit is not None else -1
                return []

        store = cast(CaptureStore, FakeStore())
        await BrowserCaptureRequestsTool(store).run({}, signal, prompter)

        assert seen_limit == 50

    @pytest.mark.asyncio
    async def test_serializes_requests_compactly(self):
        class FakeStore:
            def list_requests(self, url_substr=None, method=None, limit=None):
                return [
                    CapturedRequest(
                        id="wr:1",
                        source="webRequest",
                        method="GET",
                        url="https://x/a",
                        received_at=0,
                        status=200,
                        type="xhr",
                        elapsed_ms=5,
                    )
                ]

        store = cast(CaptureStore, FakeStore())

        out = await BrowserCaptureRequestsTool(store).run(
            {},
            signal,
            prompter,
        )

        assert "\n  " not in out
        assert '"id":"wr:1"' in out


class TestBrowserCaptureEndpointsToolListingCaps:
    @pytest.mark.asyncio
    async def test_limits_endpoints_listed_and_notes_omission(self):
        eps = [
            {
                "method": "GET",
                "url": f"https://x/{i}",
                "query_params": [],
                "body_params": [],
            }
            for i in range(600)
        ]

        class FakeStore:
            def list_endpoints(self, url_substr=None, method=None):
                return eps

        store = cast(CaptureStore, FakeStore())

        out = await BrowserCaptureEndpointsTool(store).run(
            {},
            signal,
            prompter,
        )

        assert "more omitted; showing first 200" in out
        assert "\n  " not in out


class TestBrowserCaptureBurpTasksToolListingCaps:
    @pytest.mark.asyncio
    async def test_returns_friendly_message_when_empty(self):
        class FakeStore:
            def list_burp_tasks(self):
                return []

        store = cast(CaptureStore, FakeStore())

        out = await BrowserCaptureBurpTasksTool(store).run(
            {},
            signal,
            prompter,
        )

        assert out == "No Burp tasks queued."

    @pytest.mark.asyncio
    async def test_caps_number_of_tasks_listed(self):
        tasks = [
            BurpTask(
                id=str(i),
                action="scan",
                created_at=0,
            )
            for i in range(250)
        ]

        class FakeStore:
            def list_burp_tasks(self):
                return tasks

        store = cast(CaptureStore, FakeStore())

        out = await BrowserCaptureBurpTasksTool(store).run(
            {},
            signal,
            prompter,
        )

        assert "more omitted; showing first 200" in out