

from typing import cast

import pytest

from src.browser.store import (
    BurpTask,
    CaptureStore,
    CapturedRequest,
)
from src.permission.permission import AlwaysAllow, AlwaysDeny, PermissionRequest, Prompter
from src.tools.browser_capture import (
    BrowserCaptureClearTool,
    BrowserCaptureBurpTasksTool,
    BrowserCaptureEndpointsTool,
    BrowserCaptureRequestsTool,
)
from src.tools.registry import Registry as ToolRegistry

signal = None
prompter = cast(Prompter, object())


def test_clear_tool_requires_permission_and_explicit_browser_capture_intent():
    tool = BrowserCaptureClearTool(cast(CaptureStore, object()))

    assert tool.name() == "browser_capture_clear"
    assert tool.schema() == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }
    assert tool.requires_permission() is True
    assert tool.permission_hints({}) == {"noSessionCache": True}
    assert "explicitly asks to clear or reset browser capture data" in tool.description()
    assert "ambiguous request" in tool.description()


@pytest.mark.asyncio
async def test_clear_tool_rejects_unadvertised_arguments_before_permission():
    class FakeStore:
        cleared = False

        def clear(self):
            self.cleared = True

    class RecordingPrompter:
        requests: list[PermissionRequest] = []

        async def ask(self, request, signal=None):
            self.requests.append(request)
            return "allow-once"

    store = FakeStore()
    registry = ToolRegistry()
    registry.register(BrowserCaptureClearTool(cast(CaptureStore, store)))
    prompter = RecordingPrompter()

    with pytest.raises(ValueError, match="does not accept arguments"):
        await registry.execute(
            "browser_capture_clear", {"action": "clear"}, signal, prompter
        )

    assert prompter.requests == []
    assert store.cleared is False


@pytest.mark.asyncio
async def test_clear_tool_keeps_permission_gate_and_runs_when_explicitly_called():
    class FakeStore:
        cleared = False

        def clear(self):
            self.cleared = True

    store = FakeStore()
    registry = ToolRegistry()
    registry.register(BrowserCaptureClearTool(cast(CaptureStore, store)))

    with pytest.raises(PermissionError):
        await registry.execute(
            "browser_capture_clear", {}, signal, AlwaysDeny()
        )
    assert store.cleared is False

    result = await registry.execute(
        "browser_capture_clear", {}, signal, AlwaysAllow()
    )
    assert result == "cleared."
    assert store.cleared is True


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
