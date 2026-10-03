

from typing import Any, cast

import pytest

from src.browser.store import (
    BurpTask,
    CaptureStore,
    CapturedRequest,
)
from src.permission.permission import AlwaysAllow, AlwaysDeny, Decision, PermissionRequest, Prompter
from src.tools.browser_capture import (
    BrowserCaptureClearTool,
    BrowserCaptureBurpTasksTool,
    BrowserCaptureEndpointsTool,
    BrowserCaptureRequestsTool,
    BrowserCaptureGetTool,
    BrowserCaptureSnapshotTool,
    BrowserCaptureBurpIssuesTool,
)
from src.tools.registry import Registry as ToolRegistry
from src.browser.redacted_view import request_view

signal = None
prompter = cast(Prompter, object())


@pytest.mark.parametrize("name", ["Api-Key", "ApiKey", "API_KEY", "X-API-Key", "X-API_Key"])
def test_capture_view_redacts_api_key_header_variants(name):
    secret = "fixture-private-api-key"
    view = request_view({"request_headers": [{"name": name, "value": secret},
                                               {"name": "X-Correlation-ID", "value": "request-123"}]})
    assert view["request_headers"][0]["name"] == name
    assert "[REDACTED" in view["request_headers"][0]["value"]
    assert secret not in view["request_headers"][0]["value"]
    assert view["request_headers"][1] == {"name": "X-Correlation-ID", "value": "request-123"}
    assert secret not in str(view)


@pytest.mark.asyncio
async def test_model_capture_views_hide_raw_and_structured_secrets():
    store = CaptureStore()
    ingested = store.ingest({
        "id": "secret", "url": "http://target.test/api?token=short-secret",
        "requestHeaders": [{"name": "Authorization", "value": "Bearer private"},
                           {"name": "Cookie", "value": "sid=private"},
                           {"name": "X-CSRF-Token", "value": "csrf-private"}],
        "requestBody": '{"csrf":"csrf-private","q":"test"}',
        "respBody": '{"access_token":"short-secret","ok":true}',
        "rawRequestB64": "cmF3LXJlcXVlc3Qtc2VjcmV0",
    })
    store.ingest_snapshot({"url": "http://target.test/app?api_key=short-secret",
                           "documentCookie": "sid=private"})
    store.ingest_burp_issue({"title": "issue", "url": "http://target.test/?token=short-secret",
                             "detail": "Cookie: sid=private", "rawRequestB64": "cmF3LXJlcXVlc3Qtc2VjcmV0",
                             "rawResponseB64": "cmF3LXJlc3BvbnNlLXNlY3JldA=="})
    outputs = [await BrowserCaptureRequestsTool(store).run({}, signal, prompter),
               await BrowserCaptureGetTool(store).run({"id": ingested["id"]}, signal, prompter),
               await BrowserCaptureSnapshotTool(store).run({}, signal, prompter),
               await BrowserCaptureBurpIssuesTool(store).run({}, signal, prompter)]
    combined = "\n".join(outputs)
    for secret in ("short-secret", "sid=private", "csrf-private", "cmF3LXJlcXVlc3Qtc2VjcmV0",
                   "cmF3LXJlc3BvbnNlLXNlY3JldA=="):
        assert secret not in combined
    assert "raw_request_b64" not in combined and "raw_response_b64" not in combined
    stored = store.get_request(ingested["id"])
    assert stored is not None and stored.raw_request_b64 is not None


def test_clear_tool_requires_permission_and_explicit_browser_capture_intent():
    tool = BrowserCaptureClearTool(cast(CaptureStore, object()))

    assert tool.name() == "browser_capture_clear"
    assert tool.schema() == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }
    assert tool.requires_permission() is True
    assert tool.permission_hints({}) == {
        "noSessionCache": True,
        "riskTier": "high-impact",
    }
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

        async def ask(
            self,
            request: PermissionRequest,
            signal: Any = None,
        ) -> Decision:
            self.requests.append(request)
            return Decision.ALLOW_ONCE

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
    def test_endpoint_parameter_names_are_sorted_for_stable_output(self):
        store = CaptureStore()
        store.ingest(
            {
                "url": "https://x.test/api?zeta=1&alpha=2&omega=3&beta=4",
                "method": "POST",
                "requestBody": {
                    "zeta": "1",
                    "alpha": "2",
                    "omega": "3",
                    "beta": "4",
                },
            }
        )

        endpoint = store.list_endpoints()[0]

        assert endpoint.query_params == ["alpha", "beta", "omega", "zeta"]
        assert endpoint.body_params == ["alpha", "beta", "omega", "zeta"]

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
