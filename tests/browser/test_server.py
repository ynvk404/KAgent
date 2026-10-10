import pytest
import requests
import base64

from src.browser.server import IngestServerOptions, start_ingest_server, event_text
from src.browser.store import CaptureStore


@pytest.fixture
def store():
    return CaptureStore()


def test_requires_bridge_token_for_reads_and_writes(store):
    handle = start_ingest_server(
        IngestServerOptions(store=store, port=0, token="secret-token")
    )
    try:
        base = handle.url

        unauth = requests.get(f"{base}/status")
        assert unauth.status_code == 401

        query_token = requests.get(f"{base}/status?token=secret-token")
        assert query_token.status_code == 401

        authed_status = requests.get(
            f"{base}/status",
            headers={"X-KAgent-Token": "secret-token"},
        )
        assert authed_status.status_code == 200

        authed_post = requests.post(
            f"{base}/ingest",
            headers={
                "Content-Type": "application/json",
                "X-KAgent-Token": "secret-token",
            },
            json={"url": "https://app.example.com/api", "method": "GET"},
        )
        assert authed_post.status_code == 202

        status_info = store.status()
        request_count = (
            status_info.get("requestCount", status_info.get("request_count"))
            if isinstance(status_info, dict)
            else getattr(status_info, "requestCount", getattr(status_info, "request_count", 0))
        )
        assert request_count == 1

    finally:
        handle.close()


def test_capture_event_text_redacts_query_credentials():
    event = event_text("/ingest", {"method": "GET", "url": "http://target.test/?access_token=private-value"})
    assert "private-value" not in event
    assert "access_token" in event


def test_bridge_request_and_task_reads_are_redacted_but_raw_baseline_remains(store):
    raw = base64.b64encode(b"GET /api HTTP/1.1\r\nHost: fixture.test\r\nCookie: sid=private-cookie\r\n\r\n").decode()
    captured = store.ingest({"kind": "burp", "url": "http://fixture.test/api?token=private-query",
        "requestHeaders": {"Cookie": "sid=private-cookie", "Authorization": "Bearer private-auth"},
        "requestBody": '{"password":"private-password"}', "rawRequestB64": raw,
        "respBody": '{"token":"private-response"}'})
    task = store.ingest_burp_task({"action": "scan", "url": "http://fixture.test/?token=private-query",
        "rawRequestB64": raw, "notes": "Authorization: Bearer private-auth"})
    handle = start_ingest_server(IngestServerOptions(store=store, port=0, token="bridge-token"))
    try:
        for path in ("/requests", "/burp/tasks"):
            response = requests.get(handle.url + path, headers={"X-KAgent-Token": "bridge-token"})
            assert response.status_code == 200
            text = response.text
            for secret in (raw, "private-query", "private-cookie", "private-auth", "private-password", "private-response"):
                assert secret not in text
            assert "raw_request_b64" not in text
            assert response.json()[0]["baseline_request_ref"]
        assert store.resolve_baseline(captured["baseline_request_ref"]).raw_request_b64 == raw
        assert store.resolve_baseline(task["baseline_request_ref"]).raw_request_b64 == raw
    finally:
        handle.close()


def test_rejects_non_loopback_host_headers(store):
    handle = start_ingest_server(
        IngestServerOptions(store=store, port=0, token="secret-token")
    )
    try:
        res = requests.get(
            f"{handle.url}/status",
            headers={
                "Host": "evil.example",
                "X-KAgent-Token": "secret-token",
            },
        )
        assert res.status_code == 403

    finally:
        handle.close()

def test_cors_only_reflects_valid_extension_origins(store):
    handle = start_ingest_server(
        IngestServerOptions(store=store, port=0, token="secret-token")
    )
    try:
        base = handle.url
        extension = "chrome-extension://" + ("a" * 32)

        allowed = requests.options(
            f"{base}/ingest",
            headers={"Origin": extension},
        )
        assert allowed.status_code == 204
        assert allowed.headers["Access-Control-Allow-Origin"] == extension
        assert allowed.headers["Vary"] == "Origin"

        for origin in (
            "https://evil.example.com",
            "chrome-extension://short",
            "chrome-extension://../../etc",
            "null",
        ):
            denied = requests.options(
                f"{base}/ingest",
                headers={"Origin": origin},
            )
            assert "Access-Control-Allow-Origin" not in denied.headers
            assert "Access-Control-Allow-Methods" not in denied.headers

        for response in (allowed, denied):
            assert "Access-Control-Allow-Credentials" not in response.headers
    finally:
        handle.close()


def test_callback_failure_does_not_fail_a_persisted_ingest(store):
    def failing_callback(event: str) -> None:
        raise RuntimeError("notification unavailable")

    handle = start_ingest_server(
        IngestServerOptions(
            store=store,
            port=0,
            token="secret-token",
            on_event=failing_callback,
        )
    )
    try:
        response = requests.post(
            f"{handle.url}/ingest",
            headers={
                "Content-Type": "application/json",
                "X-KAgent-Token": "secret-token",
            },
            json={"url": "https://app.example.com/api", "method": "GET"},
        )

        assert response.status_code == 202
        assert store.status()["request_count"] == 1
    finally:
        handle.close()
