import pytest
import requests

from browser.server import IngestServerOptions, start_ingest_server
from browser.store import CaptureStore


@pytest.fixture
def store():
    return CaptureStore()


def test_requires_bridge_token_for_reads_and_writes(store):
    handle = start_ingest_server(
        IngestServerOptions(store=store, port=0, token="secret-token")
    )
    try:
        base = handle.url

        # Unauthenticated request -> 401
        unauth = requests.get(f"{base}/status")
        assert unauth.status_code == 401

        # Query token -> 401 (chỉ chấp nhận qua Header)
        query_token = requests.get(f"{base}/status?token=secret-token")
        assert query_token.status_code == 401

        # Authenticated GET -> 200
        authed_status = requests.get(
            f"{base}/status",
            headers={"X-Pentestagent-Token": "secret-token"},
        )
        assert authed_status.status_code == 200

        # Authenticated POST -> 202
        authed_post = requests.post(
            f"{base}/ingest",
            headers={
                "Content-Type": "application/json",
                "X-Pentestagent-Token": "secret-token",
            },
            json={"url": "https://app.example.com/api", "method": "GET"},
        )
        assert authed_post.status_code == 202

        # Kiểm tra requestCount trong store
        status_info = store.status()
        request_count = (
            status_info.get("requestCount", status_info.get("request_count"))
            if isinstance(status_info, dict)
            else getattr(status_info, "requestCount", getattr(status_info, "request_count", 0))
        )
        assert request_count == 1

    finally:
        handle.close()


def test_rejects_non_loopback_host_headers(store):
    handle = start_ingest_server(
        IngestServerOptions(store=store, port=0, token="secret-token")
    )
    try:
        # Requests cho phép ghi đè Host header trực tiếp
        res = requests.get(
            f"{handle.url}/status",
            headers={
                "Host": "evil.example",
                "X-Pentestagent-Token": "secret-token",
            },
        )
        assert res.status_code == 403

    finally:
        handle.close()