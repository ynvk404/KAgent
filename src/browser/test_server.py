import pytest
import requests

from src.browser.server import IngestServerOptions, start_ingest_server
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
