import sys
from pathlib import Path
import pytest
import json
from datetime import datetime, timezone
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

from src.browser.mcp_server import (
    parse_args,
    get_val,
    to_dict,
    format_iso,
    text_result,
    mcp_int_arg,
    mcp_string_arg,
    ParsedArgs,
    DEFAULT_PORT,
)


def test_parse_args_defaults():
    args = parse_args([])
    assert args.port == DEFAULT_PORT
    assert args.max_entries == 5000
    assert args.log_path == ""
    assert args.show_help is False


def test_parse_args_custom_values():
    argv = ["--port", "8080", "--max-entries", "1000", "--log", "/tmp/mcp.log"]
    args = parse_args(argv)
    assert args.port == 8080
    assert args.max_entries == 1000
    assert args.log_path == "/tmp/mcp.log"


def test_parse_args_invalid_port_fallback():
    argv = ["--port", "999999"]
    args = parse_args(argv)
    assert args.port == DEFAULT_PORT


def test_parse_args_help_flag():
    assert parse_args(["-h"]).show_help is True
    assert parse_args(["--help"]).show_help is True


def test_get_val_dictionary():
    data = {"request_count": 42, "elapsedMs": 150}
    assert get_val(data, "request_count", "requestCount") == 42
    assert get_val(data, "elapsed_ms", "elapsedMs") == 150
    assert get_val(data, "non_existent", default=0) == 0


def test_get_val_object():
    class DummyObj:
        requestCount = 99
    
    obj = DummyObj()
    assert get_val(obj, "request_count", "requestCount") == 99
    assert get_val(obj, "missing_attr", default="N/A") == "N/A"


@dataclass
class MockDataclass:
    id: str
    method: str
    url: str


def test_to_dict():
    d = {"key": "value"}
    assert to_dict(d) == {"key": "value"}

    dc = MockDataclass(id="req_1", method="GET", url="https://example.com")
    assert to_dict(dc) == {"id": "req_1", "method": "GET", "url": "https://example.com"}

    class RegularObj:
        def __init__(self):
            self.foo = "bar"
    
    obj = RegularObj()
    assert to_dict(obj) == {"foo": "bar"}


def test_format_iso():
    assert format_iso(None) is None
    
    ts = 1700000000
    iso_str = format_iso(ts)
    assert iso_str is not None and (iso_str.endswith("Z") or iso_str.endswith("+00:00"))

    dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    res_str = format_iso(dt)
    assert res_str is not None
    assert res_str.replace("+00:00", "Z") == "2026-01-01T12:00:00Z"


def test_text_result():
    res = text_result("Hello World", is_error=False)
    assert res.isError is False
    assert len(res.content) == 1
    assert getattr(res.content[0], "text", None) == "Hello World"


def test_mcp_argument_helpers_discard_wrong_types_and_bound_integers():
    arguments = {
        "url_contains": 42,
        "method": ["GET"],
        "limit": "500",
        "body_max_chars": "999999",
    }

    assert mcp_string_arg(arguments, "url_contains") is None
    assert mcp_string_arg(arguments, "method") is None
    assert mcp_int_arg(arguments, "limit", 50, 1, 500) == 50
    assert mcp_int_arg(arguments, "body_max_chars", 4000, 0) == 4000
    assert mcp_int_arg({"body_max_chars": True}, "body_max_chars", 4000, 0) == 4000
    assert mcp_int_arg({"body_max_chars": -1}, "body_max_chars", 4000, 0) == 0
    assert mcp_int_arg({"body_max_chars": 999999}, "body_max_chars", 4000, 0) == 999999
    assert mcp_int_arg({"limit": 999999}, "limit", 50, 1, 500) == 500


@pytest.fixture
def mock_store():
    store = MagicMock()
    store.status.return_value = {
        "request_count": 10,
        "endpoint_count": 3,
        "snapshot_count": 1,
        "last_activity_at": 1700000000
    }
    store.list_requests.return_value = [
        {
            "id": "req_101",
            "method": "POST",
            "url": "https://api.target.com/v1/login",
            "status": 200,
            "received_at": 1700000000
        }
    ]
    store.get_request.return_value = {
        "id": "req_101",
        "method": "POST",
        "url": "https://api.target.com/v1/login",
        "response_body": "A" * 5000
    }
    return store


def test_tool_browser_capture_status_output(mock_store):
    status_data = mock_store.status()
    result_json = {
        "ingestUrl": "http://127.0.0.1:9999/ingest",
        "requests": get_val(status_data, 'request_count', 'requestCount', default=0),
        "endpoints": get_val(status_data, 'endpoint_count', 'endpointCount', default=0),
        "snapshots": get_val(status_data, 'snapshot_count', 'snapshotCount', default=0),
        "lastActivityAt": format_iso(get_val(status_data, 'last_activity_at', 'lastActivityAt'))
    }
    
    assert result_json["requests"] == 10
    assert result_json["endpoints"] == 3
    assert result_json["snapshots"] == 1


def test_tool_browser_capture_get_truncation(mock_store):
    req = mock_store.get_request("req_101")
    cap = 4000
    resp_body = req["response_body"]
    
    if len(resp_body) > cap:
        resp_body = f"{resp_body[:cap]}...<truncated {len(resp_body) - cap} chars>"
    
    assert "...<truncated 1000 chars>" in resp_body
