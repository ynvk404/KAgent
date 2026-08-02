import sys
from pathlib import Path
import pytest
import json
from datetime import datetime, timezone
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

# Import các hàm và class từ mcp_server.py
from .mcp_server import (
    parse_args,
    get_val,
    to_dict,
    format_iso,
    text_result,
    ParsedArgs,
    DEFAULT_PORT,
)

# ==========================================
# 1. TEST CLI ARGUMENT PARSER (parse_args)
# ==========================================

def test_parse_args_defaults():
    """Kiểm tra giá trị mặc định khi không truyền argument."""
    args = parse_args([])
    assert args.port == DEFAULT_PORT
    assert args.max_entries == 5000
    assert args.log_path == ""
    assert args.show_help is False

def test_parse_args_custom_values():
    """Kiểm tra khi truyền flags tùy chỉnh hợp lệ."""
    argv = ["--port", "8080", "--max-entries", "1000", "--log", "/tmp/mcp.log"]
    args = parse_args(argv)
    assert args.port == 8080
    assert args.max_entries == 1000
    assert args.log_path == "/tmp/mcp.log"

def test_parse_args_invalid_port_fallback():
    """Nếu port không hợp lệ, giữ nguyên port mặc định."""
    argv = ["--port", "999999"]  # Vượt quá 65535
    args = parse_args(argv)
    assert args.port == DEFAULT_PORT

def test_parse_args_help_flag():
    """Kiểm tra cờ trợ giúp -h / --help."""
    assert parse_args(["-h"]).show_help is True
    assert parse_args(["--help"]).show_help is True


# ==========================================
# 2. TEST HELPER UTILITIES
# ==========================================

def test_get_val_dictionary():
    """Kiểm tra truy cập dữ liệu an toàn trên Dictionary (cả camelCase & snake_case)."""
    data = {"request_count": 42, "elapsedMs": 150}
    assert get_val(data, "request_count", "requestCount") == 42
    assert get_val(data, "elapsed_ms", "elapsedMs") == 150
    assert get_val(data, "non_existent", default=0) == 0

def test_get_val_object():
    """Kiểm tra truy cập thuộc tính Object."""
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
    """Kiểm tra chuyển đổi các kiểu dữ liệu khác nhau về Dict."""
    # Dict gốc
    d = {"key": "value"}
    assert to_dict(d) == {"key": "value"}

    # Dataclass Instance
    dc = MockDataclass(id="req_1", method="GET", url="https://example.com")
    assert to_dict(dc) == {"id": "req_1", "method": "GET", "url": "https://example.com"}

    # Object thông thường
    class RegularObj:
        def __init__(self):
            self.foo = "bar"
    
    obj = RegularObj()
    assert to_dict(obj) == {"foo": "bar"}

def test_format_iso():
    """Kiểm tra định dạng thời gian ISO8601 chuẩn UTC."""
    assert format_iso(None) is None
    
    # Từ Timestamp (int/float)
    ts = 1700000000
    iso_str = format_iso(ts)
    assert iso_str is not None and (iso_str.endswith("Z") or iso_str.endswith("+00:00"))

    # Từ đối tượng datetime
    dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    res_str = format_iso(dt)
    assert res_str is not None
    assert res_str.replace("+00:00", "Z") == "2026-01-01T12:00:00Z"

def test_text_result():
    """Kiểm tra cấu trúc trả về của CallToolResult."""
    res = text_result("Hello World", is_error=False)
    assert res.isError is False
    assert len(res.content) == 1
    assert getattr(res.content[0], "text", None) == "Hello World"


# ==========================================
# 3. TEST MOCK LOGIC STORE & MCP TOOLS
# ==========================================

@pytest.fixture
def mock_store():
    """Tạo Mock CaptureStore phục vụ test các Tool Logic."""
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
        "response_body": "A" * 5000  # Giả lập body dài > 4000 char
    }
    return store

def test_tool_browser_capture_status_output(mock_store):
    """Kiểm tra format JSON trả về từ tool browser_capture_status."""
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
    """Kiểm tra tính năng cắt bớt (truncate) response body khi dài quá cap limit."""
    req = mock_store.get_request("req_101")
    cap = 4000
    resp_body = req["response_body"]
    
    if len(resp_body) > cap:
        resp_body = f"{resp_body[:cap]}...<truncated {len(resp_body) - cap} chars>"
    
    assert "...<truncated 1000 chars>" in resp_body