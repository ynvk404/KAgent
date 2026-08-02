# pentestagent-browser-mcp — standalone MCP stdio server that pairs with
# the pentestagent Chrome extension companion.

import sys
import json
import asyncio
from datetime import datetime, timezone
from dataclasses import is_dataclass, asdict
from typing import Any, Dict, List, Optional, cast

import mcp.types as types
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server

import logger
from .server import start_ingest_server, IngestServerOptions
from .store import CaptureStore

# Ép kiểu Any cho module logger để tránh Pylance báo lỗi attr access khi gọi init/info
log: Any = logger

SERVER_NAME = 'pentestagent-browser'
SERVER_VERSION = '0.1.0'
DEFAULT_PORT = 9999

class ParsedArgs:
    def __init__(self):
        self.port: int = DEFAULT_PORT
        self.max_entries: int = 5000
        self.log_path: str = ''
        self.show_help: bool = False

def parse_args(argv: List[str]) -> ParsedArgs:
    out = ParsedArgs()
    i = 0
    while i < len(argv):
        a = argv[i]
        
        def next_arg() -> str:
            nonlocal i
            i += 1
            return argv[i] if i < len(argv) else ''

        if a == '--port':
            try:
                n = int(next_arg())
                if 0 < n < 65536:
                    out.port = n
            except ValueError:
                pass
        elif a == '--max-entries':
            try:
                n = int(next_arg())
                if n >= 100:
                    out.max_entries = n
            except ValueError:
                pass
        elif a == '--log':
            out.log_path = next_arg()
        elif a in ('-h', '--help'):
            out.show_help = True
        i += 1
    return out

def print_help() -> None:
    sys.stderr.write(f"""pentestagent-browser-mcp {SERVER_VERSION}

Standalone MCP stdio server that bridges the pentestagent Chrome extension
to any MCP-aware client (Cursor, pentestagent, ...).

Usage:
  python -m pentestagent_browser_mcp [flags]

Flags:
  --port <n>          ingest HTTP port (default {DEFAULT_PORT}, 127.0.0.1 only)
  --max-entries <n>   max captured requests retained (default 5000, min 100)
  --log <path>        write structured logs here (default off)
  -h, --help          this help
""")

# ---- Helper utilities ----

def text_result(text: str, is_error: bool = False) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        isError=is_error
    )

def get_val(obj: Any, *keys: str, default: Any = None) -> Any:
    """Truy cập an toàn cho cả Dict lẫn Object (hỗ trợ camelCase/snake_case)."""
    if isinstance(obj, dict):
        for k in keys:
            if k in obj: return obj[k]
    else:
        for k in keys:
            if hasattr(obj, k): return getattr(obj, k)
    return default

def to_dict(obj: Any) -> dict:
    """Chuyển đổi Object (Dataclass, Class thường hoặc Dict) sang Dictionary an toàn."""
    if isinstance(obj, dict):
        return obj.copy()
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(cast(Any, obj))
    if hasattr(obj, '__dict__'):
        return vars(obj).copy()
    return {}

def format_iso(val: Any) -> Optional[str]:
    """Format thời gian sang chuẩn ISO8601 (Python 3.12+ safe)."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val.isoformat() if val.tzinfo else val.isoformat() + "Z"
    if isinstance(val, (int, float)): 
        return datetime.fromtimestamp(val, timezone.utc).isoformat().replace("+00:00", "Z")
    return str(val)

# ---- Main Application ----

async def main() -> int:
    args = parse_args(sys.argv[1:])
    if args.show_help:
        print_help()
        return 0

    log.init(args.log_path)
    log.info('browser-mcp startup', port=args.port, max_entries=args.max_entries)

    store = CaptureStore(max_entries=args.max_entries)
    ingest_url = ''
    handle = None

    try:
        # Gọi đồng bộ với IngestServerOptions đúng như server.py yêu cầu
        handle = start_ingest_server(
            IngestServerOptions(
                store=store,
                port=args.port,
            )
        )
        ingest_url = handle.url
        sys.stderr.write(
            f"[pentestagent-browser-mcp] ingest listening at {handle.url}/ingest\n"
            f"[pentestagent-browser-mcp] token: {handle.token}\n"
            f"[pentestagent-browser-mcp] configure the Chrome extension with this base URL and token.\n"
        )
    except Exception as err:
        sys.stderr.write(f"[pentestagent-browser-mcp] failed to start ingest server on :{args.port}: {err}\n")
        return 1

    mcp = Server(SERVER_NAME)

    # ---- Tools Registration ----

    @mcp.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="browser_capture_status",
                description="Show counts (requests / endpoints / snapshots) and last-activity time for traffic captured by the pentestagent Chrome extension. Call this first to confirm the extension is connected and forwarding.",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="browser_capture_endpoints",
                description="List unique endpoints (METHOD + path-without-query) observed by the extension, with the set of query and body parameter names ever seen for each. Use this to plan IDOR / injection / fuzz targets without re-crawling.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url_contains": {"type": "string", "description": "Filter to endpoints whose URL contains this substring."},
                        "method": {"type": "string", "description": "Filter to a single HTTP method (GET, POST, ...)."}
                    }
                }
            ),
            types.Tool(
                name="browser_capture_requests",
                description="List recent captured requests (most-recent first) with id, method, url, status. Use the returned id with browser_capture_get to retrieve full headers + body for a specific request.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url_contains": {"type": "string", "description": "Filter by URL substring."},
                        "method": {"type": "string", "description": "Filter to a single HTTP method."},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 500, "description": "Max rows (default 50)."}
                    }
                }
            ),
            types.Tool(
                name="browser_capture_get",
                description="Fetch full details for one captured request: headers, request body, response body (when available). Pass the id returned by browser_capture_requests.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "Request id from browser_capture_requests."},
                        "body_max_chars": {"type": "integer", "minimum": 0, "description": "Cap for response body excerpt (default 4000)."}
                    },
                    "required": ["id"]
                }
            ),
            types.Tool(
                name="browser_capture_snapshot",
                description="Return the most recent session snapshot captured by the extension: cookies (incl. HttpOnly), localStorage, sessionStorage, document.cookie, page URL. Use this to construct authenticated requests — copy the relevant cookies into a 'Cookie' header.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url_contains": {"type": "string", "description": "Optional: most recent snapshot whose URL contains this substring."}
                    }
                }
            ),
            types.Tool(
                name="browser_capture_clear",
                description="Wipe all captured requests, endpoints, and snapshots from the in-memory store. Forwarding continues — new captures will repopulate it.",
                inputSchema={"type": "object", "properties": {}}
            )
        ]

    @mcp.call_tool()
    async def handle_call_tool(name: str, arguments: dict | None) -> types.CallToolResult:
        args_dict = arguments or {}

        if name == "browser_capture_status":
            s = store.status()
            return text_result(json.dumps({
                "ingestUrl": f"{ingest_url}/ingest" if ingest_url else None,
                "requests": get_val(s, 'request_count', 'requestCount', default=0),
                "endpoints": get_val(s, 'endpoint_count', 'endpointCount', default=0),
                "snapshots": get_val(s, 'snapshot_count', 'snapshotCount', default=0),
                "lastActivityAt": format_iso(get_val(s, 'last_activity_at', 'lastActivityAt'))
            }, indent=2))

        elif name == "browser_capture_endpoints":
            eps = store.list_endpoints(
                url_substr=args_dict.get("url_contains"),
                method=args_dict.get("method")
            )
            if not eps:
                return text_result('No endpoints captured yet. Confirm the extension is running with capture enabled and the scope regex matches the target.')
            return text_result(json.dumps([to_dict(ep) for ep in eps], indent=2))

        elif name == "browser_capture_requests":
            limit = args_dict.get("limit", 50)
            rows = store.list_requests(
                url_substr=args_dict.get("url_contains"),
                method=args_dict.get("method"),
                limit=limit
            )
            if not rows:
                return text_result('No matching requests.')

            slim = []
            for r in rows:
                slim.append({
                    "id": get_val(r, 'id'),
                    "method": get_val(r, 'method'),
                    "url": get_val(r, 'url'),
                    "status": get_val(r, 'status'),
                    "type": get_val(r, 'type'),
                    "source": get_val(r, 'source'),
                    "elapsedMs": get_val(r, 'elapsed_ms', 'elapsedMs'),
                    "receivedAt": format_iso(get_val(r, 'received_at', 'receivedAt'))
                })
            return text_result(json.dumps(slim, indent=2))

        elif name == "browser_capture_get":
            req_id = args_dict.get("id")
            if not isinstance(req_id, str) or not req_id:
                return text_result("error: missing or invalid 'id' parameter", is_error=True)

            r = store.get_request(req_id)
            if not r:
                return text_result(f"error: no request with id {req_id}", is_error=True)

            cap = args_dict.get("body_max_chars", 4000)
            r_dict = to_dict(r)
            
            resp_body = get_val(r, 'response_body', 'responseBody')
            if resp_body and isinstance(resp_body, str) and len(resp_body) > cap:
                resp_body = f"{resp_body[:cap]}...<truncated {len(resp_body) - cap} chars>"
            
            r_dict['responseBody'] = resp_body
            r_dict.pop('response_body', None)

            recv_at = get_val(r, 'received_at', 'receivedAt')
            if recv_at:
                r_dict['receivedAt'] = format_iso(recv_at)
                r_dict.pop('received_at', None)

            return text_result(json.dumps(r_dict, indent=2))

        elif name == "browser_capture_snapshot":
            snap = store.latest_snapshot(url_substr=args_dict.get("url_contains"))
            if not snap:
                return text_result('No snapshots captured yet. Click "Snapshot tab" in the extension popup.')
            
            snap_dict = to_dict(snap)
            recv_at = get_val(snap, 'received_at', 'receivedAt')
            
            if recv_at:
                snap_dict['receivedAt'] = format_iso(recv_at)
                snap_dict.pop('received_at', None)

            return text_result(json.dumps(snap_dict, indent=2))

        elif name == "browser_capture_clear":
            store.clear()
            return text_result("cleared.")

        else:
            raise ValueError(f"Unknown tool: {name}")

    # ---- Transport ----
    try:
        async with stdio_server() as (read_stream, write_stream):
            await mcp.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name=SERVER_NAME,
                    server_version=SERVER_VERSION,
                    capabilities=mcp.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        # Gọi close() đồng bộ khi stdio kết thúc
        log.info('browser-mcp shutdown')
        if handle:
            handle.close()

    return 0

if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"[pentestagent-browser-mcp] fatal: {e}\n")
        sys.exit(1)