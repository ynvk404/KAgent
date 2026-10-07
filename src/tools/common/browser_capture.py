from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable

from src.browser.store import CaptureStore
from src.browser.redacted_view import request_view, snapshot_view, issue_view, task_view
from src.redact.redact import apply_evidence
from src.permission.permission import Prompter
from src.tools.common.types import Tool, arg_number, arg_string

TOOL_PREFIX = "browser_capture_"

OUTPUT_CHAR_CAP = 64 * 1024
DEFAULT_LIST_LIMIT = 200
MAX_REQUESTS_LIMIT = 500

def _iso(ms: float | None) -> str:
    if ms is None:
        return "never"
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()

def cap_json(value: Any) -> str:
    s = json.dumps(value, separators=(",", ":"))
    if len(s) <= OUTPUT_CHAR_CAP:
        return s
    return f"{s[:OUTPUT_CHAR_CAP]}\n[... truncated {len(s) - OUTPUT_CHAR_CAP} chars ...]"

def render_list(items: list[Any], limit: int) -> str:
    shown = items[:limit]
    out = json.dumps(shown, separators=(",", ":"))
    if len(items) > limit:
        out += f"\n[... {len(items) - limit} more omitted; showing first {limit} ...]"
    if len(out) <= OUTPUT_CHAR_CAP:
        return out
    return f"{out[:OUTPUT_CHAR_CAP]}\n[... truncated {len(out) - OUTPUT_CHAR_CAP} chars ...]"

class BaseCaptureTool(Tool, ABC):
    def __init__(self, store: CaptureStore):
        self.store = store

    def bind_execution_policy(self, policy):
        from copy import copy
        from src.browser.scoped_store import ScopedCaptureStore
        bound = copy(self)
        bound.store = ScopedCaptureStore(self.store, policy)
        return bound

    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def description(self) -> str: ...

    @abstractmethod
    def schema(self) -> dict[str, Any]: ...

    @abstractmethod
    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str: ...

    def requires_permission(self) -> bool:
        return False

class BrowserCaptureStatusTool(BaseCaptureTool):
    def name(self) -> str:
        return f"{TOOL_PREFIX}status"

    def description(self) -> str:
        return (
            "Show counts and last-activity time for traffic captured by the "
            "KAgent Chrome extension. Call this first to confirm the "
            "extension is connected and forwarding before relying on the other "
            "browser_capture_* tools."
        )

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {}}

    async def run(self, args=None, signal=None, prompter=None) -> str:
        s = self.store.status()
        last_activity_at = s.get("last_activity_at")
        last_seen = _iso(last_activity_at) if last_activity_at else "never"
        return json.dumps(
            {
                "requests": s.get("request_count", 0),
                "endpoints": s.get("endpoint_count", 0),
                "snapshots": s.get("snapshot_count", 0),
                "lastActivityAt": last_seen,
            },
            indent=2,
        )

class BrowserCaptureEndpointsTool(BaseCaptureTool):
    def name(self) -> str:
        return f"{TOOL_PREFIX}endpoints"

    def description(self) -> str:
        return (
            "List unique endpoints (METHOD + path-without-query) observed by "
            "the Chrome extension, with the set of query and body parameter "
            "names ever seen for each. Use this to plan IDOR / injection / "
            "fuzz targets without re-crawling."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url_contains": {
                    "type": "string",
                    "description": "Filter to endpoints whose URL contains this substring.",
                },
                "method": {
                    "type": "string",
                    "description": "Filter to a single HTTP method (GET, POST, ...).",
                },
            },
        }

    async def run(self, args: dict[str, Any], signal=None, prompter=None) -> str:
        eps = self.store.list_endpoints(
            url_substr=arg_string(args, "url_contains") or None,
            method=arg_string(args, "method") or None,
        )
        if len(eps) == 0:
            return (
                "No endpoints captured yet. Confirm the extension is running "
                "with capture enabled and the scope regex matches the target."
            )
        return render_list(eps, DEFAULT_LIST_LIMIT)

class BrowserCaptureRequestsTool(BaseCaptureTool):
    def name(self) -> str:
        return f"{TOOL_PREFIX}requests"

    def description(self) -> str:
        return (
            "List captured requests, newest first, with method, URL and status. "
            "Use id with browser_capture_get for details; "
            "use baseline_request_ref for HTTP replay."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url_contains": {
                    "type": "string",
                    "description": "Filter to requests whose URL contains this substring.",
                },
                "method": {
                    "type": "string",
                    "description": "Filter to a single HTTP method.",
                },
                "limit": {
                    "type": "number",
                    "description": "Maximum number of requests to return (default 50).",
                },
            },
        }

    async def run(self, args: dict[str, Any], signal=None, prompter=None) -> str:
        requested_val = arg_number(args, "limit")
        requested = int(requested_val) if requested_val is not None else 50
        limit = min(max(1, requested), MAX_REQUESTS_LIMIT)
        rows = self.store.list_requests(
            url_substr=arg_string(args, "url_contains") or None,
            method=arg_string(args, "method") or None,
            limit=limit,
        )
        if len(rows) == 0:
            return "No matching requests."
        slim = [
            {
                "id": r.id,
                "baseline_request_ref": r.baseline_request_ref,
                "method": r.method,
                "url": apply_evidence(r.url),
                "status": r.status,
                "type": r.type,
                "source": r.source,
                "elapsedMs": r.elapsed_ms,
                "receivedAt": _iso(r.received_at),
            }
            for r in rows
        ]
        return cap_json(slim)

class BrowserCaptureGetTool(BaseCaptureTool):
    def name(self) -> str:
        return f"{TOOL_PREFIX}get"

    def description(self) -> str:
        return (
            "Fetch full details for one captured request: headers, request "
            "body, response body (when available). Pass the id returned by "
            "browser_capture_requests."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Request id from browser_capture_requests."},
                "body_max_chars": {
                    "type": "number",
                    "description": "Optional cap for the response body excerpt (default 4000).",
                },
            },
            "required": ["id"],
        }

    async def run(self, args: dict[str, Any], signal=None, prompter=None) -> str:
        id_ = arg_string(args, "id")
        if not id_:
            return "error: id is required"
        r = self.store.get_request(id_)
        if not r:
            return f"error: no request with id {id_}"
        cap_val = arg_number(args, "body_max_chars")
        cap = int(cap_val) if cap_val is not None else 4000
        response_body = request_view(r).get("response_body")
        if response_body and len(response_body) > cap:
            response_body = (
                f"{response_body[:cap]}...<truncated {len(response_body) - cap} chars>"
            )
        trimmed = {
            **request_view(r),
            "responseBody": response_body,
            "receivedAt": _iso(r.received_at),
        }
        from src.permission.runtime.execution import policy_for
        policy = policy_for(prompter)
        if policy is not None and policy.observations.owner_provider() is not None:
            trimmed["runtime_observation_id"] = policy.observations.import_capture(
                r, owner=policy.observations.owner_provider())
            trimmed["evidence_source_kind"] = "imported-capture"
        return json.dumps(trimmed, indent=2)

class BrowserCaptureSnapshotTool(BaseCaptureTool):
    def name(self) -> str:
        return f"{TOOL_PREFIX}snapshot"

    def description(self) -> str:
        return (
            "Return the most recent session snapshot captured by the "
            "extension: redacted cookie and storage metadata plus page URL. "
            "Use a runtime identity context for authenticated replay."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url_contains": {
                    "type": "string",
                    "description": "Optional: return the most recent snapshot whose URL contains this substring.",
                },
            },
        }

    async def run(self, args: dict[str, Any], signal=None, prompter=None) -> str:
        snap = self.store.latest_snapshot(arg_string(args, "url_contains") or None)
        if not snap:
            return 'No snapshots captured yet. Click "Snapshot tab" in the extension popup.'
        return json.dumps(
            {**snapshot_view(snap), "receivedAt": _iso(snap.received_at)},
            indent=2,
        )

class BrowserCaptureClearTool(BaseCaptureTool):
    def name(self) -> str:
        return f"{TOOL_PREFIX}clear"

    def description(self) -> str:
        return (
            "Irreversibly clear the browser capture store: all captured "
            "requests, endpoints, and snapshots. Call only when the user "
            "explicitly asks to clear or reset browser capture data (for "
            "example, between named testing phases or after a scope change); "
            "do not infer this action from an ambiguous request. This tool "
            "takes no arguments."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        }

    def validate_args(self, args: dict[str, Any]) -> None:
        if args:
            raise ValueError(
                "browser_capture_clear does not accept arguments"
            )

    def requires_permission(self) -> bool:
        return True

    def summarize(self, args: dict[str, Any]) -> dict[str, str]:
        return {
            "summary": "clear browser capture store",
            "detail": (
                "Wipes all captured requests, endpoints, and snapshots from "
                "memory. Forwarding continues — new captures will "
                "repopulate the store."
            ),
        }

    def permission_hints(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"noSessionCache": True, "riskTier": "high-impact"}

    async def run(self, args=None, signal=None, prompter=None) -> str:
        self.store.clear()
        return "cleared."

class BrowserCaptureBurpTasksTool(BaseCaptureTool):
    def name(self) -> str:
        return f"{TOOL_PREFIX}burp_tasks"

    def description(self) -> str:
        return (
            "List Burp scan/plan/scope tasks after the user sends requests. "
            "Use baseline_request_ref for HTTP replay; id is retrieval-only."
        )

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {}}

    async def run(self, args=None, signal=None, prompter=None) -> str:
        tasks = self.store.list_burp_tasks()
        if len(tasks) == 0:
            return "No Burp tasks queued."
        return render_list(
            [{**task_view(t),
              "createdAt": _iso(t.created_at)} for t in tasks],
            DEFAULT_LIST_LIMIT,
        )

class BrowserCaptureBurpIssuesTool(BaseCaptureTool):
    def name(self) -> str:
        return f"{TOOL_PREFIX}burp_issues"

    def description(self) -> str:
        return (
            "List KAgent issues exposed to the Burp extension for "
            "import into Burp Scanner issues."
        )

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {}}

    async def run(self, args=None, signal=None, prompter=None) -> str:
        issues = self.store.list_burp_issues()
        if len(issues) == 0:
            return "No KAgent issues queued for Burp import."
        return render_list(
            [{**issue_view(i), "createdAt": _iso(i.created_at)} for i in issues],
            DEFAULT_LIST_LIMIT,
        )

def register_browser_capture_tools(
    register: Callable[[Tool], None],
    store: CaptureStore,
) -> None:
    register(BrowserCaptureStatusTool(store))
    register(BrowserCaptureEndpointsTool(store))
    register(BrowserCaptureRequestsTool(store))
    register(BrowserCaptureGetTool(store))
    register(BrowserCaptureSnapshotTool(store))
    register(BrowserCaptureBurpTasksTool(store))
    register(BrowserCaptureBurpIssuesTool(store))
    register(BrowserCaptureClearTool(store))
