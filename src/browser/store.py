from __future__ import annotations

import itertools
import json
import time
from dataclasses import dataclass, field
from typing import Any, Literal, Optional
from urllib.parse import parse_qsl, urlsplit

BODY_STRING_CAP = 64 * 1024
MAX_ENDPOINTS = 2000
MAX_PARAMS_PER_ENDPOINT = 256

RequestSource = Literal["webRequest", "fetch", "xhr", "ws", "unknown"]
BurpAction = Literal["scan", "plan", "scope"]


@dataclass
class CapturedHeader:
    name: str
    value: str


@dataclass
class CapturedRequest:
    id: str
    source: RequestSource
    method: str
    url: str
    received_at: int
    tab_id: Optional[int] = None
    type: Optional[str] = None
    initiator: Optional[str] = None
    status: Optional[int] = None
    from_cache: Optional[bool] = None
    request_headers: Optional[list[CapturedHeader]] = None
    response_headers: Optional[list[CapturedHeader]] = None
    request_body: Any = None
    response_body: Optional[str] = None
    time_start: Optional[float] = None
    time_end: Optional[float] = None
    elapsed_ms: Optional[float] = None


@dataclass
class EndpointSummary:
    method: str
    url: str
    query_params: list[str]
    body_params: list[str]
    hit_count: int
    first_seen: int
    last_seen: int


@dataclass
class SessionSnapshot:
    received_at: int
    url: str
    title: Optional[str] = None
    user_agent: Optional[str] = None
    document_cookie: Optional[str] = None
    cookies: Optional[list[Any]] = None
    local_storage: Optional[dict[str, str]] = None
    session_storage: Optional[dict[str, str]] = None


@dataclass
class BurpTask:
    id: str
    action: BurpAction
    created_at: int
    source: Literal["burp"] = "burp"
    target: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None
    host: Optional[str] = None
    raw_request_b64: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class BurpIssue:
    id: str
    title: str
    severity: str
    url: str
    detail: str
    created_at: int
    confidence: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    remediation: Optional[str] = None
    path: Optional[str] = None
    raw_request_b64: Optional[str] = None
    raw_response_b64: Optional[str] = None


@dataclass
class _EndpointRecord:
    method: str
    url: str
    first_seen: int
    last_seen: int
    query_params: set[str] = field(default_factory=set)
    body_params: set[str] = field(default_factory=set)
    hit_count: int = 0


def _now_ms() -> int:
    return int(time.time() * 1000)


def _coalesce(*values: Any) -> Any:
    for v in values:
        if v is not None:
            return v
    return None


def _str_or_none(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def _int_or_none(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    return None


def _float_or_none(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    return None


def _bool_or_none(v: Any) -> Optional[bool]:
    return v if isinstance(v, bool) else None


def cap_body(value: Any) -> Any:
    if isinstance(value, str):
        return cap_string(value)
    if isinstance(value, list):
        return [cap_body(v) for v in value]
    if isinstance(value, dict):
        return {k: cap_body(v) for k, v in value.items()}
    return value


def cap_string(value: str) -> str:
    if len(value) <= BODY_STRING_CAP:
        return value
    return f"{value[:BODY_STRING_CAP]}...<truncated {len(value) - BODY_STRING_CAP} chars>"


class CaptureStore:
    def __init__(self, max_entries: Optional[int] = None) -> None:
        self.requests: dict[str, CapturedRequest] = {}
        self.endpoints: dict[str, _EndpointRecord] = {}
        self.snapshots: list[SessionSnapshot] = []
        self.burp_tasks: list[BurpTask] = []
        self.burp_issues: dict[str, BurpIssue] = {}
        self.max_entries = max(100, max_entries if max_entries is not None else 5000)
        self._next_seq = 1
        self.last_activity_at = 0

    def _next_id(self) -> int:
        n = self._next_seq
        self._next_seq += 1
        return n

    def ingest(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            return {"ok": False, "reason": "not an object"}
        obj: dict[str, Any] = raw

        kind = _str_or_none(obj.get("kind"))

        if kind in ("ws-open", "ws-send", "ws-recv"):
            ws_url = _str_or_none(obj.get("url"))
            self._record_endpoint("WS", ws_url if ws_url is not None else "", None, None)
            self.last_activity_at = _now_ms()
            return {"ok": True}

        url = _str_or_none(obj.get("url"))
        if not url:
            return {"ok": False, "reason": "missing url"}

        method_raw = _str_or_none(obj.get("method"))
        method = (method_raw if method_raw is not None else "GET").upper()

        raw_id = obj.get("id")
        id_seed = raw_id if raw_id is not None else f"{kind or 'wr'}-{self._next_id()}"
        id_ = f"{kind or 'wr'}:{id_seed}"

        source: RequestSource
        if kind in ("fetch", "xhr", "ws"):
            source = kind
        elif kind:
            source = "unknown"
        else:
            source = "webRequest"

        request_body = cap_body(_coalesce(obj.get("requestBody"), obj.get("reqBody")))
        response_body_str = _str_or_none(obj.get("respBody"))

        entry = CapturedRequest(
            id=id_,
            source=source,
            tab_id=_int_or_none(obj.get("tabId")),
            method=method,
            url=url,
            type=_str_or_none(obj.get("type")),
            initiator=_str_or_none(obj.get("initiator")),
            status=_int_or_none(obj.get("status")),
            from_cache=_bool_or_none(obj.get("fromCache")),
            request_headers=self._coerce_headers(
                _coalesce(obj.get("requestHeaders"), obj.get("reqHeaders"))
            ),
            response_headers=self._coerce_headers(
                _coalesce(obj.get("responseHeaders"), obj.get("respHeaders"))
            ),
            request_body=request_body,
            response_body=cap_string(response_body_str) if response_body_str is not None else None,
            time_start=_float_or_none(obj.get("timeStart")),
            time_end=_float_or_none(obj.get("timeEnd")),
            elapsed_ms=_float_or_none(obj.get("elapsedMs")),
            received_at=_now_ms(),
        )

        self.requests.pop(id_, None)
        self.requests[id_] = entry
        self._record_endpoint(method, url, entry.request_body, self._query_params(url))
        self._prune_if_needed()
        self.last_activity_at = _now_ms()
        return {"ok": True}

    def ingest_snapshot(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            return {"ok": False, "reason": "not an object"}
        obj: dict[str, Any] = raw
        url = _str_or_none(obj.get("url"))
        if url is None:
            return {"ok": False, "reason": "missing url"}
        document_cookie = _str_or_none(obj.get("documentCookie"))
        cookies_val = obj.get("cookies")
        snap = SessionSnapshot(
            received_at=_now_ms(),
            url=url,
            title=_str_or_none(obj.get("title")),
            user_agent=_str_or_none(obj.get("userAgent")),
            document_cookie=cap_string(document_cookie) if document_cookie is not None else None,
            cookies=cookies_val if isinstance(cookies_val, list) else None,
            local_storage=self._coerce_string_map(obj.get("localStorage")),
            session_storage=self._coerce_string_map(obj.get("sessionStorage")),
        )
        self.snapshots.append(snap)
        if len(self.snapshots) > 100:
            del self.snapshots[: len(self.snapshots) - 100]
        self.last_activity_at = _now_ms()
        return {"ok": True}

    def status(self) -> dict[str, int]:
        return {
            "request_count": len(self.requests),
            "endpoint_count": len(self.endpoints),
            "snapshot_count": len(self.snapshots),
            "last_activity_at": self.last_activity_at,
        }

    def list_requests(
        self,
        url_substr: Optional[str] = None,
        method: Optional[str] = None,
        limit: int = 200,
    ) -> list[CapturedRequest]:
        substr = url_substr.lower() if url_substr else None
        meth = method.upper() if method else None
        out: list[CapturedRequest] = []
        for r in reversed(self.requests.values()):
            if substr and substr not in r.url.lower():
                continue
            if meth and r.method != meth:
                continue
            out.append(r)
            if len(out) >= limit:
                break
        return out

    def get_request(self, id_: str) -> Optional[CapturedRequest]:
        return self.requests.get(id_)

    def list_endpoints(
        self, url_substr: Optional[str] = None, method: Optional[str] = None
    ) -> list[EndpointSummary]:
        substr = url_substr.lower() if url_substr else None
        meth = method.upper() if method else None
        result = [
            EndpointSummary(
                method=e.method,
                url=e.url,
                query_params=list(e.query_params),
                body_params=list(e.body_params),
                hit_count=e.hit_count,
                first_seen=e.first_seen,
                last_seen=e.last_seen,
            )
            for e in self.endpoints.values()
            if (not substr or substr in e.url.lower()) and (not meth or e.method == meth)
        ]
        result.sort(key=lambda s: s.hit_count, reverse=True)
        return result

    def latest_snapshot(self, url_substr: Optional[str] = None) -> Optional[SessionSnapshot]:
        if not url_substr:
            return self.snapshots[-1] if self.snapshots else None
        needle = url_substr.lower()
        for snap in reversed(self.snapshots):
            if needle in snap.url.lower():
                return snap
        return None

    def list_snapshots(self) -> list[SessionSnapshot]:
        return list(self.snapshots)

    def clear(self) -> None:
        self.requests.clear()
        self.endpoints.clear()
        self.snapshots.clear()
        self.burp_tasks.clear()
        self.burp_issues.clear()

    def ingest_burp_task(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            return {"ok": False, "reason": "not an object"}
        obj: dict[str, Any] = raw
        action = obj.get("action")
        if action not in ("scan", "plan", "scope"):
            return {"ok": False, "reason": "action must be scan, plan, or scope"}
        task = BurpTask(
            id=f"burp-task-{self._next_id()}",
            action=action,
            target=_str_or_none(obj.get("target")),
            method=_str_or_none(obj.get("method")),
            url=_str_or_none(obj.get("url")),
            host=_str_or_none(obj.get("host")),
            raw_request_b64=_str_or_none(obj.get("rawRequestB64")),
            notes=_str_or_none(obj.get("notes")),
            source="burp",
            created_at=_now_ms(),
        )
        self.burp_tasks.append(task)
        if len(self.burp_tasks) > 1000:
            del self.burp_tasks[: len(self.burp_tasks) - 1000]
        self.last_activity_at = _now_ms()
        return {"ok": True, "task": task}

    def list_burp_tasks(self) -> list[BurpTask]:
        return list(reversed(self.burp_tasks))

    def ingest_burp_issue(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            return {"ok": False, "reason": "not an object"}
        obj: dict[str, Any] = raw

        title = _str_or_none(obj.get("title")) or ""
        url = _str_or_none(obj.get("url")) or ""
        detail = _str_or_none(obj.get("detail")) or ""
        if not title or not url or not detail:
            return {"ok": False, "reason": "title, url, and detail required"}

        existing_id = _str_or_none(obj.get("id"))
        issue_id = existing_id if existing_id is not None else f"burp-issue-{self._next_id()}"

        severity = _str_or_none(obj.get("severity"))
        confidence = _str_or_none(obj.get("confidence"))
        created_at = _int_or_none(obj.get("createdAt"))

        issue = BurpIssue(
            id=issue_id,
            title=title,
            severity=severity if severity is not None else "Information",
            confidence=confidence if confidence is not None else "Tentative",
            url=url,
            method=_str_or_none(obj.get("method")),
            parameter=_str_or_none(obj.get("parameter")),
            detail=detail,
            remediation=_str_or_none(obj.get("remediation")),
            path=_str_or_none(obj.get("path")),
            raw_request_b64=_str_or_none(obj.get("rawRequestB64")),
            raw_response_b64=_str_or_none(obj.get("rawResponseB64")),
            created_at=created_at if created_at is not None else _now_ms(),
        )
        self._upsert_burp_issue(issue)
        self.last_activity_at = _now_ms()
        return {"ok": True, "issue": issue}

    def add_burp_issue(
        self,
        *,
        title: str,
        severity: str,
        url: str,
        detail: str,
        confidence: Optional[str] = None,
        method: Optional[str] = None,
        parameter: Optional[str] = None,
        remediation: Optional[str] = None,
        path: Optional[str] = None,
        raw_request_b64: Optional[str] = None,
        raw_response_b64: Optional[str] = None,
        id: Optional[str] = None,
        created_at: Optional[int] = None,
    ) -> None:
        issue = BurpIssue(
            id=id if id is not None else f"pf-finding-{self._next_id()}",
            title=title,
            severity=severity,
            confidence=confidence,
            url=url,
            method=method,
            parameter=parameter,
            detail=detail,
            remediation=remediation,
            path=path,
            raw_request_b64=raw_request_b64,
            raw_response_b64=raw_response_b64,
            created_at=created_at if created_at is not None else _now_ms(),
        )
        self._upsert_burp_issue(issue)
        self.last_activity_at = _now_ms()

    def list_burp_issues(self) -> list[BurpIssue]:
        return list(reversed(list(self.burp_issues.values())))

    def _upsert_burp_issue(self, issue: BurpIssue) -> None:
        self.burp_issues[issue.id] = issue
        if len(self.burp_issues) > 1000:
            drop = len(self.burp_issues) - 1000
            for k in itertools.islice(list(self.burp_issues.keys()), drop):
                del self.burp_issues[k]

    def _record_endpoint(
        self,
        method: str,
        url: str,
        body: Any,
        query_params_hint: Optional[list[str]],
    ) -> None:
        no_query = self._url_no_query(url)
        key = f"{method} {no_query}"
        rec = self.endpoints.pop(key, None)
        if rec is None:
            now = _now_ms()
            rec = _EndpointRecord(method=method, url=no_query, first_seen=now, last_seen=now)
        self.endpoints[key] = rec
        rec.hit_count += 1
        rec.last_seen = _now_ms()
        qp = query_params_hint if query_params_hint is not None else self._query_params(url)
        for q in qp:
            if len(rec.query_params) >= MAX_PARAMS_PER_ENDPOINT:
                break
            rec.query_params.add(q)
        for b in self._body_param_names(body):
            if len(rec.body_params) >= MAX_PARAMS_PER_ENDPOINT:
                break
            rec.body_params.add(b)
        self._prune_endpoints_if_needed()

    def _prune_endpoints_if_needed(self) -> None:
        if len(self.endpoints) <= MAX_ENDPOINTS:
            return
        drop = len(self.endpoints) - MAX_ENDPOINTS
        for k in itertools.islice(list(self.endpoints.keys()), drop):
            del self.endpoints[k]

    def _url_no_query(self, url: str) -> str:
        try:
            u = urlsplit(url)
            if not u.scheme or not u.netloc:
                raise ValueError("not an absolute url")
            return f"{u.scheme}://{u.netloc}{u.path}"
        except Exception:
            i = url.find("?")
            return url[:i] if i >= 0 else url

    def _query_params(self, url: str) -> list[str]:
        try:
            u = urlsplit(url)
            if not u.scheme or not u.netloc:
                raise ValueError("not an absolute url")
            return [k for k, _ in parse_qsl(u.query, keep_blank_values=True)]
        except Exception:
            return []

    def _body_param_names(self, body: Any) -> list[str]:
        if not body:
            return []
        if isinstance(body, dict):
            data = body.get("data")
            if body.get("type") == "form" and isinstance(data, dict):
                return list(data.keys())
            if body.get("type") == "raw" and isinstance(data, str):
                return self._parse_raw_body(data)
            return list(body.keys())
        if isinstance(body, str):
            return self._parse_raw_body(body)
        return []

    def _parse_raw_body(self, raw: str) -> list[str]:
        trimmed = raw.strip()
        if not trimmed:
            return []
        if trimmed.startswith("{") or trimmed.startswith("["):
            try:
                parsed = json.loads(trimmed)
                if isinstance(parsed, dict):
                    return list(parsed.keys())
            except (json.JSONDecodeError, TypeError):
                pass
        if "=" in trimmed:
            try:
                return [k for k, _ in parse_qsl(trimmed, keep_blank_values=True)]
            except Exception:
                return []
        return []

    def _coerce_headers(self, v: Any) -> Optional[list[CapturedHeader]]:
        if not v:
            return None
        if isinstance(v, list):
            out: list[CapturedHeader] = []
            for item in v:
                if isinstance(item, dict):
                    name = item.get("name")
                    if isinstance(name, str):
                        value = item.get("value")
                        out.append(
                            CapturedHeader(name=name, value=value if isinstance(value, str) else "")
                        )
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    out.append(CapturedHeader(name=str(item[0]), value=str(item[1])))
                elif isinstance(item, str):
                    i = item.find(":")
                    if i > 0:
                        out.append(
                            CapturedHeader(name=item[:i].strip(), value=item[i + 1 :].strip())
                        )
            return out
        if isinstance(v, dict):
            return [
                CapturedHeader(name=k, value=val if isinstance(val, str) else str(val))
                for k, val in v.items()
            ]
        return None

    def _coerce_string_map(self, v: Any) -> Optional[dict[str, str]]:
        if not v or not isinstance(v, dict):
            return None
        return {k: (val if isinstance(val, str) else str(val)) for k, val in v.items()}

    def _prune_if_needed(self) -> None:
        if len(self.requests) <= self.max_entries:
            return
        drop = len(self.requests) - self.max_entries
        for k in itertools.islice(list(self.requests.keys()), drop):
            del self.requests[k]