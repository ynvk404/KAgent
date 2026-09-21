from __future__ import annotations

import asyncio
import codecs
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from src.engagement.state import EngagementState
from src.permission.permission import Prompter
from .private_host import gate_private_request, parse_http_url
from .types import Tool, arg_string

FETCH_TIMEOUT_SECONDS = 30.0
FETCH_BODY_CAP = 512 * 1024
SEARCH_BODY_CAP = 1024 * 1024
FETCH_TEXT_CAP = 40 * 1024
STRIP_INPUT_CAP = 256 * 1024

CACHE_TTL_SECONDS = 10 * 60
CACHE_MAX_ENTRIES = 50

ABORT_POLL_SECONDS = 0.05

@dataclass
class _CacheEntry:
    value: str
    expires: float

_result_cache: "OrderedDict[str, _CacheEntry]" = OrderedDict()

def _cache_get(key: str) -> str | None:
    entry = _result_cache.get(key)
    if entry is None:
        return None
    if time.monotonic() > entry.expires:
        _result_cache.pop(key, None)
        return None
    _result_cache.move_to_end(key)
    return entry.value

def _cache_set(key: str, value: str) -> None:
    _result_cache.pop(key, None)
    _result_cache[key] = _CacheEntry(value=value, expires=time.monotonic() + CACHE_TTL_SECONDS)
    while len(_result_cache) > CACHE_MAX_ENTRIES:
        _result_cache.popitem(last=False)

def clear_web_cache() -> None:
    _result_cache.clear()

TAG_RE = re.compile(r"<[^>]+>")
SCRIPT_RE = re.compile(r"<script[^>]*>[\s\S]*?</script>", re.IGNORECASE)
STYLE_RE = re.compile(r"<style[^>]*>[\s\S]*?</style>", re.IGNORECASE)
WS_RE = re.compile(r"[ \t]+")
NL_RE = re.compile(r"\n{3,}")

def strip_html(s: str) -> str:
    input_ = s[:STRIP_INPUT_CAP] if len(s) > STRIP_INPUT_CAP else s
    out = SCRIPT_RE.sub("", input_)
    out = STYLE_RE.sub("", out)
    out = TAG_RE.sub("", out)
    out = WS_RE.sub(" ", out)
    out = NL_RE.sub("\n\n", out)
    return out.strip()

class _FetchAborted(Exception):
    pass

class _FetchFailed(Exception):
    def __init__(self, message: str, *, timed_out: bool, code: str | None = None):
        super().__init__(message)
        self.message = message
        self.timed_out = timed_out
        self.code = code

def _is_aborted(signal: Any) -> bool:
    return signal is not None and getattr(signal, "aborted", False)

async def _run_cancelable(coro, timeout_seconds: float, signal: Any):
    if _is_aborted(signal):
        coro.close()
        raise _FetchAborted()

    task = asyncio.ensure_future(coro)
    aborted = False

    async def watch_abort() -> None:
        nonlocal aborted
        if signal is None:
            return
        while not task.done():
            if getattr(signal, "aborted", False):
                aborted = True
                task.cancel()
                return
            await asyncio.sleep(ABORT_POLL_SECONDS)

    watch_task = asyncio.create_task(watch_abort())

    try:
        return await asyncio.wait_for(task, timeout=timeout_seconds)
    except asyncio.TimeoutError as exc:
        task.cancel()
        raise _FetchFailed("request timed out", timed_out=True) from exc
    except asyncio.CancelledError as exc:
        if aborted:
            raise _FetchAborted() from exc
        raise
    finally:
        watch_task.cancel()
        try:
            await watch_task
        except asyncio.CancelledError:
            pass

def _map_httpx_error(err: Exception) -> tuple[str, str | None]:
    message = str(err)
    cause = err.__cause__ or err.__context__
    text = f"{message} {cause}".lower() if cause else message.lower()

    if isinstance(err, httpx.ConnectTimeout):
        return message, None
    if (
        "enotfound" in text
        or "name or service not known" in text
        or "nodename nor servname" in text
        or "getaddrinfo failed" in text
    ):
        return message, "ENOTFOUND"
    if "econnrefused" in text or "connection refused" in text:
        return message, "ECONNREFUSED"
    if "certificate has expired" in text or "certificate is expired" in text:
        return message, "CERT_HAS_EXPIRED"
    if (
        "unable to get local issuer certificate" in text
        or "self-signed certificate" in text
        or "certificate verify failed" in text
    ):
        return message, "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
    return message, None

async def _decode_capped(response: httpx.Response, cap: int) -> str:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    parts: list[str] = []
    total = 0
    truncated = False

    async for chunk in response.aiter_bytes():
        if total >= cap:
            break
        if not chunk:
            continue
        remaining = cap - total
        if len(chunk) > remaining:
            parts.append(decoder.decode(chunk[:remaining], True))
            total += remaining
            truncated = True
            break
        parts.append(decoder.decode(chunk, False))
        total += len(chunk)

    if not truncated:
        parts.append(decoder.decode(b"", True))

    return "".join(parts)

class WebFetchTool(Tool):
    def __init__(self, engagement: EngagementState) -> None:
        self.engagement = engagement

    def name(self) -> str:
        return "web_fetch"

    def description(self) -> str:
        return (
            "Fetch a public web page and return its readable text (HTML tags "
            "stripped). Use for CVE lookups, exploit-DB pages, vendor "
            "advisories, technical articles."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to fetch (http/https)."},
            },
            "required": ["url"],
        }

    def requires_permission(self) -> bool:
        return False

    async def run(self, args: dict[str, Any], signal: Any, prompter: Prompter) -> str:
        url = arg_string(args, "url")
        if not url:
            raise ValueError("url is required")

        parsed = parse_http_url(url)
        self.engagement.require_in_scope(url)
        private_reason = await gate_private_request(prompter, parsed, signal, "web_fetch")

        cache_key = f"fetch:{parsed}"
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            resp = await _run_cancelable(_do_fetch(url), FETCH_TIMEOUT_SECONDS, signal)
        except _FetchAborted:
            raise
        except _FetchFailed as err:
            return format_fetch_failure(url, err.message, err.timed_out, err.code)
        except httpx.HTTPError as err:
            message, code = _map_httpx_error(err)
            return format_fetch_failure(url, message, False, code)

        async with resp:
            raw = await _decode_capped(resp, FETCH_BODY_CAP)
            status, status_text = resp.status_code, resp.reason_phrase

        text = strip_html(raw)
        if len(text) > FETCH_TEXT_CAP:
            text = f"{text[:FETCH_TEXT_CAP]}\n[... truncated ...]"

        result = f"URL: {url}\nStatus: {status} {status_text}\n\n{text}"
        if private_reason:
            result = (
                f"note: private/internal host approved for this fetch "
                f"(reason: {private_reason})\n\n{result}"
            )

        _cache_set(cache_key, result)
        return result

async def _do_fetch(url: str) -> httpx.Response:
    client = httpx.AsyncClient(follow_redirects=False)
    request = client.build_request(
        "GET",
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0 kagent/0.1 (+research)",
        },
    )
    try:
        resp = await client.send(request, stream=True)
    except Exception:
        await client.aclose()
        raise

    resp._pf_client = client  # type: ignore[attr-defined]
    original_aclose = resp.aclose

    async def _aclose():
        await original_aclose()
        await client.aclose()

    resp.aclose = _aclose  # type: ignore[method-assign]
    return resp

def format_fetch_failure(url: str, message: str, timed_out: bool, code: str | None) -> str:
    lines = [
        f"URL: {url}",
        "ERROR: fetch failed",
        f"Reason: {'request timed out' if timed_out else message}",
    ]
    if code:
        lines.append(f"Code: {code}")
    host = _hostname_of(url)
    if host:
        lines.append(f"Host: {host}")
    hint = _fetch_failure_hint(url, code)
    if hint:
        lines.append("")
        lines.append(hint)
    return "\n".join(lines)

def _fetch_failure_hint(url: str, code: str | None) -> str:
    host = _hostname_of(url)
    if host == "platform.hackerone.com":
        handle = _hackerone_handle_from_platform_path(url)
        program_url = f"https://hackerone.com/{handle}" if handle else "https://hackerone.com/<program>"
        return "\n".join(
            (
                "Hint: platform.hackerone.com is not a public HackerOne program host.",
                f"Try the public program page instead: {program_url}",
                "For scope data, use the public program page or HackerOne API with valid credentials.",
            )
        )
    if code == "ENOTFOUND":
        return "Hint: DNS lookup failed. Check the hostname or try web_search."
    if code == "ECONNREFUSED":
        return "Hint: connection refused. Check the scheme, host, and port."
    if code in ("CERT_HAS_EXPIRED", "UNABLE_TO_VERIFY_LEAF_SIGNATURE"):
        return "Hint: TLS certificate validation failed. Use the http tool or curl when you need TLS-disabled probing."
    return ""

def _hostname_of(raw: str) -> str:
    try:
        return (urlparse(raw).hostname or "").lower()
    except Exception:
        return ""

def _hackerone_handle_from_platform_path(raw: str) -> str:
    try:
        parts = [p for p in urlparse(raw).path.split("/") if p]
        return parts[0] if parts else ""
    except Exception:
        return ""

DDG_RESULT_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)</a>[\s\S]*?'
    r'<a[^>]+class="result__snippet"[^>]*>([\s\S]*?)</a>',
    re.IGNORECASE,
)

ANCHOR_RE = re.compile(r'<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)</a>', re.IGNORECASE)

def normalize_ddg_url(raw_url: str) -> str:
    url = raw_url
    if url.startswith("//"):
        url = f"https:{url}"
    try:
        u = urlparse(url)
        if u.hostname == "duckduckgo.com" and u.path == "/l/":
            qs = parse_qs(u.query)
            real = qs.get("uddg", [None])[0]
            if real:
                url = unquote(real)
    except Exception:
        pass
    return url

def extract_anchor_results(body: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    for m in ANCHOR_RE.finditer(body):
        if len(out) >= 10:
            break
        url = normalize_ddg_url(m.group(1) or "")
        title = strip_html(m.group(2) or "")
        if not title:
            continue
        if not re.match(r"^https?://", url, re.IGNORECASE):
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append((url, title))

    return out

class WebSearchTool(Tool):
    def name(self) -> str:
        return "web_search"

    def description(self) -> str:
        return (
            "Search the web (via DuckDuckGo) and return a list of result "
            "titles, URLs, and snippets. Use for finding CVEs, exploits, "
            "technique writeups, vendor docs."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query."},
            },
            "required": ["query"],
        }

    def requires_permission(self) -> bool:
        return False

    async def run(self, args: dict[str, Any], signal: Any, prompter: Prompter) -> str:
        query = arg_string(args, "query")
        if not query:
            raise ValueError("query is required")

        endpoint = f"https://html.duckduckgo.com/html/?q={_url_encode(query)}"

        cache_key = f"search:{query.strip()}"
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            resp = await _run_cancelable(_do_search(endpoint), FETCH_TIMEOUT_SECONDS, signal)
        except _FetchAborted:
            raise
        except _FetchFailed as err:
            return format_fetch_failure(endpoint, err.message, err.timed_out, err.code)
        except httpx.HTTPError as err:
            message, code = _map_httpx_error(err)
            return format_fetch_failure(endpoint, message, False, code)

        async with resp:
            body = await _decode_capped(resp, SEARCH_BODY_CAP)

        results: list[tuple[str, str, str]] = []
        for m in DDG_RESULT_RE.finditer(body):
            if len(results) >= 10:
                break
            results.append((m.group(1) or "", m.group(2) or "", m.group(3) or ""))

        if not results:
            if body.strip():
                anchors = extract_anchor_results(body)
                if anchors:
                    out_lines = [
                        f"{i + 1}. {title}\n   {url}\n"
                        for i, (url, title) in enumerate(anchors)
                    ]
                    result = (
                        "degraded results (DuckDuckGo markup changed; "
                        "extracted raw links):\n\n" + "\n".join(out_lines)
                    )
                    _cache_set(cache_key, result)
                    return result
            return (
                "no results parsed (DuckDuckGo may have changed its HTML; "
                "try web_fetch on a specific URL instead)"
            )

        out_lines = []
        for i, (raw_url, raw_title, raw_snippet) in enumerate(results):
            url = normalize_ddg_url(raw_url)
            title = strip_html(raw_title)
            snippet = strip_html(raw_snippet)
            out_lines.append(f"{i + 1}. {title}\n   {url}\n   {snippet}\n")

        result = "\n".join(out_lines)
        _cache_set(cache_key, result)
        return result

async def _do_search(endpoint: str) -> httpx.Response:
    client = httpx.AsyncClient(follow_redirects=True)
    request = client.build_request(
        "GET",
        endpoint,
        headers={"User-Agent": "Mozilla/5.0 kagent/0.1"},
    )
    try:
        resp = await client.send(request, stream=True)
    except Exception:
        await client.aclose()
        raise
    original_aclose = resp.aclose

    async def _aclose():
        await original_aclose()
        await client.aclose()

    resp.aclose = _aclose  # type: ignore[method-assign]
    return resp

def _url_encode(s: str) -> str:
    from urllib.parse import quote

    return quote(s, safe="")
