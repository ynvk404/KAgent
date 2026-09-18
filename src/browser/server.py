from __future__ import annotations

import hmac
import json
import re
import secrets
import threading
from dataclasses import asdict, dataclass, is_dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Literal, Optional, cast
from urllib.parse import urlparse

from src.logger.logger import get_logger

from .store import CaptureStore

logger = get_logger("browser.server")

MAX_BODY_BYTES = 4 * 1024 * 1024


class DataclassJSONEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if is_dataclass(o) and not isinstance(o, type):
            return asdict(o)
        return super().default(o)


@dataclass(slots=True)
class IngestServerOptions:
    store: CaptureStore
    port: int
    host: str = "127.0.0.1"
    token: Optional[str] = None
    on_event: Optional[Callable[[str], None]] = None


@dataclass(slots=True)
class IngestServerHandle:
    port: int
    host: str
    url: str
    token: str

    server: ThreadingHTTPServer
    thread: threading.Thread

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@dataclass(slots=True)
class BurpBridgeState:
    running: bool
    port: Optional[int] = None
    url: Optional[str] = None
    token: Optional[str] = None


@dataclass(slots=True)
class BurpBridgeResult:
    status: Literal[
        "started",
        "already_running",
        "restarted",
        "stopped",
        "not_running",
    ]
    state: BurpBridgeState
    old_port: Optional[int] = None


class IngestHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: type[BaseHTTPRequestHandler], opts: IngestServerOptions, token: str):
        self.store = opts.store
        self.token = token
        self.on_event = opts.on_event
        super().__init__(server_address, RequestHandlerClass)


class Handler(BaseHTTPRequestHandler):
    @property
    def ingest_server(self) -> IngestHTTPServer:
        return cast(IngestHTTPServer, self.server)

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def send_json(self, payload: Any, status: int = 200, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, cls=DataclassJSONEncoder).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text: str, status: int, extra_headers: dict[str, str] | None = None) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def get_cors_headers(self) -> dict[str, str]:
        origin = self.headers.get("Origin")

        cors_headers = {"Vary": "Origin"}

        if not origin or not allowed_origin(origin):
            return cors_headers

        cors_headers["Access-Control-Allow-Origin"] = origin
        cors_headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, DELETE"
        cors_headers["Access-Control-Allow-Headers"] = (
            "Content-Type, X-KAgent-Source, X-KAgent-Token"
        )
        return cors_headers

    def _check_security(self) -> bool:
        if not valid_loopback_host(self.headers.get("Host")):
            self.send_json({"ok": False, "error": "invalid host"}, status=403)
            return False

        if not authorized(self.headers.get("X-KAgent-Token"), self.ingest_server.token):
            self.send_json(
                {"ok": False, "error": "unauthorized"},
                status=401,
                extra_headers=self.get_cors_headers()
            )
            return False

        return True

    def do_OPTIONS(self) -> None:
        if not valid_loopback_host(self.headers.get("Host")):
            self.send_json({"ok": False, "error": "invalid host"}, status=403)
            return

        self.send_response(204)
        for k, v in self.get_cors_headers().items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        if not self._check_security():
            return

        store = self.ingest_server.store
        cors = self.get_cors_headers()
        path = urlparse(self.path).path

        if path in ("/", "/status"):
            self.send_json({"ok": True, **store.status()}, extra_headers=cors)
        elif path == "/endpoints":
            self.send_json(store.list_endpoints(), extra_headers=cors)
        elif path == "/requests":
            self.send_json(store.list_requests(limit=500), extra_headers=cors)
        elif path == "/burp/tasks":
            self.send_json(store.list_burp_tasks(), extra_headers=cors)
        elif path == "/burp/issues":
            self.send_json(store.list_burp_issues(), extra_headers=cors)
        else:
            self.send_text("not found", status=404, extra_headers=cors)

    def do_DELETE(self) -> None:
        if not self._check_security():
            return

        store = self.ingest_server.store
        cors = self.get_cors_headers()
        path = urlparse(self.path).path

        if path == "/clear":
            store.clear()
            self.send_json({"ok": True}, extra_headers=cors)
        else:
            self.send_text("method not allowed", status=405, extra_headers=cors)

    def do_POST(self) -> None:
        if not self._check_security():
            return

        store = self.ingest_server.store
        cors = self.get_cors_headers()
        path = urlparse(self.path).path

        if path not in ("/ingest", "/snapshot", "/burp/task", "/burp/issues"):
            self.send_text("not found", status=404, extra_headers=cors)
            return

        content_length_str = self.headers.get("Content-Length")
        if not content_length_str:
            self.send_text("bad request", status=400, extra_headers=cors)
            return

        try:
            length = int(content_length_str)
            if length < 0:
                raise ValueError("negative content-length")
            if length > MAX_BODY_BYTES:
                raise ValueError("payload too large")

            body = self.rfile.read(length).decode("utf-8")
            parsed = json.loads(body)

        except json.JSONDecodeError:
            self.send_json(
                {"ok": False, "error": "invalid JSON"},
                status=400,
                extra_headers=cors,
            )
            return

        except ValueError as exc:
            logger.warning(
                "burp bridge bad request",
                extra={"err": str(exc)},
            )
            self.send_text(
                "bad request",
                status=400,
                extra_headers=cors,
            )
            return

        except Exception as exc:
            logger.warning(
                "burp bridge read error",
                extra={"err": str(exc)},
            )
            self.send_text(
                "bad request",
                status=400,
                extra_headers=cors,
            )
            return

        if path == "/snapshot":
            result = store.ingest_snapshot(parsed)
        elif path == "/burp/task":
            result = store.ingest_burp_task(parsed)
        elif path == "/burp/issues":
            result = store.ingest_burp_issue(parsed)
        else:
            result = store.ingest(parsed)

        is_ok = result.get("ok") if isinstance(result, dict) else getattr(result, "ok", False)
        if not is_ok:
            reason = (
                (result.get("reason") or result.get("error", "unknown error"))
                if isinstance(result, dict)
                else getattr(result, "reason", getattr(result, "error", "unknown error"))
            )
            self.send_json({"ok": False, "error": reason}, status=400, extra_headers=cors)
            return

        on_event = self.ingest_server.on_event
        if on_event is not None:
            try:
                on_event(event_text(path, parsed))
            except Exception:
                logger.warning("browser ingest callback failed", exc_info=True)

        self.send_json({"ok": True}, status=202, extra_headers=cors)


def start_ingest_server(opts: IngestServerOptions) -> IngestServerHandle:
    token = opts.token or secrets.token_hex(16)

    server = IngestHTTPServer((opts.host, opts.port), Handler, opts, token)

    bound_port = server.server_port
    url = f"http://{opts.host}:{bound_port}"

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    logger.info("burp bridge server listening", extra={"url": url})

    return IngestServerHandle(
        port=bound_port,
        host=opts.host,
        url=url,
        token=token,
        server=server,
        thread=thread,
    )


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def scrub_control(s: str, max_len: int = 512) -> str:
    cleaned = _CONTROL_RE.sub("", s)
    if len(cleaned) > max_len:
        return cleaned[:max_len] + "…"
    return cleaned


def event_text(path: str, parsed: Any) -> str:
    if not isinstance(parsed, dict):
        return "Burp bridge: received event"

    method = scrub_control(parsed.get("method", "")) if isinstance(parsed.get("method"), str) else ""

    target = ""
    if isinstance(parsed.get("url"), str):
        target = scrub_control(parsed["url"])
    elif isinstance(parsed.get("target"), str):
        target = scrub_control(parsed["target"])

    if path == "/burp/task":
        action = (
            scrub_control(parsed.get("action", "task"))
            if isinstance(parsed.get("action"), str)
            else "task"
        )

        if target:
            if method:
                return f"Burp bridge: queued {action} for {method} {target}"
            return f"Burp bridge: queued {action} for {target}"

        return f"Burp bridge: queued {action}"

    if path == "/burp/issues":
        return "Burp bridge: received issue for import"

    if path == "/snapshot":
        return "Burp bridge: received session snapshot"

    if target:
        if method:
            return f"Burp bridge: captured request {method} {target}"
        return f"Burp bridge: captured request {target}"

    return "Burp bridge: captured request"


EXTENSION_ORIGIN_RE = re.compile(
    r"^chrome-extension://[a-p]{32}$"
)


def allowed_origin(origin: str) -> bool:
    return bool(EXTENSION_ORIGIN_RE.match(origin))


def authorized(header_token: str | None, token: str) -> bool:
    if not header_token:
        return False
    return constant_time_equal(header_token, token)


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(
        a.encode(),
        b.encode(),
    )


def valid_loopback_host(raw: str | None) -> bool:
    if not raw:
        return False

    host = raw

    if host.startswith("["):
        host = host.strip("[]")
        if "]:" in raw:
            host = raw.split("]:", 1)[0].strip("[]")
    else:
        host = host.split(":", 1)[0]

    host = host.lower()

    return host in (
        "127.0.0.1",
        "localhost",
        "::1",
    )
