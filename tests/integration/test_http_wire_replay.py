"""Real localhost socket checks for the approved HTTP request boundary."""
import asyncio
import base64
import gzip
import json
import threading
import httpx
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from src.browser.store import CaptureStore
from src.engagement.state import EngagementState
from src.permission.permission import Decision
from src.target.target import Target
from src.tools.http.http_tool import HTTPTool
from src.tools.discovery.content import ContentDiscoveryTool
from src.tools.common.capabilities import CapabilityInventory
from src.tools.http.request_builder import NATIVE_USER_AGENT
from src.tools.http.web import _do_fetch, _do_search
from src.version.version import VERSION
from src.workflow.state import Candidate, WorkflowState


class Approve:
    def __init__(self):
        self.requests = []

    async def ask(self, request, signal=None):
        self.requests.append(request)
        return Decision.ALLOW_ONCE


@pytest.mark.asyncio
async def test_localhost_wire_capture_and_approval_invariant(monkeypatch):
    wire = []

    class Receiver(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def respond(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            wire.append((self.command, self.path, list(self.headers.items()), body))
            if self.path.startswith("/bad-location"):
                code, headers, content = 302, {"Location": "http://[broken"}, b""
            elif self.path.startswith("/redirect-302"):
                code, headers, content = 302, {"Location": "/final"}, b""
            elif self.path.startswith("/redirect-303"):
                code, headers, content = 303, {"Location": "/final"}, b""
            elif self.path.startswith("/redirect-307"):
                code, headers, content = 307, {"Location": "/final"}, b""
            elif self.path.startswith("/gzip"):
                code, headers, content = 200, {"Content-Encoding": "gzip"}, gzip.compress(b"decoded body")
            else:
                code, headers, content = 200, {}, b"ok"
            self.send_response(code)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    target = Target(origin)
    engagement = EngagementState()
    engagement.initialize_target(origin)
    workflow = WorkflowState()
    capture = CaptureStore()
    tool = HTTPTool(target, engagement, workflow, capture)
    approved = []
    original_authorize = tool.permissions.authorize

    async def record_authorization(action, prompter, signal, revision):
        approved.append(action)
        return await original_authorize(action, prompter, signal, revision)

    monkeypatch.setattr(tool.permissions, "authorize", record_authorization)

    async def send(args):
        before = len(wire)
        before_approval = len(approved)
        action, _ = tool.prepare(args)
        result = await tool.run(args, None, Approve())
        assert len(wire) > before
        assert len(approved) - before_approval == len(wire) - before
        for expected, actual_wire in zip(approved[before_approval:], wire[before:]):
            actual_method, actual_path, actual_headers, actual_body = actual_wire
            assert actual_method == expected.method
            assert actual_path == expected.url.removeprefix(origin)
            assert actual_body == expected.body
            actual_map = {key.lower(): value for key, value in actual_headers}
            for key, value in expected.headers:
                assert actual_map[key.decode().lower()] == value.decode("latin1")
        method, path, headers, body = wire[before]
        assert method == action.method
        assert path == action.url.removeprefix(origin)
        assert body == action.body
        actual = {key.lower(): value for key, value in headers}
        for key, value in action.headers:
            assert actual[key.decode().lower()] == value.decode("latin1")
        return result

    def add_capture(name, content_type, body, identity=None, extra_headers=None, raw=False, path="/input"):
        headers = [("Host", f"127.0.0.1:{server.server_port}"), ("Content-Type", content_type),
                   *(extra_headers or [])]
        payload = {"id": name, "method": "POST", "url": origin + path, "authContextRef": identity,
                   "requestHeaders": [{"name": key, "value": value} for key, value in headers],
                   "requestBody": body.decode("utf-8", errors="replace")}
        if raw:
            head = f"POST {path} HTTP/1.1\r\n".encode() + b"\r\n".join(
                key.encode() + b": " + value.encode() for key, value in headers)
            head += b"\r\nContent-Length: " + str(len(body)).encode()
            payload["rawRequestB64"] = base64.b64encode(head + b"\r\n\r\n" + body).decode()
        ref = capture.ingest(payload)["id"]
        kind = "form" if "urlencoded" in content_type else "body"
        candidate, _ = workflow.add_candidate(Candidate(
            candidate_class="sql-injection", target=origin, method="POST", endpoint=path,
            parameter="q", location=kind, content_type=content_type,
            baseline_request_ref=ref, auth_context_ref=identity))
        return candidate

    try:
        native_args = {"phase": "recon", "url": "/native"}
        expected_native_ua = f"KAgent/{VERSION}"
        assert f"user-agent: {expected_native_ua}" in tool.summarize(native_args)["detail"]
        await send(native_args)
        assert f"user-agent: {expected_native_ua}" in approved[-1].preview()
        native_headers = {key.lower(): value for key, value in wire[-1][2]}
        assert native_headers["user-agent"] == expected_native_ua
        profile_headers = {"native": native_headers}
        discovery = ContentDiscoveryTool(target, engagement, CapabilityInventory(), lambda: "minimal")
        await discovery.run({"paths": ["content-discovery"], "mode": "native", "max_requests": 3,
                             "rate_limit": 10, "timeout_seconds": 5}, None, Approve())
        discovered = [entry for entry in wire if entry[1] == "/content-discovery"]
        assert discovered and dict(discovered[-1][2])["User-Agent"] == NATIVE_USER_AGENT
        profile_headers["discovery"] = {key.lower(): value for key, value in discovered[-1][2]}
        assert profile_headers["discovery"]["user-agent"] == native_headers["user-agent"]
        for profile, operation in (("web_fetch", _do_fetch), ("web_search", _do_search)):
            # Exercise each web transport against the local receiver, not an external provider.
            response = await operation(origin + "/" + profile)
            try:
                await response.aread()
            finally:
                await response.aclose()
            headers = {key.lower(): value for key, value in wire[-1][2]}
            assert headers["user-agent"] == expected_native_ua
            if profile == "web_fetch":
                assert headers["accept"].startswith("text/html")
            else:
                assert headers["accept"] == "*/*"
            profile_headers[profile] = headers
        captured_headers = [("User-Agent", "CapturedClient/7"), ("Accept", "application/json"),
                            ("Accept-Language", "vi"), ("Origin", origin), ("Referer", origin + "/app")]
        captured = add_capture("profile-captured", "application/json", b'{"q":"old"}',
                               extra_headers=captured_headers)
        await send({"phase": "validation", "candidate_id": captured.id, "mutation_value": "new"})
        profile_headers["captured"] = {key.lower(): value for key, value in wire[-1][2]}
        for key, value in captured_headers:
            assert profile_headers["captured"][key.lower()] == value
        browser_args = {"phase": "recon", "url": "/browser-like", "profile": "browser-like",
                        "browser_context": "fetch", "browser_user_agent": "SnapshotClient/9"}
        before = len(wire), len(approved)
        with pytest.raises(ValueError, match="snapshot"):
            await tool.run(browser_args, None, Approve())
        assert (len(wire), len(approved)) == before
        capture.ingest_snapshot({"url": origin + "/app", "userAgent": "SnapshotClient/9"})
        for context, accept_prefix in (("fetch", "application/json"), ("navigation", "text/html")):
            await send({**browser_args, "browser_context": context})
            headers = {key.lower(): value for key, value in wire[-1][2]}
            assert headers["user-agent"] == "SnapshotClient/9"
            assert headers["accept"].startswith(accept_prefix)
            profile_headers["browser-like-" + context] = headers
        before = len(wire), len(approved)
        with pytest.raises(ValueError, match="User-Agent conflicts"):
            await tool.run({**browser_args, "headers": {"User-Agent": "UnrelatedClient/3"}}, None, Approve())
        assert (len(wire), len(approved)) == before
        for profile, headers in profile_headers.items():
            assert not any(key.startswith("sec-fetch-") for key in headers)
            assert not headers["user-agent"].startswith(("python-httpx/", "python-requests/", "aiohttp/"))
            if profile != "captured":
                assert "origin" not in headers and "referer" not in headers
                assert "accept-language" not in headers
            print("wire-profile " + json.dumps({"profile": profile, "headers": {
                key: value for key, value in headers.items()
                if key in {"user-agent", "accept", "accept-language", "accept-encoding", "connection", "content-type"}
            }}, sort_keys=True))
        await send({"phase": "recon", "url": "/query?q=first&q=second"})
        json_candidate = add_capture("json", "application/json", b'{"q":"old","items":[10,20]}')
        await send({"phase": "validation", "candidate_id": json_candidate.id, "mutation_value": "new"})
        array_candidate = add_capture("array", "application/json", b'{"q":[10,20]}')
        await send({"phase": "validation", "candidate_id": array_candidate.id,
                    "mutation_value": "30", "input_path": "/q/1"})
        form_candidate = add_capture("form", "application/x-www-form-urlencoded", "user=Nguyên&q=old".encode())
        await send({"phase": "validation", "candidate_id": form_candidate.id, "mutation_value": "mới"})
        binary = (b"--lab\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nold\r\n"
                  b"--lab\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n\r\n\x00\xff\r\n--lab--\r\n")
        multi = add_capture("multi", "multipart/form-data; boundary=lab", binary, raw=True)
        await send({"phase": "validation", "candidate_id": multi.id, "mutation_value": "new"})
        for identity in ("user", "admin"):
            candidate = add_capture(identity, "application/json", b'{"q":"old"}', identity,
                                    [("Cookie", f"sid={identity}")])
            tool.context_store.sync_target(target.revision, engagement.revision)
            context_request = httpx.Request("GET", origin + "/input")
            context_response = httpx.Response(200, headers={"Set-Cookie": f"sid={identity}; Path=/"},
                                              request=context_request)
            tool.context_store.extract(context_request, context_response, identity)
            await send({"phase": "validation", "candidate_id": candidate.id, "mutation_value": "new"})
            assert dict(wire[-1][2])["Cookie"] == f"sid={identity}"
        proxy = add_capture("proxy", "application/json", b'{"q":"old"}',
                            extra_headers=[("Proxy-Authorization", "Basic hidden")])
        await send({"phase": "validation", "candidate_id": proxy.id, "mutation_value": "new"})
        assert "proxy-authorization" not in {key.lower() for key, _ in wire[-1][2]}
        with pytest.raises(ValueError, match="Host override"):
            tool.prepare({"phase": "recon", "url": "/host", "headers": {"Host": "outside.example"}})
        for status in (302, 303, 307):
            result = await send({"phase": "validation", "url": f"/redirect-{status}",
                                 "method": "POST", "body": "x", "max_redirects": 1})
            assert "[hop 1]" in result
            assert wire[-1][0] == ("POST" if status == 307 else "GET")
        explicit = add_capture("explicit-redirect", "application/json", b'{"q":"old"}', "user",
                               [("Cookie", "sid=user")], path="/redirect-302")
        before = len(wire)
        result = await send({"phase": "validation", "candidate_id": explicit.id,
                             "mutation_value": "new", "max_redirects": 1})
        assert "unknown path provenance" in result and len(wire) == before + 1
        result = await send({"phase": "recon", "url": "/bad-location", "max_redirects": 1})
        assert "malformed redirect" in result
        result = await send({"phase": "recon", "url": "/gzip"})
        assert "decoded body" in result
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
