import json
import gzip
from unittest.mock import AsyncMock

import httpx
import pytest

from src.browser.store import CaptureStore
from src.engagement.state import EngagementState
from src.permission.permission import Decision
from src.target.target import Target
from src.tools.http.http_tool import HTTPTool
from src.workflow.state import Candidate, WorkflowState


class Allow:
    def __init__(self):
        self.requests = []

    async def ask(self, request, signal=None):
        self.requests.append(request)
        return Decision.ALLOW_ONCE


def make_tool(url="http://target.test"):
    target = Target(url)
    engagement = EngagementState()
    engagement.initialize_target(url)
    workflow = WorkflowState()
    capture = CaptureStore()
    return HTTPTool(target, engagement, workflow, capture), capture, workflow


def capture_json(capture):
    ingested = capture.ingest({
        "id": "baseline-1", "method": "POST", "url": "http://target.test/api",
        "authContextRef": "user",
        "requestHeaders": [{"name": "User-Agent", "value": "Captured/1"},
                           {"name": "Content-Type", "value": "application/json"},
                           {"name": "Cookie", "value": "sid=private"},
                           {"name": "X-CSRF-Token", "value": "csrf-private"}],
        "requestBody": '{"q":"old","csrf":"csrf-private","items":[1,2]}',
    })
    return ingested["baseline_request_ref"]


def baseline_ref(capture, external_id):
    row = capture.get_request(external_id)
    assert row is not None and row.baseline_request_ref
    return row.baseline_request_ref


def add_candidate(workflow, ref, identity="user"):
    candidate, _ = workflow.add_candidate(Candidate(
        candidate_class="sql-injection", target="http://target.test", method="POST",
        endpoint="/api", parameter="q", location="body", content_type="application/json",
        baseline_request_ref=ref, auth_context_ref=identity,
    ))
    return candidate


def bind_cookie(tool, identity, value):
    tool.context_store.sync_target(tool.target.revision, tool.engagement.revision)
    request = httpx.Request("GET", "http://target.test/api")
    response = httpx.Response(200, headers={"Set-Cookie": f"sid={value}; Path=/"}, request=request)
    tool.context_store.extract(request, response, identity)


@pytest.mark.asyncio
async def test_captured_replay_approves_and_sends_exact_mutated_request(monkeypatch):
    tool, capture, workflow = make_tool()
    candidate = add_candidate(workflow, capture_json(capture))
    bind_cookie(tool, "user", "private")
    seen = []
    original = httpx.AsyncClient
    async def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok", request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    prompter = Allow()
    args = {"phase": "validation", "candidate_id": candidate.id, "mutation_value": "new"}
    prepared, expected = tool.prepare(args)
    output = await tool.run(args, None, prompter)
    assert len(seen) == 1
    assert seen[0].method == expected.method == prepared.method
    assert str(seen[0].url) == str(expected.url) == prepared.url
    assert seen[0].content == expected.content == prepared.body
    assert tuple(seen[0].headers.raw) == prepared.headers
    assert json.loads(seen[0].content) == {"q": "new", "csrf": "csrf-private", "items": [1, 2]}
    assert seen[0].headers["cookie"] == "sid=private"
    assert seen[0].headers["x-csrf-token"] == "csrf-private"
    assert "csrf-private" not in str(output)
    assert prompter.requests and "csrf-private" not in prompter.requests[0].detail
    assert "mutation: body q" in output


@pytest.mark.asyncio
async def test_capture_mutation_after_approval_does_not_change_sent_request(monkeypatch):
    tool, capture, workflow = make_tool()
    candidate = add_candidate(workflow, capture_json(capture))
    bind_cookie(tool, "user", "private")
    original = httpx.AsyncClient
    seen = []
    async def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok", request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    class ReplaceDuringApproval(Allow):
        async def ask(self, request, signal=None):
            capture.ingest({"id": "baseline-1", "method": "POST", "url": "http://target.test/api",
                            "requestHeaders": [{"name": "Content-Type", "value": "application/json"}],
                            "requestBody": '{"q":"tampered"}'})
            return await super().ask(request, signal)
    await tool.run({"phase": "validation", "candidate_id": candidate.id, "mutation_value": "new"},
                   None, ReplaceDuringApproval())
    assert json.loads(seen[0].content)["csrf"] == "csrf-private"


def test_http_replay_rejects_same_reference_after_oversize_update():
    from src.browser.store import MAX_RAW_REQUEST_B64

    tool, capture, workflow = make_tool()
    payload = {"id": "oversize-baseline", "method": "POST", "url": "http://target.test/api",
               "rawRequestB64": "A" * (MAX_RAW_REQUEST_B64 + 1),
               "requestHeaders": [{"name": "Content-Type", "value": "text/plain"}],
               "requestBody": "old"}
    ref = capture.ingest(payload)["baseline_request_ref"]
    candidate = add_candidate(workflow, ref)
    capture.ingest({key: value for key, value in payload.items() if key != "rawRequestB64"})

    with pytest.raises(ValueError, match="size limit"):
        tool.prepare({"phase": "validation", "candidate_id": candidate.id, "mutation_value": "new",
                      "old_value": "old"})


@pytest.mark.asyncio
async def test_cookie_context_isolated_by_identity_and_origin(monkeypatch):
    tool, _, _ = make_tool()
    original = httpx.AsyncClient
    seen = []
    async def handler(request):
        seen.append((str(request.url), request.headers.get("cookie")))
        headers = {"Set-Cookie": "sid=one; Path=/private; HttpOnly"} if request.url.path == "/set" else {}
        return httpx.Response(200, headers=headers, content=b"ok", request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    for path, identity in [("/set", "user"), ("/private/a", "user"), ("/public", "user"),
                           ("/private/a", "admin"), ("/private/a", None)]:
        await tool.run({"phase": "recon", "url": path, **({"auth_context_ref": identity} if identity else {})},
                       None, Allow())
    assert [cookie for _, cookie in seen] == [None, "sid=one", None, None, None]
    tool.engagement.add_origin("http://other.test")
    await tool.run({"phase": "recon", "url": "http://other.test/private/a", "auth_context_ref": "user"}, None, Allow())
    assert seen[-1][1] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("status, expected_method", [(301, "GET"), (302, "GET"), (303, "GET"),
                                                  (307, "POST"), (308, "POST")])
async def test_redirect_semantics_and_per_hop_approval(monkeypatch, status, expected_method):
    tool, _, _ = make_tool()
    seen = []
    original = httpx.AsyncClient
    async def handler(request):
        seen.append(request)
        if request.url.path == "/start":
            return httpx.Response(status, headers={"Location": "/end"}, request=request)
        return httpx.Response(200, content=b"ok", request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    prompter = Allow()
    output = await tool.run({"phase": "validation", "url": "/start", "method": "POST", "body": "q=one",
                             "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "max_redirects": 2},
                            None, prompter)
    assert len(seen) == 2
    assert tool.dispatch_attempts == 2
    assert len(prompter.requests) == 2
    assert seen[1].method == expected_method
    assert seen[1].content == (b"q=one" if expected_method == "POST" else b"")
    assert "[hop 0]" in output and "[hop 1]" in output


@pytest.mark.asyncio
async def test_cross_origin_redirect_never_forwards_credentials(monkeypatch):
    tool, _, _ = make_tool()
    tool.engagement.add_origin("http://other.test")
    seen = []
    original = httpx.AsyncClient
    async def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "http://other.test/next"}, request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    output = await tool.run({"phase": "recon", "url": "/start", "headers": {"Authorization": "Bearer private"},
                             "max_redirects": 3}, None, Allow())
    assert len(seen) == 1
    assert "cross-origin redirect not followed" in output
    assert tool.dispatch_attempts == 1
    assert "private" not in output


def test_browser_like_profile_requires_same_origin_snapshot_and_fetch_headers():
    tool, capture, _ = make_tool()
    args = {"phase": "validation", "url": "/api", "method": "POST", "body": "{}",
            "headers": {"Content-Type": "application/json"}, "profile": "browser-like",
            "browser_context": "fetch", "browser_user_agent": "CapturedBrowser/1"}
    with pytest.raises(ValueError, match="snapshot"):
        tool.prepare(args)
    capture.ingest_snapshot({"url": "http://target.test/app", "userAgent": "CapturedBrowser/1"})
    _, request = tool.prepare(args)
    assert request.headers["user-agent"] == "CapturedBrowser/1"
    assert request.headers["accept"].startswith("application/json")
    assert request.headers["content-type"] == "application/json"
    assert not any(key.startswith("sec-fetch") for key in request.headers)
    assert "origin" not in request.headers and "referer" not in request.headers


@pytest.mark.asyncio
async def test_gzip_output_distinguishes_wire_and_decoded_body(monkeypatch):
    tool, _, _ = make_tool()
    original = httpx.AsyncClient
    encoded = gzip.compress(b"decoded body")
    async def handler(request):
        return httpx.Response(200, headers={"Content-Encoding": "gzip", "Content-Length": str(len(encoded))},
                              content=encoded, request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    output = await tool.run({"phase": "recon", "url": "/gzip"}, None, Allow())
    assert "HTTP/1.1 200" in output
    assert "decoded body bytes retained before redaction: 12" in output
    assert f"wire Content-Length: {len(encoded)}" in output
    assert "Content-Encoding: gzip" in output
    assert output.endswith("decoded body")


@pytest.mark.asyncio
async def test_redirect_loop_stops_with_bounded_hops(monkeypatch):
    tool, _, _ = make_tool()
    original = httpx.AsyncClient
    seen = []
    async def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "/loop"}, request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    output = await tool.run({"phase": "recon", "url": "/loop", "max_redirects": 5}, None, Allow())
    assert len(seen) == 1
    assert "redirect loop stopped" in output
    assert tool.dispatch_attempts == 1


@pytest.mark.asyncio
async def test_redirect_uses_updated_scoped_cookie(monkeypatch):
    tool, _, _ = make_tool()
    original = httpx.AsyncClient
    seen = []
    async def handler(request):
        seen.append(request.headers.get("cookie"))
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/end", "Set-Cookie": "sid=new; Path=/"}, request=request)
        return httpx.Response(200, content=b"ok", request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    await tool.run({"phase": "recon", "url": "/start", "auth_context_ref": "user", "max_redirects": 1},
                   None, Allow())
    assert seen == [None, "sid=new"]


@pytest.mark.asyncio
async def test_explicit_baseline_cookie_stops_on_redirect_cookie_update(monkeypatch):
    tool, capture, workflow = make_tool()
    candidate = add_candidate(workflow, capture_json(capture))
    bind_cookie(tool, "user", "private")
    original = httpx.AsyncClient
    seen = []
    async def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "/end", "Set-Cookie": "sid=new; Path=/"}, request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    output = await tool.run({"phase": "validation", "candidate_id": candidate.id,
                             "mutation_value": "new", "max_redirects": 2}, None, Allow())
    assert len(seen) == 1
    assert "recapture required" in output


def test_replay_identity_binding_and_runtime_cookie_rotation():
    tool, capture, workflow = make_tool()
    ref = capture_json(capture)
    candidate = add_candidate(workflow, ref)
    bind_cookie(tool, "user", "private")
    args = {"phase": "validation", "candidate_id": candidate.id, "mutation_value": "new"}
    with pytest.raises(ValueError, match="identity"):
        tool.prepare({**args, "auth_context_ref": "admin"})
    _, request = tool.prepare(args)
    response = httpx.Response(200, headers={"Set-Cookie": "sid=rotated; Path=/"}, request=request)
    tool.context_store.extract(request, response, "user")
    with pytest.raises(ValueError, match="runtime session cookie"):
        tool.prepare(args)
    capture.ingest({"id": "unbound", "method": "POST", "url": "http://target.test/api",
                    "requestHeaders": [{"name": "Content-Type", "value": "application/json"},
                                       {"name": "Cookie", "value": "sid=opaque"}],
                    "requestBody": '{"q":"old"}'})
    unbound = add_candidate(workflow, baseline_ref(capture, "wr:unbound"))
    with pytest.raises(ValueError, match="identity binding"):
        tool.prepare({"phase": "validation", "candidate_id": unbound.id, "mutation_value": "new"})
    capture.ingest({"id": "spoofed", "method": "POST", "url": "http://target.test/api",
                    "authContextRef": "admin",
                    "requestHeaders": [{"name": "Content-Type", "value": "application/json"},
                                       {"name": "Cookie", "value": "sid=admin"}],
                    "requestBody": '{"q":"old"}'})
    spoofed = add_candidate(workflow, baseline_ref(capture, "wr:spoofed"), "admin")
    with pytest.raises(ValueError, match="runtime session cookie"):
        tool.prepare({"phase": "validation", "candidate_id": spoofed.id, "mutation_value": "new"})


def test_same_input_user_admin_candidates_and_replay_are_isolated():
    tool, capture, workflow = make_tool()
    for identity in ("user", "admin"):
        capture.ingest({"id": identity, "method": "POST", "url": "http://target.test/api",
                        "authContextRef": identity,
                        "requestHeaders": [{"name": "Content-Type", "value": "application/json"},
                                           {"name": "Cookie", "value": f"sid={identity}"}],
                        "requestBody": '{"q":"old"}'})
    user = add_candidate(workflow, baseline_ref(capture, "wr:user"), "user")
    admin = add_candidate(workflow, baseline_ref(capture, "wr:admin"), "admin")
    bind_cookie(tool, "user", "user")
    bind_cookie(tool, "admin", "admin")
    assert user.id != admin.id
    assert add_candidate(workflow, baseline_ref(capture, "wr:user"), "user") is user
    assert workflow.from_dict(workflow.to_dict()).candidates[admin.id].auth_context_ref == "admin"
    for candidate, identity in ((user, "user"), (admin, "admin")):
        _, request = tool.prepare({"phase": "validation", "candidate_id": candidate.id, "mutation_value": "new"})
        assert request.headers["cookie"] == f"sid={identity}"


def test_captured_authorization_requires_matching_runtime_identity():
    tool, capture, workflow = make_tool()
    capture.ingest({"id": "auth", "method": "POST", "url": "http://target.test/api",
                    "authContextRef": "user",
                    "requestHeaders": [{"name": "Content-Type", "value": "application/json"},
                                       {"name": "Authorization", "value": "Bearer user"}],
                    "requestBody": '{"q":"old"}'})
    candidate = add_candidate(workflow, baseline_ref(capture, "wr:auth"))
    args = {"phase": "validation", "candidate_id": candidate.id, "mutation_value": "new"}
    with pytest.raises(ValueError, match="runtime authorization"):
        tool.prepare(args)
    runtime_request = httpx.Request("GET", "http://target.test/api",
                                    headers={"Authorization": "Bearer user"})
    tool.context_store.extract(runtime_request, httpx.Response(200, request=runtime_request), "user")
    _, replay = tool.prepare(args)
    assert replay.headers["authorization"] == "Bearer user"


def test_host_override_and_browser_user_agent_conflict():
    tool, capture, _ = make_tool()
    for host in ("outside-scope.example", "target.test:81"):
        with pytest.raises(ValueError, match="Host override"):
            tool.prepare({"phase": "recon", "url": "/a", "headers": {"Host": host}})
    _, normal = tool.prepare({"phase": "recon", "url": "/a", "headers": {"Host": "target.test:80"}})
    assert normal.headers["host"] == "target.test"
    capture.ingest_snapshot({"url": "http://target.test/app", "userAgent": "Captured/1"})
    with pytest.raises(ValueError, match="User-Agent conflicts"):
        tool.prepare({"phase": "recon", "url": "/a", "profile": "browser-like",
                      "browser_context": "fetch", "browser_user_agent": "Captured/1",
                      "headers": {"User-Agent": "Unrelated/9"}})


@pytest.mark.asyncio
async def test_malformed_location_and_explicit_cookie_redirect_stop(monkeypatch):
    tool, capture, workflow = make_tool()
    original = httpx.AsyncClient
    seen = []
    async def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "http://[broken" if request.url.path == "/bad" else "/end"}, request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    result = await tool.run({"phase": "recon", "url": "/bad", "max_redirects": 2}, None, Allow())
    assert "malformed redirect" in result and len(seen) == 1
    candidate = add_candidate(workflow, capture_json(capture))
    bind_cookie(tool, "user", "private")
    result = await tool.run({"phase": "validation", "candidate_id": candidate.id,
                             "mutation_value": "new", "max_redirects": 2}, None, Allow())
    assert "unknown path provenance" in result and len(seen) == 2


@pytest.mark.asyncio
async def test_native_proxy_credential_never_reaches_origin(monkeypatch):
    tool, _, _ = make_tool()
    original = httpx.AsyncClient
    seen = []
    async def handler(request):
        seen.append(request)
        return httpx.Response(200, request=request)
    monkeypatch.setattr("src.tools.http.http_tool.httpx.AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    await tool.run({"phase": "recon", "url": "/", "headers": {
        "Proxy-Authorization": "Basic hidden", "Connection": "X-Hop", "X-Hop": "hidden"}}, None, Allow())
    assert "proxy-authorization" not in seen[0].headers
    assert "x-hop" not in seen[0].headers
