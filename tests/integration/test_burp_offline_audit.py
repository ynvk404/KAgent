"""Burp bridge and capture runtime checks without sockets, Burp or providers."""
import asyncio
import base64
from contextlib import asynccontextmanager
from email.message import Message
from io import BytesIO
import json
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest

from src.browser import mcp_server, server
from src.browser.store import CaptureStore
from src.findings.store import Store as FindingsStore
from src.config.config import MCPServerConfig
from src.tools.mcp import integration as mcp_client
from src.tools.workflow.finding import ConfirmFindingTool
from tests.helpers.agent_fakes import FakeSignal
from tests.integration.test_burp_selection import burp_ingest, runtime  # noqa: F401
from tests.integration.test_kagent_burp import extender, RAW_REQUEST, RAW_RESPONSE, _message  # noqa: F401


def dispatch(store, verb, path, payload=None, *, token: str | None = "fixture-token", host="127.0.0.1:8888",
             events=None, extra_headers=None):
    """Execute the real HTTP handler using byte streams instead of a socket."""
    handler = cast(Any, object.__new__(server.Handler))
    handler.server = SimpleNamespace(store=store, token="fixture-token", on_event=events)
    handler.path = path
    handler.headers = Message()
    handler.headers["Host"] = host
    if token is not None:
        handler.headers["X-KAgent-Token"] = token
    body = json.dumps(payload).encode() if payload is not None else b""
    handler.headers["Content-Length"] = str(len(body))
    for name, value in (extra_headers or {}).items():
        handler.headers[name] = value
    handler.rfile, handler.wfile = BytesIO(body), BytesIO()
    status, headers = [], {}
    handler.send_response = status.append
    handler.send_header = lambda name, value: headers.update({name: value})
    handler.end_headers = lambda: None
    getattr(handler, "do_" + verb)()
    return status[0], headers, handler.wfile.getvalue()


def test_bridge_start_and_close_without_binding(monkeypatch):
    transport = Mock(server_port=43210)
    factory, thread = Mock(return_value=transport), Mock()
    thread_factory = Mock(return_value=thread)
    monkeypatch.setattr(server, "IngestHTTPServer", factory)
    monkeypatch.setattr(server.threading, "Thread", thread_factory)
    store = CaptureStore()
    handle = server.start_ingest_server(server.IngestServerOptions(store, 0))
    args = factory.call_args.args
    assert args[:2] == (("127.0.0.1", 0), server.Handler)
    assert args[2].store is store and len(args[3]) == 32
    assert handle.url == "http://127.0.0.1:43210" and handle.token == args[3]
    thread_factory.assert_called_once_with(target=transport.serve_forever, daemon=True)
    thread.start.assert_called_once()
    handle.close()
    transport.shutdown.assert_called_once()
    transport.server_close.assert_called_once()
    thread.join.assert_called_once_with(timeout=2)


@pytest.mark.parametrize("verb,path", [("GET", "/status"), ("GET", "/requests"),
                                      ("POST", "/ingest"), ("DELETE", "/clear")])
@pytest.mark.parametrize("token,host,status", [(None, "127.0.0.1:8888", 401),
    ("wrong", "localhost:8888", 401), ("fixture-token", "evil.test", 403)])
def test_bridge_security_precedes_reads_and_mutations(verb, path, token, host, status):
    store = CaptureStore()
    before = store.status()
    assert dispatch(store, verb, path + "?token=fixture-token", {"url": "http://fixture.test"},
                    token=token, host=host)[0] == status
    assert store.status() == before


def test_extension_to_handler_preserves_response_and_redacts_request_exports(extender):
    store, events = CaptureStore(), []

    def post(path, payload):
        assert dispatch(store, "POST", path, payload, events=events.append)[0] == 202

    extender._post_json = post
    extender._send_requests([_message()])
    row = store.list_requests()[0]
    assert (row.method, row.status, row.source) == ("POST", 200, "burp")
    assert row.raw_request_b64 is not None and row.response_headers is not None
    assert base64.b64decode(row.raw_request_b64) == RAW_REQUEST
    assert row.request_body == RAW_REQUEST.split(b"\r\n\r\n", 1)[1].decode()
    assert row.response_body == RAW_RESPONSE.split(b"\r\n\r\n", 1)[1].decode()
    assert row.url.endswith("/api?token=private-query")
    assert {h.name: h.value for h in row.response_headers}["Set-Cookie"] == "sid=private-response-cookie"
    endpoint = store.list_endpoints()[0]
    assert endpoint.query_params == ["token"] and endpoint.body_params == ["password", "q"]
    status, _, exported = dispatch(store, "GET", "/requests")
    assert status == 200
    exported_row = json.loads(exported)[0]
    assert exported_row['response_body'] == row.response_body
    assert 'private-' not in json.dumps({key: value for key, value in exported_row.items() if key != 'response_body'})
    assert "raw_request_b64" not in exported.decode() and "private-" not in "".join(events)
    original_ref = row.baseline_request_ref
    assert original_ref is not None
    extender._send_requests([_message()])
    assert len(store.list_requests()) == 1 and store.list_requests()[0].baseline_request_ref == original_ref
    assert dispatch(store, "DELETE", "/clear")[0] == 200
    assert store.resolve_baseline(original_ref) is None
    extender._send_requests([_message()])
    assert store.list_requests()[0].baseline_request_ref != original_ref


@pytest.mark.parametrize("origin,allowed", [("chrome-extension://" + "a" * 32, True),
                                         ("https://evil.test", False), ("null", False)])
def test_bridge_cors_in_memory(origin, allowed):
    status, headers, _ = dispatch(CaptureStore(), "OPTIONS", "/ingest", token=None,
                                 extra_headers={"Origin": origin})
    assert status == 204
    assert (headers.get("Access-Control-Allow-Origin") == origin) is allowed
    assert "Access-Control-Allow-Credentials" not in headers


def test_bridge_issue_export_uses_existing_redacted_view():
    store = CaptureStore()
    raw = base64.b64encode(RAW_REQUEST).decode()
    result = store.ingest_burp_issue({"title": "Fixture issue", "url": "http://fixture.test/?token=private-query",
        "detail": "Authorization: Bearer private-auth", "rawRequestB64": raw,
        "rawResponseB64": base64.b64encode(RAW_RESPONSE).decode()})
    assert result["ok"]
    status, _, exported = dispatch(store, "GET", "/burp/issues")
    assert status == 200
    assert "private-" not in exported.decode() and raw not in exported.decode()
    assert "raw_request_b64" not in exported.decode() and "raw_response_b64" not in exported.decode()
    issue = json.loads(exported)[0]
    assert issue["title"] == "Fixture issue" and issue["severity"] == "Information"
    assert issue["confidence"] == "Tentative" and "Authorization" in issue["detail"]
    assert issue["url"].startswith("http://fixture.test/")
    assert store.list_burp_issues()[0].raw_request_b64 == raw


@pytest.mark.parametrize("failure", [None, "timeout", "cancel"])
async def test_capture_mcp_handshake_and_discovery_cleanup(monkeypatch, failure):
    owners, closed = [], []

    @asynccontextmanager
    async def transport(params, **kwargs):
        assert params.args == ["-m", "src.browser.mcp_server"]
        owners.append(asyncio.current_task())
        try:
            yield object(), object()
        finally:
            assert asyncio.current_task() is owners[0]
            closed.append("transport")

    class Session:
        def __init__(self, *args):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            assert asyncio.current_task() is owners[0]
            closed.append("session")

        async def initialize(self):
            if failure == "cancel":
                raise asyncio.CancelledError
            if failure == "timeout":
                await asyncio.Future()

        async def list_tools(self):
            return SimpleNamespace(tools=[SimpleNamespace(name="browser_capture_get", description="Fixture capture",
                inputSchema={"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]})])

    monkeypatch.setattr(mcp_client, "stdio_client", transport)
    monkeypatch.setattr(mcp_client, "ClientSession", Session)
    monkeypatch.setattr(mcp_client, "HANDSHAKE_TIMEOUT_S", 0.01)
    config = MCPServerConfig("capture_fixture", "fixture-python", ["-m", "src.browser.mcp_server"])
    if failure:
        with pytest.raises(TimeoutError if failure == "timeout" else asyncio.CancelledError):
            await mcp_client.discover_mcp_tools(config)
    else:
        discovered = await mcp_client.discover_mcp_tools(config)
        tool = discovered["tools"][0]
        assert tool.name() == "mcp_capture_fixture_browser_capture_get"
        assert tool.schema()["required"] == ["id"] and tool.requires_permission()
        assert tool.permission_hints({"id": "fixture"})["noSessionCache"]
        await discovered["session"].close()
        await discovered["session"].close()
    assert closed == ["session", "transport"]


@pytest.mark.parametrize("stop", ["timeout", "event"])
async def test_capture_mcp_rpc_interruption_drains_call(monkeypatch, stop):
    from contextlib import AsyncExitStack
    started, drained, cancellation = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def call(*args, **kwargs):
        started.set()
        try:
            await asyncio.Future()
        finally:
            drained.set()

    monkeypatch.setattr(mcp_client, "MCP_CALL_TIMEOUT_S", 0.05)
    session = mcp_client.MCPSession("capture_fixture", cast(Any, SimpleNamespace(call_tool=call)), AsyncExitStack())
    task = asyncio.create_task(session.call_tool("browser_capture_get", {"id": "fixture"}, cancellation))
    await asyncio.wait_for(started.wait(), 2)
    if stop == "event":
        cancellation.set()
    with pytest.raises(TimeoutError if stop == "timeout" else asyncio.CancelledError):
        await task
    assert drained.is_set()
    await session.close()
    with pytest.raises(RuntimeError, match="closed"):
        await session.call_tool("browser_capture_get", {"id": "fixture"})


@pytest.mark.parametrize("stop", ["normal", "cancel", "error"])
async def test_standalone_capture_mcp_real_handlers_and_cleanup(monkeypatch, stop):
    handle = SimpleNamespace(url="http://127.0.0.1:9999", token="fixture-token", close=Mock())
    captured = {}
    monkeypatch.setattr("src.browser.store._now_ms", lambda: 1700000000123)

    def start(opts):
        captured["store"] = opts.store
        opts.store.ingest({"kind": "burp", "id": "fixture",
            "url": "http://fixture-user:private-url@fixture.test/api?token=private-query&echo=private-cookie",
            "method": "POST", "status": 201, "requestHeaders": {"Cookie": "sid=private-cookie"},
            "requestBody": '{"q":"sample","password":"private-password"}',
            "respBody": '{"marker":"fixture response"}'})
        return handle

    class ProtocolHarness:
        def __init__(self, name):
            assert name == mcp_server.SERVER_NAME
            self.list: Any = None
            self.call: Any = None

        def list_tools(self):
            def register(fn):
                self.list = fn
                return fn
            return register

        def call_tool(self):
            def register(fn):
                self.call = fn
                return fn
            return register

        def get_capabilities(self, **kwargs):
            return mcp_server.types.ServerCapabilities()

        async def run(self, *args):
            names = [tool.name for tool in await self.list()]
            assert names == ["browser_capture_status", "browser_capture_endpoints", "browser_capture_requests",
                             "browser_capture_get", "browser_capture_snapshot", "browser_capture_clear"]
            status = await self.call("browser_capture_status", {})
            assert json.loads(status.content[0].text)["requests"] == 1
            assert json.loads(status.content[0].text)["lastActivityAt"] == "2023-11-14T22:13:20.123000Z"
            endpoints = json.loads((await self.call("browser_capture_endpoints", {})).content[0].text)
            assert endpoints[0]["method"] == "POST" and endpoints[0]["body_params"] == ["password", "q"]
            assert "private-" not in json.dumps(endpoints) and "@" not in endpoints[0]["url"]
            listed = json.loads((await self.call("browser_capture_requests", {})).content[0].text)
            assert listed[0]["receivedAt"] == "2023-11-14T22:13:20.123000Z"
            assert "private-" not in json.dumps(listed) and "@" not in listed[0]["url"]
            result = await self.call("browser_capture_get", {"id": "burp:fixture", "body_max_chars": 4})
            detail = json.loads(result.content[0].text)
            assert (detail["method"], detail["status"], detail["source"]) == ("POST", 201, "burp")
            assert detail["receivedAt"] == "2023-11-14T22:13:20.123000Z"
            assert "private-" not in result.content[0].text and "raw_request_b64" not in detail
            assert detail["responseBody"] == detail["response_body"] == '{"ma'
            assert detail["response_body_excerpt_truncated"] is True
            assert (await self.call("browser_capture_get", {"id": "missing"})).isError
            assert (await self.call("browser_capture_clear", {"unexpected": True})).isError
            assert len(captured["store"].requests) == 1
            assert not (await self.call("browser_capture_clear", {})).isError
            assert not captured["store"].requests
            if stop == "cancel":
                raise asyncio.CancelledError
            if stop == "error":
                raise RuntimeError("fixture protocol failure")

    @asynccontextmanager
    async def stdio():
        yield object(), object()

    monkeypatch.setattr(mcp_server, "start_ingest_server", start)
    monkeypatch.setattr(mcp_server, "Server", ProtocolHarness)
    monkeypatch.setattr(mcp_server, "stdio_server", stdio)
    monkeypatch.setattr(mcp_server, "log", Mock())
    monkeypatch.setattr(mcp_server.sys, "argv", ["capture-mcp"])
    if stop == "normal":
        assert await mcp_server.main() == 0
    else:
        with pytest.raises(asyncio.CancelledError if stop == "cancel" else RuntimeError):
            await mcp_server.main()
    handle.close.assert_called_once()


@pytest.mark.parametrize("confirmed", [False, True])
async def test_burp_evidence_and_finding_ledger_with_native_replay(runtime, tmp_path, monkeypatch, confirmed):
    row = burp_ingest(runtime)
    runtime.agent.select_burp_captures()
    original_tool, original_chat = runtime.client.tool, runtime.client.chat

    def tool(name, args):
        if confirmed and name == "file_write":
            args["content"] = args["content"].replace(
                "SQL injection is not confirmed by this probe.", "Synthetic ledger confirmation fixture.")
        if confirmed and name == "workflow" and args.get("action") == "record_result":
            args["outcome"] = "confirmed"
        return original_tool(name, args)

    async def chat(request, signal=None):
        if confirmed and runtime.client.stage == 8:
            last = next(m for m in reversed(request.messages) if m.role == "tool")
            assert json.loads(last.content)["result"]["outcome"] == "confirmed"
            return runtime.client.done("Synthetic ledger fixture completed; finding persistence remains required.")
        return await original_chat(request, signal)

    monkeypatch.setattr(runtime.client, "tool", tool)
    monkeypatch.setattr(runtime.client, "chat", chat)
    await runtime.agent.run("Test the selected request for SQL injection", FakeSignal(), lambda _: None)
    candidate = next(iter(runtime.workflow.candidates.values()))
    result = runtime.workflow.latest_result(candidate.id)
    assert result is not None and result.evidence_manifest
    assert candidate.baseline_request_ref == row["baseline_request_ref"] and candidate.source_ref == row["id"]
    assert result.attempt_id == runtime.client.attempt and result.assessment_source == "agent"
    assert len(runtime.sent) == 1
    assert "captured-cookie-fixture" not in json.dumps(result.to_dict())
    runtime.registry.register(ConfirmFindingTool(FindingsStore(project_directory=tmp_path), workflow=runtime.workflow))
    args = {
        "candidate_id": candidate.id, "title": "Synthetic Burp ledger fixture", "severity": "info",
        "url": candidate.target + "/search", "method": "POST", "parameter": "q",
        "observed_impact": "Mocked fixture response observed.",
        "potential_impact": "No real target or vulnerability was evaluated.",
    }
    if confirmed:
        output = await runtime.registry.execute("confirm_finding", args, None, runtime.prompter)
    else:
        with pytest.raises(Exception, match="latest ValidationResult must have outcome=confirmed"):
            await runtime.registry.execute("confirm_finding", args, None, runtime.prompter)
        output = "Rejected negative result as expected"
    assert runtime.workflow.finding_is_persisted(candidate.id) is confirmed, output
    reports = list((tmp_path / "artifacts/findings").glob("*.md"))
    assert len(reports) == int(confirmed)
    if confirmed:
        assert "captured-cookie-fixture" not in reports[0].read_text()
        assert not runtime.workflow_tool.validation_completion_error(candidate.id, runtime.policy)


async def test_burp_committed_result_checkpoint_survives_cancel_before_receipt(runtime, monkeypatch):
    row = burp_ingest(runtime)
    runtime.agent.select_burp_captures()
    reached = asyncio.Event()
    original = runtime.workflow_tool.run

    async def run(args, signal, prompter):
        output = await original(args, signal, prompter)
        if args.get("action") == "record_result":
            assert json.loads(output)["ok"]
            reached.set()
            await asyncio.Future()
        return output

    monkeypatch.setattr(runtime.workflow_tool, "run", run)
    task = asyncio.create_task(runtime.agent.run("Test the selected request for SQL injection", FakeSignal(), lambda _: None))
    await asyncio.wait_for(reached.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    runtime.agent.resume_saved()
    candidate = next(iter(runtime.workflow.candidates.values()))
    assert candidate.baseline_request_ref == row["baseline_request_ref"]
    result = runtime.workflow.latest_result(candidate.id)
    assert result is not None and result.outcome == "not-confirmed" and result.coverage_synced
    assert len(runtime.workflow.validation_results) == len(runtime.sent) == 1
    assert not runtime.agent.pending_capture_selection and not runtime.agent.running
    assert not runtime.policy.active and not runtime.workflow.mutation_lock.locked()
    assert "captured-cookie-fixture" not in runtime.agent.store.path.read_text()


async def test_burp_validator_activation_is_admitted_and_old_scope_is_rejected(runtime):
    from src.agent.agent import _to_agent_event
    from src.agent.scope import runtime_scope
    from src.ui.core.state import AgentEventAction, SetBusy
    from tests.ui.test_app import make_app

    # Exercise real load_skill events from the Burp -> native replay workflow,
    # including a same-origin Target revision before selecting the capture.
    burp_ingest(runtime)
    runtime.target.set_base_url(runtime.target.base_url() + "/")
    runtime.agent.select_burp_captures()
    app = make_app()
    app.agent = runtime.agent
    app.dispatch(SetBusy(True))
    events = []

    def emit(event):
        events.append(event)
        app.dispatch(AgentEventAction(_to_agent_event(event)))

    await runtime.agent.run("Test the selected request for SQL injection", FakeSignal(), emit)
    assert app.state.presentation_scope == runtime_scope(runtime.agent)
    assert "sql-injection" in app.state.activated_skills
    assert sum(name == "sql-injection" for _, name in app.state.skill_receipts) == 1
    activation = next(event for event in events if event["type"] == "skill-active")
    runtime.agent.apply_target_base_url("http://127.0.0.1:3001")
    before = app.state
    app.dispatch(AgentEventAction(_to_agent_event(activation)))
    # A completed turn retains its historical UI. Re-delivering the old event
    # must not reactivate skills or publish progress for the new target.
    assert app.state == before
    assert sum(name == "sql-injection" for _, name in app.state.skill_receipts) == 1
