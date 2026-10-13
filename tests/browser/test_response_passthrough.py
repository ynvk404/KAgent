"""Operator-selected raw response views; synthetic data and mocked IO only."""
from contextlib import asynccontextmanager
from copy import deepcopy
from email.message import Message as HeaderMessage
import json
from types import SimpleNamespace
from typing import Any, cast

import pytest

import src.browser.mcp_server as mcp_module
from src.browser.redacted_view import request_excerpt, request_view
from src.browser.server import Handler
from src.browser.store import BODY_STRING_CAP, CaptureStore
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import AlwaysAllow
from src.tools.common.browser_capture import BrowserCaptureGetTool
from src.tools.common.registry import Registry
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.helpers.burp_selection import make_runtime, ORIGIN


BODIES = [
    '<h1>Results</h1><input type="password" value="pw7">',
    '{"token":"tok7", "cookie":"sid=cook7", "password":"pw7"}',
    'Results\r\npassword=pw7\r\nCookie: sid=cook7\r\nAuthorization: Bearer tok7',
    '<input name="password" value="pw7',
    '{"token":"tok7"',
    'Tiếng Việt 😀 &amp; %70w7 [REDACTED] ...<truncated 99 chars>',
    '', None,
]


def ingest(store, body, mime=None):
    return store.ingest({
        'kind': 'burp', 'id': 'fixture', 'url': ORIGIN + '/search?token=query7',
        'requestHeaders': [{'name': 'Authorization', 'value': 'Bearer tok7'},
                           {'name': 'Cookie', 'value': 'sid=cook7'},
                           {'name': 'Content-Type', 'value': 'application/json'}],
        'requestBody': '{"password":"pw7","q":"{INJECTION_POINT}"}',
        'responseHeaders': [{'name': 'Set-Cookie', 'value': 'sid=cook7'}] +
                           ([{'name': 'Content-Type', 'value': mime}] if mime else []),
        'respBody': body,
    })


@pytest.mark.parametrize('body', BODIES)
@pytest.mark.parametrize('mime', [None, 'text/html', 'application/json', 'text/plain'])
def test_view_keeps_exact_captured_response_independent_of_mime(body, mime):
    store = CaptureStore()
    receipt = ingest(store, body, mime)
    source = store.get_request(receipt['id'])
    original = deepcopy(source)
    row = request_view(source)
    assert row['response_body'] == body
    assert source == original
    protected = {key: value for key, value in row.items() if key != 'response_body'}
    for secret in ('pw7', 'tok7', 'cook7', 'query7'):
        assert secret not in json.dumps(protected)
    assert '{INJECTION_POINT}' in row['request_body']


@pytest.mark.parametrize('key', ['response_body', 'responseBody'])
def test_dictionary_alias_is_preserved_exactly(key):
    body = '<input type="password" value="pw7">'
    row = request_view({key: body})
    assert row[key] == body


async def mcp_get(monkeypatch, store, receipt, cap):
    results = []

    class Server:
        def __init__(self, name):
            self.handler: Any = None

        def list_tools(self):
            return lambda function: function

        def call_tool(self):
            def register(function):
                self.handler = function
                return function
            return register

        def get_capabilities(self, **kwargs):
            return {}

        async def run(self, *args):
            results.append(await self.handler('browser_capture_get', {'id': receipt['id'], 'body_max_chars': cap}))

    @asynccontextmanager
    async def stdio():
        yield None, None

    monkeypatch.setattr(mcp_module, 'CaptureStore', lambda **kwargs: store)
    monkeypatch.setattr(mcp_module, 'Server', Server)
    monkeypatch.setattr(mcp_module, 'stdio_server', stdio)
    monkeypatch.setattr(mcp_module, 'start_ingest_server', lambda *args: SimpleNamespace(
        url='http://127.0.0.1:9999', token='synthetic-bridge-token', close=lambda: None))
    # Mock lifecycle logging too: the pre-existing logger keyword signature
    # issue is outside response passthrough, not a reason to alter runtime.
    monkeypatch.setattr(mcp_module, 'log', SimpleNamespace(init=lambda *a: None, info=lambda *a, **kw: None))
    monkeypatch.setattr(mcp_module.sys, 'argv', ['offline-mcp'])
    assert await mcp_module.main() == 0
    return json.loads(results[0].content[0].text)


@pytest.mark.asyncio
@pytest.mark.parametrize('cap,limit', [(0, 0), (-1, 0), (7, 7), (None, 4000), (65536, 65536),
                                     (999999, 65536), ('7', 4000), (True, 4000), (2.5, 4000),
                                     (float('nan'), 4000), (float('inf'), 4000)])
async def test_registered_native_and_mcp_share_hard_cap_and_exact_aliases(monkeypatch, cap, limit):
    store = CaptureStore()
    body = '<input type="password" value="pw7">' + '😀' * 8000
    receipt = ingest(store, body)
    registry = Registry()
    registry.register(BrowserCaptureGetTool(store))
    native = json.loads(await registry.execute('browser_capture_get', {'id': receipt['id'], 'body_max_chars': cap}, None, AlwaysAllow()))
    mcp = await mcp_get(monkeypatch, store, receipt, cap)
    expected = body[:limit]
    assert native['response_body'] == native['responseBody'] == mcp['response_body'] == mcp['responseBody'] == expected
    assert len(expected) <= limit
    assert native['response_body_excerpt_truncated'] == mcp['response_body_excerpt_truncated'] == (len(body) > limit)


@pytest.mark.asyncio
@pytest.mark.parametrize('body', BODIES)
async def test_native_mcp_preserve_short_response_bodies_including_secrets(monkeypatch, body):
    store = CaptureStore()
    receipt = ingest(store, body)
    native = json.loads(await BrowserCaptureGetTool(store).run({'id': receipt['id']}))
    mcp = await mcp_get(monkeypatch, store, receipt, None)
    assert native['response_body'] == native['responseBody'] == mcp['response_body'] == mcp['responseBody'] == body
    assert not native['response_body_excerpt_truncated'] and not mcp['response_body_excerpt_truncated']


@pytest.mark.parametrize('size', [65535, 65536, 65537])
def test_store_boundary_and_existing_truncation_are_unchanged(size):
    store = CaptureStore()
    receipt = ingest(store, 'x' * size)
    source = store.get_request(receipt['id'])
    assert source is not None and source.response_body is not None
    expected = 'x' * size if size <= BODY_STRING_CAP else 'x' * BODY_STRING_CAP + '...<truncated 1 chars>'
    assert request_view(source)['response_body'] == source.response_body == expected
    result = request_excerpt(source, 999999)
    assert result['response_body'] == result['responseBody'] == expected[:BODY_STRING_CAP]
    assert result['response_body_excerpt_truncated'] == (size > BODY_STRING_CAP)
    assert source.response_complete is (False if size > BODY_STRING_CAP else None)


@pytest.mark.parametrize('body', BODIES)
def test_bridge_requests_route_returns_exact_store_body_and_retains_authentication(body):
    store = CaptureStore()
    ingest(store, body)
    handler = cast(Any, object.__new__(Handler))
    handler.server = SimpleNamespace(store=store, token='synthetic-bridge-token')
    handler.headers = HeaderMessage()
    handler.headers['Host'] = '127.0.0.1:9999'
    handler.path = '/requests'
    responses = []
    handler.send_json = lambda payload, **kwargs: responses.append((payload, kwargs))
    handler.do_GET()
    assert responses[-1][1]['status'] == 401
    assert 'response_body' not in str(responses[-1][0])
    handler.headers['X-KAgent-Token'] = 'synthetic-bridge-token'
    handler.do_GET()
    assert responses[-1][0][0]['response_body'] == body


def test_literal_markers_do_not_control_excerpt_metadata():
    body = 'Results [REDACTED] ...<truncated 999 chars>'
    row = request_excerpt({'response_body': body, 'response_body_excerpt_truncated': True}, len(body))
    assert row['responseBody'] == body and row['response_body_excerpt_truncated'] is False
    assert request_excerpt({'responseBody': body}, 0)['response_body_excerpt_truncated'] is True


@pytest.mark.asyncio
async def test_response_html_secret_can_reach_next_agent_model_request_without_core_changes(tmp_path, monkeypatch):
    monkeypatch.setattr('src.agent.tool_results.project_root', lambda: tmp_path)
    runtime = make_runtime(tmp_path)
    body = '<h1>Results</h1><input type="password" value="pw7">'
    receipt = ingest(runtime.capture, body)
    client = FakeClient([
        ChatResponse(Message('assistant', '', tool_calls=[ToolCall('capture', FunctionCall(
            'browser_capture_get', json.dumps({'id': receipt['id']})))]), 'tool_calls'),
        ChatResponse(Message('assistant', 'Captured response read.'), 'stop'),
    ])
    runtime.agent.client = client
    await runtime.agent.run('Read the captured response', FakeSignal(), lambda _: None)
    assert len(client.requests) == 2
    result = next(message for message in client.requests[1].messages if message.name == 'browser_capture_get')
    assert json.loads(result.content)['responseBody'] == body
    assert 'pw7' in result.content
