import base64
import os
import sys
import types
import urllib.request
from unittest.mock import Mock, patch

import pytest

from src.browser.server import IngestServerOptions, start_ingest_server
from src.browser.store import CaptureStore


class _SwingComponent:
    def __init__(self, *args, **kwargs):
        self.text = args[0] if args and isinstance(args[0], str) else ""
        self.selected = args[1] if len(args) > 1 and isinstance(args[1], bool) else False
        self.actionPerformed = kwargs.get("actionPerformed")
        self.children = [arg for arg in args if isinstance(arg, _SwingComponent)]

    def add(self, component, _constraint=None):
        self.children.append(component)

    def setLayout(self, layout):
        self.layout = layout

    def setEditable(self, editable):
        self.editable = editable

    def setText(self, text):
        self.text = text

    def getText(self):
        return self.text

    def append(self, text):
        self.text += text

    def isSelected(self):
        return self.selected

    def setSelected(self, selected):
        self.selected = selected


class _ArrayList(list):
    def add(self, item):
        self.append(item)


def _make_module(name, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


def _load_extension():
    marker = "_kagent_burp_test_module"
    if marker in sys.modules:
        return sys.modules[marker]

    burp = _make_module(
        "burp",
        IBurpExtender=type("IBurpExtender", (object,), {}),
        IContextMenuFactory=type("IContextMenuFactory", (object,), {}),
        IHttpListener=type("IHttpListener", (object,), {}),
        ITab=type("ITab", (object,), {}),
    )
    border_layout = type("BorderLayout", (object,), {"NORTH": "North", "CENTER": "Center"})
    swing = {
        name: type(name, (_SwingComponent,), {})
        for name in (
            "JPanel", "JLabel", "JTextField", "JButton", "JCheckBox", "JTextArea",
            "JScrollPane", "JMenuItem",
        )
    }
    swing["BoxLayout"] = type("BoxLayout", (_SwingComponent,), {"Y_AXIS": 1})
    stubs = {
        "burp": burp,
        "java": _make_module("java"),
        "java.awt": _make_module("java.awt", BorderLayout=border_layout),
        "java.net": _make_module("java.net", URL=type("URL", (object,), {})),
        "javax": _make_module("javax"),
        "javax.swing": _make_module("javax.swing", **swing),
        "java.util": _make_module("java.util", ArrayList=_ArrayList),
    }

    module = types.ModuleType(marker)
    path = os.path.join(
        os.path.dirname(__file__), "..", "..", "integrations", "burp", "kagent_burp.py"
    )
    # Keep Java/Burp stand-ins local to loading this extension.
    with patch.dict(sys.modules, stubs), open(path, "r", encoding="utf-8") as source:
        exec(compile(source.read(), path, "exec"), module.__dict__)
    sys.modules[marker] = module
    return module


extension_module = _load_extension()
BurpExtender = extension_module.BurpExtender


TRAFFIC_URL = "http://fixture.test/api?token=private-query"
RAW_REQUEST = (
    b"POST /api?token=private-query HTTP/1.1\r\n"
    b"Host: fixture.test\r\nCookie: sid=private-cookie\r\n"
    b"Authorization: Bearer private-auth\r\nContent-Type: application/json\r\n\r\n"
    b'{"password":"private-password","q":"test"}'
)
RAW_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
    b"Set-Cookie: sid=private-response-cookie\r\n\r\n"
    b'{"token":"private-response"}'
)


def _traffic_info(raw):
    headers = raw.split(b"\r\n\r\n", 1)[0]
    return types.SimpleNamespace(
        getHeaders=lambda: headers.decode("latin-1").split("\r\n"),
        getBodyOffset=lambda: len(headers) + 4,
        getMethod=lambda: "POST",
        getUrl=lambda: types.SimpleNamespace(toString=lambda: TRAFFIC_URL),
        getStatusCode=lambda: 200,
    )


def _message(response: bytes | None = RAW_RESPONSE):
    service = types.SimpleNamespace(getHost=lambda: "fixture.test", getPort=lambda: 80)
    return types.SimpleNamespace(
        getHttpService=lambda: service,
        getRequest=lambda: RAW_REQUEST,
        getResponse=lambda: response,
    )


def _components(root):
    yield root
    for child in root.children:
        yield from _components(child)


@pytest.fixture
def extender():
    registrations = []
    callbacks = types.SimpleNamespace(
        TOOL_PROXY=1,
        TOOL_REPEATER=2,
        registrations=registrations,
        getHelpers=lambda: types.SimpleNamespace(
            analyzeRequest=lambda service, raw: _traffic_info(raw),
            analyzeResponse=_traffic_info,
        ),
        setExtensionName=lambda name: registrations.append(("name", name)),
        registerContextMenuFactory=lambda obj: registrations.append(("context", obj)),
        registerHttpListener=lambda obj: registrations.append(("http", obj)),
        addSuiteTab=lambda obj: registrations.append(("tab", obj)),
        getStdout=Mock,
        getStderr=Mock,
    )
    instance = BurpExtender()
    instance.registerExtenderCallbacks(callbacks)
    instance.getUiComponent()
    # Jython's byte strings are str; use CPython bytes for the same traffic.
    instance._raw_bytes = bytes
    return instance


def test_registers_only_context_menu_http_listener_and_tab(extender):
    assert extender.callbacks.registrations == [
        ("name", "KAgent"), ("context", extender), ("http", extender), ("tab", extender),
    ]
    assert extender.getTabCaption() == "KAgent"
    for name in (
        "_send_and_queue", "_burp_active_scan", "newScanIssue", "_import_issues",
        "_maybe_import_issues", "_issue_import_key", "_scanner_issue_to_payload",
        "_show_tasks", "auto_import_issues", "forward_scanner_issues", "imported_issue_keys",
    ):
        assert not hasattr(extender, name)
    assert not hasattr(extension_module, "KAgentIssue")
    assert not hasattr(extension_module, "HttpRequestResponse")


def test_context_menu_keeps_only_send_and_scope_actions(extender):
    messages = [_message(), _message(None)]
    invocation = types.SimpleNamespace(getSelectedMessages=lambda: messages)
    extender._send_requests = Mock()
    extender._queue_task = Mock()

    items = extender.createMenuItems(invocation)
    assert [item.text for item in items] == ["Send to KAgent", "Add Host to Scope"]
    items[0].actionPerformed(None)
    extender._send_requests.assert_called_once_with(messages)
    extender._queue_task.assert_not_called()
    items[1].actionPerformed(None)
    extender._queue_task.assert_called_once_with(messages, "scope")


@pytest.mark.parametrize("selection", [None, []])
def test_context_menu_is_empty_without_selected_messages(extender, selection):
    invocation = types.SimpleNamespace(getSelectedMessages=lambda: selection)
    assert extender.createMenuItems(invocation) == []


def test_tab_keeps_connection_capture_management_and_activity_log(extender):
    components = list(_components(extender.getUiComponent()))
    assert [c.text for c in components if isinstance(c, extension_module.JButton)] == [
        "Save", "Check Status", "Show Requests", "Clear Bridge", "Clear Console",
    ]
    assert [c.text for c in components if isinstance(c, extension_module.JCheckBox)] == [
        "Auto-capture Proxy traffic", "Auto-capture Repeater traffic",
    ]
    assert [c.text for c in components if isinstance(c, extension_module.JLabel)] == [
        "KAgent URL:", "Token:", "Activity Log",
    ]
    assert extender.url_field.getText() == extension_module.DEFAULT_BASE_URL
    assert extender.token_field.getText() == ""
    assert not extender.auto_proxy_box.isSelected()
    assert not extender.auto_repeater_box.isSelected()
    assert not extender.auto_send_proxy and not extender.auto_send_repeater
    assert extender.log_area.editable is False


def test_save_updates_connection_and_capture_settings_without_logging_secrets(extender):
    extender.url_field.setText(" http://127.0.0.1:9999/?token=private-url ")
    extender.token_field.setText(" private-bridge-token ")
    extender.auto_proxy_box.setSelected(True)
    extender._save_settings(None)

    assert extender.base_url == "http://127.0.0.1:9999/?token=private-url"
    assert extender.token == "private-bridge-token"
    assert extender.auto_send_proxy and not extender.auto_send_repeater
    assert "private" not in extender.log_area.getText()
    assert "private" not in repr(extender.stdout.mock_calls)

    extender.auto_proxy_box.setSelected(False)
    extender.auto_repeater_box.setSelected(True)
    extender._save_settings(None)
    assert not extender.auto_send_proxy and extender.auto_send_repeater


@pytest.mark.parametrize("response", [None, RAW_RESPONSE])
def test_manual_send_forwards_complete_traffic_only_to_ingest(extender, response):
    extender._post_json = Mock()
    extender._get_json = Mock()
    extender._send_requests([_message(response)])

    extender._post_json.assert_called_once()
    path, payload = extender._post_json.call_args.args
    assert path == "/ingest"
    assert payload["kind"] == payload["source"] == "burp"
    assert payload["url"] == TRAFFIC_URL and payload["method"] == "POST"
    assert payload["requestBody"] == RAW_REQUEST.split(b"\r\n\r\n", 1)[1].decode()
    assert base64.b64decode(payload["rawRequestB64"]) == RAW_REQUEST
    headers = {h["name"]: h["value"] for h in payload["requestHeaders"]}
    assert headers["Cookie"] == "sid=private-cookie"
    assert headers["Authorization"] == "Bearer private-auth"
    if response is None:
        assert all(key not in payload for key in ("status", "responseHeaders", "respBody", "rawResponseB64"))
    else:
        assert payload["status"] == 200
        assert payload["respBody"] == response.split(b"\r\n\r\n", 1)[1].decode()
        assert base64.b64decode(payload["rawResponseB64"]) == response
        assert {h["name"]: h["value"] for h in payload["responseHeaders"]}["Set-Cookie"] == "sid=private-response-cookie"
    extender._get_json.assert_not_called()
    assert "private" not in extender.log_area.getText()
    assert "private" not in repr(extender.stdout.mock_calls)


def test_manual_send_continues_after_failure_and_logs_only_success_count(extender):
    extender._post_json = Mock(side_effect=[RuntimeError("Bearer private-auth"), None])
    extender._send_requests([_message(), _message(None)])
    assert extender._post_json.call_count == 2
    assert "sent 1 request(s)" in extender.log_area.getText()
    assert "private" not in extender.log_area.getText()


@pytest.mark.parametrize("proxy,repeater,tool,is_request,expected", [
    (False, False, 1, False, False),
    (False, False, 2, False, False),
    (True, False, 1, False, True),
    (True, False, 2, False, False),
    (False, True, 1, False, False),
    (False, True, 2, False, True),
    (True, True, 1, True, False),
    (True, True, 2, True, False),
    (True, True, 99, False, False),
])
def test_auto_capture_respects_independent_toggles_and_response_events(
    extender, proxy, repeater, tool, is_request, expected,
):
    extender.auto_send_proxy = proxy
    extender.auto_send_repeater = repeater
    extender._post_json = Mock()
    extender.processHttpMessage(tool, is_request, _message())
    assert extender._post_json.call_count == int(expected)
    if expected:
        path, payload = extender._post_json.call_args.args
        assert path == "/ingest"
        assert base64.b64decode(payload["rawRequestB64"]) == RAW_REQUEST
        assert base64.b64decode(payload["rawResponseB64"]) == RAW_RESPONSE
        assert payload["notes"] == "Auto-forwarded from Burp listener"
    assert "private" not in extender.log_area.getText()


def test_bridge_traffic_is_skipped_before_capture_payload_is_built(extender):
    extender.auto_send_proxy = True
    extender._bridge_port = lambda: 8888
    extender._post_json = Mock()
    extender._message_to_ingest_payload = Mock()
    message = types.SimpleNamespace(
        getHttpService=lambda: types.SimpleNamespace(getHost=lambda: "127.0.0.1", getPort=lambda: 8888),
    )
    extender.processHttpMessage(1, False, message)
    extender._post_json.assert_not_called()
    extender._message_to_ingest_payload.assert_not_called()


def test_scope_action_only_queues_existing_scope_task_payload(extender):
    extender._post_json = Mock()
    extender._get_json = Mock()
    items = extender.createMenuItems(types.SimpleNamespace(getSelectedMessages=lambda: [_message()]))
    items[1].actionPerformed(None)
    extender._post_json.assert_called_once_with("/burp/task", {
        "action": "scope", "target": "fixture.test", "host": "fixture.test",
        "method": "POST", "url": TRAFFIC_URL,
        "rawRequestB64": base64.b64encode(RAW_REQUEST).decode(),
        "notes": "Queued from Burp context menu",
    })
    extender._get_json.assert_not_called()
    assert "queued 1 scope task(s)" in extender.log_area.getText()
    assert "private" not in extender.log_area.getText()


def test_failed_clear_bridge_preserves_deduplication_state(extender):
    extender._remember_auto_key("captured-key")
    extender._delete = Mock(side_effect=RuntimeError("private-bridge-token"))
    extender._clear_bridge()
    extender._delete.assert_called_once_with("/clear")
    assert extender.auto_sent_keys == {"captured-key"}
    assert extender.auto_sent_order == ["captured-key"]
    assert "private" not in extender.log_area.getText()


@pytest.mark.parametrize("capture_action", ["manual", "proxy", "repeater"])
def test_retained_actions_against_local_bridge_preserve_capture_and_clear_contracts(
    extender, monkeypatch, capture_action,
):
    store = CaptureStore()
    events = []
    handle = start_ingest_server(IngestServerOptions(
        store=store, port=0, token="private-bridge-token", on_event=events.append,
    ))
    monkeypatch.setattr(extension_module, "urllib2", urllib.request)
    extender.base_url = handle.url
    extender.token = handle.token
    extender._post_json = Mock(wraps=extender._post_json)
    try:
        messages = [_message()]
        items = extender.createMenuItems(types.SimpleNamespace(getSelectedMessages=lambda: messages))
        if capture_action == "manual":
            items[0].actionPerformed(None)
        else:
            tool = extender.callbacks.TOOL_PROXY if capture_action == "proxy" else extender.callbacks.TOOL_REPEATER
            extender.auto_send_proxy = capture_action == "proxy"
            extender.auto_send_repeater = capture_action == "repeater"
            extender.processHttpMessage(tool, False, messages[0])

        extender._post_json.assert_called_once()
        assert extender._post_json.call_args.args[0] == "/ingest"
        captured = store.list_requests()
        assert len(captured) == 1
        row = captured[0]
        assert row.source == "burp" and row.status == 200
        assert row.raw_request_b64 == base64.b64encode(RAW_REQUEST).decode()
        assert {h.name: h.value for h in row.request_headers or []}["Cookie"] == "sid=private-cookie"
        assert {h.name: h.value for h in row.request_headers or []}["Authorization"] == "Bearer private-auth"
        assert row.response_body == '{"token":"private-response"}'
        assert {h.name: h.value for h in row.response_headers or []}["Set-Cookie"] == "sid=private-response-cookie"
        assert store.list_burp_tasks() == [] and store.list_burp_issues() == []

        extender._show_requests()
        assert "1 record(s)" in extender.log_area.getText()
        extender._check_status(None)
        assert '"ok": true' in extender.log_area.getText()
        assert "private" not in extender.log_area.getText()

        items[1].actionPerformed(None)
        tasks = store.list_burp_tasks()
        assert len(tasks) == 1 and tasks[0].action == "scope"
        assert tasks[0].target == tasks[0].host == "fixture.test"
        assert tasks[0].raw_request_b64 == row.raw_request_b64
        assert store.list_burp_issues() == []

        extender._clear_console()
        assert extender.log_area.getText() == ""
        assert store.list_requests() == captured and store.list_burp_tasks() == tasks
        assert "private" not in repr(extender.stdout.mock_calls)
        assert "private" not in "\n".join(events)

        extender._clear_bridge()
        assert store.list_requests() == [] and store.list_burp_tasks() == []
        assert store.list_burp_issues() == []
        assert extender.auto_sent_keys == set() and extender.auto_sent_order == []
    finally:
        handle.close()


def test_show_requests_never_prints_server_traffic_or_credentials():
    extender = object.__new__(BurpExtender)
    logs = []
    extender._log = logs.append
    extender._get_json = lambda _: [{"url": "http://fixture.test/?token=private-query",
        "raw_request_b64": "cHJpdmF0ZS1yYXc=", "Cookie": "sid=private-cookie",
        "Authorization": "Bearer private-auth", "notes": "private-notes"}]
    extender._show_requests()
    assert len(logs) == 1 and "1 record(s)" in logs[0]
    assert all("private" not in line and "cHJpdmF0ZS1yYXc=" not in line for line in logs)


def test_error_logging_does_not_print_raw_or_encoded_bridge_response():
    extender = object.__new__(BurpExtender)
    logs = []
    extender._log = logs.append
    try:
        extender._decode_json_response("/requests", b"Cookie: sid=private-cookie cHJpdmF0ZS1yYXc=")
    except Exception as exc:
        extender._log_error("Show requests failed", exc)
    extender._log_error("Bridge failed", RuntimeError("Bearer private-auth cHJpdmF0ZS1yYXc="))
    assert len(logs) == 2
    assert all("private" not in line and "cHJpdmF0ZS1yYXc=" not in line for line in logs)


def test_auto_forward_retries_after_a_failed_post_and_deduplicates_successes():
    extender = object.__new__(BurpExtender)
    extender.callbacks = types.SimpleNamespace(TOOL_PROXY=1)
    extender.auto_send_proxy = True
    extender.auto_send_repeater = False
    extender.auto_sent_keys = set()
    extender.auto_sent_order = []
    extender._is_bridge_message = lambda message: False
    extender._message_key = lambda message: "request-key"
    extender._message_to_ingest_payload = lambda message: {"method": "GET", "url": "https://x"}
    extender._log = lambda message: None
    calls = []

    def post(path, payload):
        calls.append((path, payload))
        if len(calls) == 1:
            raise RuntimeError("bridge unavailable")

    extender._post_json = post
    extender._log_error = lambda prefix, exc: None

    extender.processHttpMessage(1, False, object())
    assert extender.auto_sent_keys == set()

    extender.processHttpMessage(1, False, object())
    extender.processHttpMessage(1, False, object())

    assert len(calls) == 2
    assert extender.auto_sent_keys == {"request-key"}
    assert extender.auto_sent_order == ["request-key"]


def test_auto_forward_key_includes_request_content():
    class Info:
        def getMethod(self):
            return "POST"

        def getUrl(self):
            return types.SimpleNamespace(toString=lambda: "https://x.test/api")

    class Message:
        def __init__(self, request):
            self.request = request

        def getHttpService(self):
            return object()

        def getRequest(self):
            return self.request

        def getResponse(self):
            return None

    extender = object.__new__(BurpExtender)
    extender.helpers = types.SimpleNamespace(analyzeRequest=lambda service, request: Info())
    extender._raw_bytes = lambda request: request

    assert extender._message_key(Message(b"aaaa")) != extender._message_key(Message(b"bbbb"))


def test_ipv6_bridge_traffic_is_not_auto_forwarded_back_to_the_bridge():
    extender = object.__new__(BurpExtender)
    extender._bridge_port = lambda: 8888
    message = types.SimpleNamespace(
        getHttpService=lambda: types.SimpleNamespace(getHost=lambda: "::1", getPort=lambda: 8888)
    )

    assert extender._is_bridge_message(message) is True
