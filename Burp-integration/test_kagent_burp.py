import os
import sys
import types


def _install_module(name, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules[name] = module
    return module


def _load_extension():
    marker = "_kagent_burp_test_module"
    if marker in sys.modules:
        return sys.modules[marker]

    _install_module(
        "burp",
        IBurpExtender=type("IBurpExtender", (object,), {}),
        IContextMenuFactory=type("IContextMenuFactory", (object,), {}),
        IHttpListener=type("IHttpListener", (object,), {}),
        IHttpRequestResponse=type("IHttpRequestResponse", (object,), {}),
        IScanIssue=type("IScanIssue", (object,), {}),
        IScannerListener=type("IScannerListener", (object,), {}),
        ITab=type("ITab", (object,), {}),
    )
    base = type("JavaBase", (object,), {})
    _install_module("java")
    _install_module("java.awt", BorderLayout=base)
    _install_module("java.net", URL=base)
    _install_module(
        "javax.swing",
        JPanel=base,
        JLabel=base,
        JTextField=base,
        JButton=base,
        JCheckBox=base,
        JTextArea=base,
        JScrollPane=base,
        JMenuItem=base,
        BoxLayout=base,
    )
    _install_module("java.util", ArrayList=list)

    module = types.ModuleType(marker)
    sys.modules[marker] = module
    path = os.path.join(os.path.dirname(__file__), "kagent_burp.py")
    with open(path, "r") as source:
        exec(compile(source.read(), path, "exec"), module.__dict__)
    return module


extension_module = _load_extension()
BurpExtender = extension_module.BurpExtender
KAgentIssue = extension_module.KAgentIssue


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


def test_fallback_request_uses_correct_host_header_for_port_and_ipv6():
    class URL:
        def __init__(self, host, port, protocol):
            self.host = host
            self.port = port
            self.protocol = protocol

        def getPath(self):
            return "/path"

        def getQuery(self):
            return "q=1"

        def getHost(self):
            return self.host

        def getPort(self):
            return self.port

        def getProtocol(self):
            return self.protocol

    issue = object.__new__(KAgentIssue)
    issue.data = {"method": "POST"}
    issue.helpers = types.SimpleNamespace(stringToBytes=lambda value: value)

    issue._issue_url = URL("example.test", 8443, "https")
    assert "Host: example.test:8443" in issue._fallback_request()

    issue._issue_url = URL("::1", 8080, "http")
    assert "Host: [::1]:8080" in issue._fallback_request()
