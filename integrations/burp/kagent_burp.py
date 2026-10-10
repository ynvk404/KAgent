# -*- coding: utf-8 -*-
# KAgent Burp Suite integration.
#
# Load in Burp: Extender -> Extensions -> Add -> Extension type: Python.
# Requires Jython 2.7.x configured in Burp.

from burp import (
    IBurpExtender,
    IContextMenuFactory,
    IHttpListener,
    ITab,
)
from java.awt import BorderLayout
from java.net import URL
from javax.swing import JPanel, JLabel, JTextField, JButton, JCheckBox, JTextArea, JScrollPane, JMenuItem, BoxLayout
from java.util import ArrayList
import base64
import hashlib
import json

try:
    import urllib2
except ImportError:
    urllib2 = None


DEFAULT_BASE_URL = "http://127.0.0.1:8888"


class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.base_url = DEFAULT_BASE_URL
        self.token = ""
        self.auto_send_proxy = False
        self.auto_send_repeater = False
        self.auto_sent_keys = set()
        self.auto_sent_order = []

        callbacks.setExtensionName("KAgent")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        self.stdout = callbacks.getStdout()
        self.stderr = callbacks.getStderr()
        self._println("KAgent Burp extension loaded. Start KAgent with --burp.")

    def getTabCaption(self):
        return "KAgent"

    def getUiComponent(self):
        panel = JPanel(BorderLayout())

        # Tạo một container chính cho phần top, xếp các hàng theo chiều dọc
        top_container = JPanel()
        top_container.setLayout(BoxLayout(top_container, BoxLayout.Y_AXIS))

        # Hàng 1: URL và Token
        row1 = JPanel()
        row1.add(JLabel("KAgent URL:"))
        self.url_field = JTextField(self.base_url, 32)
        row1.add(self.url_field)
        row1.add(JLabel("Token:"))
        self.token_field = JTextField(self.token, 24)
        row1.add(self.token_field)

        # Hàng 2: Các nút bấm (Bao gồm cả Clear)
        row2 = JPanel()
        save = JButton("Save", actionPerformed=self._save_settings)
        status = JButton("Check Status", actionPerformed=self._check_status)
        requests = JButton("Show Requests", actionPerformed=self._show_requests)
        clear = JButton("Clear Bridge", actionPerformed=self._clear_bridge)
        clear_console = JButton("Clear Console", actionPerformed=self._clear_console)

        row2.add(save)
        row2.add(status)
        row2.add(requests)
        row2.add(clear)
        row2.add(clear_console)

        # Hàng 3: Các ô Checkbox
        row3 = JPanel()
        self.auto_proxy_box = JCheckBox("Auto-capture Proxy traffic", False)
        self.auto_repeater_box = JCheckBox("Auto-capture Repeater traffic", False)

        row3.add(self.auto_proxy_box)
        row3.add(self.auto_repeater_box)

        # Thêm các hàng vào container chính
        top_container.add(row1)
        top_container.add(row2)
        top_container.add(row3)

        self.log_area = JTextArea(12, 80)
        self.log_area.setEditable(False)

        log_container = JPanel(BorderLayout())
        log_container.add(JLabel("Activity Log"), BorderLayout.NORTH)
        log_container.add(JScrollPane(self.log_area), BorderLayout.CENTER)

        # Đưa container chính lên vị trí NORTH
        panel.add(top_container, BorderLayout.NORTH)
        panel.add(log_container, BorderLayout.CENTER)
        return panel

    def createMenuItems(self, invocation):
        items = ArrayList()
        selected = invocation.getSelectedMessages()
        if not selected:
            return items

        items.add(JMenuItem("Send to KAgent", actionPerformed=lambda e: self._send_requests(selected)))
        # Queue the existing scope task; this does not change runtime scope.
        items.add(JMenuItem("Add Host to Scope", actionPerformed=lambda e: self._queue_task(selected, "scope")))
        return items

    def _save_settings(self, _event):
        self.base_url = self.url_field.getText().strip().rstrip("/") or DEFAULT_BASE_URL
        self.token = self.token_field.getText().strip()
        self.auto_send_proxy = self.auto_proxy_box.isSelected()
        self.auto_send_repeater = self.auto_repeater_box.isSelected()
        self._log("bridge settings saved")

    def _check_status(self, _event):
        try:
            data = self._get_json("/status")
            self._log("status: %s" % json.dumps(data))
        except Exception as exc:
            self._log_error("status failed", exc)

    def _send_requests(self, messages):
        count = 0
        for msg in messages:
            try:
                payload = self._message_to_ingest_payload(msg)
                self._post_json("/ingest", payload)
                count += 1
            except Exception as exc:
                self._log_error("send request failed", exc)
        self._log("sent %d request(s) to KAgent capture" % count)

    def _queue_task(self, messages, action):
        count = 0
        for msg in messages:
            try:
                payload = self._message_to_task_payload(msg, action)
                self._post_json("/burp/task", payload)
                count += 1
            except Exception as exc:
                self._log_error("queue %s failed" % action, exc)
        self._log("queued %d %s task(s) for KAgent" % (count, action))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        if not self._should_auto_forward(toolFlag):
            return
        if self._is_bridge_message(messageInfo):
            return
        key = self._message_key(messageInfo)
        if key in self.auto_sent_keys:
            return
        try:
            payload = self._message_to_ingest_payload(messageInfo)
            payload["notes"] = "Auto-forwarded from Burp listener"
            self._post_json("/ingest", payload)
            self._remember_auto_key(key)
            self._log("auto-sent captured request to KAgent")
        except Exception as exc:
            self._log_error("auto-send failed", exc)

    def _show_requests(self, _event=None):
        try:
            data = self._get_json("/requests")
            self._log("recent KAgent requests: %d record(s); inspect redacted captures in KAgent" % len(data))
        except Exception as exc:
            self._log_error("Show requests failed", exc)

    def _clear_bridge(self, _event=None):
        try:
            self._delete("/clear")
            self.auto_sent_keys.clear()
            self.auto_sent_order = []
            self._log("cleared KAgent bridge state")
        except Exception as exc:
            self._log_error("clear bridge failed", exc)

    def _clear_console(self, _event=None):
        try:
            self.log_area.setText("")
            self._println("console cleared")
        except Exception as exc:
            self._log_error("clear console failed", exc)

    def _message_to_ingest_payload(self, msg):
        service = msg.getHttpService()
        request = msg.getRequest()
        response = msg.getResponse()
        req_info = self.helpers.analyzeRequest(service, request)
        url = req_info.getUrl().toString()
        method = req_info.getMethod()

        payload = {
            "kind": "burp",
            "id": "burp-%s" % self._stable_id(url, method, request),
            "method": method,
            "url": url,
            "requestHeaders": self._headers(req_info.getHeaders()),
            "requestBody": self._body_to_text(request, req_info.getBodyOffset()),
            "rawRequestB64": self._b64encode(self._raw_bytes(request)),
            "source": "burp",
        }
        if response:
            resp_info = self.helpers.analyzeResponse(response)
            payload["status"] = resp_info.getStatusCode()
            payload["responseHeaders"] = self._headers(resp_info.getHeaders())
            payload["respBody"] = self._body_to_text(response, resp_info.getBodyOffset())
            payload["rawResponseB64"] = self._b64encode(self._raw_bytes(response))
        return payload

    def _message_to_task_payload(self, msg, action):
        service = msg.getHttpService()
        req_info = self.helpers.analyzeRequest(service, msg.getRequest())
        url = req_info.getUrl()
        host = service.getHost()
        payload = {
            "action": action,
            "target": url.toString() if action != "scope" else host,
            "host": host,
            "method": req_info.getMethod(),
            "url": url.toString(),
            "rawRequestB64": self._b64encode(self._raw_bytes(msg.getRequest())),
            "notes": "Queued from Burp context menu",
        }
        return payload

    def _headers(self, headers):
        out = []
        for header in headers:
            text = str(header)
            idx = text.find(":")
            if idx > 0:
                out.append({"name": text[:idx].strip(), "value": text[idx + 1:].strip()})
        return out

    def _body_to_text(self, data, offset):
        try:
            if data is None:
                return ""
            raw = self._raw_bytes(data[offset:])
            try:
                return raw.decode("utf-8", "replace")
            except AttributeError:
                return raw.encode("latin-1", "replace").decode("utf-8", "replace")
        except Exception:
            return ""

    def _raw_bytes(self, data):
        return "".join(chr((int(b) + 256) % 256) for b in data)

    def _b64encode(self, raw):
        encoded = base64.b64encode(raw)
        return encoded.decode("ascii") if hasattr(encoded, "decode") else encoded

    def _stable_id(self, url, method, request):
        digest = hashlib.sha1()
        digest.update(method.encode("utf-8") if hasattr(method, "encode") else str(method))
        digest.update(b"|" if hasattr(b"|", "decode") else "|")
        digest.update(url.encode("utf-8") if hasattr(url, "encode") else str(url))
        digest.update(b"|" if hasattr(b"|", "decode") else "|")
        digest.update(self._raw_bytes(request).encode("latin-1", "replace") if hasattr(self._raw_bytes(request), "encode") else self._raw_bytes(request))
        return digest.hexdigest()[:16]

    def _should_auto_forward(self, toolFlag):
        try:
            if toolFlag == self.callbacks.TOOL_PROXY:
                return self.auto_send_proxy
            if toolFlag == self.callbacks.TOOL_REPEATER:
                return self.auto_send_repeater
        except Exception:
            return False
        return False

    def _is_bridge_message(self, msg):
        try:
            service = msg.getHttpService()
            if service.getHost() not in ["127.0.0.1", "localhost", "::1", "[::1]"]:
                return False
            bridge_port = self._bridge_port()
            return bridge_port is not None and service.getPort() == bridge_port
        except Exception:
            return False

    def _bridge_port(self):
        try:
            url = URL(self.base_url)
            port = url.getPort()
            if port == -1:
                port = 443 if url.getProtocol() == "https" else 80
            return port
        except Exception:
            return None

    def _message_key(self, msg):
        service = msg.getHttpService()
        req = msg.getRequest()
        info = self.helpers.analyzeRequest(service, req)
        resp = msg.getResponse()
        status = ""
        if resp:
            try:
                status = str(self.helpers.analyzeResponse(resp).getStatusCode())
            except Exception:
                status = ""
        digest = hashlib.sha1()
        digest.update(self._raw_bytes(req))
        return "%s|%s|%s|%s" % (
            info.getMethod(),
            info.getUrl().toString(),
            digest.hexdigest(),
            status,
        )

    def _remember_auto_key(self, key):
        self.auto_sent_keys.add(key)
        self.auto_sent_order.append(key)
        if len(self.auto_sent_order) > 1000:
            old = self.auto_sent_order.pop(0)
            self.auto_sent_keys.discard(old)

    def _auth_headers(self, extra=None):
        headers = {}
        if extra:
            headers.update(extra)
        if self.token:
            headers["X-KAgent-Token"] = self.token
        return headers

    def _post_json(self, path, payload):
        body = json.dumps(payload).encode("utf-8")
        req = urllib2.Request(
            self.base_url + path,
            body,
            self._auth_headers({
                "Accept": "application/json; charset=utf-8",
                "Content-Type": "application/json; charset=utf-8",
            }),
        )
        res = urllib2.urlopen(req, timeout=10)
        status = res.getcode()
        text = res.read()
        if status < 200 or status >= 300:
            raise Exception(u"bridge HTTP %s" % status)
        return text

    def _get_json(self, path):
        req = urllib2.Request(self.base_url + path, None, self._auth_headers())
        res = urllib2.urlopen(req, timeout=10)
        text = res.read()
        return self._decode_json_response(path, text)

    def _decode_json_response(self, path, raw):
        text = self._strip_bom(self._response_text(raw)).strip()
        try:
            return json.loads(text)
        except ValueError as exc:
            decoder = json.JSONDecoder()
            try:
                data, end = decoder.raw_decode(text)
                trailing = text[end:].strip()
                if trailing:
                    self._log(
                        "warning: ignored %d trailing byte(s) after JSON from %s"
                        % (len(trailing), path)
                    )
                return data
            except Exception:
                raise Exception(
                    u"invalid JSON from bridge endpoint %s" % path
                )

    def _response_text(self, raw):
        if raw is None:
            return u""
        if hasattr(raw, "decode"):
            try:
                return raw.decode("utf-8-sig", "replace")
            except TypeError:
                try:
                    return raw.decode("utf-8-sig")
                except Exception:
                    return self._safe_unicode(raw)
            except Exception:
                return self._safe_unicode(raw)
        return self._safe_unicode(raw)

    def _strip_bom(self, text):
        text = self._safe_unicode(text)
        if text.startswith(u"\ufeff"):
            return text[1:]
        if text.startswith(u"\xef\xbb\xbf"):
            return text[3:]
        return text

    def _safe_unicode(self, value):
        if value is None:
            return u""
        try:
            unicode_type = unicode
        except NameError:
            unicode_type = str
        try:
            if isinstance(value, unicode_type):
                return value
        except Exception:
            pass
        if hasattr(value, "decode"):
            try:
                return value.decode("utf-8-sig", "replace")
            except TypeError:
                try:
                    return value.decode("utf-8-sig")
                except Exception:
                    pass
            except Exception:
                pass
        try:
            return unicode_type(value)
        except Exception:
            try:
                return str(value).decode("utf-8", "replace")
            except Exception:
                return u"<unprintable>"

    def _delete(self, path):
        req = urllib2.Request(self.base_url + path, None, self._auth_headers())
        req.get_method = lambda: "DELETE"
        res = urllib2.urlopen(req, timeout=10)
        return res.read()

    def _log(self, message):
        message = self._safe_unicode(message)
        try:
            self.log_area.append(message + u"\n")
        except Exception:
            pass
        self._println(message)

    def _log_error(self, prefix, exc):
        # Exceptions may include a response, request URL or encoded traffic.
        self._log(u"%s (%s)" % (self._safe_unicode(prefix), type(exc).__name__))

    def _println(self, message):
        message = self._safe_unicode(message)
        try:
            self.stdout.println(u"[KAgent] " + message)
        except Exception:
            try:
                self.stdout.println(("[KAgent] " + message).encode("utf-8", "replace"))
            except Exception:
                pass
