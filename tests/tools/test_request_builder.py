import base64
import json
from types import SimpleNamespace

import pytest

from src.tools.request_builder import build_captured_request
from src.browser.store import CaptureStore, MAX_RAW_REQUEST_B64
from src.browser.redacted_view import request_view
from src.workflow.state import Candidate


def row(method="POST", url="http://target.test/api", body=b"", content_type="text/plain", raw=False):
    headers = [("Host", "target.test"), ("User-Agent", "CapturedBrowser/1"),
               ("Content-Type", content_type), ("Authorization", "Bearer lab-token"),
               ("Content-Length", str(len(body)))]
    if raw:
        target = url.removeprefix("http://target.test") or "/"
        wire = (f"{method} {target} HTTP/1.1\r\n" +
                "\r\n".join(f"{k}: {v}" for k, v in headers) + "\r\n\r\n").encode() + body
        return SimpleNamespace(method=method, url=url, raw_request_b64=base64.b64encode(wire).decode(),
                               request_headers=None, request_body=None)
    return SimpleNamespace(method=method, url=url, raw_request_b64=None,
                           request_headers=[SimpleNamespace(name=k, value=v) for k, v in headers],
                           request_body=body.decode())


def candidate(method="POST", endpoint="/api", parameter="q", location="body", content_type="text/plain"):
    return Candidate(candidate_class="sql-injection", target="http://target.test", method=method,
                     endpoint=endpoint, parameter=parameter, location=location, content_type=content_type)


def test_query_preserves_duplicate_keys_and_other_raw_encoding():
    captured = row("GET", "http://target.test/api?q=a%20b&x=%2f&q=second", b"", "text/plain")
    request, diff = build_captured_request(captured, candidate(method="GET", location="query"),
                                           "new value", occurrence=1)
    assert str(request.url).endswith("/api?q=a%20b&x=%2f&q=new+value")
    assert request.headers["user-agent"] == "CapturedBrowser/1"
    assert request.headers["authorization"] == "Bearer lab-token"
    assert diff.occurrence == 1


def test_nested_json_array_preserves_other_fields():
    original = {"items": [{"id": "a", "qty": 1}, {"id": "b", "qty": 2}], "csrf": "keep"}
    captured = row(body=json.dumps(original).encode(), content_type="application/json")
    request, _ = build_captured_request(captured, candidate(parameter="id", content_type="application/json"),
                                        "changed", input_path="/items/1/id")
    expected = json.loads(request.content)
    assert expected["items"][1]["id"] == "changed"
    assert expected["items"][0] == original["items"][0]
    assert expected["items"][1]["qty"] == 2
    assert expected["csrf"] == "keep"
    assert request.headers["content-length"] == str(len(request.content))


def test_form_preserves_order_duplicate_keys_and_bytes():
    captured = row(body=b"q=first&csrf=keep&q=second&x=%2f", content_type="application/x-www-form-urlencoded")
    request, _ = build_captured_request(captured, candidate(location="form", content_type="application/x-www-form-urlencoded"),
                                        "new value", occurrence=1)
    assert request.content == b"q=first&csrf=keep&q=new+value&x=%2f"


def test_raw_xml_replaces_only_named_existing_value():
    captured = row(body=b"<root><q>old</q><csrf>keep</csrf></root>", content_type="application/xml")
    request, _ = build_captured_request(captured, candidate(location="raw", content_type="application/xml"),
                                        "new", old_value="old")
    assert request.content == b"<root><q>new</q><csrf>keep</csrf></root>"


def test_multipart_preserves_binary_part_and_boundary():
    boundary = b"lab-boundary"
    body = (b"--lab-boundary\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nold\r\n"
            b"--lab-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.bin\"\r\n"
            b"Content-Type: application/octet-stream\r\n\r\n\x00\xff\x81\r\n--lab-boundary--\r\n")
    captured = row(body=body, content_type="multipart/form-data; boundary=lab-boundary", raw=True)
    request, _ = build_captured_request(captured, candidate(content_type="multipart/form-data"), "new")
    assert request.content.count(boundary) == body.count(boundary)
    assert b"\x00\xff\x81" in request.content
    assert b'name="q"\r\n\r\nnew\r\n' in request.content
    assert request.headers["content-type"] == "multipart/form-data; boundary=lab-boundary"
    assert request.headers["content-length"] == str(len(request.content))


def test_binary_raw_request_preserves_unrelated_bytes():
    captured = row(body=b"\x00\xffOLD\x81", raw=True)
    request, _ = build_captured_request(captured, candidate(location="raw"), "new", old_value="OLD")
    assert request.content == b"\x00\xffnew\x81"


def test_burp_raw_capture_survives_ingest_and_distinguishes_same_url_requests():
    store = CaptureStore()
    first = row(body=b"q=first", content_type="application/x-www-form-urlencoded", raw=True)
    second = row(body=b"q=second", content_type="application/x-www-form-urlencoded", raw=True)
    payload = {"kind": "burp", "id": "same", "method": "POST", "url": first.url,
               "rawRequestB64": first.raw_request_b64, "requestBody": "q=first"}
    one = store.ingest(payload)["id"]
    two = store.ingest({**payload, "rawRequestB64": second.raw_request_b64,
                        "requestBody": "q=second"})["id"]
    assert one != two
    first_row, second_row = store.get_request(one), store.get_request(two)
    assert first_row is not None and second_row is not None
    assert first_row.raw_request_b64 == first.raw_request_b64
    assert second_row.raw_request_b64 == second.raw_request_b64
    request, _ = build_captured_request(first_row,
                                        candidate(location="form", content_type="application/x-www-form-urlencoded"),
                                        "changed")
    assert request.content == b"q=changed"


def test_capture_id_differentiates_same_bytes_with_distinct_identity_metadata():
    store = CaptureStore()
    payload = {"id": "same", "method": "POST", "url": "http://target.test/api",
               "requestHeaders": [{"name": "Content-Type", "value": "application/json"}],
               "requestBody": '{"q":"old"}'}
    user = store.ingest({**payload, "authContextRef": "user"})["id"]
    admin = store.ingest({**payload, "authContextRef": "admin"})["id"]
    assert user != admin
    user_row, admin_row = store.get_request(user), store.get_request(admin)
    assert user_row is not None and user_row.auth_context_ref == "user"
    assert admin_row is not None and admin_row.auth_context_ref == "admin"


def test_oversize_raw_capture_fails_closed_and_model_view_hides_raw_credentials():
    store = CaptureStore()
    result = store.ingest({"id": "large", "method": "POST", "url": "http://target.test/api",
                           "rawRequestB64": "A" * (MAX_RAW_REQUEST_B64 + 1),
                           "requestHeaders": [{"name": "Cookie", "value": "sid=private"}],
                           "requestBody": "q=old"})
    captured = store.get_request(result["id"])
    assert captured is not None and captured.raw_request_oversize
    assert captured.raw_request_b64 is None
    assert "private" not in str(request_view(captured))
    with pytest.raises(ValueError, match="size limit"):
        build_captured_request(captured, candidate(), "new", old_value="old")


def test_oversize_capture_signature_preserves_incomplete_semantics():
    store = CaptureStore()
    payload = {"id": "incomplete", "method": "POST", "url": "http://target.test/api",
               "rawRequestB64": "A" * (MAX_RAW_REQUEST_B64 + 1),
               "requestHeaders": [{"name": "Content-Type", "value": "text/plain"}],
               "requestBody": "old"}
    first_id = store.ingest(payload)["id"]
    first = store.get_request(first_id)
    assert first is not None and first.raw_request_oversize

    second_id = store.ingest({key: value for key, value in payload.items() if key != "rawRequestB64"})["id"]
    second = store.get_request(second_id)
    assert second_id == first_id
    assert second is not None and second.raw_request_oversize
    with pytest.raises(ValueError, match="size limit"):
        build_captured_request(second, candidate(), "new", old_value="old")


def test_path_mutation_preserves_query_and_origin():
    captured = row("GET", "http://target.test/api/old?csrf=keep", b"")
    request, _ = build_captured_request(captured, candidate(method="GET", endpoint="/api/{id}", parameter="id", location="path"),
                                        "new", old_value="old")
    assert str(request.url) == "http://target.test/api/new?csrf=keep"


@pytest.mark.parametrize("change", ["origin", "method", "content_type", "missing_path"])
def test_mismatched_provenance_fails_closed(change):
    captured = row(body=b'{"q":"old"}', content_type="application/json")
    cand = candidate(content_type="application/json")
    if change == "origin":
        captured.url = "http://other.test/api"
    elif change == "method":
        captured.method = "GET"
    elif change == "content_type":
        cand.content_type = "text/plain"
    else:
        cand.endpoint = "/elsewhere"
    with pytest.raises(ValueError):
        build_captured_request(captured, cand, "new")


def test_json_scalar_array_and_unrelated_representation():
    original = b'{ "user_ids": [1e2, 20], "keep": "\\u00e9", "name":"Nguy\xc3\xaan" }'
    captured = row(body=original, content_type="application/json")
    request, _ = build_captured_request(captured, candidate(parameter="user_ids", content_type="application/json"),
                                        "changed", input_path="/user_ids/1")
    assert request.content == original.replace(b"20", b'"changed"')


@pytest.mark.parametrize("path", ["/missing", "/items/4/q", "/items/no/q", "/items/0/q/x"])
def test_json_invalid_path_is_controlled(path):
    captured = row(body=b'{"items":[{"q":1}]}', content_type="application/json")
    with pytest.raises(ValueError):
        build_captured_request(captured, candidate(parameter="q", content_type="application/json"),
                               "new", input_path=path)


def test_duplicate_json_keys_fail_closed():
    captured = row(body=b'{"q":"first","q":"second","keep":1}', content_type="application/json")
    with pytest.raises(ValueError, match="duplicate JSON"):
        build_captured_request(captured, candidate(content_type="application/json"), "new")


def test_xml_named_field_and_ambiguous_raw():
    captured = row(body=b"<root><csrf>old</csrf><q>old</q><tail>old</tail></root>", content_type="application/xml")
    request, _ = build_captured_request(captured, candidate(location="raw", content_type="application/xml"),
                                        "new", old_value="old")
    assert request.content == b"<root><csrf>old</csrf><q>new</q><tail>old</tail></root>"
    for body, content_type in [(b"old:old", "text/plain"), (b"<root><q>old</q><q>old</q></root>", "application/xml"),
                               (b"<q>old", "application/xml")]:
        with pytest.raises(ValueError):
            build_captured_request(row(body=body, content_type=content_type),
                                   candidate(location="raw", content_type=content_type), "new", old_value="old")


def test_missing_or_recursive_truncated_body_needs_recapture():
    captured = row(body=b"q=old", content_type="application/x-www-form-urlencoded")
    captured.request_body = None
    with pytest.raises(ValueError, match="missing"):
        build_captured_request(captured, candidate(location="form", content_type="application/x-www-form-urlencoded"), "new")
    nested = row(body=b"{}", content_type="application/json")
    nested.request_headers = [SimpleNamespace(name="Content-Type", value="application/json")]
    nested.request_body = {"items": [{"q": "abc...<truncated 5 chars>"}]}
    with pytest.raises(ValueError, match="truncated"):
        build_captured_request(nested, candidate(content_type="application/json"), "new")
    raw = row(body=b'{"q":"old"}', content_type="application/json", raw=True)
    raw.request_body = nested.request_body
    request, _ = build_captured_request(raw, candidate(content_type="application/json"), "new")
    assert request.content == b'{"q":"new"}'
    form = row(body=b"q=old", content_type="application/x-www-form-urlencoded")
    form.request_headers = [SimpleNamespace(name="Content-Type", value="application/x-www-form-urlencoded")]
    form.request_body = "q=old...<truncated 4 chars>"
    with pytest.raises(ValueError, match="truncated"):
        build_captured_request(form, candidate(location="form", content_type="application/x-www-form-urlencoded"), "new")


def test_form_utf8_duplicates_and_escapes():
    body = "user=Nguy%C3%AAn&q=one+two&x=%2f&q=second%20value&native=Nguyên".encode()
    captured = row(body=body, content_type="application/x-www-form-urlencoded")
    request, _ = build_captured_request(captured, candidate(location="form", content_type="application/x-www-form-urlencoded"),
                                        "mới value", occurrence=1)
    assert request.content == body.replace(b"q=second%20value", b"q=m%E1%BB%9Bi+value")


@pytest.mark.parametrize("name", [b'name="q"', b"name='q'", b"name=q"])
def test_multipart_names_and_boundary_collision(name):
    body = b"--lab\r\nContent-Disposition: form-data; " + name + b"\r\n\r\nold\r\n--lab--\r\n"
    captured = row(body=body, content_type="multipart/form-data; boundary=lab", raw=True)
    request, _ = build_captured_request(captured, candidate(content_type="multipart/form-data"), "new")
    assert request.content == body.replace(b"old", b"new")
    with pytest.raises(ValueError, match="boundary"):
        build_captured_request(captured, candidate(content_type="multipart/form-data"), "x--laby")


def test_multipart_duplicate_names_mutate_only_selected_occurrence():
    body = (b"--lab\r\nContent-Disposition: form-data; name=q\r\n\r\nfirst\r\n"
            b"--lab\r\nContent-Disposition: form-data; name=q\r\n\r\nsecond\r\n--lab--\r\n")
    request, _ = build_captured_request(
        row(body=body, content_type="multipart/form-data; boundary=lab", raw=True),
        candidate(content_type="multipart/form-data"), "new", occurrence=1)
    assert request.content == body.replace(b"second", b"new")
    assert request.content.count(b"\r\n--lab") == body.count(b"\r\n--lab")


def test_proxy_headers_are_not_forwarded_from_capture():
    captured = row(body=b"q=old", content_type="application/x-www-form-urlencoded")
    captured.request_headers.extend([SimpleNamespace(name="Proxy-Authorization", value="Basic hidden"),
                                     SimpleNamespace(name="Connection", value="X-Hop"),
                                     SimpleNamespace(name="X-Hop", value="hidden")])
    request, _ = build_captured_request(captured, candidate(location="form", content_type="application/x-www-form-urlencoded"), "new")
    assert "proxy-authorization" not in request.headers and "x-hop" not in request.headers
