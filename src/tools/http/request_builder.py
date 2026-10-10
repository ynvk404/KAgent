"""Small, byte-preserving request mutation helpers for captured HTTP traffic."""
from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
from dataclasses import dataclass
from email.message import Message
from typing import Any
from urllib.parse import quote, quote_plus, unquote_plus, unquote_to_bytes, urlsplit, urlunsplit

import httpx

from src.target.origin import HTTPOrigin
from src.version import VERSION

NATIVE_USER_AGENT = f"KAgent/{VERSION}"
DROP_REQUEST_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection",
    "proxy-connection", "proxy-authorization", "proxy-authenticate",
    "keep-alive", "te", "trailer", "upgrade",
})


def validate_host(headers: Any, url: str) -> None:
    host = headers.get("host")
    if host and HTTPOrigin.from_url(f"{urlsplit(url).scheme}://{host}") != HTTPOrigin.from_url(url):
        raise ValueError("Host override differs from approved origin; explicit virtual-host scope is required")


def origin_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    nominated = {token.strip().lower() for key, value in headers if key.lower() == "connection"
                 for token in value.split(",")}
    dropped = DROP_REQUEST_HEADERS | nominated
    return [(key, value) for key, value in headers if key.lower() not in dropped]


def _truncated(value: Any) -> bool:
    if isinstance(value, str):
        return "...<truncated " in value
    if isinstance(value, dict):
        return any(_truncated(item) for item in value.values())
    if isinstance(value, list):
        return any(_truncated(item) for item in value)
    return False


@dataclass(frozen=True)
class RequestDiff:
    location: str
    input_path: str
    occurrence: int
    before_bytes: int
    after_bytes: int

    def summary(self) -> str:
        return (f"mutation: {self.location} {self.input_path} occurrence={self.occurrence}; "
                f"body bytes {self.before_bytes}->{self.after_bytes}; non-target body bytes preserved")


def _raw_capture(row: Any) -> tuple[str, str, list[tuple[str, str]], bytes]:
    if getattr(row, "raw_request_oversize", False):
        raise ValueError("captured raw request exceeds replay size limit")
    raw_b64 = getattr(row, "raw_request_b64", None)
    if raw_b64:
        try:
            raw = base64.b64decode(raw_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("captured raw request base64 is invalid") from exc
        head, marker, body = raw.partition(b"\r\n\r\n")
        if not marker:
            raise ValueError("captured raw request has no header terminator")
        lines = head.split(b"\r\n")
        first = lines[0].split(b" ")
        if len(first) != 3 or first[0].decode("ascii") != str(row.method).upper() or first[2] != b"HTTP/1.1":
            raise ValueError("captured raw request line is invalid")
        raw_target = first[1].decode("ascii")
        expected = urlsplit(str(row.url))
        if raw_target != (expected.path or "/") + ("?" + expected.query if expected.query else ""):
            raise ValueError("captured raw request target differs from capture URL")
        headers = []
        for line in lines[1:]:
            name, sep, value = line.partition(b":")
            if not sep:
                raise ValueError("captured raw header is invalid")
            headers.append((name.decode("ascii"), value.strip().decode("latin1")))
        parsed_headers = httpx.Headers(headers)
        if not parsed_headers.get("host"):
            raise ValueError("captured Host is missing")
        validate_host(parsed_headers, str(row.url))
        if "transfer-encoding" in parsed_headers:
            raise ValueError("chunked captured request is not replayable")
        if body and "content-length" not in parsed_headers:
            raise ValueError("captured raw body has no framing; recapture required")
        if "content-length" in parsed_headers and int(parsed_headers["content-length"]) != len(body):
            raise ValueError("captured body length differs from framing")
        return str(row.method).upper(), str(row.url), headers, body
    headers = [(h.name, h.value) for h in (getattr(row, "request_headers", None) or [])]
    if not headers:
        raise ValueError("captured request headers are unavailable")
    parsed_headers = httpx.Headers(headers)
    validate_host(parsed_headers, str(row.url))
    if "transfer-encoding" in parsed_headers:
        raise ValueError("captured transfer encoding requires raw recapture")
    body = getattr(row, "request_body", None)
    if _truncated(body):
        raise ValueError("captured request body is truncated")
    if body is None:
        if int(parsed_headers.get("content-length", "0")) > 0:
            raise ValueError("captured request body is missing; recapture required")
        payload = b""
    elif isinstance(body, str):
        payload = body.encode("utf-8")
    elif isinstance(body, dict) and body.get("type") == "raw" and isinstance(body.get("data"), str):
        payload = body["data"].encode("utf-8")
    elif isinstance(body, (dict, list)):
        raise ValueError("structured capture has no original body bytes; raw recapture required")
    else:
        raise ValueError("captured body is not replayable")
    if "content-length" in parsed_headers and int(parsed_headers["content-length"]) != len(payload):
        raise ValueError("structured capture differs from Content-Length; raw recapture required")
    return str(row.method).upper(), str(row.url), headers, payload


def _replace_pair(raw: str, key: str, value: str, occurrence: int) -> str:
    parts = raw.split("&")
    matches = [i for i, part in enumerate(parts) if unquote_plus(part.partition("=")[0]) == key]
    if not matches or occurrence >= len(matches):
        raise ValueError("target parameter occurrence is absent from baseline")
    i = matches[occurrence]
    old = parts[i]
    key_raw, _, _ = old.partition("=")
    parts[i] = key_raw + "=" + quote_plus(value)
    return "&".join(parts)


def _json_path(parameter: str, supplied: str | None) -> list[str]:
    path = supplied or parameter
    if path.startswith("/"):
        if re.search(r"~(?![01])", path):
            raise ValueError("invalid JSON Pointer escape")
        tokens = [part.replace("~1", "/").replace("~0", "~") for part in path.split("/")[1:]]
    else:
        if not re.fullmatch(r"[^.\[\]]+(?:\.[^.\[\]]+|\[(?:0|[1-9][0-9]*)\])*", path):
            raise ValueError("invalid JSON path syntax")
        tokens = re.findall(r"[^.\[\]]+", path)
    if not tokens:
        raise ValueError("JSON path does not identify the candidate parameter")
    identifies_field = tokens[-1] == parameter or (
        len(tokens) >= 2 and tokens[-2] == parameter and tokens[-1].isdigit()
    )
    if supplied and not identifies_field and supplied != parameter:
        raise ValueError("JSON path does not identify the candidate parameter")
    return tokens


def _replace_json(body: bytes, parameter: str, value: str, input_path: str | None) -> bytes:
    try:
        source = body.decode("utf-8")
        def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON keys make safe mutation unsupported")
                result[key] = item
            return result
        json.loads(source, object_pairs_hook=unique_pairs)
    except UnicodeDecodeError as exc:
        raise ValueError("unsupported JSON body encoding") from exc
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds safe mutation limit") from exc
    tokens = _json_path(parameter, input_path)
    spans: dict[tuple[str, ...], tuple[int, int, Any]] = {}
    decoder = json.JSONDecoder()

    def skip(index: int) -> int:
        while index < len(source) and source[index] in " \t\r\n":
            index += 1
        return index

    def scan(index: int, path: tuple[str, ...]) -> int:
        index = skip(index)
        start = index
        if source[index] == "{":
            index = skip(index + 1)
            if source[index] == "}":
                return index + 1
            while True:
                key, end = decoder.raw_decode(source, index)
                if not isinstance(key, str):
                    raise ValueError("invalid JSON object key")
                index = skip(end)
                if source[index] != ":":
                    raise ValueError("invalid JSON object separator")
                index = skip(scan(index + 1, (*path, key)))
                if source[index] == "}":
                    return index + 1
                if source[index] != ",":
                    raise ValueError("invalid JSON object delimiter")
                index = skip(index + 1)
        if source[index] == "[":
            index = skip(index + 1)
            if source[index] == "]":
                return index + 1
            number = 0
            while True:
                index = skip(scan(index, (*path, str(number))))
                if source[index] == "]":
                    return index + 1
                if source[index] != ",":
                    raise ValueError("invalid JSON array delimiter")
                index = skip(index + 1)
                number += 1
        parsed, end = decoder.raw_decode(source, index)
        if isinstance(parsed, (dict, list)):
            raise ValueError("JSON target parser lost structure")
        spans[path] = (start, end, parsed)
        return end

    try:
        if skip(scan(0, ())) != len(source):
            raise ValueError("JSON has trailing bytes")
    except (IndexError, TypeError, RecursionError) as exc:
        raise ValueError("invalid JSON structure") from exc
    target = spans.get(tuple(tokens))
    if target is None:
        raise ValueError("JSON scalar path is absent from baseline")
    start, end, before = target
    if before == value:
        raise ValueError("mutation value equals baseline value")
    return (source[:start] + json.dumps(value, ensure_ascii=False) + source[end:]).encode("utf-8")


def _validate_form_charset(content_type: str) -> None:
    header = Message()
    header["Content-Type"] = content_type
    charsets = [value for name, value in header.get_params() or [] if name.lower() == "charset"]
    if len(charsets) > 1:
        raise ValueError("ambiguous form charset; recapture required")
    if charsets:
        try:
            charset = charsets[0]
            supported = isinstance(charset, str) and codecs.lookup(charset).name == "utf-8"
        except (LookupError, TypeError):
            supported = False
        if not supported:
            raise ValueError("unsupported form charset; UTF-8 recapture required")


def _replace_form(body: bytes, parameter: str, value: str, occurrence: int) -> bytes:
    parts = body.split(b"&")
    matches = []
    for index, part in enumerate(parts):
        key = part.partition(b"=")[0]
        try:
            decoded = unquote_to_bytes(key.replace(b"+", b" ")).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("unsupported form key encoding") from exc
        if decoded == parameter:
            matches.append(index)
    if occurrence >= len(matches):
        raise ValueError("form target occurrence is absent")
    index = matches[occurrence]
    key = parts[index].partition(b"=")[0]
    parts[index] = key + b"=" + quote_plus(value, encoding="utf-8").encode("ascii")
    return b"&".join(parts)


def _replace_multipart(body: bytes, content_type: str, parameter: str, value: str, occurrence: int) -> bytes:
    match = re.search(r'(?:^|;)\s*boundary=(?:"([^"]+)"|([^;\s]+))', content_type, re.I)
    if not match:
        raise ValueError("multipart boundary is missing")
    boundary = (match.group(1) or match.group(2)).encode("ascii")
    delimiter = b"--" + boundary
    replacement = value.encode("utf-8")
    if delimiter in replacement:
        raise ValueError("multipart payload collides with boundary")
    if not body.startswith(delimiter + b"\r\n") or not body.rstrip(b"\r\n").endswith(delimiter + b"--"):
        raise ValueError("multipart framing does not match boundary")
    separator = b"\r\n" + delimiter
    # A prefix inside a file (e.g. CRLF--boundaryZ) is not a delimiter line.
    parts = re.split(re.escape(separator) + rb"(?=\r\n|--(?:\r\n|$))", body)
    if parts[-1] not in {b"--", b"--\r\n"}:
        raise ValueError("multipart closing delimiter is malformed")
    matches = []
    for i, part in enumerate(parts[:-1]):
        head, marker, content = part.partition(b"\r\n\r\n")
        dispositions = re.findall(rb"(?im)^content-disposition:[ \t]*([^\r\n]*)", head)
        if not marker or len(dispositions) != 1 or not re.match(rb"(?i)form-data(?:\s*;|$)", dispositions[0]):
            raise ValueError("multipart part headers are malformed or ambiguous")
        name_match = re.search(rb'(?i)(?:^|;)\s*name\s*=\s*(?:"([^"]+)"|\x27([^\x27]+)\x27|([^;\s]+))', dispositions[0])
        if name_match and next(group for group in name_match.groups() if group is not None) == parameter.encode():
            matches.append((i, head, content))
    if not matches or occurrence >= len(matches):
        raise ValueError("multipart target part is absent")
    i, head, content = matches[occurrence]
    if b"filename=" in head.lower():
        raise ValueError("binary file part mutation requires a dedicated byte payload")
    parts[i] = head + b"\r\n\r\n" + replacement
    return separator.join(parts)


def _captured_parts(row: Any, candidate: Any) -> tuple[str, str, list[tuple[str, str]], bytes]:
    """Validate the capture binding without consulting shared runtime identity."""
    method, url, raw_headers, body = _raw_capture(row)
    if urlsplit(url).username or urlsplit(url).password:
        raise ValueError("captured URL credentials require a credential-free recapture")
    if method != candidate.method or HTTPOrigin.from_url(url) != HTTPOrigin.from_url(candidate.target):
        raise ValueError("baseline method or origin differs from candidate")
    endpoint = urlsplit(candidate.endpoint or "").path
    pattern = '^' + re.sub(r'\\\{[^{}]+\\\}', r'[^/]+', re.escape(endpoint)) + '$'
    if endpoint and not re.fullmatch(pattern, urlsplit(url).path):
        raise ValueError("baseline path differs from candidate")
    content_type = httpx.Headers(raw_headers).get('content-type', '')
    if candidate.content_type and content_type.split(';', 1)[0].strip().lower() != candidate.content_type.split(';', 1)[0].strip().lower():
        raise ValueError('baseline content type differs from candidate')
    return method, url, raw_headers, body


def build_captured_baseline(row: Any, candidate: Any) -> httpx.Request:
    method, url, raw_headers, body = _captured_parts(row, candidate)
    return httpx.Request(method, url, headers=origin_headers(raw_headers), content=body)


def build_captured_request(row: Any, candidate: Any, value: str, *, occurrence: int = 0,
                           input_path: str | None = None, old_value: str | None = None) -> tuple[httpx.Request, RequestDiff]:
    method, url, raw_headers, body = _captured_parts(row, candidate)
    if not isinstance(value, str) or occurrence < 0:
        raise ValueError("mutation value and occurrence are invalid")
    header_map = httpx.Headers(raw_headers)
    content_type = header_map.get("content-type", "")
    if header_map.get("content-encoding", "identity").lower() != "identity":
        raise ValueError("encoded baseline request body cannot be safely mutated")
    parameter = candidate.parameter
    location = (candidate.location or "").lower()
    if not parameter or location not in {"query", "body", "form", "json", "path", "raw", "header", "cookie"}:
        raise ValueError("candidate has no supported target input")
    if location in {"header", "cookie"}:
        raise ValueError("header/cookie mutation is not supported by captured replay")
    original_size = len(body)
    parts = urlsplit(url)
    if location == "query":
        query = _replace_pair(parts.query, parameter, value, occurrence)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
    elif location == "path":
        if old_value is None:
            raise ValueError("path mutation needs the exact old segment")
        segments = parts.path.split("/")
        matches = [i for i, segment in enumerate(segments) if segment == old_value]
        if not matches or occurrence >= len(matches):
            raise ValueError("path target segment is absent")
        segments[matches[occurrence]] = quote(value, safe="")
        url = urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query, parts.fragment))
    elif "multipart/form-data" in content_type.lower():
        body = _replace_multipart(body, content_type, parameter, value, occurrence)
    elif location == "json" or "application/json" in content_type.lower() or "+json" in content_type.lower():
        body = _replace_json(body, parameter, value, input_path)
    elif location == "form" or "application/x-www-form-urlencoded" in content_type.lower():
        _validate_form_charset(content_type)
        body = _replace_form(body, parameter, value, occurrence)
    elif location in {"raw", "body"}:
        if old_value is None:
            raise ValueError("raw mutation needs the exact old value")
        old = old_value.encode("utf-8")
        if "xml" in content_type.lower():
            import xml.etree.ElementTree as ET
            if b"<!--" in body or b"<![CDATA[" in body:
                raise ValueError("XML comments/CDATA require a dedicated selector; replay unsupported")
            try:
                ET.fromstring(body)
            except ET.ParseError as exc:
                raise ValueError("malformed XML baseline") from exc
            tag = re.escape(parameter.encode("utf-8"))
            pattern = rb"<" + tag + rb"(?:\s[^<>]*)?>" + re.escape(old) + rb"</" + tag + rb">"
            matches = list(re.finditer(pattern, body))
            if len(matches) != 1 or occurrence:
                raise ValueError("XML target element with exact old value is absent")
            offset = matches[occurrence].end() - len(old) - len(tag) - 3
        else:
            matches = [m.start() for m in re.finditer(re.escape(old), body)]
            if len(matches) != 1 or occurrence:
                raise ValueError("raw target location is ambiguous or absent")
            offset = matches[0]
        body = body[:offset] + value.encode("utf-8") + body[offset + len(old):]
    else:
        raise ValueError("header/cookie mutation is not supported by captured replay")
    if HTTPOrigin.from_url(url) != HTTPOrigin.from_url(row.url):
        raise ValueError("mutation changed request origin")
    headers = origin_headers(raw_headers)
    request = httpx.Request(method, url, headers=headers, content=body)
    return request, RequestDiff(location, input_path or parameter, occurrence, original_size, len(body))
