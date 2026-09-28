
from __future__ import annotations

import importlib
import json
import os
import re

import pytest

ESC = chr(0x1B)
_ANSI_RE = re.compile(rf"{re.escape(ESC)}\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


GREEN = f"{ESC}[32m"
RED = f"{ESC}[31m"
YELLOW = f"{ESC}[33m"


@pytest.fixture(scope="module", autouse=True)
def t(request):
    os.environ.pop("NO_COLOR", None)
    os.environ["FORCE_COLOR"] = "1"
    module = importlib.import_module("src.ui.render.tool_result_format")
    importlib.reload(module)
    yield module
    os.environ.pop("FORCE_COLOR", None)


class TestLooksLikeShellResult:
    def test_recognises_exit_line_opener(self, t):
        assert t.looks_like_shell_result("exit: 0\nstdout:\nhello") is True
        assert t.looks_like_shell_result("exit: 1\nstderr:\nboom") is True

    def test_recognises_bare_stdout_opener(self, t):
        assert t.looks_like_shell_result("stdout:\nhello") is True

    def test_rejects_plain_prose(self, t):
        assert t.looks_like_shell_result("the file contains 12 lines of yaml") is False
        assert t.looks_like_shell_result("") is False


class TestColorizeShellResult:
    def test_colors_exit_0_green_and_dims_label(self, t):
        out = t.colorize_shell_result("exit: 0\nstdout:\nhello")
        assert GREEN in out
        assert strip_ansi(out) == "exit: 0\nstdout:\nhello"

    def test_colors_nonzero_exit_red(self, t):
        out = t.colorize_shell_result("exit: 3\nstdout:\nhello\nstderr:\nboom")
        assert RED in out
        assert "exit: 3" in strip_ansi(out)

    def test_colors_timeout_exit_yellow(self, t):
        out = t.colorize_shell_result("exit: timeout after 300s\nstdout:\n")
        assert YELLOW in out
        assert "exit: timeout" in strip_ansi(out)

    def test_tints_stderr_section_red_but_leaves_stdout_alone(self, t):
        out = t.colorize_shell_result("exit: 1\nstdout:\nfine line\nstderr:\nbad line")
        assert "fine line" in out  
        idx = out.index("bad line")
        assert idx > 0
        assert RED in out[:idx]

    def test_passes_blank_lines_and_plain_text_inside_stdout_unchanged(self, t):
        input_ = "exit: 0\nstdout:\nline a\n\nline b"
        assert strip_ansi(t.colorize_shell_result(input_)) == input_

    def test_empty_input_returns_empty(self, t):
        assert t.colorize_shell_result("") == ""


class TestExtractTextContent:
    def test_pulls_text_out_of_mcp_text_block_array(self, t):
        raw = json.dumps(
            [{"type": "text", "text": "- Page URL: x\n- Title: Google"}], indent=2
        )
        assert t.extract_text_content(raw) == "- Page URL: x\n- Title: Google"

    def test_joins_multiple_text_blocks_with_newlines(self, t):
        raw = json.dumps([{"type": "text", "text": "one"}, {"type": "text", "text": "two"}])
        assert t.extract_text_content(raw) == "one\ntwo"

    def test_leaves_non_text_content_as_raw_json(self, t):
        raw = json.dumps([{"type": "image", "data": "base64..."}])
        assert t.extract_text_content(raw) == raw

    def test_passes_plain_non_json_strings_through_unchanged(self, t):
        assert t.extract_text_content("exit: 0\nstdout:\nhi") == "exit: 0\nstdout:\nhi"


class TestBuildToolResultView:
    def test_compacts_successful_shell_stdout_to_meaningful_output(self, t):
        v = t.build_tool_result_view("exit: 0\nstdout:\n404 ftp.gobus.net")
        assert v.collapsible is False
        assert strip_ansi(v.preview) == "404 ftp.gobus.net"

    def test_removes_exit_stdout_wrappers_from_multiline_successful_output(self, t):
        html = "\n".join(
            [
                "<!DOCTYPE html>",
                '<html lang="ar" dir="rtl">',
                "<head>",
                '  <meta charset="UTF-8" />',
            ]
        )
        v = t.build_tool_result_view(f"exit: 0\r\nstdout:\r\n{html}")
        plain = strip_ansi(v.preview)
        assert plain == html
        assert "exit: 0" not in plain
        assert "stdout:" not in plain

    def test_keeps_shell_structure_when_exit_nonzero_or_stderr_exists(self, t):
        failed = t.build_tool_result_view("exit: 1\nstdout:\nnope")
        assert "exit: 1" in strip_ansi(failed.preview)
        assert "stdout:\nnope" in strip_ansi(failed.preview)

        warned = t.build_tool_result_view("exit: 0\nstdout:\nok\nstderr:\nwarning")
        assert "exit: 0" in strip_ansi(warned.preview)
        assert "stderr:\nwarning" in strip_ansi(warned.preview)

    def test_renders_empty_nonzero_shell_output_as_no_output(self, t):
        v = t.build_tool_result_view("exit: 1\nstdout:\n")
        assert strip_ansi(v.preview) == "exit: 1\n(no output)"

    def test_omits_empty_stdout_when_nonzero_shell_result_only_has_stderr(self, t):
        v = t.build_tool_result_view(
            "\n".join(
                [
                    "exit: 2",
                    "stdout:",
                    "stderr:",
                    "/bin/bash: -c: line 0: unexpected EOF while looking for matching `''",
                    "/bin/bash: -c: line 1: syntax error: unexpected end of file",
                ]
            )
        )
        plain = strip_ansi(v.preview)
        assert "exit: 2\nstderr:\n/bin/bash" in plain
        assert "stdout:" not in plain

    def test_does_not_collapse_short_output(self, t):
        v = t.build_tool_result_view("a\nb\nc")
        assert v.collapsible is False
        assert v.preview == v.full

    def test_collapses_long_output_to_head_preview_with_expand_notice(self, t):
        body = "\n".join(f"line {i}" for i in range(200))
        v = t.build_tool_result_view(body)
        assert v.collapsible is True
        preview_lines = strip_ansi(v.preview).split("\n")
        assert len(preview_lines) == 6
        assert preview_lines[:5] == [f"line {i}" for i in range(5)]
        assert "more lines" in strip_ansi(v.preview)
        assert "Ctrl-O to expand" in strip_ansi(v.preview)
        assert "line 199" in strip_ansi(v.full)

    def test_collapses_giant_single_line_by_char_cap(self, t):
        v = t.build_tool_result_view("x" * 5000)
        assert v.collapsible is True
        preview_lines = strip_ansi(v.preview).splitlines()
        assert len(preview_lines) == 2
        assert len(preview_lines[0]) <= t.PREVIEW_LINE_CHAR_CAP + 24
        assert "<5000 chars>" in preview_lines[0]
        assert "Ctrl-O to expand" in strip_ansi(v.preview)

    def test_extracts_mcp_text_then_collapses_it(self, t):
        snapshot = "\n".join(f'  link "item {i}"' for i in range(100))
        raw = json.dumps([{"type": "text", "text": snapshot}])
        v = t.build_tool_result_view(raw)
        assert v.collapsible is True
        assert '"type"' not in strip_ansi(v.preview)
        assert 'link "item 0"' in strip_ansi(v.preview)


def http_resp(status: str, body: str = "") -> str:
    return f"HTTP/1.1 {status}\ncontent-type: application/json\nserver: nginx\n\n{body}"


def noisy_http_resp(status: str, body: str = "") -> str:
    headers = [
        "content-type: text/plain; charset=utf-8",
        "etag: \"abc123\"",
        "x-recruiting: /#/jobs",
        "cache-control: public, max-age=0",
        "accept-ranges: bytes",
        "last-modified: Mon, 01 Jan 2024 00:00:00 GMT",
        "x-frame-options: SAMEORIGIN",
        "feature-policy: payment 'self'",
        "connection: keep-alive",
        "date: Mon, 01 Jan 2024 00:00:00 GMT",
        "vary: accept-encoding",
        "x-content-type-options: nosniff",
        "x-request-id: request-1",
        "server: nginx",
        "pragma: no-cache",
        "expires: 0",
        "access-control-allow-origin: *",
    ]
    if 300 <= int(status.split()[0]) < 400:
        headers.insert(1, "location: /login")
    return "\n".join([f"HTTP/1.1 {status}", *headers, "", *body.split("\n")])


class TestLooksLikeHTTPResult:
    def test_recognises_http_response_rejects_other_shapes(self, t):
        assert t.looks_like_http_result("HTTP/1.1 200 OK\n\n{}") is True
        assert t.looks_like_http_result("HTTP/2 404 Not Found") is True
        assert t.looks_like_http_result("exit: 0\nstdout:\nhi") is False
        assert t.looks_like_http_result("just some text") is False


class TestColorizeHTTPResult:
    def test_colors_2xx_green_4xx_yellow_5xx_red(self, t):
        assert GREEN in t.colorize_http_result(http_resp("200 OK", '{"ok":true}'))
        assert YELLOW in t.colorize_http_result(http_resp("403 Forbidden"))
        assert RED in t.colorize_http_result(http_resp("500 Internal Server Error"))

    def test_keeps_status_line_and_header_values_readable(self, t):
        stripped = strip_ansi(t.colorize_http_result(http_resp("200 OK")))
        assert "HTTP/1.1 200 OK" in stripped
        assert "content-type: application/json" in stripped
        assert "server: nginx" in stripped

    def test_does_not_change_line_count(self, t):
        body = http_resp("200 OK", '{"a":1}')
        assert len(t.colorize_http_result(body).split("\n")) == len(body.split("\n"))

    def test_passes_non_http_body_through_unchanged(self, t):
        assert t.colorize_http_result("not http") == "not http"


class TestBuildToolResultViewRoutesHTTP:
    def test_colorizes_an_http_tool_result(self, t):
        raw = http_resp("301 Moved Permanently")
        view = t.build_tool_result_view(raw)
        assert view.full != raw  
        assert "301 Moved Permanently" in strip_ansi(view.full)

    def test_http_preview_keeps_status_and_content_type_without_dumping_headers(self, t):
        raw = noisy_http_resp("200 OK", "body first\nbody second\nbody third\nbody fourth")
        view = t.build_tool_result_view(raw)

        assert view.collapsible is True
        preview = strip_ansi(view.preview)
        assert "HTTP/1.1 200 OK" in preview
        assert "content-type: text/plain; charset=utf-8" in preview
        assert "etag:" not in preview
        assert "x-recruiting:" not in preview
        assert "cache-control:" not in preview
        assert "body first\nbody second\nbody third" in preview
        assert "body fourth" not in preview
        assert strip_ansi(view.full) == raw

    def test_http_body_preview_shows_at_most_three_lines(self, t):
        body = "\n".join(f"body line {index}" for index in range(8))
        preview = strip_ansi(t.build_tool_result_view(noisy_http_resp("200 OK", body)).preview)
        before_notice = preview.rsplit("\n… ", 1)[0]
        body_preview = before_notice.split("\n\n", 1)[1]

        assert body_preview.splitlines() == [
            "body line 0",
            "body line 1",
            "body line 2",
        ]

    def test_http_redirect_preview_keeps_location(self, t):
        view = t.build_tool_result_view(
            noisy_http_resp("302 Found", "<!doctype html>\n<html>\n...\n</html>")
        )
        preview = strip_ansi(view.preview)

        assert "HTTP/1.1 302 Found" in preview
        assert "location: /login" in preview
        assert "etag:" not in preview

    def test_http_no_body_preview_has_no_empty_body_block(self, t):
        view = t.build_tool_result_view(noisy_http_resp("204 No Content"))
        preview = strip_ansi(view.preview)

        assert "HTTP/1.1 204 No Content" in preview
        assert "\n\n" not in preview
        assert all(line.strip() for line in preview.splitlines())

    def test_malformed_http_uses_compact_generic_preview(self, t):
        raw = "\n".join(
            ["HTTP/1.1 200 OK", "malformed header"]
            + [f"generic line {index}" for index in range(20)]
        )
        preview = strip_ansi(t.build_tool_result_view(raw).preview).splitlines()

        assert preview[:5] == [
            "HTTP/1.1 200 OK",
            "malformed header",
            "generic line 0",
            "generic line 1",
            "generic line 2",
        ]
        assert len(preview) == 6

    def test_http_preview_keeps_body_truncation_marker_visible(self, t):
        body = "\n".join(
            ["body first", "body second", "body third", "body fourth", "[response body truncated at 65536 bytes]"]
        )
        view = t.build_tool_result_view(noisy_http_resp("200 OK", body))

        assert "[response body truncated at 65536 bytes]" in strip_ansi(view.preview)
