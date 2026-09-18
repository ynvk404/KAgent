from src.findings.store import Finding
from src.findings.http_request import finding_request_for_burp


def finding_with_curl(curl: str) -> Finding:
    return Finding(
        title="Finding",
        severity="high",
        url="https://app.example.com/fallback",
        impact="Impact.",
        curl=curl,
        createdAt="2026-06-02T12:21:02.243Z",
        slug="finding",
    )


def test_data_urlencode_plain_content_is_percent_encoded():
    request = finding_request_for_burp(
        finding_with_curl(
            'curl --data-urlencode "a b/c" '
            '"https://app.example.com/api/search"'
        )
    )

    assert "POST /api/search HTTP/1.1" in request
    assert request.endswith("\r\n\r\na%20b%2Fc")


def test_data_urlencode_name_equals_content_only_encodes_content():
    request = finding_request_for_burp(
        finding_with_curl(
            'curl --data-urlencode "query=a/b c" '
            '"https://app.example.com/api/search"'
        )
    )

    assert request.endswith("\r\n\r\nquery=a%2Fb%20c")


def test_data_urlencode_name_at_file_uses_placeholder():
    request = finding_request_for_burp(
        finding_with_curl(
            'curl --data-urlencode "avatar@photo.png" '
            '"https://app.example.com/api/upload"'
        )
    )

    assert (
        "avatar=<URL-encoded contents of file photo.png>"
        in request
    )


def test_data_urlencode_leading_at_file_uses_whole_body_placeholder():
    request = finding_request_for_burp(
        finding_with_curl(
            'curl --data-urlencode "@body.json" '
            '"https://app.example.com/api/upload"'
        )
    )

    assert (
        "<URL-encoded contents of file body.json>"
        in request
    )


def test_userinfo_in_target_url_is_stripped_from_host_header():
    request = finding_request_for_burp(
        finding_with_curl(
            "curl https://alice:s3cr3t@app.example.com:8443/api/x"
        )
    )

    assert "Host: app.example.com:8443" in request
    assert "alice" not in request
    assert "s3cr3t" not in request

def test_user_equals_form_sets_basic_auth_header():
    request = finding_request_for_burp(
        finding_with_curl(
            "curl --user=alice:secret "
            "https://app.example.com/api/session"
        )
    )

    assert "Authorization: Basic YWxpY2U6c2VjcmV0" in request


def test_form_flag_falls_back_instead_of_misrepresenting_multipart_body():
    request = finding_request_for_burp(
        finding_with_curl(
            'curl -F "file=@upload.txt" '
            "https://app.example.com/api/upload"
        )
    )

    assert request == (
        "GET /fallback HTTP/1.1\r\n"
        "Host: app.example.com\r\n"
        "User-Agent: kagent\r\n"
        "\r\n"
    )


def test_ipv6_host_keeps_required_brackets_and_port():
    request = finding_request_for_burp(
        finding_with_curl("curl http://[::1]:8080/test")
    )

    assert "Host: [::1]:8080" in request


def test_get_moves_data_to_the_query_string():
    request = finding_request_for_burp(
        finding_with_curl(
            "curl -G -d 'q=test' https://example.com/search?existing=1"
        )
    )

    assert request.startswith("GET /search?existing=1&q=test HTTP/1.1")
    assert "Content-Length:" not in request
    assert request.endswith("\r\n\r\n")


def test_json_sets_json_content_type_and_post_body():
    request = finding_request_for_burp(
        finding_with_curl("curl --json '{\"name\": \"test\"}' https://example.com/api")
    )

    assert request.startswith("POST /api HTTP/1.1")
    assert "Content-Type: application/json" in request
    assert request.endswith('\r\n\r\n{"name": "test"}')


def test_explicit_host_header_from_curl_is_not_duplicated():
    request = finding_request_for_burp(
        finding_with_curl(
            'curl https://app.example.com/api/x '
            '-H "Host: internal.example.com"'
        )
    )

    assert request.count("Host:") == 1
    assert "Host: internal.example.com" in request
    assert "Host: app.example.com" not in request

def test_unterminated_quote_falls_back_instead_of_raising():
    finding = finding_with_curl('curl "https://app.example.com/api/x')
    finding.url = "https://app.example.com/api/fallback"
    finding.method = "GET"

    request = finding_request_for_burp(finding)

    assert request == (
        "GET /api/fallback HTTP/1.1\r\n"
        "Host: app.example.com\r\n"
        "User-Agent: kagent\r\n"
        "\r\n"
    )


def test_lf_line_continuation_is_joined():
    request = finding_request_for_burp(
        finding_with_curl(
            "curl https://app.example.com/api/x \\\n"
            '  -H "X-Test: one"'
        )
    )

    assert "X-Test: one" in request


def test_crlf_line_continuation_is_joined():
    request = finding_request_for_burp(
        finding_with_curl(
            "curl https://app.example.com/api/x \\\r\n"
            '  -H "X-Test: two"'
        )
    )

    assert "X-Test: two" in request
