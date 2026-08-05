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


def test_prefers_finding_curl_so_burp_imports_full_query_and_headers():
    request = finding_request_for_burp(
        Finding(
            title="IDOR",
            severity="high",
            url="https://wuzzuf.net/api/company/employers",
            method="GET",
            parameter="filter[status]",
            impact="Account enumeration.",
            curl=(
                'curl -ksS -X GET '
                '"https://wuzzuf.net/api/company/employers?'
                'include=employer.company&filter%5Bstatus%5D=1" '
                '-H "Authorization: Bearer <JWT_TOKEN>" '
                '-H "Accept: application/vnd.api+json" '
                '-H "X-Requested-With: XMLHttpRequest" '
                '-H "Referer: https://wuzzuf.net/dashboard"'
            ),
            createdAt="2026-06-02T12:21:02.243Z",
            slug="idor",
        )
    )

    assert (
        "GET /api/company/employers?"
        "include=employer.company&filter%5Bstatus%5D=1 HTTP/1.1"
        in request
    )
    assert "Host: wuzzuf.net" in request
    assert "Authorization: Bearer <JWT_TOKEN>" in request
    assert "Accept: application/vnd.api+json" in request
    assert "X-Requested-With: XMLHttpRequest" in request
    assert "Referer: https://wuzzuf.net/dashboard" in request


def test_reconstructs_post_requests_with_json_body_and_generated_length():
    request = finding_request_for_burp(
        finding_with_curl(
            'curl --json \'{"role":"admin"}\' '
            '"https://app.example.com/api/users/42" '
            '-H "Authorization: Bearer tok"'
        )
    )

    assert "POST /api/users/42 HTTP/1.1" in request
    assert "Host: app.example.com" in request
    assert "Content-Type: application/json" in request
    assert "Authorization: Bearer tok" in request
    assert "Content-Length: 16" in request
    assert request.endswith('\r\n\r\n{"role":"admin"}')


def test_keeps_arbitrary_methods_from_curl_option_forms():
    request = finding_request_for_burp(
        finding_with_curl(
            "curl --request=PATCH "
            "--url=https://app.example.com/api/profile "
            '-H "Content-Type: application/json" '
            '--data-raw=\'{"name":"x"}\''
        )
    )

    assert "PATCH /api/profile HTTP/1.1" in request
    assert "Content-Type: application/json" in request
    assert request.endswith('\r\n\r\n{"name":"x"}')


def test_includes_cookie_and_basic_auth_headers():
    request = finding_request_for_burp(
        finding_with_curl(
            "curl -XDELETE "
            "https://app.example.com/api/session "
            '-b "sid=abc; theme=dark" '
            "-u alice:secret"
        )
    )

    assert "DELETE /api/session HTTP/1.1" in request
    assert "Cookie: sid=abc; theme=dark" in request
    assert (
        "Authorization: Basic YWxpY2U6c2VjcmV0"
        in request
    )


def test_emits_curl_user_agent_header_forms():
    space = finding_request_for_burp(
        finding_with_curl(
            'curl -A "MyScanner/1.0" '
            "https://app.example.com/api/x"
        )
    )

    assert "User-Agent: MyScanner/1.0" in space
    assert "User-Agent: kagent" not in space


    long = finding_request_for_burp(
        finding_with_curl(
            'curl --user-agent "Custom UA" '
            "https://app.example.com/api/x"
        )
    )

    assert "User-Agent: Custom UA" in long
    assert "User-Agent: kagent" not in long


    attached = finding_request_for_burp(
        finding_with_curl(
            "curl -AAttachedUA "
            "https://app.example.com/api/x"
        )
    )

    assert "User-Agent: AttachedUA" in attached


    eq = finding_request_for_burp(
        finding_with_curl(
            "curl --user-agent=EqualsUA "
            "https://app.example.com/api/x"
        )
    )

    assert "User-Agent: EqualsUA" in eq


def test_falls_back_to_finding_url_and_method_when_no_curl_parsed():
    finding = finding_with_curl("echo not-curl")

    finding.url = "https://app.example.com/api/items?id=7"
    finding.method = "OPTIONS"

    request = finding_request_for_burp(finding)

    assert request == (
        "OPTIONS /api/items?id=7 HTTP/1.1\r\n"
        "Host: app.example.com\r\n"
        "User-Agent: kagent\r\n"
        "\r\n"
    )