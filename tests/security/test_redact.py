import pytest

from src.redact.redact import apply


def test_redacts_json_style_quoted_api_key_assignment():
    secret = "abcdefghijklmnop"

    redacted = apply(f'{{"api_key": "{secret}"}}')

    assert secret not in redacted
    assert '"api_key": "ab…[REDACTED:' in redacted


def test_redacts_short_json_password_without_altering_safe_examples():
    text = '{"username":"admin","password":"admin123"}'

    redacted = apply(text)

    assert "admin123" not in redacted
    assert '"username":"admin","password":' in redacted
    assert apply("' OR 1=1 --") == "' OR 1=1 --"
    assert apply('\"><script>alert(1)</script>') == '\"><script>alert(1)</script>'
    assert apply("http://juice.lab:3000/rest/user/login") == (
        "http://juice.lab:3000/rest/user/login"
    )


@pytest.mark.parametrize(
    "text",
    [
        "Set-Cookie: session=abcdef0123456789; Path=/; HttpOnly",
        "https://target.test/?token=abc%2Fdef%3Dghi",
    ],
)
def test_redaction_is_idempotent_for_masked_header_and_query_values(text):
    once = apply(text)

    assert apply(once) == once


@pytest.mark.parametrize(
    "text,secret",
    [
        (
            "Cookie: session=attacker[REDACTED]controlled; Path=/",
            "session=attacker[REDACTED]controlled; Path=/",
        ),
        (
            "https://target.test/?token=attacker[REDACTED]controlled",
            "attacker[REDACTED]controlled",
        ),
    ],
)
def test_literal_redacted_substring_in_real_secret_does_not_bypass(text, secret):
    assert secret not in apply(text)
