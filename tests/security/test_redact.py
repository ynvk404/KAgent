import json

import pytest

from src.redact.redact import apply, redact_payload


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


def test_redacts_nested_sensitive_fields_and_preserves_injection_marker():
    payload = {
        "outer": {
            "csrf_token": "{INJECTION_POINT}",
            "session_cookie": "session-secret",
            "username": "alice",
        }
    }

    sanitized = redact_payload(payload)

    assert sanitized == {
        "outer": {
            "csrf_token": "{INJECTION_POINT}",
            "session_cookie": "[REDACTED]",
            "username": "alice",
        }
    }
    logged = apply('{"csrf_token":"{INJECTION_POINT}"}')
    assert '"csrf_token":"{INJECTION_POINT}"' in logged


@pytest.mark.parametrize("field", ["password", "access_token"])
def test_sensitive_field_keeps_exact_injection_marker(field: str):
    marker = redact_payload({field: "{INJECTION_POINT}"})
    secret = redact_payload({field: "real-secret"})
    compound = redact_payload({field: "real-secret-{INJECTION_POINT}"})

    assert marker[field] == "{INJECTION_POINT}"
    assert secret[field] == "[REDACTED]"
    assert compound[field] == "[REDACTED]"


def test_redacts_form_encoded_short_secrets_and_keeps_safe_fields_and_marker():
    value = "username=alice&password=demo-pass&csrf_token={INJECTION_POINT}"

    sanitized = redact_payload(value)

    assert "username=alice" in sanitized
    assert "demo-pass" not in sanitized
    assert "csrf_token={INJECTION_POINT}" in sanitized


def test_redacts_nested_json_request_skeleton_without_removing_email_or_marker():
    raw = (
        '{"auth":{"access_token":"nested-secret"},'
        '"filters":{"q":"{INJECTION_POINT}","email":"user@example.test"}}'
    )

    sanitized = redact_payload(raw)

    assert "nested-secret" not in sanitized
    assert "{INJECTION_POINT}" in sanitized
    assert "user@example.test" in sanitized


def test_redacts_sensitive_multipart_parts_and_keeps_injection_field():
    value = (
        "--fixture\r\n"
        'Content-Disposition: form-data; name="username"\r\n\r\n'
        "alice\r\n"
        "--fixture\r\n"
        'Content-Disposition: form-data; name="password"\r\n\r\n'
        "multipart-password-secret\r\n"
        "--fixture\r\n"
        'Content-Disposition: form-data; name="session_cookie"\r\n\r\n'
        "session-secret\r\n"
        "--fixture\r\n"
        'Content-Disposition: form-data; name="csrf_token"\r\n\r\n'
        "{INJECTION_POINT}\r\n"
        "--fixture--\r\n"
    )

    sanitized = redact_payload({
        "content_type": "multipart/form-data; boundary=fixture",
        "sample_payload": value,
    })["sample_payload"]

    assert "name=\"username\"" in sanitized and "alice" in sanitized
    assert "session-secret" not in sanitized
    assert "multipart-password-secret" not in sanitized
    assert "name=\"csrf_token\"" in sanitized
    assert "{INJECTION_POINT}" in sanitized


def test_session_identifier_is_not_classified_as_a_secret_in_dict_or_json():
    assert redact_payload({"session_id": "runtime-session-123"}) == {
        "session_id": "runtime-session-123"
    }
    serialized = redact_payload('{"session_id":"runtime-session-123"}')
    assert json.loads(serialized) == {"session_id": "runtime-session-123"}

    credentials = json.loads(redact_payload(
        '{"session_cookie":"cookie-secret","session_token":"token-secret"}'
    ))
    assert credentials["session_cookie"] == "[REDACTED]"
    assert credentials["session_token"] == "[REDACTED]"


@pytest.mark.parametrize("field", ["password", "access_token"])
@pytest.mark.parametrize("position", ["first", "middle", "last"])
@pytest.mark.parametrize("marker", ["{INJECTION_POINT}", "%7BINJECTION_POINT%7D"])
def test_form_marker_is_preserved_independent_of_field_order(
    field: str, position: str, marker: str
):
    target = (field, marker)
    safe_fields = [("username", "alice"), ("mode", "user")]
    if position == "first":
        fields = [target, *safe_fields]
    elif position == "middle":
        fields = [safe_fields[0], target, safe_fields[1]]
    else:
        fields = [*safe_fields, target]
    payload = "&".join(f"{key}={value}" for key, value in fields)

    sanitized = redact_payload(payload)

    assert f"{field}={marker}" in sanitized
    assert "username=alice" in sanitized


@pytest.mark.parametrize("field", ["password", "access_token"])
def test_form_secret_with_compound_marker_is_still_redacted(field: str):
    payload = f"username=alice&{field}=real-secret%7BINJECTION_POINT%7D"

    sanitized = redact_payload(payload)

    assert f"{field}=[REDACTED]" in sanitized
    assert "real-secret" not in sanitized


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
