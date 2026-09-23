from __future__ import annotations

import os
import socket
import ssl
from typing import Any

import httpx
import pytest

from src.llm import transport
from src.llm.errors import ProviderControlError


PROXY_ENV_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)


def test_provider_client_ignores_proxy_environment_without_mutating_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = {
        name: f"http://proxy.invalid/{name}"
        for name in PROXY_ENV_VARS
    }
    for name, value in configured.items():
        monkeypatch.setenv(name, value)

    captured: dict[str, Any] = {}
    sentinel = object()

    def fake_async_client(**kwargs: Any) -> object:
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(transport.httpx, "AsyncClient", fake_async_client)

    assert transport.new_provider_async_client(12.5) is sentinel
    assert captured == {"timeout": 12.5, "trust_env": False}
    assert {name: os.environ[name] for name in PROXY_ENV_VARS} == configured


def test_provider_session_ignores_proxy_environment_without_mutating_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = {
        name: f"http://proxy.invalid/{name}"
        for name in PROXY_ENV_VARS
    }
    for name, value in configured.items():
        monkeypatch.setenv(name, value)

    class FakeSession:
        trust_env = True

    session = FakeSession()
    monkeypatch.setattr(transport.requests, "Session", lambda: session)

    assert transport.new_provider_session() is session
    assert session.trust_env is False
    assert {name: os.environ[name] for name in PROXY_ENV_VARS} == configured


@pytest.mark.asyncio
async def test_provider_ping_uses_the_provider_transport_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[float] = []

    class FakeClient:
        async def __aenter__(self) -> "FakeClient":
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str, headers: dict[str, str]):
            assert url == "https://provider.invalid/v1/models"
            assert headers == {"Authorization": "Bearer test"}
            return type(
                "Response",
                (),
                {"status_code": 200, "json": lambda self: {"data": []}},
            )()

    def fake_factory(timeout: float = transport.CHAT_TIMEOUT_SEC) -> FakeClient:
        calls.append(timeout)
        return FakeClient()

    monkeypatch.setattr(transport, "new_provider_async_client", fake_factory)

    await transport.ping_models_endpoint(
        "https://provider.invalid/v1",
        {"Authorization": "Bearer test"},
        "test-provider",
    )

    assert calls == [transport.PING_TIMEOUT_SEC]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "category"),
    [
        (200, None),
        (400, "incompatible-request"),
        (401, "authentication"),
        (403, "authorization"),
        (404, "unsupported-endpoint"),
        (408, "timeout"),
        (429, "rate-limited"),
        (503, "server-error"),
    ],
)
async def test_ping_classifies_http_statuses_and_validates_response(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    category: str | None,
) -> None:
    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, *_args: object, **_kwargs: object):
            body = {"data": []} if status == 200 else {"error": "secret response"}
            return type(
                "Response",
                (),
                {"status_code": status, "json": lambda self: body},
            )()

    monkeypatch.setattr(transport, "new_provider_async_client", lambda *_args: FakeClient())
    if category is None:
        await transport.ping_models_endpoint("https://provider.invalid/v1/", {}, "display")
    else:
        with pytest.raises(ProviderControlError) as caught:
            await transport.ping_models_endpoint(
                "https://provider.invalid/v1/",
                {},
                "display",
            )
        assert caught.value.category == category
        assert "secret" not in str(caught.value)


@pytest.mark.asyncio
async def test_ping_rejects_malformed_json_and_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bodies = [ValueError("bad json"), {"models": []}, {"data": [None]}]
    expected = ["malformed-json", "malformed-response", "malformed-response"]

    for body, category in zip(bodies, expected, strict=True):
        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

            async def get(self, *_args: object, **_kwargs: object):
                def parse():
                    if isinstance(body, Exception):
                        raise body
                    return body

                return type("Response", (), {"status_code": 200, "json": lambda self: parse()})()

        monkeypatch.setattr(transport, "new_provider_async_client", lambda *_args: FakeClient())
        with pytest.raises(ProviderControlError) as caught:
            await transport.ping_models_endpoint("https://provider.invalid/v1", {}, "safe")
        assert caught.value.category == category


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "valid_body", "invalid_body"),
    [
        ("gemini", {"models": []}, {"data": []}),
        ("anthropic", {"data": []}, {"models": []}),
    ],
)
async def test_ping_preserves_builtin_provider_model_envelopes(
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    valid_body: dict[str, list[object]],
    invalid_body: dict[str, list[object]],
) -> None:
    body = valid_body

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, *_args: object, **_kwargs: object):
            return type(
                "Response",
                (),
                {"status_code": 200, "json": lambda self: body},
            )()

    monkeypatch.setattr(transport, "new_provider_async_client", lambda *_args: FakeClient())
    await transport.ping_models_endpoint("https://provider.invalid/v1", {}, provider)

    body = invalid_body
    with pytest.raises(ProviderControlError) as caught:
        await transport.ping_models_endpoint("https://provider.invalid/v1", {}, provider)
    assert caught.value.category == "malformed-response"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "category"),
    [
        (httpx.ReadTimeout("secret url timeout"), "timeout"),
        (httpx.ConnectError("connection refused"), "connection-failure"),
        (httpx.ConnectError("dns lookup"), "dns-failure"),
        (httpx.ConnectError("certificate"), "tls-failure"),
    ],
)
async def test_ping_classifies_transport_errors_without_exposing_details(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    category: str,
) -> None:
    cause: BaseException | None = None
    if category == "dns-failure":
        cause = socket.gaierror("private hostname detail")
    elif category == "tls-failure":
        cause = ssl.SSLCertVerificationError("certificate secret")
    if cause is not None:
        error.__cause__ = cause

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, *_args: object, **_kwargs: object):
            raise error

    monkeypatch.setattr(transport, "new_provider_async_client", lambda *_args: FakeClient())
    with pytest.raises(ProviderControlError) as caught:
        await transport.ping_models_endpoint("https://provider.invalid/v1", {}, "safe")
    assert caught.value.category == category
    assert "secret" not in str(caught.value)
