from __future__ import annotations

import os
from typing import Any

import pytest

from . import transport


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
            return type("Response", (), {"status_code": 200})()

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
