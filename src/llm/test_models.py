from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from src.llm import models as models_module
from src.llm.models import list_models
from src.llm.providers import validate_base_url


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/models":
            auth = self.headers.get("Authorization")
            if auth and not auth.startswith("Bearer "):
                self.send_response(401)
                self.end_headers()
                return
            self._send_json(
                200,
                {
                    "data": [
                        {"id": "qwen-coder-32b-instruct"},
                        {"id": "gpt-4o-mini"},
                        {"id": "kimi-k2.6"},
                        {"id": "openai/gpt-oss-120b"},
                        {"id": "openai/gpt-oss-20b"},
                        {"id": "llama-3.3-70b-versatile"},
                        {"id": "anthropic/claude-sonnet-4.5"},
                        {"id": "deepseek-v4-pro"},
                        {"id": "deepseek-v4-flash"},
                        {"id": "deepseek-flash"},
                        {"id": "deepseek-chat"},
                        {"id": "qwen/qwen3.6-27b"},
                    ]
                },
            )
            return

        if self.path == "/gemini/models":
            self._send_json(
                200,
                {
                    "models": [
                        {
                            "name": "models/other",
                            "supportedGenerationMethods": ["generateContent"],
                        },
                        {
                            "name": "models/gemini-3.5-flash",
                            "supportedGenerationMethods": ["generateContent"],
                        },
                        {
                            "name": "models/gemini-3.8-flash",
                            "supportedGenerationMethods": ["generateContent"],
                        },
                        {
                            "name": "models/gemini-3.5-flash-lite",
                            "supportedGenerationMethods": ["generateContent"],
                        },
                        {
                            "name": "models/gemini-3.1-flash-lite",
                            "supportedGenerationMethods": ["generateContent"],
                        },
                        {
                            "name": "models/gemini-embedding-001",
                            "supportedGenerationMethods": ["embedContent"],
                        },
                    ]
                },
            )
            return

        self.send_response(404)
        self.end_headers()

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture(scope="module")
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class TestListModels:
    def test_model_discovery_uses_provider_transport_policy(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sessions = []

        class FakeResponse:
            status_code = 200

            @staticmethod
            def json() -> dict[str, list[dict[str, str]]]:
                return {"data": []}

        class FakeSession:
            trust_env = False

            def __enter__(self):
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def get(self, *args: object, **kwargs: object) -> FakeResponse:
                return FakeResponse()

        def fake_provider_session() -> FakeSession:
            session = FakeSession()
            sessions.append(session)
            return session

        monkeypatch.setattr(
            models_module,
            "new_provider_session",
            fake_provider_session,
        )

        assert list_models("openai-compat", "https://provider.invalid/v1") == []
        assert len(sessions) == 1
        assert sessions[0].trust_env is False

    def test_parses_lmstudio_openai_compat_v1_models(self, base_url: str) -> None:
        models = list_models("lmstudio", f"{base_url}/v1")

        assert models == [
            "qwen-coder-32b-instruct",
            "gpt-4o-mini",
            "kimi-k2.6",
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "llama-3.3-70b-versatile",
            "anthropic/claude-sonnet-4.5",
            "deepseek-v4-pro",
            "deepseek-v4-flash",
            "deepseek-flash",
            "deepseek-chat",
            "qwen/qwen3.6-27b",
        ]

    def test_parses_openai_compat_v1_models_with_bearer_auth(self, base_url: str) -> None:
        models = list_models("openai-compat", f"{base_url}/v1", "sk-fake")

        assert len(models) == 12

    def test_parses_kimi_v1_models_with_bearer_auth(self, base_url: str) -> None:
        models = list_models("kimi", f"{base_url}/v1", "sk-kimi")

        assert models == ["kimi-k2.6"]

    def test_parses_groq_v1_models_with_bearer_auth(self, base_url: str) -> None:
        models = list_models("groq", f"{base_url}/v1", "gsk-fake")

        assert models == [
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "qwen/qwen3.6-27b",
        ]

    def test_parses_openrouter_v1_models_and_prepends_auto_router(self, base_url: str) -> None:
        models = list_models("openrouter", f"{base_url}/v1", "sk-or-fake")

        assert models[:3] == [
            "openrouter/auto",
            "qwen-coder-32b-instruct",
            "gpt-4o-mini",
        ]

    def test_parses_deepseek_models_and_prefers_current_model_names(self, base_url: str) -> None:
        models = list_models("deepseek", f"{base_url}/v1", "sk-deepseek")

        assert models == [
            "deepseek-flash",
            "deepseek-v4-pro",
            "qwen-coder-32b-instruct",
            "gpt-4o-mini",
            "kimi-k2.6",
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "llama-3.3-70b-versatile",
            "anthropic/claude-sonnet-4.5",
            "deepseek-v4-flash",
            "deepseek-chat",
            "qwen/qwen3.6-27b",
        ]

    def test_parses_gemini_models_and_sorts_recommendations_first(self, base_url: str) -> None:
        models = list_models("gemini", f"{base_url}/gemini", "gemini-key")

        assert models == [
            "models/gemini-3.8-flash",
            "models/gemini-3.5-flash-lite",
            "models/gemini-3.1-flash-lite",
            "models/other",
            "models/gemini-3.5-flash",
        ]

    def test_raises_on_non_200(self, base_url: str) -> None:
        with pytest.raises(requests.HTTPError, match="returned 404"):
            list_models("openai-compat", f"{base_url}/missing")

    def test_raises_on_connection_failure(self) -> None:
        with pytest.raises(requests.RequestException):
            list_models("openai-compat", "http://127.0.0.1:1")

@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.evil.example.com/v1",
        "http://10.0.0.5:8000/v1",
        "ftp://api.example.com/v1",
        "api.example.com/v1",
    ],
)
def test_list_models_rejects_cleartext_and_unknown_schemes(base_url: str) -> None:
    with pytest.raises(ValueError):
        list_models("openai-compat", base_url=base_url, api_key="sk-secret")


@pytest.mark.parametrize(
    "base_url",
    [
        "https://api.example.com/v1",
        "http://127.0.0.1:1234/v1",
        "http://localhost:1234/v1",
        "http://[::1]:1234/v1",
    ],
)
def test_validate_base_url_allows_https_and_loopback(base_url: str) -> None:
    assert validate_base_url(base_url) == base_url
