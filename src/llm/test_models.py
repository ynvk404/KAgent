from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from src.llm.models import list_models


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
                        {"id": "deepseek-chat"},
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
                            "name": "models/gemini-flash-lite-latest",
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
            "deepseek-chat",
        ]

    def test_parses_openai_compat_v1_models_with_bearer_auth(self, base_url: str) -> None:
        models = list_models("openai-compat", f"{base_url}/v1", "sk-fake")

        assert len(models) == 10

    def test_parses_kimi_v1_models_with_bearer_auth(self, base_url: str) -> None:
        models = list_models("kimi", f"{base_url}/v1", "sk-kimi")

        assert models == ["kimi-k2.6"]

    def test_parses_groq_v1_models_with_bearer_auth(self, base_url: str) -> None:
        models = list_models("groq", f"{base_url}/v1", "gsk-fake")

        assert models == [
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "llama-3.3-70b-versatile",
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

        assert models == ["deepseek-v4-flash", "deepseek-v4-pro", "deepseek-chat"]

    def test_parses_gemini_models_and_sorts_recommendations_first(self, base_url: str) -> None:
        models = list_models("gemini", f"{base_url}/gemini", "gemini-key")

        assert models == [
            "models/gemini-3.5-flash",
            "models/gemini-flash-lite-latest",
            "models/other",
        ]

    def test_raises_on_non_200(self, base_url: str) -> None:
        with pytest.raises(requests.HTTPError, match="returned 404"):
            list_models("openai-compat", f"{base_url}/missing")

    def test_raises_on_connection_failure(self) -> None:
        with pytest.raises(requests.RequestException):
            list_models("openai-compat", "http://127.0.0.1:1")