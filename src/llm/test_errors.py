from __future__ import annotations

import json

from src.llm.errors import (
    BackendError,
    classify_backend,
    is_transient,
)


class TestClassifyBackend:
    def test_tags_econnrefused_as_backend_down(self) -> None:
        err = Exception(
            "fetch failed: connect ECONNREFUSED 127.0.0.1:11434"
        )

        out = classify_backend(
            "ollama",
            err,
            0,
            None,
        )

        assert isinstance(out, BackendError)
        assert out.category == "backend-down"

    def test_tags_enotfound_as_backend_down(self) -> None:
        err = Exception(
            "getaddrinfo ENOTFOUND missing.host"
        )

        out = classify_backend(
            "openai-compat",
            err,
            0,
            None,
        )

        assert out.category == "backend-down"

    def test_tags_ollama_model_not_found_body(self) -> None:
        body = json.dumps(
            {
                "error": (
                    "model qwen2.5:7b not found, "
                    "try pulling it first"
                )
            }
        )

        out = classify_backend(
            "ollama",
            None,
            404,
            body,
        )

        assert out.category == "model-not-found"
        assert out.status_code == 404

    def test_tags_lmstudio_no_model_loaded_body(self) -> None:
        body = json.dumps(
            {
                "error": {
                    "message": (
                        "No models loaded; "
                        "please load a model in the UI"
                    )
                }
            }
        )

        out = classify_backend(
            "lmstudio",
            None,
            400,
            body,
        )

        assert out.category == "model-not-loaded"

    def test_leaves_unrecognized_errors_as_unknown(self) -> None:
        out = classify_backend(
            "ollama",
            None,
            500,
            "internal server error",
        )

        assert out.category == "unknown"
        assert "500" in str(out)

    def test_falls_back_to_raw_body_when_not_json(self) -> None:
        out = classify_backend(
            "ollama",
            None,
            500,
            "plain text",
        )

        assert out.detail == "plain text"

    def test_extracts_message_from_openai_envelope(self) -> None:
        body = json.dumps(
            {
                "error": {
                    "message": "invalid api key",
                }
            }
        )

        out = classify_backend(
            "openai-compat",
            None,
            401,
            body,
        )

        assert out.detail == "invalid api key"

    def test_maps_rate_limit_200_body_to_retryable_429(self) -> None:
        out = classify_backend(
            "openrouter",
            None,
            200,
            "Rate limit exceeded, retry shortly",
        )

        assert out.status_code == 429
        assert is_transient(out)

    def test_keeps_original_status_for_rate_limit_error(self) -> None:
        out = classify_backend(
            "openrouter",
            None,
            503,
            "too many requests",
        )

        assert out.status_code == 503
        assert is_transient(out)


class TestIsTransient:
    def test_flags_408_request_timeout(self) -> None:
        assert is_transient(
            BackendError(
                "test",
                "unknown",
                408,
                "timeout",
            )
        )

class TestBackendErrorConstruction:
    def test_is_raisable_and_formats_status_and_detail(self) -> None:
        err = BackendError("ollama", "backend-down", 503, "unavailable")

        assert str(err) == "ollama error 503: unavailable"

        try:
            raise err
        except BackendError as caught:
            assert caught is err

    def test_omits_status_when_there_is_no_response(self) -> None:
        err = BackendError("groq", "unknown", 0, "connection refused")

        assert str(err) == "groq: connection refused"
