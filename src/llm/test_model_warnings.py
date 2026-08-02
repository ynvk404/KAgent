# tests/llm/test_model_warnings.py

from __future__ import annotations

from src.config.config import Backend
from src.llm.model_warnings import (
    infer_model_billions,
    model_reliability_warning,
)


class TestInferModelBillions:
    def test_parses_common_local_model_size_suffixes(self) -> None:
        assert infer_model_billions("qwen2.5-coder:7b-instruct-q4_K_M") == 7.0
        assert infer_model_billions("qwen2.5-coder:14b-instruct-q4_K_M") == 14.0
        assert infer_model_billions("llama-3.1-8b") == 8.0
        assert infer_model_billions("mixtral-8x7b") == 7.0

    def test_returns_none_when_no_model_size_is_encoded(self) -> None:
        assert infer_model_billions("gpt-4.1-mini") is None


class TestModelReliabilityWarning:
    def test_warns_for_small_openai_compatible_hosted_models(
        self,
    ) -> None:
        warning = model_reliability_warning(
            Backend.OPENAI_COMPAT,
            "llama-3.1-8b",
        )

        assert warning is not None
        assert "70b+" in warning

    def test_does_not_warn_for_70b_hosted_models(self) -> None:
        assert (
            model_reliability_warning(
                Backend.OPENAI_COMPAT,
                "llama-3.1-70b",
            )
            is None
        )

    def test_treats_kimi_as_a_hosted_provider_for_size_warnings(
        self,
    ) -> None:
        warning = model_reliability_warning(
            Backend.KIMI,
            "llama-3.1-8b",
        )

        assert warning is not None
        assert "70b+" in warning

    def test_treats_groq_as_a_hosted_provider_for_size_warnings(
        self,
    ) -> None:
        warning = model_reliability_warning(
            Backend.GROQ,
            "openai/gpt-oss-20b",
        )

        assert warning is not None
        assert "70b+" in warning

    def test_treats_openrouter_as_a_hosted_provider_for_size_warnings(
        self,
    ) -> None:
        warning = model_reliability_warning(
            Backend.OPENROUTER,
            "openai/gpt-oss-20b",
        )

        assert warning is not None
        assert "70b+" in warning

    def test_treats_deepseek_as_a_hosted_provider_for_size_warnings(
        self,
    ) -> None:
        warning = model_reliability_warning(
            Backend.DEEPSEEK,
            "openai/gpt-oss-20b",
        )

        assert warning is not None
        assert "70b+" in warning

    def test_treats_gemini_as_a_hosted_provider_for_size_warnings(
        self,
    ) -> None:
        warning = model_reliability_warning(
            Backend.GEMINI,
            "gemma-4-26b-a4b-it",
        )

        assert warning is not None
        assert "70b+" in warning