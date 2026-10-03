from __future__ import annotations

import re

from src.config.config import Backend


def model_reliability_warning(
    backend: Backend | None,
    model: str,
) -> str | None:
    size = infer_model_billions(model)
    if size is None:
        return None

    normalized_backend = backend or "openai-compat"

    if (
        normalized_backend
        in (
            "openai-compat",
            "kimi",
            "groq",
            "openrouter",
            "deepseek",
            "gemini",
            "anthropic",
        )
        and size < 70
    ):
        return (
            f"⚠  model {model}: if this is a hosted API, sub-70b models may "
            "be unreliable for agentic tool calls. Recommended hosted size: "
            "70b+."
        )

    return None


def infer_model_billions(model: str) -> float | None:
    normalized = model.lower()

    matches = list(
        re.finditer(
            r"(\d+(?:\.\d+)?)\s*b(?:$|[^a-z0-9])",
            normalized,
            flags=re.IGNORECASE,
        )
    )

    if not matches:
        return None

    size = matches[-1].group(1)

    try:
        return float(size)
    except ValueError:
        return None


def format_billions(n: float) -> str:
    if n.is_integer():
        return f"{int(n)}b"
    return f"{n:.1f}b"