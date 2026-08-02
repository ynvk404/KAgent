from __future__ import annotations

import asyncio
import inspect
from typing import Any, Callable

from src.ask.ask import Option, Question
from src.config.config import Backend
from src.llm.models import list_models
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.core.state import Action, Append, SetAsk, TranscriptEntry
from src.llm.providers import (
    KIMI_MODELS,
    GROQ_MODELS,
    OPENROUTER_RECOMMENDED_MODELS,
    DEEPSEEK_MODELS,
    GEMINI_CHEAP_MODELS,
    GEMINI_RECOMMENDED_MODELS,
    ANTHROPIC_RECOMMENDED_MODELS,
)
MODEL_PICKER_CAP = 20


def backend_label(backend: Backend | str) -> str:
    value = backend.value if isinstance(backend, Backend) else str(backend or "")

    labels = {
        "openai-compat": "OpenAI-compatible",
        "kimi": "Kimi",
        "groq": "Groq",
        "openrouter": "OpenRouter",
        "deepseek": "DeepSeek",
        "gemini": "Gemini",
        "anthropic": "Claude",
    }

    return labels.get(value, value or "provider")


def model_description(
    backend: Backend | str,
    model: str,
    current_model: str | dict[str, Any] | None,
) -> str | None:
    if isinstance(current_model, dict):
        current_model = current_model.get("currentModel")

    backend_name = backend.value if isinstance(backend, Backend) else str(backend)

    parts: list[str] = []

    if current_model and model == current_model:
        parts.append("current / used before")

    if backend_name == "kimi" and model in KIMI_MODELS:
        parts.append("Kimi/Moonshot")

    if backend_name == "groq" and model in GROQ_MODELS:
        parts.append("Groq")

    if backend_name == "openrouter" and model in OPENROUTER_RECOMMENDED_MODELS:
        parts.append("OpenRouter router")

    if backend_name == "deepseek" and model in DEEPSEEK_MODELS:
        parts.append("DeepSeek")

    if backend_name == "gemini":
        if model in GEMINI_CHEAP_MODELS:
            parts.append("cheap cost")
        elif model in GEMINI_RECOMMENDED_MODELS:
            parts.append("best fit")

    if backend_name == "anthropic" and model in ANTHROPIC_RECOMMENDED_MODELS:
        parts.append("Claude")

    return " · ".join(parts) if parts else None


async def fetch_and_pick_model(
    backend: Backend | str,
    base_url: str,
    api_key: str,
    dispatch: Callable[[Action], None],
    apply_provider: Callable[..., Any],
    current_model: str | dict[str, Any] | None = None,
    success_text: Callable[[str], str] | dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
) -> None:
    if options is None and isinstance(current_model, dict):
        options = current_model
        current_model = None
    elif options is None and isinstance(success_text, dict):
        options = success_text
        success_text = None

    try:
        models = await asyncio.to_thread(
            list_models,
            backend,
            base_url,
            api_key,
        )
    except Exception as err:
        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="error",
                    text=f"{backend_label(backend).lower()} list-models failed: {err}",
                )
            )
        )
        return

    current_model_value: str | None

    if current_model is None and options is not None:
        current_model_value = options.get("currentModel")
        if not isinstance(current_model_value, str):
            current_model_value = None
    elif current_model is None and options is None:
        current_model_value = None
    elif isinstance(current_model, dict):
        current_model_value = current_model.get("currentModel")
        if not isinstance(current_model_value, str):
            current_model_value = None
    elif isinstance(current_model, str):
        current_model_value = current_model
    else:
        current_model_value = None

    if isinstance(models, list):
        model_list = list(models)
    else:
        model_list = list(models or [])

    all_models = (
        [current_model_value, *model_list]
        if current_model_value and current_model_value not in model_list
        else model_list
    )

    if not all_models:
        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="error",
                    text=(
                        f"{backend_label(backend)} returned no models — is it running with a model loaded?"
                    ),
                )
            )
        )
        return

    shown = all_models[:MODEL_PICKER_CAP]
    overflow = len(all_models) - len(shown)

    question_text = (
        f"Select model for {backend_label(backend)}"
        + (
            f"  (showing {len(shown)} of {len(all_models)} — use /model <id> for unlisted)"
            if overflow > 0
            else ""
        )
        + ":"
    )

    req = AskRequest(
        question=Question(
            header="model",
            question=question_text,
            options=[
                Option(
                    label=model,
                    description=model_description(backend, model, current_model_value),
                )
                for model in shown
            ],
        ),
        resolve=lambda picked: None,
        reject=lambda _: None,
    )

    async def resolve(picked: str) -> None:
        dispatch(SetAsk(req=None))

        try:
            result = apply_provider(
                {
                    "backend": backend,
                    "model": picked,
                    "baseURL": base_url,
                    "apiKey": api_key,
                }
            )
            if inspect.isawaitable(result):
                await result

            resolved_success_text = success_text
            if resolved_success_text is None and options is not None:
                resolved_success_text = options.get("successText")

            if callable(resolved_success_text):
                message = resolved_success_text(picked)
            else:
                message = f"provider set to {backend_label(backend)} · model {picked}"

            if not isinstance(message, str):
                message = str(message)

            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=message,
                    )
                )
            )
        except Exception as err:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=f"provider switch failed: {err}",
                    )
                )
            )

    def on_resolve(picked: str) -> None:
        asyncio.create_task(resolve(picked))

    def reject(_: Exception | None = None) -> None:
        dispatch(SetAsk(req=None))

    req.resolve = on_resolve
    req.reject = reject

    dispatch(SetAsk(req=req))
