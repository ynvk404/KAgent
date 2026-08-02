from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine
from src.ui.core.app import ConfigSnapshot
from src.ask.ask import Question, Option
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.core.state import Action, Append, SetAsk, TranscriptEntry
from src.ui.widgets.secret_input_modal import SecretInputRequest
# ============================================================
# Constants
# ============================================================

KIMI_DEFAULT_BASE_URL = "https://api.moonshot.ai/v1"
GROQ_DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"
GEMINI_DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
OPENROUTER_DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEEPSEEK_DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
ANTHROPIC_DEFAULT_BASE_URL = "https://api.anthropic.com"

# ============================================================
# Types
# ============================================================

# ============================================================
# Provider picker
# ============================================================

def open_provider_picker(
    dispatch: Callable[[Action], None],
    read_config: Callable[[], ConfigSnapshot],
    apply_provider: Callable[..., Any],
    prompt_secret: Callable[
        [SecretInputRequest],
        Coroutine[Any, Any, str | None],
    ],
) -> None:
    cur = read_config()
    current_backend = cur.get("backend", "")

    label_oai = (
        "OpenAI-compatible (current)"
        if current_backend == "openai-compat"
        else "OpenAI-compatible"
    )
    label_kimi = (
        "Kimi (current)" if current_backend == "kimi" else "Kimi"
    )
    label_groq = (
        "Groq (current)" if current_backend == "groq" else "Groq"
    )
    label_gemini = (
        "Gemini (current)"
        if current_backend == "gemini"
        else "Gemini"
    )
    label_openrouter = (
        "OpenRouter (current)"
        if current_backend == "openrouter"
        else "OpenRouter"
    )
    label_deepseek = (
        "DeepSeek (current)"
        if current_backend == "deepseek"
        else "DeepSeek"
    )
    label_claude = (
        "Claude (current)"
        if current_backend == "anthropic"
        else "Claude"
    )

    async def resolve(picked: str) -> None:
        dispatch(SetAsk(req=None))

        backend_map = {
            "Ollama": "ollama",
            "LM Studio": "lmstudio",
            "Kimi": "kimi",
            "Groq": "groq",
            "Gemini": "gemini",
            "OpenRouter": "openrouter",
            "DeepSeek": "deepseek",
            "Claude": "anthropic",
        }

        backend = "openai-compat"

        for prefix, value in backend_map.items():
            if picked.startswith(prefix):
                backend = value
                break

        config = read_config()
        config_base_url = config.get("base_url") or ""
        config_api_key = config.get("api_key") or ""

        if (
            backend == "openai-compat"
            and (not config_base_url or not config_api_key)
        ):
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=(
                            "openai-compat needs a base URL + API key. "
                            "Restart with --base-url + --api-key."
                        ),
                    )
                )
            )
            return

        async def _handle_remote_setup(
            target_backend: str,
            default_url: str,
            header: str,
            question: str,
            placeholder: str,
            success_name: str,
        ) -> bool:
            if (
                backend == target_backend
                and (
                    config.get("backend") != target_backend
                    or not config.get("api_key")
                )
            ):
                try:
                    api_key = await prompt_secret(
                        SecretInputRequest(
                            header=header,
                            question=question,
                            placeholder=placeholder,
                            resolve=lambda _value: None,
                            reject=lambda _err: None,
                        )
                    )

                    if not api_key:
                        dispatch(
                            Append(
                                entry=TranscriptEntry(
                                    kind="error",
                                    text=f"{header} key cannot be empty.",
                                )
                            )
                        )
                        return True

                    base_url = (
                        config_base_url
                        if (
                            config.get("backend") == target_backend
                            and config_base_url
                        )
                        else default_url
                    )

                    import importlib

                    fetch_and_pick_model = importlib.import_module(
                        "src.ui.commands.model_picker"
                    ).fetch_and_pick_model

                    await fetch_and_pick_model(
                        target_backend,
                        base_url,
                        api_key,
                        dispatch,
                        apply_provider,
                        {
                            "successText": (
                                lambda picked: (
                                    f"provider set to {success_name} · model {picked}"
                                )
                            )
                        },
                    )
                except Exception:
                    dispatch(
                        Append(
                            entry=TranscriptEntry(
                                kind="system",
                                text=f"{success_name} setup cancelled.",
                            )
                        )
                    )

                return True

            return False

        if await _handle_remote_setup(
            "kimi",
            KIMI_DEFAULT_BASE_URL,
            "Kimi API",
            "Enter Kimi API key (MOONSHOT_API_KEY)",
            "sk-...",
            "Kimi",
        ):
            return

        if await _handle_remote_setup(
            "groq",
            GROQ_DEFAULT_BASE_URL,
            "Groq API",
            "Enter Groq API key (GROQ_API_KEY)",
            "gsk_...",
            "Groq",
        ):
            return

        if await _handle_remote_setup(
            "gemini",
            GEMINI_DEFAULT_BASE_URL,
            "Gemini API",
            "Enter Gemini API key (GEMINI_API_KEY)",
            "AIza...",
            "Gemini",
        ):
            return

        if await _handle_remote_setup(
            "openrouter",
            OPENROUTER_DEFAULT_BASE_URL,
            "OpenRouter",
            "Enter OpenRouter API key (OPENROUTER_API_KEY)",
            "sk-or-...",
            "OpenRouter",
        ):
            return

        if await _handle_remote_setup(
            "deepseek",
            DEEPSEEK_DEFAULT_BASE_URL,
            "DeepSeek",
            "Enter DeepSeek API key (DEEPSEEK_API_KEY)",
            "sk-...",
            "DeepSeek",
        ):
            return

        if await _handle_remote_setup(
            "anthropic",
            ANTHROPIC_DEFAULT_BASE_URL,
            "Claude API",
            "Enter Anthropic API key (ANTHROPIC_API_KEY)",
            "sk-ant-...",
            "Claude",
        ):
            return

        default_urls = {
            "kimi": KIMI_DEFAULT_BASE_URL,
            "groq": GROQ_DEFAULT_BASE_URL,
            "gemini": GEMINI_DEFAULT_BASE_URL,
            "openrouter": OPENROUTER_DEFAULT_BASE_URL,
            "deepseek": DEEPSEEK_DEFAULT_BASE_URL,
            "anthropic": ANTHROPIC_DEFAULT_BASE_URL,
        }

        if backend == "openai-compat":
            base_url = config_base_url
        elif backend in default_urls:
            if config.get("backend") == backend and config_base_url:
                base_url = config_base_url
            else:
                base_url = default_urls[backend]
        else:
            base_url = ""

        api_key = (
            config_api_key
            if backend == "openai-compat" or config.get("backend") == backend
            else ""
        )

        import importlib

        fetch_and_pick_model = importlib.import_module(
            "src.ui.commands.model_picker"
        ).fetch_and_pick_model

        await fetch_and_pick_model(
            backend,
            base_url,
            api_key,
            dispatch,
            apply_provider,
        )

    def on_resolve(picked: str) -> None:
        asyncio.ensure_future(resolve(picked))

    def reject(_err: Exception) -> None:
        dispatch(SetAsk(req=None))
        
    req = AskRequest(
        question=Question(
            header="provider",
            question="Which LLM backend should pentestagent use?",
            options=[
                Option(label=label_kimi, description="remote — api.moonshot.ai OpenAI-compatible API"),
                Option(label=label_groq, description="remote — api.groq.com OpenAI-compatible Chat API"),
                Option(label=label_gemini, description="remote — Gemini API with native tool calls"),
                Option(label=label_claude, description="remote — Anthropic Messages API"),
                Option(label=label_openrouter, description="remote — OpenRouter API"),
                Option(label=label_deepseek, description="remote — DeepSeek API"),
                Option(
                    label=label_oai,
                    description="remote — needs base URL + API key (uses current config values)",
                ),
            ],
        ),
        resolve=on_resolve,
        reject=reject,
    )

    dispatch(SetAsk(req=req))