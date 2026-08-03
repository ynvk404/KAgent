from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable
from src.ui.core.app import ConfigSnapshot
from src.ask.ask import Question, Option
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.core.state import Action, Append, SetAsk, TranscriptEntry
from src.ui.widgets.text_input_modal import TextInputRequest
from src.llm.providers import (
    KIMI_DEFAULT_BASE_URL,
    GROQ_DEFAULT_BASE_URL,
    GEMINI_DEFAULT_BASE_URL,
    OPENROUTER_DEFAULT_BASE_URL,
    DEEPSEEK_DEFAULT_BASE_URL,
    ANTHROPIC_DEFAULT_BASE_URL,
)

REMOTE_PROVIDERS: tuple[tuple[str, str, str], ...] = (
    ("kimi", "Kimi", "sk-..."),
    ("groq", "Groq", "gsk_..."),
    ("gemini", "Gemini", "AIza..."),
    ("anthropic", "Claude", "sk-ant-..."),
    ("openrouter", "OpenRouter", "sk-or-..."),
    ("deepseek", "DeepSeek", "sk-..."),
    ("openai-compat", "OpenAI-compatible", "sk-..."),
)
# ============================================================
# Constants
# ============================================================
# Base URLs are imported from src.llm.providers (single source of truth),
# shared with src/llm/factory.py and src/llm/models.py.

# ============================================================
# Types
# ============================================================

# ============================================================
# Provider picker
# ============================================================

def mask_api_key(value: str) -> str:
    if not value:
        return "(empty)"

    if len(value) <= 8:
        return "*" * len(value)

    return f"{value[:4]}****{value[-5:]}"


def open_provider_picker(
    dispatch: Callable[[Action], None],
    read_config: Callable[[], ConfigSnapshot],
    apply_provider: Callable[..., Any],
    prompt_text: Callable[
        [TextInputRequest],
        Awaitable[str | None],
    ],
    update_provider_api_key: Callable[
        [str, str],
        Awaitable[None],
    ] | None = None,
    test_connection: Callable[
        [],
        Awaitable[None],
    ] | None = None,
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

        if picked.startswith("Change API key"):
            open_change_api_key_picker()
            return

        if picked.startswith("Show current config"):
            show_current_config()
            return

        if picked.startswith("Test connection"):
            await run_test_connection()
            return

        for prefix, value in backend_map.items():
            if picked.startswith(prefix):
                backend = value
                break

        config = read_config()
        config_base_url = config.get("base_url") or ""
        config_api_keys = config.get("api_keys", {}) or {}
        config_api_key = (
            config_api_keys.get(backend, "")
            if isinstance(config_api_keys, dict)
            else ""
        )

        if not config_api_key and config.get("backend") == backend:
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
                and not config_api_key
            ):
                try:
                    api_key = await prompt_text(
                        TextInputRequest(
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
            if backend == "openai-compat" or backend in default_urls
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

    async def change_api_key(
        provider: str,
        label: str,
        placeholder: str,
    ) -> None:
        dispatch(SetAsk(req=None))

        if update_provider_api_key is None:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text="Change API key is not available in this session.",
                    )
                )
            )
            return

        try:
            api_key = await prompt_text(
                TextInputRequest(
                    header=f"{label} API key",
                    question=f"Enter new {label} API key",
                    placeholder=placeholder,
                    resolve=lambda _value: None,
                    reject=lambda _err: None,
                )
            )
        except Exception:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=f"{label} API key update cancelled.",
                    )
                )
            )
            return

        if not api_key:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=f"{label} key cannot be empty.",
                    )
                )
            )
            return

        await update_provider_api_key(provider, api_key)

        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text=f"{label} API key updated.",
                )
            )
        )

    def open_change_api_key_picker() -> None:
        def on_change_resolve(picked_provider: str) -> None:
            for provider, label, placeholder in REMOTE_PROVIDERS:
                if picked_provider.startswith(label):
                    asyncio.ensure_future(
                        change_api_key(provider, label, placeholder)
                    )
                    return

            dispatch(SetAsk(req=None))

        req = AskRequest(
            question=Question(
                header="provider key",
                question="Which provider API key should be changed?",
                options=[
                    Option(
                        label=label,
                        description=f"update stored {provider} API key",
                    )
                    for provider, label, _placeholder in REMOTE_PROVIDERS
                ],
            ),
            resolve=on_change_resolve,
            reject=lambda _err: dispatch(SetAsk(req=None)),
        )

        dispatch(SetAsk(req=req))

    def show_current_config() -> None:
        config = read_config()
        api_keys = config.get("api_keys", {}) or {}

        if isinstance(api_keys, dict) and api_keys:
            key_lines = [
                f"- {provider}: {mask_api_key(value)}"
                for provider, value in sorted(api_keys.items())
            ]
        else:
            key_lines = ["- (none)"]

        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text="\n".join(
                        [
                            "Backend:",
                            f"{config.get('backend') or '(unset)'}",
                            "Model:",
                            f"{config.get('model') or '(unset)'}",
                            "Base URL:",
                            f"{config.get('base_url') or '(unset)'}",
                            "",
                            "API keys:",
                            *key_lines,
                        ]
                    ),
                )
            )
        )

    async def run_test_connection() -> None:
        config = read_config()

        if test_connection is None:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text="Test connection is not available in this session.",
                    )
                )
            )
            return

        try:
            await test_connection()
        except Exception as err:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text="\n".join(
                            [
                                "✗ Connection failed",
                                str(err),
                            ]
                        ),
                    )
                )
            )
            return

        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text="\n".join(
                        [
                            "✓ Connection OK",
                            f"Provider: {config.get('backend') or '(unset)'}",
                            f"Model: {config.get('model') or '(unset)'}",
                        ]
                    ),
                )
            )
        )

    def on_resolve(picked: str) -> None:
        asyncio.ensure_future(resolve(picked))

    def reject(_err: Exception) -> None:
        dispatch(SetAsk(req=None))
        
    req = AskRequest(
        question=Question(
            header="provider",
            question="Select LLM provider or manage provider settings",
            options=[
                Option(label="Change API key", description="update a saved provider key"),
                Option(label="Test connection", description="ping the current provider"),
                Option(label="Show current config", description="display current provider settings"),
                Option(label=label_kimi, description="remote — api.moonshot.ai OpenAI-compatible API"),
                Option(label=label_groq, description="remote — api.groq.com OpenAI-compatible Chat API"),
                Option(label=label_gemini, description="remote — Gemini API with native tool calls"),
                Option(label=label_claude, description="remote — api.anthropic.com Messages API with native tool calls"),
                Option(label=label_openrouter, description="remote — openrouter.ai OpenAI-compatible API"),
                Option(label=label_deepseek, description="remote — api.deepseek.com OpenAI-compatible API"),
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
