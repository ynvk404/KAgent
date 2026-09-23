from __future__ import annotations

import asyncio
import inspect
from typing import Any, Awaitable, Callable
from src.config.config import Backend
from src.ui.core.app import ConfigSnapshot, ProviderChange
from src.llm.errors import ProviderControlError
from src.llm.models import list_models
from src.llm.providers import validate_base_url
from src.ask.ask import Question, Option
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.core.state import Action, Append, Clear, SetAsk, TranscriptEntry
from src.ui.widgets.text_input_modal import TextInputRequest
from src.llm.providers import (
    KIMI_DEFAULT_BASE_URL,
    GROQ_DEFAULT_BASE_URL,
    GEMINI_DEFAULT_BASE_URL,
    OPENROUTER_DEFAULT_BASE_URL,
    DEEPSEEK_DEFAULT_BASE_URL,
    ANTHROPIC_DEFAULT_BASE_URL,
    OPENAI_DEFAULT_BASE_URL,
)

from src.ui.core.custom_provider_adapter import (
    CustomProviderAdapter,
    CustomProviderProfile,
    get_custom_provider_adapter,
)
from src.ui.widgets.provider_picker_modal import (
    ProviderPickerModal,
    SECTION_OFFICIAL,
    SECTION_CUSTOM,
    SECTION_MANUAL,
)

REMOTE_PROVIDERS: tuple[tuple[str, str, str], ...] = (
    ("openai", "OpenAI", "sk-..."),
    ("kimi", "Kimi", "sk-..."),
    ("groq", "Groq", "gsk_..."),
    ("gemini", "Gemini", "AIza..."),
    ("anthropic", "Claude", "sk-ant-..."),
    ("openrouter", "OpenRouter", "sk-or-..."),
    ("deepseek", "DeepSeek", "sk-..."),
    ("openai-compat", "OpenAI-compatible", "sk-..."),
)


class ProviderPickerRequest(AskRequest):
    def __init__(
        self,
        question: Question,
        resolve: Callable[[str], None],
        reject: Callable[[Exception], None],
        adapter: CustomProviderAdapter,
        current_backend: str,
        current_custom_provider_id: str | None,
        on_add_provider: Callable[[], Any],
        on_edit_provider: Callable[[CustomProviderProfile], Any],
        on_delete_provider: Callable[[CustomProviderProfile], Any],
        on_activate_provider: Callable[[CustomProviderProfile], Any],
        on_active_delete_blocked: Callable[[CustomProviderProfile], Any],
        initial_section: int = SECTION_OFFICIAL,
    ) -> None:
        super().__init__(question=question, resolve=resolve, reject=reject)
        self.adapter = adapter
        self.current_backend = current_backend
        self.current_custom_provider_id = current_custom_provider_id
        self.on_add_provider = on_add_provider
        self.on_edit_provider = on_edit_provider
        self.on_delete_provider = on_delete_provider
        self.on_activate_provider = on_activate_provider
        self.on_active_delete_blocked = on_active_delete_blocked
        self.initial_section = initial_section

def mask_api_key(value: str) -> str:
    if not value:
        return "(empty)"

    if len(value) <= 8:
        return "*" * len(value)

    return f"{value[:4]}****{value[-5:]}"


async def _prompt_custom_model(
    prompt_text: Callable[[TextInputRequest], Awaitable[str | None]],
    base_url: str,
    api_key: str,
    *,
    current_model: str = "",
    keep_current_on_blank: bool = False,
    discover_models: Callable[[], Awaitable[list[str]]] | None = None,
) -> str:
    discovery_note = ""
    while True:
        try:
            models = (
                await discover_models()
                if discover_models is not None
                else await asyncio.to_thread(
                    list_models,
                    Backend.OPENAI_COMPAT,
                    base_url,
                    api_key,
                )
            )
            if models:
                preview = ", ".join(models[:20])
                discovery_note = f"Available models: {preview}. "
                if len(models) > 20:
                    discovery_note += "Enter another ID to use an unlisted model. "
            else:
                discovery_note = (
                    "The endpoint returned a valid but empty model list. "
                    "Enter a model ID manually. "
                )
            break
        except ProviderControlError as error:
            if error.category in {"authentication", "authorization"}:
                raise error
            if error.category == "rate-limited":
                retry = await prompt_text(
                    TextInputRequest(
                        header="Model discovery rate limited",
                        question=f"{error}. Type retry to try again, or leave blank to cancel.",
                        placeholder="retry",
                        resolve=lambda _value: None,
                        reject=lambda _error: None,
                    )
                )
                if retry and retry.strip().lower() == "retry":
                    continue
                raise error
            discovery_note = (
                f"Discovery could not complete: {error}. Enter a model ID manually. "
            )
            break
        except Exception:
            discovery_note = (
                "Model discovery failed. Enter a model ID manually. "
            )
            break

    model = await prompt_text(
        TextInputRequest(
            header="Step 4 of 4: Default model",
            question=discovery_note + "Choose a discovered model ID or enter one manually.",
            placeholder="e.g. llama-3.3-70b",
            initial_value=current_model,
            resolve=lambda _value: None,
            reject=lambda _error: None,
        )
    )
    if not model or not model.strip():
        if keep_current_on_blank and current_model:
            return current_model
        raise ValueError("default model ID cannot be empty")
    return model.strip()


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
    adapter: CustomProviderAdapter | None = None,
    initial_section: int = SECTION_OFFICIAL,
) -> None:
    cur = read_config()
    current_backend = (
        ""
        if cur.get("active_custom_provider_id")
        else cur.get("backend", "")
    ) or ""
    current_custom_provider_id = cur.get("active_custom_provider_id")

    label_oai = (
        "OpenAI-compatible (current)"
        if current_backend == "openai-compat"
        else "OpenAI-compatible"
    )
    label_official_openai = (
        "OpenAI (current)" if current_backend == "openai" else "OpenAI"
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
            "OpenAI": "openai",
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

        if not picked.startswith("OpenAI-compatible"):
            for prefix, value in backend_map.items():
                if picked.startswith(prefix):
                    backend = value
                    break

        config = read_config()
        config_base_url = (
            (
                config.get("base_url")
                if config.get("backend") == "openai-compat"
                else config.get("manual_base_url")
            ) or ""
            if backend == "openai-compat"
            else config.get("base_url") or ""
        )
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
                            masked=True,
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
                        apply_provider_and_sync,
                        {
                            "successText": (
                                lambda picked: (
                                    f"provider set to {success_name} · model {picked}"
                                )
                            )
                        },
                        manual_model_prompt=lambda reason: prompt_text(
                            TextInputRequest(
                                header="Manual model ID",
                                question=(
                                    f"Model discovery could not complete: {reason}. "
                                    "Enter a model ID manually."
                                ),
                                placeholder="model-id",
                                resolve=lambda _value: None,
                                reject=lambda _error: None,
                            )
                        ),
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
            "openai",
            OPENAI_DEFAULT_BASE_URL,
            "OpenAI API",
            "Enter OpenAI API key (OPENAI_API_KEY)",
            "sk-...",
            "OpenAI",
        ):
            return

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
            "openai": OPENAI_DEFAULT_BASE_URL,
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
            apply_provider_and_sync,
            manual_model_prompt=lambda reason: prompt_text(
                TextInputRequest(
                    header="Manual model ID",
                    question=(
                        f"Model discovery could not complete: {reason}. "
                        "Enter a model ID manually."
                    ),
                    placeholder="model-id",
                    resolve=lambda _value: None,
                    reject=lambda _error: None,
                )
            ),
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
                    masked=True,
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
                if picked_provider == label:
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

    active_adapter = adapter or get_custom_provider_adapter()

    async def apply_provider_and_sync(change: ProviderChange) -> None:
        result = apply_provider(change)
        if inspect.isawaitable(result):
            await result
        active_adapter.activate_custom_provider(change.custom_provider_id)

    async def _add_custom_provider_flow() -> None:
        dispatch(SetAsk(req=None))
        try:
            name_hint = ""
            while True:
                q_text = "Enter provider name" + (f" ({name_hint})" if name_hint else "")
                name = await prompt_text(
                    TextInputRequest(
                        header="Step 1 of 4: Provider name",
                        question=q_text,
                        placeholder="e.g. My Gateway",
                        resolve=lambda _v: None,
                        reject=lambda _e: None,
                    )
                )
                if name and name.strip():
                    break
                name_hint = "cannot be empty"

            url_hint = ""
            while True:
                q_text = "Enter base URL" + (f" ({url_hint})" if url_hint else "")
                base_url = await prompt_text(
                    TextInputRequest(
                        header="Step 2 of 4: Base URL",
                        question=q_text,
                        placeholder="https://api.example.com/v1",
                        resolve=lambda _v: None,
                        reject=lambda _e: None,
                    )
                )
                if base_url and base_url.strip():
                    try:
                        base_url = validate_base_url(base_url.strip())
                    except ValueError as err:
                        url_hint = str(err)
                        continue
                    break
                url_hint = "cannot be empty"

            api_key = await prompt_text(
                TextInputRequest(
                    header="Step 3 of 4: API key",
                    question="Enter API key (optional)",
                    placeholder="sk-...",
                    masked=True,
                    resolve=lambda _v: None,
                    reject=lambda _e: None,
                )
            )

            model = await _prompt_custom_model(
                prompt_text,
                base_url,
                api_key or "",
            )

            add_result = active_adapter.add_custom_provider(
                name=name.strip(),
                base_url=base_url,
                api_key=api_key or "",
                default_model=model,
            )
            profile = await add_result if inspect.isawaitable(add_result) else add_result
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=f"Custom provider '{profile.name}' added.",
                    )
                )
            )
        except (ProviderControlError, ValueError) as err:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=f"Custom provider setup failed: {err}",
                    )
                )
            )
        except Exception as err:
            was_cancelled = str(err).lower() == "cancelled"
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system" if was_cancelled else "error",
                        text=(
                            "Custom provider setup cancelled."
                            if was_cancelled
                            else "Custom provider setup failed; no profile was saved."
                        ),
                    )
                )
            )
        finally:
            open_provider_picker(
                dispatch,
                read_config,
                apply_provider,
                prompt_text,
                update_provider_api_key,
                test_connection,
                adapter=active_adapter,
                initial_section=SECTION_CUSTOM,
            )

    async def _edit_custom_provider_flow(profile: CustomProviderProfile) -> None:
        dispatch(SetAsk(req=None))
        try:
            name = await prompt_text(
                TextInputRequest(
                    header="Step 1 of 4: Provider name",
                    question="Edit provider name",
                    placeholder="e.g. My Gateway",
                    initial_value=profile.name,
                    resolve=lambda _v: None,
                    reject=lambda _e: None,
                )
            )
            if not name or not name.strip():
                name = profile.name

            base_url = await prompt_text(
                TextInputRequest(
                    header="Step 2 of 4: Base URL",
                    question="Edit base URL",
                    placeholder="https://api.example.com/v1",
                    initial_value=profile.base_url,
                    resolve=lambda _v: None,
                    reject=lambda _e: None,
                )
            )
            if not base_url or not base_url.strip():
                base_url = profile.base_url
            base_url = validate_base_url(base_url.strip())

            api_key = await prompt_text(
                TextInputRequest(
                    header="Step 3 of 4: API key",
                    question="Edit API key",
                    placeholder="(leave blank to keep existing key)",
                    masked=True,
                    initial_value="",
                    resolve=lambda _v: None,
                    reject=lambda _e: None,
                )
            )

            model = await _prompt_custom_model(
                prompt_text,
                base_url,
                api_key if api_key else "",
                current_model=profile.default_model,
                keep_current_on_blank=True,
                discover_models=lambda: active_adapter.discover_custom_models(
                    profile.id,
                    base_url,
                    api_key if api_key else None,
                ),
            )

            update_result = active_adapter.edit_custom_provider(
                profile_id=profile.id,
                name=name.strip(),
                base_url=base_url,
                api_key=api_key if api_key else None,
                default_model=model,
            )
            updated = (
                await update_result
                if inspect.isawaitable(update_result)
                else update_result
            )
            name_shown = updated.name if updated else profile.name
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=f"Custom provider '{name_shown}' updated.",
                    )
                )
            )
        except (ProviderControlError, ValueError) as err:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=f"Custom provider edit failed: {err}",
                    )
                )
            )
        except Exception as err:
            was_cancelled = str(err).lower() == "cancelled"
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system" if was_cancelled else "error",
                        text=(
                            "Provider edit cancelled."
                            if was_cancelled
                            else "Custom provider edit failed; prior profile/runtime state was retained."
                        ),
                    )
                )
            )
        finally:
            open_provider_picker(
                dispatch,
                read_config,
                apply_provider,
                prompt_text,
                update_provider_api_key,
                test_connection,
                adapter=active_adapter,
                initial_section=SECTION_CUSTOM,
            )

    def on_add_cb() -> None:
        asyncio.ensure_future(_add_custom_provider_flow())

    def on_edit_cb(p: CustomProviderProfile) -> None:
        asyncio.ensure_future(_edit_custom_provider_flow(p))

    def on_delete_cb(p: CustomProviderProfile) -> None:
        async def delete() -> None:
            try:
                result = active_adapter.delete_custom_provider(p.id)
                deleted = await result if inspect.isawaitable(result) else result
                if not deleted:
                    raise ValueError("profile could not be deleted because it is active or missing")
            except Exception as err:
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text=f"provider delete failed: {err}",
                        )
                    )
                )
                return
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=f"Custom provider '{p.name}' deleted.",
                    )
                )
            )
            open_provider_picker(
                dispatch,
                read_config,
                apply_provider,
                prompt_text,
                update_provider_api_key,
                test_connection,
                adapter=active_adapter,
                initial_section=SECTION_CUSTOM,
            )

        asyncio.ensure_future(delete())

    def on_activate_cb(p: CustomProviderProfile) -> None:
        dispatch(SetAsk(req=None))
        async def activate() -> None:
            try:
                result = apply_provider_and_sync(
                    ProviderChange(
                        backend=Backend.OPENAI_COMPAT,
                        model=p.default_model,
                        custom_provider_id=p.id,
                    )
                )
                if inspect.isawaitable(result):
                    await result
            except Exception as err:
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text=f"provider switch failed: {err}",
                        )
                    )
                )
                return
            dispatch(Clear())
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=f"provider set to {p.name} · custom provider active",
                    )
                )
            )

        asyncio.ensure_future(activate())

    def on_delete_blocked_cb(p: CustomProviderProfile) -> None:
        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="error",
                    text=(
                        "This custom provider is currently active.\n"
                        "Select another provider before deleting it."
                    ),
                )
            )
        )

    def on_resolve(picked: str) -> None:
        asyncio.ensure_future(resolve(picked))

    def reject(_err: Exception) -> None:
        dispatch(SetAsk(req=None))

    req = ProviderPickerRequest(
        question=Question(
            header="provider",
            question="Select LLM provider or manage provider settings",
            options=[
                Option(label="Change API key", description="update a saved provider key"),
                Option(label="Test connection", description="ping the current provider"),
                Option(label="Show current config", description="display current provider settings"),
                Option(label=label_official_openai, description="remote — api.openai.com official OpenAI API"),
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
        adapter=active_adapter,
        current_backend=current_backend,
        current_custom_provider_id=current_custom_provider_id,
        on_add_provider=on_add_cb,
        on_edit_provider=on_edit_cb,
        on_delete_provider=on_delete_cb,
        on_activate_provider=on_activate_cb,
        on_active_delete_blocked=on_delete_blocked_cb,
        initial_section=initial_section,
    )

    dispatch(SetAsk(req=req))
