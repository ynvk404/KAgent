from __future__ import annotations

import copy
import asyncio
from dataclasses import dataclass, fields
from typing import Any, Callable

from src.config.config import Backend, Config, resolve_custom_provider
from src.llm.client import Client
from src.llm import factory
from src.llm.providers import OPENAI_DEFAULT_BASE_URL, OPENAI_DEFAULT_MODEL


ClientFactory = Callable[..., Client]
ConfigSaver = Callable[[Config], Any]


@dataclass(slots=True)
class ProviderRuntime:
    config: Config
    client: Client
    active_custom_provider_id: str | None
    display_name: str


@dataclass(slots=True)
class PreparedProviderSwitch(ProviderRuntime):
    persisted_config: Config


RuntimeCommit = Callable[[PreparedProviderSwitch], None]


def build_startup_runtime(
    cfg: Config,
    *,
    custom_provider_id: str | None = None,
    model_override: str | None = None,
    base_url_override: str | None = None,
    api_key_override: str | None = None,
    client_factory: ClientFactory | None = None,
) -> ProviderRuntime:
    """Build startup runtime state without changing the persisted config."""
    make_client = client_factory or factory.new_from_config
    if custom_provider_id is None:
        runtime_config = copy.deepcopy(cfg)
        if model_override is not None:
            runtime_config.model = model_override
        if base_url_override is not None:
            runtime_config.base_url = base_url_override
        if api_key_override is not None:
            runtime_config.api_key = api_key_override
        client = make_client(runtime_config)
        return ProviderRuntime(
            config=runtime_config,
            client=client,
            active_custom_provider_id=None,
            display_name=str(runtime_config.backend),
        )

    runtime_config, profile = resolve_custom_provider(
        cfg,
        custom_provider_id,
        model_override=model_override,
        base_url_override=base_url_override,
        api_key_override=api_key_override,
    )
    client = make_client(runtime_config)
    return ProviderRuntime(
        config=runtime_config,
        client=client,
        active_custom_provider_id=custom_provider_id,
        display_name=profile.name,
    )


def prepare_provider_switch(
    cfg: Config,
    *,
    backend: Backend | str,
    model: str,
    base_url: str | None = None,
    api_key: str | None = None,
    custom_provider_id: str | None = None,
    client_factory: ClientFactory | None = None,
) -> PreparedProviderSwitch:
    """Resolve and build a provider switch while leaving ``cfg`` untouched."""
    make_client = client_factory or factory.new_from_config
    persisted = copy.deepcopy(cfg)

    if custom_provider_id is None:
        previous_backend = str(persisted.backend)
        target_backend = str(backend)
        if previous_backend == Backend.OPENAI_COMPAT.value and target_backend != previous_backend:
            persisted.manual_openai_compat_model = persisted.model
            persisted.manual_openai_compat_base_url = persisted.base_url
        persisted.backend = backend
        if target_backend == Backend.OPENAI_COMPAT.value:
            persisted.model = model or persisted.manual_openai_compat_model
            if base_url is not None:
                persisted.base_url = base_url
            elif previous_backend != target_backend:
                persisted.base_url = persisted.manual_openai_compat_base_url
            persisted.manual_openai_compat_model = persisted.model
            persisted.manual_openai_compat_base_url = persisted.base_url
        elif target_backend == Backend.OPENAI.value:
            persisted.model = model or (
                persisted.model if previous_backend == target_backend else OPENAI_DEFAULT_MODEL
            )
            persisted.base_url = (
                base_url if base_url is not None else (
                    persisted.base_url if previous_backend == target_backend else OPENAI_DEFAULT_BASE_URL
                )
            )
        else:
            persisted.model = model
            if base_url is not None:
                persisted.base_url = base_url
        if api_key is not None:
            persisted.api_key = api_key
        persisted.active_custom_provider_id = None
        runtime_config = copy.deepcopy(persisted)
        client = make_client(runtime_config)
        return PreparedProviderSwitch(
            config=runtime_config,
            client=client,
            active_custom_provider_id=None,
            display_name=str(backend),
            persisted_config=persisted,
        )

    _, profile = resolve_custom_provider(persisted, custom_provider_id)
    if model:
        profile.default_model = model
    persisted.active_custom_provider_id = custom_provider_id

    runtime_config, resolved_profile = resolve_custom_provider(
        persisted,
        custom_provider_id,
        model_override=model or None,
        base_url_override=base_url,
        api_key_override=api_key,
    )
    client = make_client(runtime_config)
    return PreparedProviderSwitch(
        config=runtime_config,
        client=client,
        active_custom_provider_id=custom_provider_id,
        display_name=resolved_profile.name,
        persisted_config=persisted,
    )


async def switch_provider_transactionally(
    cfg: Config,
    agent: Any,
    *,
    backend: Backend | str,
    model: str,
    base_url: str | None = None,
    api_key: str | None = None,
    custom_provider_id: str | None = None,
    save_config: ConfigSaver,
    client_factory: ClientFactory | None = None,
    mutation_lock: asyncio.Lock | None = None,
    on_commit: RuntimeCommit | None = None,
) -> PreparedProviderSwitch:
    """Serialize build, persistence, client activation, and live commit."""
    async with mutation_lock or asyncio.Lock():
        prepared = prepare_provider_switch(
            cfg,
            backend=backend,
            model=model,
            base_url=base_url,
            api_key=api_key,
            custom_provider_id=custom_provider_id,
            client_factory=client_factory,
        )
        await _persist_and_activate(cfg, agent, prepared, save_config)
        if on_commit is not None:
            on_commit(prepared)
        return prepared


async def edit_custom_provider_transactionally(
    cfg: Config,
    candidate_config: Config,
    agent: Any,
    *,
    custom_provider_id: str,
    save_config: ConfigSaver,
    client_factory: ClientFactory | None = None,
) -> PreparedProviderSwitch:
    """Persist and activate edits to the currently active Custom profile."""
    if candidate_config.active_custom_provider_id != custom_provider_id:
        raise ValueError("active custom provider identity changed during edit")
    runtime_config, profile = resolve_custom_provider(
        candidate_config,
        custom_provider_id,
    )
    client = (client_factory or factory.new_from_config)(runtime_config)
    prepared = PreparedProviderSwitch(
        config=runtime_config,
        client=client,
        active_custom_provider_id=custom_provider_id,
        display_name=profile.name,
        persisted_config=copy.deepcopy(candidate_config),
    )

    await _persist_and_activate(cfg, agent, prepared, save_config)
    return prepared


async def _persist_and_activate(
    cfg: Config,
    agent: Any,
    prepared: PreparedProviderSwitch,
    save_config: ConfigSaver,
) -> None:
    previous_client = agent.client
    try:
        # Keep the old client available to an agent turn while disk I/O is
        # unresolved. There is no await between a successful save and switch.
        await save_config(prepared.persisted_config)
        agent.set_client(prepared.client)
    except BaseException:
        try:
            agent.set_client(previous_client)
        except Exception:
            agent.client = previous_client
        await _restore_disk(save_config, cfg)
        raise

    for config_field in fields(Config):
        setattr(
            cfg,
            config_field.name,
            copy.deepcopy(getattr(prepared.persisted_config, config_field.name)),
        )


async def _restore_disk(save_config: ConfigSaver, cfg: Config) -> None:
    # A second cancellation must not abandon the compensating write.
    restore = asyncio.create_task(save_config(copy.deepcopy(cfg)))
    while not restore.done():
        try:
            await asyncio.shield(restore)
        except asyncio.CancelledError:
            continue
        except Exception:
            break
    try:
        restore.result()
    except Exception:
        # The original failure is the useful error for the caller. Atomic
        # save leaves the old file intact when it fails before replace.
        pass
