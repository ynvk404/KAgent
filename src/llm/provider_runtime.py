from __future__ import annotations

import copy
from dataclasses import dataclass, fields
from typing import Any, Callable

from src.config.config import Backend, Config, resolve_custom_provider
from src.llm.client import Client
from src.llm import factory


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
        persisted.backend = backend
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
) -> PreparedProviderSwitch:
    """Build first, switch the client, then persist and commit config state."""
    prepared = prepare_provider_switch(
        cfg,
        backend=backend,
        model=model,
        base_url=base_url,
        api_key=api_key,
        custom_provider_id=custom_provider_id,
        client_factory=client_factory,
    )
    previous_client = agent.client
    try:
        agent.set_client(prepared.client)
    except BaseException:
        try:
            agent.set_client(previous_client)
        except Exception:
            agent.client = previous_client
        raise

    try:
        await save_config(prepared.persisted_config)
    except BaseException:
        try:
            agent.set_client(previous_client)
        except Exception:
            # The runtime is still the same process; restore even if a new
            # turn began while a custom saver was awaiting I/O.
            agent.client = previous_client
        try:
            await save_config(copy.deepcopy(cfg))
        except BaseException:
            pass
        raise

    for config_field in fields(Config):
        setattr(
            cfg,
            config_field.name,
            copy.deepcopy(getattr(prepared.persisted_config, config_field.name)),
        )
    return prepared
