from __future__ import annotations

import copy
import asyncio
from types import SimpleNamespace
from typing import cast

import pytest

from src.config.config import (
    Backend,
    Config,
    add_custom_provider,
    config_from_dict,
    config_to_dict,
)
from src.llm.openai import OpenAIClient
from src.llm.provider_runtime import (
    build_startup_runtime,
    edit_custom_provider_transactionally,
    switch_provider_transactionally,
)
from src.ui.commands.slash_handler import _handle_model
from src.ui.core.app import KAgent
from src.ui.core.custom_provider_adapter import ConfigBackedCustomProviderAdapter


class FakeAgent:
    def __init__(self, client: object) -> None:
        self.client = client

    def set_client(self, client: object) -> None:
        self.client = client


def make_config() -> tuple[Config, str]:
    cfg = Config(
        backend=Backend.OPENAI_COMPAT,
        model="manual-model",
        base_url="http://localhost:1234/v1",
        api_keys={"openai-compat": "manual-key", "groq": "groq-key"},
    )
    profile_id = add_custom_provider(
        cfg,
        "Gateway",
        "https://gateway.example/v1",
        "custom-key",
        "model-a",
    )
    return cfg, profile_id


@pytest.mark.asyncio
async def test_config_adapter_persists_profiles_keys_and_masks_secrets():
    cfg, first_id = make_config()
    persisted: list[Config] = []
    active_id: str | None = None

    async def save(candidate: Config) -> None:
        persisted.append(copy.deepcopy(candidate))

    adapter = ConfigBackedCustomProviderAdapter(
        cfg,
        save,
        lambda: active_id,
    )
    first = adapter.list_custom_providers()[0]
    assert first.id == first_id
    assert first.has_api_key is True
    assert not hasattr(first, "api_key")
    assert "custom-key" not in repr(first)

    second = await adapter.add_custom_provider(
        "Gateway",
        "https://second.example/v1",
        "second-key",
        "model-b",
    )
    assert second.id != first_id
    assert second.has_api_key is True
    assert cfg.custom_provider_api_keys == {
        first_id: "custom-key",
        second.id: "second-key",
    }
    assert cfg.api_keys["openai-compat"] == "manual-key"
    assert cfg.api_keys["groq"] == "groq-key"

    renamed = await adapter.edit_custom_provider(
        first_id,
        "Gateway renamed",
        "https://gateway.example/v2",
        api_key=None,
        default_model="model-renamed",
    )
    assert renamed is not None
    assert renamed.id == first_id
    assert renamed.has_api_key is True
    assert cfg.custom_provider_api_keys[first_id] == "custom-key"

    replaced = await adapter.edit_custom_provider(
        first_id,
        "Gateway renamed",
        "https://gateway.example/v2",
        api_key="replacement-key",
        default_model="model-renamed",
    )
    assert replaced is not None
    assert cfg.custom_provider_api_keys[first_id] == "replacement-key"
    assert cfg.custom_provider_api_keys[second.id] == "second-key"
    assert cfg.api_keys["openai-compat"] == "manual-key"

    restarted = config_from_dict(config_to_dict(cfg))
    restarted_adapter = ConfigBackedCustomProviderAdapter(
        restarted,
        save,
        lambda: None,
    )
    listed = {profile.id: profile for profile in restarted_adapter.list_custom_providers()}
    assert listed[first_id].name == "Gateway renamed"
    assert listed[first_id].default_model == "model-renamed"
    assert listed[first_id].has_api_key is True
    assert listed[second.id].has_api_key is True
    assert "replacement-key" not in repr(listed[first_id])
    assert len(persisted) == 3


@pytest.mark.asyncio
async def test_config_adapter_delete_removes_only_inactive_profile_secret():
    cfg, first_id = make_config()
    second_id = add_custom_provider(
        cfg,
        "Second",
        "https://second.example/v1",
        "second-key",
        "model-b",
    )
    cfg.active_custom_provider_id = first_id
    runtime_active_id: str | None = None
    persisted: list[Config] = []

    async def save(candidate: Config) -> None:
        persisted.append(copy.deepcopy(candidate))

    adapter = ConfigBackedCustomProviderAdapter(cfg, save, lambda: runtime_active_id)
    assert await adapter.delete_custom_provider(first_id) is True
    assert first_id not in cfg.custom_providers
    assert first_id not in cfg.custom_provider_api_keys
    assert cfg.active_custom_provider_id is None
    assert cfg.custom_provider_api_keys[second_id] == "second-key"
    assert cfg.api_keys == {"openai-compat": "manual-key", "groq": "groq-key"}

    runtime_active_id = second_id
    assert await adapter.delete_custom_provider(second_id) is False
    assert second_id in cfg.custom_providers
    assert len(persisted) == 1


@pytest.mark.asyncio
async def test_config_adapter_save_failure_keeps_live_config_unchanged():
    cfg, _profile_id = make_config()
    before = config_to_dict(cfg)

    async def fail_save(_candidate: Config) -> None:
        raise OSError("save failed")

    adapter = ConfigBackedCustomProviderAdapter(cfg, fail_save, lambda: None)
    with pytest.raises(OSError, match="save failed"):
        await adapter.add_custom_provider(
            "Unsaved",
            "https://unsaved.example/v1",
            "secret",
            "model",
        )
    assert config_to_dict(cfg) == before


@pytest.mark.asyncio
async def test_active_profile_edit_updates_client_and_config_transactionally():
    cfg, profile_id = make_config()
    cfg.active_custom_provider_id = profile_id
    initial = build_startup_runtime(cfg, custom_provider_id=profile_id)
    agent = FakeAgent(initial.client)
    persisted: list[Config] = []

    async def save(candidate: Config) -> None:
        persisted.append(copy.deepcopy(candidate))

    async def active_edit(candidate: Config, active_id: str) -> None:
        await edit_custom_provider_transactionally(
            cfg, candidate, agent, custom_provider_id=active_id, save_config=save,
        )

    adapter = ConfigBackedCustomProviderAdapter(
        cfg,
        save,
        lambda: profile_id,
        active_edit,
    )
    edited = await adapter.edit_custom_provider(
        profile_id,
        "Gateway edited",
        "https://edited.example/v1",
        api_key="edited-key",
        default_model="edited-model",
    )

    assert edited is not None
    assert edited.name == "Gateway edited"
    assert cfg.active_custom_provider_id == profile_id
    assert cfg.custom_provider_api_keys[profile_id] == "edited-key"
    assert cfg.custom_providers[profile_id].default_model == "edited-model"
    assert isinstance(agent.client, OpenAIClient)
    assert agent.client.base_url == "https://edited.example/v1"
    assert agent.client.api_key == "edited-key"
    assert agent.client.model_id == "edited-model"
    assert persisted[-1].custom_providers[profile_id].name == "Gateway edited"
    assert cfg.model == "manual-model"
    assert cfg.api_keys["openai-compat"] == "manual-key"


@pytest.mark.asyncio
async def test_failed_active_profile_edit_restores_runtime_live_and_saved_state():
    cfg, profile_id = make_config()
    cfg.active_custom_provider_id = profile_id
    initial = build_startup_runtime(cfg, custom_provider_id=profile_id)
    agent = FakeAgent(initial.client)
    runtime = SimpleNamespace(value=initial)
    banner = {"provider": initial.display_name, "model": initial.config.model}
    before = config_to_dict(cfg)
    disk_state = copy.deepcopy(cfg)
    save_calls = 0

    async def fail_save(candidate: Config) -> None:
        nonlocal save_calls
        save_calls += 1
        if save_calls == 1:
            raise OSError("save failed before replace")
        disk_state.__dict__.update(candidate.__dict__)

    async def active_edit(candidate: Config, active_id: str) -> None:
        prepared = await edit_custom_provider_transactionally(
            cfg, candidate, agent, custom_provider_id=active_id, save_config=fail_save,
        )
        runtime.value = prepared
        banner.update(provider=prepared.display_name, model=prepared.config.model)

    adapter = ConfigBackedCustomProviderAdapter(
        cfg,
        fail_save,
        lambda: profile_id,
        active_edit,
    )
    with pytest.raises(OSError, match="save failed"):
        await adapter.edit_custom_provider(
            profile_id,
            "Failed rename",
            "https://edited.example/v1",
            api_key="new-key",
            default_model="new-model",
        )

    assert save_calls == 2
    assert agent.client is initial.client
    assert config_to_dict(cfg) == before
    assert config_to_dict(disk_state) == before
    assert runtime.value is initial
    assert banner == {"provider": "Gateway", "model": "model-a"}
    assert cfg.active_custom_provider_id == profile_id


@pytest.mark.asyncio
async def test_config_adapter_active_marker_tracks_real_switch_and_failed_restore():
    cfg, profile_id = make_config()
    agent = FakeAgent(object())
    disk_state = copy.deepcopy(cfg)
    runtime_active_id: str | None = None

    async def save(candidate: Config) -> None:
        nonlocal disk_state
        disk_state = copy.deepcopy(candidate)

    adapter = ConfigBackedCustomProviderAdapter(
        cfg,
        save,
        lambda: runtime_active_id,
    )
    old_client = agent.client

    def fail_build(_candidate: Config) -> OpenAIClient:
        raise RuntimeError("client construction failed")

    with pytest.raises(RuntimeError, match="construction failed"):
        await switch_provider_transactionally(
            cfg,
            agent,
            backend=Backend.OPENAI_COMPAT,
            model="model-a",
            custom_provider_id=profile_id,
            save_config=save,
            client_factory=fail_build,
        )

    assert agent.client is old_client
    assert runtime_active_id is None
    assert adapter.get_current_provider_id() is None
    assert not adapter.is_active(profile_id)
    assert cfg.active_custom_provider_id is None
    assert disk_state.active_custom_provider_id is None

    switched = await switch_provider_transactionally(
        cfg,
        agent,
        backend=Backend.OPENAI_COMPAT,
        model="model-a",
        custom_provider_id=profile_id,
        save_config=save,
    )
    runtime_active_id = switched.active_custom_provider_id

    assert adapter.get_current_provider_id() == profile_id
    assert adapter.is_active(profile_id)
    assert cfg.active_custom_provider_id == profile_id
    assert disk_state.active_custom_provider_id == profile_id
    assert cfg.model == "manual-model"
    assert cfg.api_keys[Backend.OPENAI_COMPAT.value] == "manual-key"

    switched = await switch_provider_transactionally(
        cfg,
        agent,
        backend=Backend.OPENAI_COMPAT,
        model=cfg.model,
        base_url=cfg.base_url,
        api_key=cfg.api_keys[Backend.OPENAI_COMPAT.value],
        save_config=save,
    )
    runtime_active_id = switched.active_custom_provider_id

    assert adapter.get_current_provider_id() is None
    assert not adapter.is_active(profile_id)
    assert cfg.active_custom_provider_id is None
    assert disk_state.active_custom_provider_id is None
    assert profile_id in cfg.custom_providers
    assert cfg.custom_provider_api_keys[profile_id] == "custom-key"
    assert cfg.api_keys[Backend.OPENAI_COMPAT.value] == "manual-key"


@pytest.mark.asyncio
async def test_overlapping_custom_adds_keep_both_profiles_and_keys():
    cfg, first_id = make_config()
    disk = copy.deepcopy(cfg)
    entered = asyncio.Event()
    release = asyncio.Event()
    writes = 0

    async def save(candidate: Config) -> None:
        nonlocal disk, writes
        writes += 1
        if writes == 1:
            entered.set()
            await release.wait()
        disk = copy.deepcopy(candidate)

    adapter = ConfigBackedCustomProviderAdapter(cfg, save, lambda: None)
    first = asyncio.create_task(adapter.add_custom_provider("A", "https://a.example/v1", "key-a"))
    await entered.wait()
    second = asyncio.create_task(adapter.add_custom_provider("B", "https://b.example/v1", "key-b"))
    await asyncio.sleep(0)
    assert not second.done()
    release.set()
    added_a, added_b = await asyncio.gather(first, second)
    assert set(disk.custom_providers) == {first_id, added_a.id, added_b.id}
    assert disk.custom_provider_api_keys[added_a.id] == "key-a"
    assert disk.custom_provider_api_keys[added_b.id] == "key-b"
    assert config_to_dict(disk) == config_to_dict(cfg)


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_switch", [False, True])
async def test_custom_add_overlapping_runtime_switch_keeps_successful_change(fail_switch):
    cfg, profile_id = make_config()
    disk = copy.deepcopy(cfg)
    agent = FakeAgent(object())
    old_client = agent.client
    lock = asyncio.Lock()
    entered = asyncio.Event()
    release = asyncio.Event()
    writes = 0

    async def save(candidate: Config) -> None:
        nonlocal disk, writes
        writes += 1
        if writes == 1:
            entered.set()
            await release.wait()
        disk = copy.deepcopy(candidate)
        if writes == 1 and fail_switch:
            raise OSError("switch save failed after replace")

    adapter = ConfigBackedCustomProviderAdapter(
        cfg, save, lambda: cfg.active_custom_provider_id, mutation_lock=lock,
    )
    switching = asyncio.create_task(switch_provider_transactionally(
        cfg, agent, backend=Backend.OPENAI_COMPAT, model="model-a",
        custom_provider_id=profile_id, save_config=save, mutation_lock=lock,
    ))
    await entered.wait()
    adding = asyncio.create_task(adapter.add_custom_provider("Second", "https://second.example/v1", "second-key"))
    await asyncio.sleep(0)
    assert not adding.done()
    release.set()
    if fail_switch:
        with pytest.raises(OSError, match="switch save failed"):
            await switching
        assert agent.client is old_client
        assert cfg.active_custom_provider_id is None
    else:
        await switching
        assert cfg.active_custom_provider_id == profile_id
    added = await adding
    assert added.id in cfg.custom_providers
    assert disk.custom_provider_api_keys[added.id] == "second-key"
    assert config_to_dict(disk) == config_to_dict(cfg)


@pytest.mark.asyncio
async def test_active_edit_updates_snapshot_used_by_later_model_command(monkeypatch):
    from src.ui.commands import slash_handler

    cfg, profile_id = make_config()
    cfg.active_custom_provider_id = profile_id
    runtime = SimpleNamespace(value=build_startup_runtime(cfg, custom_provider_id=profile_id))
    agent = FakeAgent(runtime.value.client)
    lock = asyncio.Lock()
    disk = copy.deepcopy(cfg)
    banner = {"provider": runtime.value.display_name, "model": "model-a"}

    async def save(candidate: Config) -> None:
        nonlocal disk
        disk = copy.deepcopy(candidate)

    async def active_edit(candidate: Config, active_id: str) -> None:
        prepared = await edit_custom_provider_transactionally(
            cfg, candidate, agent, custom_provider_id=active_id, save_config=save,
        )
        runtime.value = prepared
        banner.update(provider=prepared.display_name, model=prepared.config.model)

    adapter = ConfigBackedCustomProviderAdapter(
        cfg, save, lambda: cfg.active_custom_provider_id,
        active_edit=active_edit, mutation_lock=lock,
    )
    await adapter.edit_custom_provider(
        profile_id, "Renamed", "https://edited.example/v1", "edited-key", "edited-model",
    )

    def read_config():
        return {
            "backend": cfg.backend,
            "model": cfg.model,
            "base_url": cfg.base_url,
            "api_key": cfg.api_key,
            "active_custom_provider_id": cfg.active_custom_provider_id,
            "active_custom_provider_base_url": runtime.value.config.base_url,
            "active_custom_provider_api_key": runtime.value.config.api_key,
            "active_custom_provider_model": runtime.value.config.model,
        }

    async def apply_provider(change) -> None:
        def commit(prepared) -> None:
            runtime.value = prepared
            banner.update(provider=prepared.display_name, model=prepared.config.model)

        await switch_provider_transactionally(
            cfg, agent, backend=change.backend, model=change.model,
            base_url=change.base_url, api_key=change.api_key,
            custom_provider_id=change.custom_provider_id,
            save_config=save, mutation_lock=lock, on_commit=commit,
        )

    seen_discovery: list[tuple[object, ...]] = []

    def list_models(*args):
        seen_discovery.append(args)
        return ["next-model"]

    monkeypatch.setattr(slash_handler, "list_models", list_models)
    app = SimpleNamespace(agent=agent, read_config=read_config, apply_provider=apply_provider)
    await _handle_model(cast(KAgent, app), ["next-model"], lambda _action: None)

    assert seen_discovery[-1][1:] == ("https://edited.example/v1", "edited-key")
    assert agent.client.base_url == "https://edited.example/v1"
    assert agent.client.api_key == "edited-key"
    assert cfg.custom_providers[profile_id].default_model == "next-model"
    assert cfg.custom_provider_api_keys[profile_id] == "edited-key"
    assert runtime.value.config.model == "next-model"
    assert banner == {"provider": "Renamed", "model": "next-model"}
    assert config_to_dict(disk) == config_to_dict(cfg)
