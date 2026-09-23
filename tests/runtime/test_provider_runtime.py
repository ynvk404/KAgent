from __future__ import annotations

import copy

import pytest

from src.config import config as config_module
from src.config.config import (
    Backend,
    Config,
    add_custom_provider,
    config_to_dict,
)
from src.llm.openai import OpenAIClient
from src.llm.provider_runtime import (
    build_startup_runtime,
    switch_provider_transactionally,
)
from src.llm.factory import new_from_config


class FakeAgent:
    def __init__(self, client: object) -> None:
        self.client = client
        self.fail_next_switch = False
        self.fail_after_mutating = False

    def set_client(self, client: object) -> None:
        self.client = client
        if self.fail_after_mutating:
            self.fail_after_mutating = False
            raise RuntimeError("switch failed after mutation")
        if self.fail_next_switch:
            self.fail_next_switch = False
            raise RuntimeError("switch rejected")


def _manual_config() -> tuple[Config, str, str]:
    cfg = Config(
        backend=Backend.OPENAI_COMPAT,
        model="manual-model",
        base_url="http://localhost:1234/v1",
        api_keys={"openai-compat": "manual-key", "groq": "groq-key"},
    )
    first_id = add_custom_provider(
        cfg,
        "Gateway A",
        "https://gateway-a.example/v1",
        "key-a",
        "model-a",
    )
    second_id = add_custom_provider(
        cfg,
        "Gateway B",
        "https://gateway-b.example/v1",
        "key-b",
        "model-b",
    )
    return cfg, first_id, second_id


def _assert_manual_state(cfg: Config) -> None:
    assert cfg.backend == Backend.OPENAI_COMPAT
    assert cfg.model == "manual-model"
    assert cfg.base_url == "http://localhost:1234/v1"
    assert cfg.api_keys["openai-compat"] == "manual-key"


def test_startup_restores_active_custom_profile_and_cli_overrides_are_ephemeral():
    cfg, profile_id, _ = _manual_config()
    cfg.active_custom_provider_id = profile_id

    runtime = build_startup_runtime(cfg, custom_provider_id=profile_id)
    assert isinstance(runtime.client, OpenAIClient)
    assert runtime.active_custom_provider_id == profile_id
    assert runtime.display_name == "Gateway A"
    assert runtime.client.base_url == "https://gateway-a.example/v1"
    assert runtime.client.model_id == "model-a"
    assert runtime.client.api_key == "key-a"
    _assert_manual_state(cfg)

    overridden = build_startup_runtime(
        cfg,
        custom_provider_id=profile_id,
        model_override="cli-model",
        base_url_override="https://cli.example/v1",
        api_key_override="cli-key",
    )
    assert isinstance(overridden.client, OpenAIClient)
    assert overridden.client.model_id == "cli-model"
    assert overridden.client.base_url == "https://cli.example/v1"
    assert overridden.client.api_key == "cli-key"
    _assert_manual_state(cfg)


def test_startup_rejects_dangling_or_malformed_custom_profile():
    cfg, profile_id, _ = _manual_config()
    with pytest.raises(ValueError, match="profile not found"):
        build_startup_runtime(cfg, custom_provider_id="missing")

    cfg.custom_providers[profile_id].protocol = "unsupported"
    with pytest.raises(ValueError, match="protocol is unsupported"):
        build_startup_runtime(cfg, custom_provider_id=profile_id)
    _assert_manual_state(cfg)


def test_startup_fallback_applies_cli_overrides_without_mutating_manual_config():
    cfg, profile_id, _ = _manual_config()
    calls = 0

    def fail_custom_then_build_fallback(candidate: Config, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("invalid custom runtime")
        return new_from_config(candidate)

    with pytest.raises(ValueError, match="invalid custom runtime"):
        build_startup_runtime(
            cfg,
            custom_provider_id=profile_id,
            model_override="cli-model",
            base_url_override="https://cli.example/v1",
            api_key_override="cli-key",
            client_factory=fail_custom_then_build_fallback,
        )

    fallback = build_startup_runtime(
        cfg,
        model_override="cli-model",
        base_url_override="https://cli.example/v1",
        api_key_override="cli-key",
        client_factory=fail_custom_then_build_fallback,
    )

    assert calls == 2
    assert isinstance(fallback.client, OpenAIClient)
    assert fallback.config.backend == Backend.OPENAI_COMPAT
    assert fallback.client.model_id == "cli-model"
    assert fallback.client.base_url == "https://cli.example/v1"
    assert fallback.client.api_key == "cli-key"
    _assert_manual_state(cfg)


@pytest.mark.asyncio
async def test_builtin_to_custom_builds_before_commit_and_preserves_builtin_and_manual_slots():
    cfg, profile_id, _ = _manual_config()
    cfg.backend = Backend.GROQ
    cfg.model = "groq-model"
    cfg.base_url = "https://api.groq.com/openai/v1"
    old_config = copy.deepcopy(cfg)
    old_client = object()
    agent = FakeAgent(old_client)
    persisted: list[Config] = []

    async def save(candidate: Config) -> None:
        assert agent.client is not old_client
        persisted.append(copy.deepcopy(candidate))

    switched = await switch_provider_transactionally(
        cfg,
        agent,
        backend=Backend.OPENAI_COMPAT,
        model="model-a",
        custom_provider_id=profile_id,
        save_config=save,
    )

    assert isinstance(agent.client, OpenAIClient)
    assert agent.client.base_url == "https://gateway-a.example/v1"
    assert agent.client.api_key == "key-a"
    assert agent.client.model_id == "model-a"
    assert switched.display_name == "Gateway A"
    assert cfg.active_custom_provider_id == profile_id
    assert persisted[0].active_custom_provider_id == profile_id
    assert cfg.backend == old_config.backend
    assert cfg.model == old_config.model
    assert cfg.base_url == old_config.base_url
    assert cfg.api_keys == old_config.api_keys


@pytest.mark.asyncio
async def test_manual_to_custom_and_custom_to_manual_preserve_manual_configuration():
    cfg, profile_id, _ = _manual_config()
    agent = FakeAgent(object())

    async def save(_candidate: Config) -> None:
        return None

    await switch_provider_transactionally(
        cfg,
        agent,
        backend=Backend.OPENAI_COMPAT,
        model="model-a",
        custom_provider_id=profile_id,
        save_config=save,
    )
    assert isinstance(agent.client, OpenAIClient)
    assert agent.client.api_key == "key-a"
    _assert_manual_state(cfg)

    await switch_provider_transactionally(
        cfg,
        agent,
        backend=Backend.OPENAI_COMPAT,
        model=cfg.model,
        base_url=cfg.base_url,
        api_key=cfg.api_keys["openai-compat"],
        save_config=save,
    )
    assert isinstance(agent.client, OpenAIClient)
    assert agent.client.name() == "openai-compat"
    assert agent.client.api_key == "manual-key"
    assert cfg.active_custom_provider_id is None
    _assert_manual_state(cfg)


@pytest.mark.asyncio
async def test_custom_to_builtin_clears_active_id_and_custom_a_to_b_uses_separate_key():
    cfg, profile_a, profile_b = _manual_config()
    agent = FakeAgent(object())
    saved: list[Config] = []

    async def save(candidate: Config) -> None:
        saved.append(copy.deepcopy(candidate))

    await switch_provider_transactionally(
        cfg,
        agent,
        backend=Backend.OPENAI_COMPAT,
        model="model-a",
        custom_provider_id=profile_a,
        save_config=save,
    )
    await switch_provider_transactionally(
        cfg,
        agent,
        backend=Backend.OPENAI_COMPAT,
        model="model-b",
        custom_provider_id=profile_b,
        save_config=save,
    )
    assert isinstance(agent.client, OpenAIClient)
    assert agent.client.name() == "openai-compat"
    assert agent.client.api_key == "key-b"
    assert cfg.active_custom_provider_id == profile_b
    assert cfg.custom_provider_api_keys[profile_a] == "key-a"
    assert cfg.custom_provider_api_keys[profile_b] == "key-b"
    _assert_manual_state(cfg)

    await switch_provider_transactionally(
        cfg,
        agent,
        backend=Backend.GROQ,
        model="groq-model",
        base_url="https://api.groq.com/openai/v1",
        save_config=save,
    )
    assert isinstance(agent.client, OpenAIClient)
    assert agent.client.name() == "groq"
    assert agent.client.api_key == "groq-key"
    assert cfg.active_custom_provider_id is None
    assert saved[-1].active_custom_provider_id is None
    assert cfg.custom_provider_api_keys[profile_a] == "key-a"
    assert cfg.custom_provider_api_keys[profile_b] == "key-b"


@pytest.mark.asyncio
async def test_failed_client_build_or_agent_switch_leaves_config_and_client_unchanged():
    cfg, profile_id, _ = _manual_config()
    cfg.active_custom_provider_id = profile_id
    agent = FakeAgent(object())
    previous_client = agent.client
    old_config = config_to_dict(cfg)
    saved: list[Config] = []

    async def save(candidate: Config) -> None:
        saved.append(candidate)

    def fail_build(*_args: object, **_kwargs: object) -> OpenAIClient:
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
    assert agent.client is previous_client
    assert config_to_dict(cfg) == old_config
    assert saved == []

    agent.fail_after_mutating = True
    with pytest.raises(RuntimeError, match="after mutation"):
        await switch_provider_transactionally(
            cfg,
            agent,
            backend=Backend.OPENAI_COMPAT,
            model="model-a",
            custom_provider_id=profile_id,
            save_config=save,
        )
    assert agent.client is previous_client
    assert config_to_dict(cfg) == old_config
    assert saved == []

    agent.fail_next_switch = True
    with pytest.raises(RuntimeError, match="switch rejected"):
        await switch_provider_transactionally(
            cfg,
            agent,
            backend=Backend.OPENAI_COMPAT,
            model="model-a",
            custom_provider_id=profile_id,
            save_config=save,
        )
    assert agent.client is previous_client
    assert config_to_dict(cfg) == old_config
    assert saved == []


@pytest.mark.asyncio
async def test_failed_save_rolls_back_runtime_and_persisted_configuration():
    cfg, profile_id, _ = _manual_config()
    agent = FakeAgent(object())
    previous_client = agent.client
    old_config = copy.deepcopy(cfg)
    disk_state = copy.deepcopy(cfg)
    calls = 0

    async def save(candidate: Config) -> None:
        nonlocal calls, disk_state
        calls += 1
        disk_state = copy.deepcopy(candidate)
        if calls == 1:
            raise OSError("save failed after replace")

    with pytest.raises(OSError, match="save failed"):
        await switch_provider_transactionally(
            cfg,
            agent,
            backend=Backend.OPENAI_COMPAT,
            model="model-a",
            custom_provider_id=profile_id,
            save_config=save,
        )

    assert calls == 2
    assert agent.client is previous_client
    assert config_to_dict(cfg) == config_to_dict(old_config)
    assert config_to_dict(disk_state) == config_to_dict(old_config)


@pytest.mark.asyncio
async def test_failed_save_and_failed_rollback_before_replace_keep_disk_consistent(
    tmp_path,
    monkeypatch,
):
    config_path = tmp_path / "config.json"
    monkeypatch.setenv("kagent_CONFIG", str(config_path))
    cfg, profile_id, _ = _manual_config()
    await config_module.save(cfg)
    old_disk = config_path.read_bytes()

    agent = FakeAgent(object())
    previous_client = agent.client
    old_config = config_to_dict(cfg)
    chmod_calls = 0

    def fail_temp_chmod(_path, _mode):
        nonlocal chmod_calls
        chmod_calls += 1
        raise OSError("permission setup failed before replace")

    monkeypatch.setattr(config_module.os, "chmod", fail_temp_chmod)

    async def save(candidate: Config) -> None:
        await config_module.save(candidate)

    with pytest.raises(RuntimeError, match="permission setup failed"):
        await switch_provider_transactionally(
            cfg,
            agent,
            backend=Backend.OPENAI_COMPAT,
            model="model-a",
            custom_provider_id=profile_id,
            save_config=save,
        )

    assert chmod_calls == 2  # candidate save and failed best-effort rollback
    assert agent.client is previous_client
    assert config_to_dict(cfg) == old_config
    assert config_path.read_bytes() == old_disk
