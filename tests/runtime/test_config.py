from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from src.config import config
from src.config.config import (
    Backend,
    CustomProviderConfig,
    ToolingProfile,
    MCPServerConfig,
    PluginConfig,
    add_custom_provider,
    default_config,
    delete_custom_provider,
    edit_custom_provider,
    load,
    save,
)


@pytest.fixture()
def temp_config(monkeypatch):
    with tempfile.TemporaryDirectory(
        prefix="pf-config-"
    ) as tmp:
        path = Path(tmp) / "config.json"

        monkeypatch.setenv(
            "kagent_CONFIG",
            str(path),
        )

        yield path


def test_returns_default_config_when_missing(
    temp_config,
):
    cfg = load()

    assert cfg.backend == Backend.EMPTY
    assert cfg.mcp_servers == []


def test_migrates_legacy_api_key(
    temp_config,
):
    temp_config.write_text(
        json.dumps(
            {
                "backend": "groq",
                "api_key": "old-key",
            }
        ),
        encoding="utf-8",
    )

    cfg = load()

    assert cfg.api_keys["groq"] == "old-key"
    assert cfg.api_key == "old-key"


def test_old_config_without_custom_provider_fields_loads(
    temp_config,
):
    temp_config.write_text(
        json.dumps(
            {
                "backend": "openai-compat",
                "model": "manual-model",
                "base_url": "http://localhost:1234/v1",
                "api_keys": {"openai-compat": "manual-key"},
            }
        ),
        encoding="utf-8",
    )

    cfg = load()

    assert cfg.backend == "openai-compat"
    assert cfg.model == "manual-model"
    assert cfg.base_url == "http://localhost:1234/v1"
    assert cfg.api_keys == {"openai-compat": "manual-key"}
    assert cfg.custom_providers == {}
    assert cfg.custom_provider_api_keys == {}
    assert cfg.active_custom_provider_id is None


def test_api_key_tracks_backend_without_dropping_other_keys(
    temp_config,
):
    cfg = default_config()

    cfg.backend = Backend.GROQ
    cfg.api_key = "groq-key"

    cfg.backend = Backend.KIMI
    cfg.api_key = "kimi-key"

    assert cfg.api_keys == {
        "groq": "groq-key",
        "kimi": "kimi-key",
    }


def test_switching_provider_returns_current_backend_key(
    temp_config,
):
    cfg = default_config()

    cfg.backend = Backend.GROQ
    cfg.api_key = "groq-key"

    cfg.backend = Backend.KIMI
    cfg.api_key = "kimi-key"

    cfg.backend = Backend.GROQ
    assert cfg.api_key == "groq-key"

    cfg.backend = Backend.KIMI
    assert cfg.api_key == "kimi-key"


@pytest.mark.asyncio
async def test_round_trips_save_load(
    temp_config,
):
    cfg = default_config()

    cfg.backend = Backend.GROQ
    cfg.model = "openai/gpt-oss-20b"
    cfg.base_url = (
        "https://api.groq.com/openai/v1"
    )
    cfg.api_key = "sk-test"

    cfg.mcp_servers = [
        MCPServerConfig(
            name="browser",
            command="npx",
            args=[
                "-y",
                "@browsermcp/mcp@latest",
            ],
        )
    ]

    await save(cfg)

    reloaded = load()

    assert reloaded.backend == Backend.GROQ
    assert reloaded.model == (
        "openai/gpt-oss-20b"
    )

    assert reloaded.base_url == (
        "https://api.groq.com/openai/v1"
    )

    assert reloaded.api_key == "sk-test"

    assert (
        reloaded.mcp_servers[0].command
        == "npx"
    )


@pytest.mark.asyncio
async def test_round_trips_multiple_provider_api_keys(
    temp_config,
):
    cfg = default_config()

    cfg.backend = Backend.GROQ
    cfg.api_key = "xxx"

    cfg.backend = Backend.KIMI
    cfg.api_key = "yyy"

    await save(cfg)

    saved = json.loads(
        temp_config.read_text(
            encoding="utf-8",
        )
    )

    assert saved["api_keys"] == {
        "groq": "xxx",
        "kimi": "yyy",
    }
    assert "api_key" not in saved

    reloaded = load()

    assert reloaded.api_keys == {
        "groq": "xxx",
        "kimi": "yyy",
    }


@pytest.mark.asyncio
async def test_custom_provider_profile_round_trip_preserves_manual_config(
    temp_config,
):
    cfg = default_config()
    cfg.backend = Backend.OPENAI_COMPAT
    cfg.model = "manual-model"
    cfg.base_url = "http://localhost:1234/v1"
    cfg.api_keys["openai-compat"] = "manual-key"

    profile_id = add_custom_provider(
        cfg,
        name="Gateway One",
        base_url="https://gateway.example/v1",
        api_key="custom-key-one",
        default_model="model-one",
    )
    cfg.active_custom_provider_id = profile_id

    await save(cfg)
    reloaded = load()

    assert len(profile_id) == 32
    assert reloaded.custom_providers == {
        profile_id: CustomProviderConfig(
            name="Gateway One",
            protocol="openai-compatible",
            base_url="https://gateway.example/v1",
            default_model="model-one",
        )
    }
    assert reloaded.custom_provider_api_keys == {profile_id: "custom-key-one"}
    assert reloaded.active_custom_provider_id == profile_id
    assert reloaded.backend == Backend.OPENAI_COMPAT
    assert reloaded.model == "manual-model"
    assert reloaded.base_url == "http://localhost:1234/v1"
    assert reloaded.api_keys == {"openai-compat": "manual-key"}


@pytest.mark.asyncio
async def test_multiple_custom_profiles_keep_separate_keys_and_builtin_slots(
    temp_config,
):
    cfg = default_config()
    cfg.api_keys.update(
        {
            "groq": "groq-key",
            "openai-compat": "manual-key",
        }
    )

    first_id = add_custom_provider(
        cfg,
        "Gateway One",
        "https://one.example/v1",
        "custom-key-one",
    )
    second_id = add_custom_provider(
        cfg,
        "Gateway Two",
        "https://two.example/v1",
        "custom-key-two",
    )

    await save(cfg)
    reloaded = load()

    assert first_id != second_id
    assert reloaded.custom_provider_api_keys == {
        first_id: "custom-key-one",
        second_id: "custom-key-two",
    }
    assert reloaded.api_keys == {
        "groq": "groq-key",
        "openai-compat": "manual-key",
    }


@pytest.mark.asyncio
async def test_renaming_custom_profile_preserves_stable_id_and_key(temp_config):
    cfg = default_config()
    profile_id = add_custom_provider(
        cfg,
        "Gateway",
        "https://gateway.example/v1",
        "custom-secret",
        "model-one",
    )

    updated = edit_custom_provider(
        cfg,
        profile_id,
        name="Renamed Gateway",
        base_url="https://gateway.example/v1",
        default_model="model-two",
    )

    assert updated is not None
    assert updated.name == "Renamed Gateway"
    assert cfg.custom_providers[profile_id] is updated
    assert cfg.custom_provider_api_keys == {profile_id: "custom-secret"}

    await save(cfg)
    reloaded = load()
    assert profile_id in reloaded.custom_providers
    assert reloaded.custom_providers[profile_id].name == "Renamed Gateway"
    assert reloaded.custom_provider_api_keys == {profile_id: "custom-secret"}


def test_duplicate_custom_provider_names_get_distinct_opaque_ids():
    cfg = default_config()

    first_id = add_custom_provider(
        cfg,
        "Same Name",
        "https://one.example/v1",
        "key-one",
    )
    second_id = add_custom_provider(
        cfg,
        "Same Name",
        "https://two.example/v1",
        "key-two",
    )

    assert first_id != second_id
    assert cfg.custom_providers[first_id].name == cfg.custom_providers[second_id].name
    assert cfg.custom_provider_api_keys == {
        first_id: "key-one",
        second_id: "key-two",
    }


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"custom_providers": []}, "custom_providers"),
        ({"custom_providers": {"not-a-uuid": {}}}, "UUID"),
        (
            {"custom_providers": {"0123456789abcdef0123456789abcdef": []}},
            "must be an object",
        ),
        (
            {
                "custom_providers": {
                    "0123456789abcdef0123456789abcdef": {
                        "protocol": "openai-compatible",
                        "base_url": "https://gateway.example/v1",
                    }
                }
            },
            "name is required",
        ),
        (
            {
                "custom_providers": {
                    "0123456789abcdef0123456789abcdef": {
                        "name": "Gateway",
                        "protocol": "openai-compatible",
                        "base_url": "https://gateway.example/v1",
                        "default_model": 42,
                    }
                }
            },
            "default_model must be a string",
        ),
        (
            {
                "custom_providers": {
                    "0123456789abcdef0123456789abcdef": {
                        "name": "Gateway",
                        "protocol": "anthropic",
                        "base_url": "https://gateway.example/v1",
                    }
                }
            },
            "protocol",
        ),
        (
            {"custom_provider_api_keys": {"0123456789abcdef0123456789abcdef": "key"}},
            "without a saved profile",
        ),
        (
            {"active_custom_provider_id": "0123456789abcdef0123456789abcdef"},
            "active_custom_provider_id",
        ),
    ],
)
def test_rejects_malformed_custom_provider_config(payload, message):
    with pytest.raises(ValueError, match=message):
        config.config_from_dict(payload)


@pytest.mark.asyncio
async def test_delete_custom_provider_removes_key_and_active_id(temp_config):
    cfg = default_config()
    cfg.backend = Backend.OPENAI_COMPAT
    cfg.model = "manual-model"
    cfg.base_url = "http://localhost:1234/v1"
    cfg.api_keys["openai-compat"] = "manual-key"
    profile_id = add_custom_provider(
        cfg,
        "Gateway",
        "https://gateway.example/v1",
        "custom-key",
    )
    cfg.active_custom_provider_id = profile_id

    assert delete_custom_provider(cfg, profile_id) is True
    assert profile_id not in cfg.custom_providers
    assert profile_id not in cfg.custom_provider_api_keys
    assert cfg.active_custom_provider_id is None
    assert cfg.backend == Backend.OPENAI_COMPAT
    assert cfg.model == "manual-model"
    assert cfg.base_url == "http://localhost:1234/v1"
    assert cfg.api_keys["openai-compat"] == "manual-key"
    assert delete_custom_provider(cfg, profile_id) is False

    await save(cfg)
    reloaded = load()
    assert profile_id not in reloaded.custom_providers
    assert profile_id not in reloaded.custom_provider_api_keys
    assert reloaded.active_custom_provider_id is None
    assert reloaded.api_keys["openai-compat"] == "manual-key"


@pytest.mark.asyncio
async def test_overlapping_saves(
    temp_config,
):
    one = default_config()

    one.backend = Backend.GROQ
    one.model = "model-one"

    two = default_config()

    two.backend = Backend.DEEPSEEK
    two.model = "model-two"
    two.api_key = "sk-test"

    await save(one)
    await save(two)

    loaded = load()

    assert loaded.model in {
        "model-one",
        "model-two",
    }


@pytest.mark.asyncio
async def test_reject_shell_meta_mcp(
    temp_config,
):
    cfg = default_config()

    cfg.mcp_servers = [
        MCPServerConfig(
            name="evil",
            command="npx; rm -rf /",
            args=[],
        )
    ]

    await save(cfg)

    with pytest.raises(
        Exception,
        match="shell",
    ):
        load()


@pytest.mark.asyncio
async def test_reject_pipe_plugin(
    temp_config,
):
    cfg = default_config()

    cfg.plugins = [
        PluginConfig(
            name="evil",
            command="sh | nc",
            args=[],
            description="",
        )
    ]

    await save(cfg)

    with pytest.raises(
        Exception,
        match="shell",
    ):
        load()


@pytest.mark.asyncio
async def test_reject_command_substitution(
    temp_config,
):
    cfg = default_config()

    cfg.plugins = [
        PluginConfig(
            name="evil",
            command="$(whoami)",
            args=[],
            description="",
        )
    ]

    await save(cfg)

    with pytest.raises(
        Exception,
        match="shell",
    ):
        load()


@pytest.mark.asyncio
async def test_tooling_profile_persist(
    temp_config,
):
    cfg = default_config()

    cfg.tooling_profile = ToolingProfile.FULL

    await save(cfg)

    loaded = load()

    assert (
        loaded.tooling_profile
        == ToolingProfile.FULL
    )


@pytest.mark.asyncio
async def test_accept_gemini(
    temp_config,
):
    cfg = default_config()

    cfg.backend = Backend.GEMINI
    cfg.model = (
        "models/gemini-3.5-flash"
    )
    cfg.api_key = "gemini-test"

    await save(cfg)

    loaded = load()

    assert loaded.backend == Backend.GEMINI


@pytest.mark.asyncio
async def test_accept_openrouter(
    temp_config,
):
    cfg = default_config()

    cfg.backend = Backend.OPENROUTER
    cfg.model = "openrouter/auto"
    cfg.api_key = "sk-or-test"

    await save(cfg)

    loaded = load()

    assert loaded.backend == Backend.OPENROUTER


@pytest.mark.asyncio
async def test_accept_deepseek(
    temp_config,
):
    cfg = default_config()

    cfg.backend = Backend.DEEPSEEK
    cfg.model = "deepseek-v4-flash"
    cfg.api_key = "sk-test"

    await save(cfg)

    loaded = load()

    assert loaded.backend == Backend.DEEPSEEK


def test_tooling_profile_default_none(
    temp_config,
):
    cfg = load()

    assert cfg.tooling_profile is None


@pytest.mark.asyncio
async def test_saved_file_permissions(
    temp_config,
):
    cfg = default_config()

    cfg.backend = Backend.GROQ
    add_custom_provider(
        cfg,
        "Gateway",
        "https://gateway.example/v1",
        "custom-secret",
    )

    await save(cfg)

    mode = (
        temp_config.stat().st_mode
        & 0o777
    )

    assert mode == 0o600


@pytest.mark.asyncio
async def test_temp_config_file_is_private_before_replace(
    temp_config,
    monkeypatch,
):
    cfg = default_config()
    cfg.backend = Backend.GROQ
    cfg.api_key = "secret"
    add_custom_provider(
        cfg,
        "Gateway",
        "https://gateway.example/v1",
        "custom-secret",
    )

    real_replace = config.os.replace
    temporary_modes: list[int] = []

    def capture_replace(source, destination):
        temporary_modes.append(
            Path(source).stat().st_mode & 0o777
        )
        real_replace(source, destination)

    monkeypatch.setattr(
        config.os,
        "replace",
        capture_replace,
    )

    await save(cfg)

    assert temporary_modes == [0o600]


@pytest.mark.asyncio
async def test_save_does_not_remove_colliding_temp_file(
    temp_config,
    monkeypatch,
):
    colliding = temp_config.parent / ".kagent.cfg.tmp.abcdef"
    colliding.write_text("keep", encoding="utf-8")

    monkeypatch.setattr(
        config.random,
        "choices",
        lambda *_args, **_kwargs: list("abcdef"),
    )

    with pytest.raises(RuntimeError, match="save failed"):
        await save(default_config())

    assert colliding.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("mcp_servers", ["bad"]),
        ("plugins", [123]),
        ("skills_dirs", "skills"),
        ("disabled_skills", "recon"),
        ("thinking_enabled", "false"),
        ("streaming_enabled", 1),
        ("max_steps", "20"),
        ("auto_compact_threshold", "16000"),
        ("temperature", "0.5"),
        ("max_tokens", "100"),
        ("gemini_thinking_budget", "512"),
        ("tooling_profile", 123),
        ("base_url", 123),
        ("model", 123),
    ],
)
def test_rejects_invalid_runtime_config_field_types(
    key,
    value,
):
    with pytest.raises(ValueError, match=key):
        config.config_from_dict({key: value})


@pytest.mark.parametrize(
    ("section", "entry"),
    [
        ("mcp_servers", {"name": "server"}),
        ("plugins", {"command": "program"}),
        (
            "mcp_servers",
            {"name": "server", "command": "program", "args": "--bad"},
        ),
        (
            "mcp_servers",
            {"name": "server", "command": "program", "env": []},
        ),
        (
            "plugins",
            {"name": "plugin", "command": "program", "schema": []},
        ),
        (
            "plugins",
            {
                "name": "plugin",
                "command": "program",
                "requires_permission": "yes",
            },
        ),
    ],
)
def test_rejects_malformed_mcp_and_plugin_entries(
    section,
    entry,
):
    with pytest.raises(ValueError, match=section):
        config.config_from_dict({section: [entry]})
