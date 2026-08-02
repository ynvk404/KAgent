from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from .config import (
    Backend,
    ToolingProfile,
    MCPServerConfig,
    PluginConfig,
    default_config,
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
            "pentestagent_CONFIG",
            str(path),
        )

        yield path


def test_returns_default_config_when_missing(
    temp_config,
):
    cfg = load()

    assert cfg.backend == Backend.EMPTY
    assert cfg.mcp_servers == []


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

    await save(cfg)

    mode = (
        temp_config.stat().st_mode
        & 0o777
    )

    assert mode == 0o600