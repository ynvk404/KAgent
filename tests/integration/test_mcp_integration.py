"""Legacy MCP configuration is inert during real CLI startup and persistence."""

import asyncio
from copy import deepcopy
import json
import subprocess
from unittest.mock import Mock

import pytest

from src.config.config import config_to_dict, load, save
from tests.runtime.test_cli_exit_diagnostics import offline_cli  # noqa: F401


@pytest.mark.parametrize("list_tools", [False, True])
async def test_legacy_mcp_config_roundtrips_and_starts_without_processes(
    offline_cli, tmp_path, monkeypatch, capsys, list_tools,
):
    fixture = offline_cli
    raw = config_to_dict(fixture.cfg)
    raw["mcp_servers"] = [
        {"name": name, "command": command, "args": ["--legacy-argument"],
         "env": {"LEGACY_TOKEN": "fixture-private-value"}}
        for name, command in [("browser", "node"), ("custom", "python")]
    ]
    path = tmp_path / "config.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setenv("kagent_CONFIG", str(path))
    monkeypatch.setattr(fixture.cli.config, "load", load)
    spawn = Mock(side_effect=AssertionError("MCP configuration must never spawn a process"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(asyncio, "create_subprocess_shell", spawn)
    monkeypatch.setattr(subprocess, "Popen", spawn)

    loaded = load()
    before = deepcopy(loaded)
    assert config_to_dict(loaded) == raw
    seen = []

    async def run_app(app):
        names = app.agent.tools.names()
        assert {"http", "shell", "content_discovery", "service_discovery", "browser_capture_get"} <= set(names)
        assert not any(name.startswith("mcp_") for name in names)
        for name in ("mcp_browser_browser_navigate", "mcp_custom_operation"):
            with pytest.raises(RuntimeError, match="unknown tool"):
                await app.agent.tools.execute(name, {}, None, app.agent.prompter)
        seen.append(True)

    monkeypatch.setattr(fixture.cli.KAgent, "run_async", run_app)
    monkeypatch.setattr(fixture.cli.sys, "argv", ["kagent", *(["--list-tools"] if list_tools else [])])
    assert await fixture.cli.main() == 0
    out, err = capsys.readouterr()
    assert bool(seen) is not list_tools
    assert "unavailable" in err and "no host fallback" in err
    assert "fixture-private-value" not in out + err
    if list_tools:
        assert "- browser_capture_get" in out and "- http" in out
        assert "mcp_" not in out
    assert load() == before
    await save(loaded)
    assert load() == before and config_to_dict(load()) == raw
    spawn.assert_not_called()
