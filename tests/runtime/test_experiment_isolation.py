"""Isolation profiles preserve native CLI behavior; all execution is offline."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from scripts import experiment_profile as profile
from tests.runtime.test_cli_exit_diagnostics import offline_cli
from tests.runtime.test_experiment_profile import layout, make_plan, original_bytes


def terminal(monkeypatch):
    monkeypatch.setattr(profile.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(profile.sys.stdout, "isatty", lambda: True)


def test_default_profile_adds_no_limits_or_task(layout):
    before = original_bytes(layout)
    value = make_plan(layout)
    assert value["version"] == 4
    assert "limits" not in value and "execution_preset" not in value
    assert value["runtime_options"] == {"max_steps": None}
    assert profile.request_bytes(value) == b""
    receipt = profile.apply(value)
    assert not (receipt.parent / "whole-target-request.txt").exists()
    assert profile.verify(receipt) == value
    assert original_bytes(layout) == before


@pytest.mark.parametrize("yolo", [False, True])
@pytest.mark.parametrize("accept", [False, True])
def test_tui_uses_native_yolo_without_injected_grant_or_prompt(layout, monkeypatch, yolo, accept):
    from src.cli import runtime
    value = make_plan(layout)
    receipt = profile.apply(value)
    terminal(monkeypatch)
    before = original_bytes(layout)
    checked = []

    def inspect():
        flags = runtime.parse_flags(profile.sys.argv[1:])
        assert flags.target_url == value["origin"]
        assert flags.yolo is yolo and flags.accept_unknown_http_effects is accept
        assert flags.max_steps == 0 and flags.http_lab_grants == []
        assert flags.prompt_file == "" and not flags.resume_id
        assert not flags.headless and not getattr(flags, "browser", False) and not flags.burp
        assert runtime.MemoryStore().list() == []
        assert runtime.EngagementStore().load() == ""
        assert runtime.IntelligenceStore().get_stats()["project"] == 0
        assert runtime.config.config_path() == layout[2]
        checked.append(True)
        return 0

    monkeypatch.setattr(runtime, "cli_main", inspect)
    assert profile.launch(receipt, yolo=yolo, accept_unknown_http_effects=accept) == 0
    assert checked == [True] and original_bytes(layout) == before


@pytest.mark.parametrize("planned,override,expected", [(None, None, 0), (17, None, 17), (17, 29, 29)])
def test_only_explicit_step_limits_are_forwarded(layout, monkeypatch, planned, override, expected):
    from src.cli import runtime
    value = profile.plan(layout[0], layout[1], layout[2], layout[3], "http://127.0.0.1:8081", planned)
    receipt = profile.apply(value)
    terminal(monkeypatch)
    checked = []

    def inspect():
        assert runtime.parse_flags(profile.sys.argv[1:]).max_steps == expected
        checked.append(True)
        return 0

    monkeypatch.setattr(runtime, "cli_main", inspect)
    assert profile.launch(receipt, override) == 0
    assert checked == [True]


def test_official_custom_and_manual_config_are_preserved_without_secret_metadata(layout, monkeypatch):
    from src.cli import runtime
    from src.config.config import resolve_custom_provider
    cfg = json.loads(layout[2].read_text())
    custom_id = "0123456789abcdef0123456789abcdef"
    cfg.update(backend="openai", model="fixture-official-model", active_custom_provider_id=custom_id,
               custom_providers={custom_id: {"name": "Fixture custom", "protocol": "openai-compatible",
                   "base_url": "https://fixture.invalid/v1", "default_model": "fixture-custom-model"}},
               custom_provider_api_keys={custom_id: "fixture-custom-secret"},
               api_keys={"openai": "fixture-official-secret", "openai-compat": "fixture-manual-secret"},
               manual_openai_compat_model="fixture-manual-model",
               manual_openai_compat_base_url="https://manual.invalid/v1",
               skills_dirs=["extra-skills"],
               plugins=[{"name": "fixture", "command": "fixture-plugin"}],
               mcp_servers=[{"name": "fixture", "command": "fixture-mcp"}])
    layout[2].write_text(json.dumps(cfg))
    before = original_bytes(layout)
    value = make_plan(layout)
    text = profile.encode(value).decode()
    assert all(secret not in text for secret in ("fixture-custom-secret", "fixture-official-secret", "fixture-manual-secret"))
    assert value["provider"]["active_custom_provider_id"] == custom_id
    assert value["provider"]["model"] == "fixture-custom-model"
    receipt = profile.apply(value)
    terminal(monkeypatch)
    checked = []

    def inspect():
        loaded = runtime.config.load()
        assert loaded.active_custom_provider_id == custom_id
        assert loaded.backend == "openai" and loaded.model == "fixture-official-model"
        effective, _ = resolve_custom_provider(loaded, custom_id)
        assert effective.model == "fixture-custom-model" and effective.api_key == "fixture-custom-secret"
        assert loaded.api_keys["openai-compat"] == "fixture-manual-secret"
        assert loaded.manual_openai_compat_model == "fixture-manual-model"
        assert len(loaded.plugins) == len(loaded.mcp_servers) == 1
        assert runtime.skill_search_dirs(loaded.skills_dirs)[-1] == str(layout[0] / "extra-skills")
        checked.append(True)
        return 0

    monkeypatch.setattr(runtime, "cli_main", inspect)
    assert profile.launch(receipt) == 0
    assert checked == [True] and original_bytes(layout) == before


def test_native_cli_options_remain_available(layout, monkeypatch):
    from src.cli import runtime
    receipt = profile.apply(make_plan(layout))
    terminal(monkeypatch)
    checked = []

    def inspect():
        flags = runtime.parse_flags(profile.sys.argv[1:])
        assert not hasattr(flags, "browser") and flags.burp and flags.burp_port == 9099
        assert flags.model == "fixture-override" and flags.no_stream
        checked.append(True)
        return 0

    monkeypatch.setattr(runtime, "cli_main", inspect)
    assert profile.main(["--launch", str(receipt), "--", "--burp", "9099",
                         "--model", "fixture-override", "--no-stream"]) == 0
    assert checked == [True]


def test_yolo_alias_records_the_actual_launch_mode(layout, monkeypatch):
    from src.cli import runtime
    receipt = profile.apply(make_plan(layout))
    terminal(monkeypatch)
    monkeypatch.setattr(runtime, "cli_main", lambda: 0)
    assert profile.launch(receipt, cli_args=["--dangerously-skip-permissions"]) == 0
    assert json.loads((layout[3] / "launch-started.json").read_text())["yolo"] is True


@pytest.mark.parametrize("failure", [RuntimeError, asyncio.CancelledError])
def test_failed_or_cancelled_startup_restores_runtime_bindings(layout, monkeypatch, failure):
    from src.cli import runtime
    value = make_plan(layout)
    receipt = profile.apply(value)
    terminal(monkeypatch)
    original = (Path.cwd(), runtime.MemoryStore, runtime.IntelligenceStore,
                runtime.EngagementStore, runtime.skill_search_dirs, sys.argv, dict(os.environ))
    def fail():
        raise failure()
    monkeypatch.setattr(runtime, "cli_main", fail)
    with pytest.raises(failure):
        profile.launch(receipt)
    assert (Path.cwd(), runtime.MemoryStore, runtime.IntelligenceStore,
            runtime.EngagementStore, runtime.skill_search_dirs, sys.argv, dict(os.environ)) == original


@pytest.mark.parametrize("native", [["--resume", "old"], ["--target", "http://other.invalid"],
                                    ["--log", "/tmp/old.log"], ["--debug-session-path=/tmp/old.jsonl"]])
def test_native_arguments_cannot_replace_isolated_paths_or_declared_target(layout, monkeypatch, native):
    receipt = profile.apply(make_plan(layout))
    terminal(monkeypatch)
    with pytest.raises(ValueError, match="launcher options"):
        profile.launch(receipt, cli_args=native)
    assert not (layout[3] / "launch-started.json").exists()


def test_headless_uses_only_explicit_native_grants_and_leaves_policy_unchanged(layout, tmp_path, monkeypatch):
    from src.cli import runtime, headless
    source = tmp_path / "request.txt"
    source.write_text("Inspect the declared authorized target.\n")
    receipt = profile.apply(profile.plan(layout[0], layout[1], layout[2], layout[3],
                                         "http://127.0.0.1:8081", prompt_file=source))
    runner = headless.run_headless
    grant = "http://127.0.0.1:8081,autonomous,90,23,1,1,1,4096,8192"
    with pytest.raises(ValueError, match="explicit finite"):
        profile.launch(receipt, headless=True, execute_prompt=True, yolo=True)
    assert not (layout[3] / "launch-started.json").exists()
    checked = []

    def inspect():
        flags = runtime.parse_flags(profile.sys.argv[1:])
        assert flags.http_lab_grants == [grant] and flags.max_steps == 0
        assert Path(flags.prompt_file).read_bytes() == source.read_bytes()
        assert headless.run_headless is runner
        checked.append(True)
        return 0

    monkeypatch.setattr(runtime, "cli_main", inspect)
    assert profile.launch(receipt, headless=True, execute_prompt=True, yolo=True,
                          accept_unknown_http_effects=True, cli_args=["--http-lab-grant", grant]) == 0
    assert checked == [True]


@pytest.mark.parametrize("yolo", [False, True])
async def test_actual_startup_matches_normal_runtime_with_fresh_stores(offline_cli, layout, monkeypatch, yolo):
    cli = offline_cli.cli
    offline_cli.cfg.max_steps = 31
    before = original_bytes(layout)
    value = make_plan(layout)
    profile.apply(value)
    states = []

    async def inspect(app):
        agent = app.agent
        rights = agent.engagement_state.http_permissions
        states.append((agent.get_max_steps(), set(agent.tools.tools),
                       set(agent.prompter.execution_policy.revoked),
                       [(o.as_url(), g.limits, g.activation) for o, g in rights.grants.items()]))
        assert agent.get_max_steps() == 31
        assert agent.engagement_state.allowed_origins == {agent.target.origin()}
        assert agent.prompter.execution_policy is not None
        if len(states) == 2:
            assert agent.memory_store.project_dir == layout[3] / "project/.kagent/memory"
            assert agent.memory_store.personal_dir == layout[3] / "profile-home/.kagent/memory"
            assert agent.engagement == "" and agent.memory is None
            assert agent.build_intelligence_context("old canary") == ""
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()

    monkeypatch.setattr(cli.KAgent, "run_async", inspect)
    argv = ["kagent", "--target", value["origin"]] + (["--yolo"] if yolo else [])
    with profile.patch.object(sys, "argv", argv):
        assert await cli.main() == 0
    with profile.bound_runtime(value), profile.patch.object(sys, "argv", [
        *argv, "--log", str(layout[3] / "logs/kagent.log"),
        "--debug-session-path", str(layout[3] / "logs/session.jsonl"),
    ]):
        assert await cli.main() == 0
    assert states[0] == states[1]
    assert original_bytes(layout) == before and offline_cli.client.requests == []


@pytest.mark.parametrize("version,expected", [(4, "native"), (2, "legacy-timeout"), (3, "legacy-timeout")])
def test_shell_launcher_has_no_default_timeout(tmp_path, version, expected):
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "venv-linux/bin").mkdir(parents=True)
    (repo / "venv-linux/bin/python").symlink_to(sys.executable)
    shutil.copyfile(profile.REPO / "scripts/run_experiment.sh", repo / "scripts/run_experiment.sh")
    (repo / "scripts/experiment_profile.py").write_text('print("native")\n')
    receipt = tmp_path / "profile.json"
    receipt.write_text(json.dumps({"version": version}))
    commands = tmp_path / "commands"
    commands.mkdir()
    timeout = commands / "timeout"
    timeout.write_text('#!/bin/sh\nprintf "%s\\n" legacy-timeout\n')
    timeout.chmod(0o700)
    result = subprocess.run(["bash", str(repo / "scripts/run_experiment.sh"), "--run", str(receipt),
                             "--headless", "--execute-prompt"],
                            env={**os.environ, "PATH": str(commands) + os.pathsep + os.environ["PATH"]},
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected
