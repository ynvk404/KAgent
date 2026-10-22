"""Opt-in experiment-only shell rights; all execution boundaries are mocked."""
import asyncio
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from scripts import experiment_profile as profile
from src.permission.network.grants import HTTPLimits
from src.permission.runtime.execution import ExecutionBlocked, policy_for
from src.tools.common.outcome import ToolOutput
from src.tools.execution.shell import BashTool
from tests.runtime.test_cli_exit_diagnostics import offline_cli
from tests.runtime.test_experiment_profile import layout
from tests.runtime.test_experiment_reviewed_request import ENGLISH
from tests.security.test_trusted_scanner_admission import runtime, NMAP, FFUF, ORIGIN


@pytest.fixture
def shell_plan(layout, tmp_path):
    source = tmp_path / "request.txt"
    source.write_bytes(ENGLISH)
    return profile.plan(layout[0], layout[1], layout[2], layout[3], "http://127.0.0.1:8081",
                        prompt_file=source, enable_headless_shell=True, legacy_bounded=True)


def test_shell_preset_is_explicit_pinned_and_preserves_native_limits(layout, shell_plan):
    legacy = profile.plan(layout[0], layout[1], layout[2], layout[3], shell_plan["origin"], legacy_bounded=True)
    assert "execution_preset" not in legacy
    assert legacy["limits"]["scanner_jobs_authorized"] == 0
    assert shell_plan["execution_preset"] == "headless-shell"
    assert shell_plan["limits"]["scanner_jobs_authorized"] is None
    assert shell_plan["limits"]["native_http"] == legacy["limits"]["native_http"]
    assert shell_plan["limits"]["max_steps"] == legacy["limits"]["max_steps"] == 60
    assert shell_plan["limits"]["wall_seconds_foreground_int"] == 1200
    receipt = profile.apply(shell_plan)
    assert profile.verify(receipt) == shell_plan
    assert (receipt.parent / "whole-target-request.txt").read_bytes() == ENGLISH


def test_shell_preset_requires_reviewed_request(layout):
    with pytest.raises(ValueError, match="reviewed request"):
        profile.plan(layout[0], layout[1], layout[2], layout[3], "http://127.0.0.1:8081",
                     enable_headless_shell=True, legacy_bounded=True)
    assert not layout[3].exists()


@pytest.mark.parametrize("preset", ["unknown", False, None])
def test_verify_rejects_invalid_execution_preset(shell_plan, preset):
    receipt = profile.apply(shell_plan)
    value = json.loads(receipt.read_text())
    value["execution_preset"] = preset
    receipt.write_bytes(profile.encode(value))
    with pytest.raises(ValueError, match="execution preset"):
        profile.verify(receipt)


@pytest.mark.parametrize("prepared,requested,headless", [(True, False, True), (False, True, True), (True, True, False)])
def test_shell_launch_requires_matching_plan_and_explicit_headless(layout, shell_plan, monkeypatch,
                                                                 prepared, requested, headless):
    value = shell_plan if prepared else profile.plan(layout[0], layout[1], layout[2], layout[3], shell_plan["origin"], legacy_bounded=True)
    receipt = profile.apply(value)
    monkeypatch.setattr(profile.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(profile.sys.stdout, "isatty", lambda: True)
    with pytest.raises(ValueError, match="shell preset"):
        profile.launch(receipt, headless=headless, execute_prompt=headless, enable_headless_shell=requested)
    assert not (Path(value["run"]) / "launch-started.json").exists()


def test_launch_installs_wrapper_only_for_matching_profile(shell_plan, monkeypatch):
    from src.cli import runtime as cli, headless
    receipt = profile.apply(shell_plan)
    runner = headless.run_headless
    calls = []
    def inspect():
        flags = cli.parse_flags(profile.sys.argv[1:])
        assert flags.headless and flags.non_interactive and flags.yolo
        assert not flags.browser and not flags.burp and not flags.resume_id
        assert "--enable-headless-shell" not in profile.sys.argv
        assert headless.run_headless is not runner
        calls.append(True)
        return 0
    monkeypatch.setattr(cli, "cli_main", inspect)
    assert profile.launch(receipt, headless=True, execute_prompt=True, yolo=True,
                          accept_unknown_http_effects=True, enable_headless_shell=True) == 0
    assert calls == [True] and headless.run_headless is runner
    assert json.loads((Path(shell_plan["run"]) / "launch-started.json").read_text())["enable_headless_shell"] is True
    with pytest.raises(ValueError, match="already been launched"):
        profile.launch(receipt, headless=True, execute_prompt=True, enable_headless_shell=True)


@pytest.mark.parametrize("yolo", [False, True])
async def test_existing_policy_admits_bash_shell_and_both_scanners_without_spawn(runtime, monkeypatch, yolo):
    from src.cli import headless
    runtime.policy.worker = SimpleNamespace(summary=lambda: "offline fixture", prepare=AsyncMock(return_value=("/unused", [])))
    for name in ("shell", "bash", "web_search"):
        runtime.policy.revoke(name)
    runtime.prompter.set_yolo(yolo)
    runtime.state.http_permissions.activate(ORIGIN, HTTPLimits(requests=500))
    runtime.registry.register(BashTool())
    capture = AsyncMock(return_value=ToolOutput("ordinary shell fixture"))
    monkeypatch.setattr("src.tools.execution.shell.run_with_capture", capture)
    scanner_calls = []
    async def scanner(binding, tool, args, signal):
        assert runtime.policy.nested_allowed()
        assert tool.scanner_plan is not None
        binding.validate(tool.scanner_plan)
        scanner_calls.append(args["scanner"])
        return ToolOutput("scanner fixture; no binary executed")
    monkeypatch.setattr(runtime.tool.scanner_binding.runtime, "run", scanner)
    before = deepcopy(runtime.state.http_permissions._budgets)
    async def inspect(agent, *_):
        assert not {"shell", "bash", "BashTool"} & runtime.policy.revoked
        assert "web_search" in runtime.policy.revoked
        for name in ("shell", "BashTool"):
            await runtime.registry.execute(name, {"command": "true"}, None, runtime.prompter)
        for args in (NMAP, FFUF):
            await runtime.registry.execute("shell", args, None, runtime.prompter)
        # Restoration happens once. Subsequent operator revocation is effective.
        runtime.policy.revoke("shell")
        with pytest.raises(ExecutionBlocked, match="revoked"):
            await runtime.registry.execute("shell", NMAP, None, runtime.prompter)
        return 0
    monkeypatch.setattr(headless, "run_headless", inspect)
    agent = SimpleNamespace(prompter=runtime.prompter, target=runtime.target)
    with profile.headless_shell_runtime({"run": str(runtime.root.parent), "origin": ORIGIN}):
        assert await getattr(headless, "run_headless")(agent) == 0
    assert headless.run_headless is inspect
    assert capture.await_count == 2 and scanner_calls == ["nmap", "ffuf"]
    assert runtime.state.http_permissions._budgets == before
    assert runtime.operator.ask.await_count == (0 if yolo else 4)
    runtime.spawn.assert_not_called()


@pytest.mark.parametrize("fault", ["worker", "root", "target", "scope", "tcp", "wildcard", "alias"])
async def test_shell_hook_refuses_wrong_runtime_without_restoring_rights(runtime, monkeypatch, fault):
    from src.cli import headless
    runtime.policy.worker = SimpleNamespace(summary=lambda: "offline fixture")
    for name in ("shell", "bash", "web_search"):
        runtime.policy.revoke(name)
    value = {"run": str(runtime.root.parent), "origin": ORIGIN}
    if fault == "worker": runtime.policy.worker = None
    elif fault == "root": value["run"] += "/wrong"
    elif fault == "target": runtime.target.set_base_url("http://127.0.0.1:9090")
    elif fault == "scope": runtime.state.add_origin("http://127.0.0.1:9090")
    elif fault == "tcp": runtime.state.add_tcp("127.0.0.1", [9090])
    elif fault == "wildcard": runtime.policy.revoke("*")
    else: runtime.policy.revoke("BashTool")
    delegate = AsyncMock()
    monkeypatch.setattr(headless, "run_headless", delegate)
    with profile.headless_shell_runtime(value):
        with pytest.raises(ValueError, match="fresh scoped runtime"):
            await getattr(headless, "run_headless")(SimpleNamespace(prompter=runtime.prompter, target=runtime.target))
    delegate.assert_not_awaited()
    assert {"shell", "bash", "web_search"} <= runtime.policy.revoked
    assert headless.run_headless is delegate


async def test_actual_cli_startup_applies_optin_after_fixed_revokes(offline_cli, layout, shell_plan, monkeypatch):
    from src.cli import headless
    from src.permission.worker.worker import OfflineWorker
    profile.apply(shell_plan)
    cli = offline_cli.cli
    monkeypatch.setattr(OfflineWorker, "available", AsyncMock(return_value=SimpleNamespace(summary=lambda: "offline worker")))
    checked = []
    async def inspect(agent, *_):
        policy = policy_for(agent.prompter)
        assert policy is not None
        assert not {"shell", "bash", "BashTool"} & policy.revoked
        assert "web_search" in policy.revoked
        assert [o.as_url() for o in policy.engagement.allowed_origins] == [shell_plan["origin"]]
        assert not policy.engagement.allowed_tcp
        assert agent.tools.get("shell") is not None and agent.tools.get("BashTool") is not None
        assert policy.browser_local is None
        assert not any(type(t).__module__ == "src.tools.mcp.integration" for t in agent.tools.tools.values())
        checked.append(True)
        return 0
    monkeypatch.setattr(headless, "run_headless", inspect)
    argv = ["kagent", "--target", shell_plan["origin"], "--headless", "--non-interactive", "--execute-prompt",
            "--prompt-file", str(Path(shell_plan["profile"]) / "whole-target-request.txt")]
    with profile.bound_runtime(shell_plan), profile.headless_shell_runtime(shell_plan), profile.patch.object(cli.sys, "argv", argv):
        assert await cli.main() == 0
    assert checked == [True]
    offline_cli.discover.assert_not_awaited()
    offline_cli.probe.assert_not_awaited()
    assert offline_cli.client.requests == []


@pytest.mark.parametrize("failure", [RuntimeError, asyncio.CancelledError])
async def test_hook_restores_frontend_binding_on_error_or_cancel(runtime, monkeypatch, failure):
    from src.cli import headless
    runtime.policy.worker = SimpleNamespace(summary=lambda: "offline fixture")
    for name in ("shell", "bash", "web_search"): runtime.policy.revoke(name)
    runner = AsyncMock(side_effect=failure())
    monkeypatch.setattr(headless, "run_headless", runner)
    with pytest.raises(failure):
        with profile.headless_shell_runtime({"run": str(runtime.root.parent), "origin": ORIGIN}):
            await getattr(headless, "run_headless")(SimpleNamespace(prompter=runtime.prompter, target=runtime.target))
    assert headless.run_headless is runner
