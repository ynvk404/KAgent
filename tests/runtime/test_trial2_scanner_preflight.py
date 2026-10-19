"""Characterize existing Headless scanner restrictions; no scanner permission changes."""
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.permission.runtime.execution import ExecutionBlocked, policy_for
from src.tools.execution.scanners import ScannerBinding
from tests.runtime.test_cli_exit_diagnostics import offline_cli
from tests.security.test_trusted_scanner_admission import runtime, NMAP, FFUF


@pytest.mark.parametrize("args", [NMAP, FFUF])
async def test_headless_revocation_stops_typed_scanners_before_preparation(runtime, monkeypatch, args):
    for name in ("shell", "bash", "web_search"):
        runtime.policy.revoke(name)
    prepare = AsyncMock(side_effect=AssertionError("No scanner plan or network allowed"))
    monkeypatch.setattr(ScannerBinding, "prepare", prepare)
    with pytest.raises(ExecutionBlocked, match="revoked"):
        await runtime.registry.execute("shell", args, None, runtime.prompter)
    prepare.assert_not_awaited()
    runtime.operator.ask.assert_not_awaited()
    runtime.spawn.assert_not_called()


async def test_actual_headless_startup_keeps_scanners_blocked_and_no_browser_burp(offline_cli, monkeypatch, tmp_path):
    cli = offline_cli.cli
    prompt = tmp_path / "request.txt"
    prompt.write_text("Perform a whole-target assessment. Validate SQL Injection and XSS.")
    monkeypatch.setattr(cli.sys, "argv", ["kagent", "--target", "http://127.0.0.1:8081",
        "--headless", "--non-interactive", "--execute-prompt", "--prompt-file", str(prompt),
        "--headless-output", str(tmp_path / "headless")])
    prepare = AsyncMock(side_effect=AssertionError("No scanner plan or network allowed"))
    monkeypatch.setattr(ScannerBinding, "prepare", prepare)
    checked = []
    async def inspect(agent, *_args):
        policy = policy_for(agent.prompter)
        assert policy is not None
        assert {"shell", "bash", "web_search"} <= policy.revoked
        assert agent.target.base_url() == "http://127.0.0.1:8081"
        for args in (
            {"scanner": "nmap", "target": "127.0.0.1", "ports": "8081"},
            {"scanner": "ffuf", "url": "http://127.0.0.1:8081/FUZZ", "wordlist_id": "web-common"},
        ):
            with pytest.raises(ExecutionBlocked, match="revoked"):
                await agent.tools.execute("shell", args, None, agent.prompter)
        # MCP tools were not discovered/registered, and neither opt-in was supplied.
        assert not any(type(tool).__module__ == "src.tools.mcp.integration" for tool in agent.tools.tools.values())
        assert policy.browser_local is None
        assert not list((Path(tmp_path) / "artifacts/findings").glob("*.md"))
        checked.append(True)
        return 0
    monkeypatch.setattr("src.cli.headless.run_headless", inspect)
    assert await cli.main() == 0
    assert checked == [True]
    prepare.assert_not_awaited()
    offline_cli.discover.assert_not_awaited()
    offline_cli.probe.assert_not_awaited()
    assert offline_cli.client.requests == []
