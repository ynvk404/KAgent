"""Offline CLI startup and Textual shutdown coverage for terminal diagnostics."""

import asyncio
import copy
import importlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.config.config import Backend, Config, ToolingProfile
from src.llm.runtime.probe import ProbeResult
from src.permission.network.grants import HTTPLimits
from src.permission.worker.worker import OfflineWorker
from tests.helpers.agent_fakes import FakeClient


ORIGIN = "http://juice.lab:3000"
LAB_GRANT = f"{ORIGIN},autonomous,60,7,1,1,1,4096,8192"


@pytest.fixture
async def offline_cli(tmp_path, monkeypatch):
    cli = importlib.import_module("src.cli.runtime")
    cfg = Config(backend=Backend.DEEPSEEK, model="fake-model",
                 tooling_profile=ToolingProfile.MINIMAL)
    client = FakeClient([])
    debug_path = tmp_path / "session.jsonl"
    session = SimpleNamespace(close=AsyncMock())
    probe = AsyncMock(return_value=ProbeResult("yes"))
    discover = AsyncMock(return_value={"session": session, "tools": []})
    intelligence = cli.IntelligenceStore(cwd=tmp_path, home=tmp_path / "home")
    memory = cli.MemoryStore(cwd=str(tmp_path), home=str(tmp_path / "home"))
    engagement = cli.EngagementStore(cwd=tmp_path, home=tmp_path / "home")
    monkeypatch.setenv("KAGENT_PROJECT_ROOT", str(tmp_path))
    monkeypatch.delenv("KAgent_DEBUG_SESSION", raising=False)
    monkeypatch.setenv("KAgent_DEBUG_SESSION_PATH", str(debug_path))
    monkeypatch.setattr(cli.config, "load", lambda: cfg)
    monkeypatch.setattr(cli.llm_factory, "new_from_config", lambda _cfg: client)
    monkeypatch.setattr(cli.logger, "init", lambda _path: None)
    monkeypatch.setattr(cli.logger, "init_error", lambda: None)
    monkeypatch.setattr(cli, "skill_search_dirs", lambda _dirs: [])
    monkeypatch.setattr(cli, "IntelligenceStore", lambda: intelligence)
    monkeypatch.setattr(cli, "MemoryStore", lambda: memory)
    monkeypatch.setattr(cli, "EngagementStore", lambda: engagement)
    monkeypatch.setattr(cli.session_store, "dir_from_path", lambda _: tmp_path / "sessions")
    monkeypatch.setattr(cli.session_store, "new_id", lambda: "exit-diagnostics-session")
    monkeypatch.setattr(cli, "probe_tool_support", probe)
    monkeypatch.setattr(OfflineWorker, "available", AsyncMock(return_value=None))
    monkeypatch.setattr("src.tools.mcp.integration.discover_mcp_tools", discover)
    monkeypatch.setattr("src.tools.mcp.browser_local.BrowserLocalBinding",
                        lambda *args, **kwargs: SimpleNamespace(invalidate=Mock()))
    monkeypatch.setattr(asyncio.get_running_loop(), "add_signal_handler", lambda *args: None)
    return SimpleNamespace(cli=cli, cfg=cfg, client=client, debug_path=debug_path,
                           session=session, probe=probe, discover=discover)


@pytest.mark.parametrize("rights_flags", [
    [],
    ["--yolo"],
    ["--browser", "--yolo"],
    ["--http-lab-grant", LAB_GRANT, "--accept-unknown-http-effects"],
])
@pytest.mark.parametrize("debug_mode", ["off", "flag", "path", "env"])
@pytest.mark.asyncio
async def test_exit_diagnostics_are_opt_in_and_preserve_permissions(
    offline_cli, monkeypatch, capsys, rights_flags, debug_mode
):
    cli = offline_cli.cli
    argv = ["kagent", "--target", ORIGIN, *rights_flags]
    if debug_mode == "flag":
        argv.append("--debug-session")
    elif debug_mode == "path":
        argv.extend(["--debug-session-path", str(offline_cli.debug_path)])
    elif debug_mode == "env":
        monkeypatch.setenv("KAgent_DEBUG_SESSION", "1")
    monkeypatch.setattr(cli.sys, "argv", argv)
    checked = []

    async def run_app(app):
        # These messages originate before Textual takes ownership of the terminal.
        startup = capsys.readouterr()
        debug_enabled = debug_mode != "off"
        assert startup.out == ""
        assert ("debug session log:" in startup.err) is debug_enabled
        assert ("hang stack dump:" in startup.err) is debug_enabled
        assert ("HTTP operator grants:" in startup.err) is (debug_enabled and bool(rights_flags))

        rights = app.agent.engagement_state.http_permissions
        grants = copy.deepcopy(rights.grants)
        assert len(grants) == int(bool(rights_flags))
        for grant in grants.values():
            assert grant.origin.as_url() == ORIGIN
            if "--yolo" in rights_flags:
                assert grant.activation == "yolo" and grant.limits == HTTPLimits()
            else:
                assert grant.activation == "manual" and grant.limits.requests == 7
            if debug_enabled:
                assert grant.id in startup.err and rights.session_id in startup.err
            else:
                assert grant.id not in startup.err and rights.session_id not in startup.err

        # Preserve a real revoke record and its journal through Textual shutdown.
        revoked_origin = "http://revoked.lab:3000"
        app.agent.engagement_state.add_origin(revoked_origin)
        revoked = rights.activate(revoked_origin, HTTPLimits())
        rights.revoke(revoked.id)
        policy = app.agent.prompter.execution_policy
        policy.persist()
        journal = policy.journal.read_bytes()
        assert revoked_origin in json.loads(journal)["http"]["origins"]
        before = copy.deepcopy((rights.grants, rights._budgets, rights._receipts,
                                rights.revocation_state(), rights.revision))
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
        assert (rights.grants, rights._budgets, rights._receipts,
                rights.revocation_state(), rights.revision) == before
        assert rights.grants == grants
        assert policy.journal.read_bytes() == journal
        assert app.hang_diagnostics is None or app.hang_diagnostics._thread is None
        checked.append(True)

    monkeypatch.setattr(cli.KAgent, "run_async", run_app)
    assert await cli.main() == 0
    assert checked
    output = capsys.readouterr()
    assert output.out == output.err == ""
    assert offline_cli.client.requests == []
    offline_cli.probe.assert_awaited_once()
    if "--browser" in rights_flags:
        offline_cli.discover.assert_awaited_once()
        offline_cli.session.close.assert_awaited_once()
    else:
        offline_cli.discover.assert_not_awaited()
    if debug_mode == "off":
        assert not offline_cli.debug_path.exists()
    else:
        events = [json.loads(line)["event"] for line in
                  offline_cli.debug_path.read_text(encoding="utf-8").splitlines()]
        assert "session_start" in events and "hang_watchdog_enabled" in events


@pytest.mark.asyncio
async def test_startup_failure_is_still_reported_without_debug(offline_cli, monkeypatch, capsys):
    cli = offline_cli.cli
    monkeypatch.setattr(cli.sys, "argv", ["kagent"])

    def fail_startup(*args, **kwargs):
        raise RuntimeError("provider startup failed")

    monkeypatch.setattr(cli, "build_startup_runtime", fail_startup)
    assert await cli.main() == 1
    assert "provider startup failed" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_grant_failure_is_still_reported_without_debug(offline_cli, monkeypatch, capsys):
    cli = offline_cli.cli
    monkeypatch.setattr(cli.sys, "argv", ["kagent", "--target", "http://other.lab:3000",
                         "--http-lab-grant", LAB_GRANT, "--accept-unknown-http-effects"])
    assert await cli.main() == 2
    error = capsys.readouterr().err
    assert "HTTP grant:" in error and "outside the active engagement scope" in error
    assert "debug session log:" not in error and "HTTP operator grants:" not in error


@pytest.mark.parametrize(("flags", "port", "bind_failure"), [
    ([], None, False),
    (["--burp"], 8888, False),
    (["--burp", "8888"], 8888, False),
    (["--burp", "9012"], 9012, False),
    (["--browser-ingest", "9012"], 9012, False),
    (["--burp", "8888"], 8888, True),
])
@pytest.mark.asyncio
async def test_burp_startup_displays_connection_details_in_tui(
    offline_cli, monkeypatch, capsys, flags, port, bind_failure
):
    cli = offline_cli.cli
    monkeypatch.setattr(cli.sys, "argv", ["kagent", *flags])
    handle = SimpleNamespace(port=port, url=f"http://127.0.0.1:{port}",
                             token="0123456789abcdef0123456789abcdef", close=Mock())

    def start_bridge(opts):
        assert opts.port == port
        if bind_failure:
            raise OSError("Address already in use")
        return handle

    start = Mock(side_effect=start_bridge)
    monkeypatch.setattr(cli, "start_ingest_server", start)
    checked = []

    async def run_app(app):
        startup = capsys.readouterr()
        assert startup.out == ""
        assert ("failed to start burp bridge" in startup.err) is bind_failure
        assert handle.token not in startup.err
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            notices = [entry for entry in app.state.transcript
                       if entry.text.startswith("Burp bridge listening at")]
            if port is not None and not bind_failure:
                assert len(notices) == 1
                assert notices[0].kind == "system"
                assert handle.url in notices[0].text
                assert f"Token: {handle.token}" in notices[0].text
                rendered = "\n".join(line.text for line in app.transcript_log.lines)
                assert handle.url in rendered and handle.token in rendered
                # Connection details belong to the operator UI, not model history.
                assert all(handle.token not in (message.content or "")
                           for message in app.agent.history)
            else:
                assert notices == []
                assert all(handle.token not in entry.text for entry in app.state.transcript)
            checked.append(True)

    monkeypatch.setattr(cli.KAgent, "run_async", run_app)
    assert await cli.main() == 0
    assert checked
    assert start.call_count == int(port is not None)
    assert handle.close.call_count == int(port is not None and not bind_failure)
    output = capsys.readouterr()
    assert handle.token not in output.out + output.err


@pytest.mark.asyncio
async def test_shutdown_failure_still_propagates_without_debug(offline_cli, monkeypatch, capsys):
    cli = offline_cli.cli
    monkeypatch.setattr(cli.sys, "argv", ["kagent", "--burp"])

    def fail_close():
        raise RuntimeError("bridge shutdown failed")

    handle = SimpleNamespace(port=8888, url="http://localhost:8888", token="fake",
                             close=fail_close)
    monkeypatch.setattr(cli, "start_ingest_server", lambda _opts: handle)

    async def run_app(app):
        async with app.run_test(size=(100, 30)):
            pass

    monkeypatch.setattr(cli.KAgent, "run_async", run_app)
    with pytest.raises(RuntimeError, match="bridge shutdown failed"):
        await cli.main()
    error = capsys.readouterr().err
    assert "debug session log:" not in error and "HTTP operator grants:" not in error
