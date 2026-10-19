"""Offline CLI/TUI/Agent regressions; no provider or lab connections."""
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from src.cli.prompt_file import read_prompt_file, PromptFileError, MAX_PROMPT_BYTES
from src.cli.runtime import parse_flags, FlagParseError
from src.llm.core.types import ChatResponse, Message, FunctionCall, ToolCall
from tests.runtime.test_cli_exit_diagnostics import offline_cli
from src.logger.logger import init as real_log_init


@pytest.mark.parametrize("data", [b"", b"  \n", b"\xff", b"x\x00", b"x\x1b[31m", b"x" * (MAX_PROMPT_BYTES + 1)])
def test_prompt_errors_do_not_echo_content(tmp_path, data):
    path = tmp_path / "prompt"
    path.write_bytes(data)
    with pytest.raises(PromptFileError) as error:
        read_prompt_file(str(path))
    assert len(str(error.value)) < 150


def test_utf8_bom_multiline_and_boundary(tmp_path):
    path = tmp_path / "prompt"
    path.write_bytes("\ufeffXin chào\r\nsecond line\n".encode())
    assert read_prompt_file(str(path)) == "Xin chào\nsecond line\n"
    path.write_bytes(b"x" * MAX_PROMPT_BYTES)
    assert len(read_prompt_file(str(path))) == MAX_PROMPT_BYTES


def test_prompt_path_safety(tmp_path):
    regular = tmp_path / "regular"
    regular.write_text("test")
    symlink = tmp_path / "symlink"
    symlink.symlink_to(regular)
    hardlink = tmp_path / "hardlink"
    os.link(regular, hardlink)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    for path in (tmp_path, tmp_path / "missing", symlink, hardlink, fifo, Path("-")):
        with pytest.raises(PromptFileError):
            read_prompt_file(str(path))


@pytest.mark.parametrize("flags", [
    ["--headless"], ["--execute-prompt"], ["--interactive"], ["--non-interactive"],
    ["--headless-output", "x"],
    ["--headless", "--execute-prompt", "--prompt-file", "x", "--interactive", "--non-interactive"],
    ["--headless", "--execute-prompt", "--prompt-file", "x", "--yolo"],
    ["--headless", "--execute-prompt", "--prompt-file", "x", "--resume", "id"],
])
def test_explicit_mode_and_execution_required(flags):
    with pytest.raises(FlagParseError):
        parse_flags(flags)


def test_prompt_alone_does_not_select_headless_or_yolo():
    flags = parse_flags(["--prompt-file", "x"])
    assert not flags.headless and not flags.yolo and not flags.execute_prompt


async def test_invalid_prompt_fails_before_provider_startup(offline_cli, monkeypatch, capsys, tmp_path):
    cli = offline_cli.cli
    monkeypatch.setattr(cli.sys, "argv", ["kagent", "--prompt-file", str(tmp_path / "missing")])
    load = Mock(side_effect=AssertionError("must not load config"))
    monkeypatch.setattr(cli.config, "load", load)
    assert await cli.main() == 2
    load.assert_not_called()
    assert not offline_cli.client.requests
    assert "prompt" in capsys.readouterr().err


@pytest.mark.parametrize("draft", ["/target http://outside.invalid", "# do not save as memory", "[Pasted text #1 +4 lines]\nXin chào", "  \n# heading\n  "])
async def test_tui_prefills_literal_user_draft_without_submit(offline_cli, monkeypatch, tmp_path, draft):
    cli = offline_cli.cli
    path = tmp_path / "prompt"
    path.write_text(draft)
    monkeypatch.setattr(cli.sys, "argv", ["kagent", "--prompt-file", str(path)])
    submitted = []

    async def app_run(app):
        app.agent.run = AsyncMock(side_effect=lambda value, **kwargs: submitted.append(value))
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            assert app.input.value == draft
            assert not app.history and not offline_cli.client.requests
            assert not submitted
            assert not app.slash_matches
            await pilot.press("enter")
            await pilot.pause()
            assert submitted == [draft]
            assert not app.input.value
    monkeypatch.setattr(cli.KAgent, "run_async", app_run)
    assert await cli.main() == 0


async def test_file_draft_edit_paste_clear_and_typed_commands(offline_cli, monkeypatch, tmp_path):
    from textual import events
    cli = offline_cli.cli
    path = tmp_path / "prompt"
    path.write_text("# draft")
    monkeypatch.setattr(cli.sys, "argv", ["kagent", "--prompt-file", str(path)])
    async def app_run(app):
        app.agent.run = AsyncMock()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            pasted = "\n" + "\n".join("extra line" for _ in range(30))
            await app.on_paste(events.Paste(pasted))
            assert app.input.value == "# draft" + pasted
            assert not app.pasted_text
            await pilot.press("escape")
            assert not app.input.value and not app._prompt_file_draft
            app.input.set_value("/maxsteps 7")
            app._recompute_menus()
            await pilot.press("enter")
            await pilot.pause()
            assert app.agent.get_max_steps() == 7
            app.agent.run.assert_not_awaited()
    monkeypatch.setattr(cli.KAgent, "run_async", app_run)
    assert await cli.main() == 0


def headless_args(cli, monkeypatch, tmp_path, *extra):
    prompt = tmp_path / "prompt"
    prompt.write_text("Inspect the offline fixture.")
    output = tmp_path / "headless"
    monkeypatch.setattr(cli.sys, "argv", ["kagent", "--headless", "--non-interactive",
        "--execute-prompt", "--prompt-file", str(prompt), "--headless-output", str(output),
        "--no-stream", "--max-steps", "3", *extra])
    monkeypatch.setattr(cli.KAgent, "run_async", AsyncMock(side_effect=AssertionError("No TUI")))
    return output


async def test_headless_calls_real_agent_run_and_persists_session(offline_cli, monkeypatch, tmp_path):
    cli = offline_cli.cli
    output = headless_args(cli, monkeypatch, tmp_path)
    offline_cli.client.scripted = [ChatResponse(message=Message("assistant", "Fixture complete"), finish_reason="stop")]
    assert await cli.main() == 0
    rows = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
    assert rows[-1]["status"] == "completed"
    assert rows[-1]["cost_usd"] == "Not measured"
    user = [m for m in offline_cli.client.requests[0].messages if m.role == "user"]
    assert user[-1].content == "Inspect the offline fixture."
    assert (output / "llm-metrics.jsonl").exists()
    assert list((tmp_path / "sessions").glob("*.json"))
    assert list((tmp_path / "context").glob("*.md"))
    offline_cli.probe.assert_not_awaited()


@pytest.mark.parametrize("yolo", [False, True])
async def test_noninteractive_ask_user_stops_without_reading_stdin(offline_cli, monkeypatch, tmp_path, capsys, yolo):
    cli = offline_cli.cli
    extra = ["--yolo", "--target", "http://127.0.0.1:8081", "--http-lab-grant",
             "http://127.0.0.1:8081,autonomous,60,2,1,1,1,4096,8192", "--accept-unknown-http-effects"] if yolo else []
    output = headless_args(cli, monkeypatch, tmp_path, *extra)
    # pytest's captured stdin raises immediately if anybody tries to read it.
    offline_cli.client.scripted = [ChatResponse(message=Message("assistant", "", tool_calls=[ToolCall(
        "ask", FunctionCall("ask_user", json.dumps({"questions": [{"question": "Which test account?"}]})))]), finish_reason="tool_calls")]
    assert await cli.main() == 3
    rows = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
    assert rows[-1]["status"] == "needs_operator"
    assert any(row.get("event") == "needs_operator" and row["tool"] == "ask_user" for row in rows)
    assert len(offline_cli.client.requests) == 1


async def test_interactive_requires_tty_before_startup(offline_cli, monkeypatch, tmp_path):
    cli = offline_cli.cli
    headless_args(cli, monkeypatch, tmp_path)
    cli.sys.argv.remove("--non-interactive")
    cli.sys.argv.append("--interactive")
    load = Mock(side_effect=AssertionError("must not load config"))
    monkeypatch.setattr(cli.config, "load", load)
    assert await cli.main() == 2
    load.assert_not_called()


async def test_headless_cancel_joins_turn_before_checkpoint(offline_cli, monkeypatch, tmp_path):
    cli = offline_cli.cli
    output = headless_args(cli, monkeypatch, tmp_path)
    entered = asyncio.Event()
    cleaned = []
    async def wait(request, signal=None):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.append(True)
    monkeypatch.setattr(offline_cli.client, "chat", wait)
    # Capture the real SIGINT callback installed by startup, without a process signal.
    handlers = {}
    monkeypatch.setattr(asyncio.get_running_loop(), "add_signal_handler", lambda sig, cb: handlers.update({sig: cb}))
    task = asyncio.create_task(cli.main())
    await asyncio.wait_for(entered.wait(), 3)
    import signal
    handlers[signal.SIGINT]()
    assert await asyncio.wait_for(task, 3) == 130
    assert cleaned == [True]
    assert json.loads((output / "events.jsonl").read_text().splitlines()[-1])["status"] == "cancelled"


def test_events_redact_secrets_and_never_overwrite(tmp_path, capsys):
    from src.cli.headless import EventSink
    sink = EventSink(tmp_path, ("arbitrary-provider-key",))
    sink.write({"event": "fixture", "text": "arbitrary-provider-key --password supersecret",
                "error": RuntimeError("arbitrary-provider-key"), "Authorization": "Bearer tokenvalue"})
    sink.close()
    data = (tmp_path / "events.jsonl").read_text() + capsys.readouterr().out
    assert all(secret not in data for secret in ("arbitrary-provider-key", "supersecret", "tokenvalue"))
    assert (tmp_path / "events.jsonl").stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        EventSink(tmp_path)


@pytest.mark.parametrize("failure", ["configuration", "provider"])
async def test_headless_startup_failure_is_private_and_does_not_recover_config(offline_cli, monkeypatch, tmp_path, capsys, failure):
    cli = offline_cli.cli
    headless_args(cli, monkeypatch, tmp_path)
    error = Mock(side_effect=RuntimeError("secret-startup-value"))
    rename = Mock(side_effect=AssertionError("must not mutate configuration"))
    monkeypatch.setattr(cli.os, "rename", rename)
    if failure == "configuration":
        monkeypatch.setattr(cli.config, "load", error)
    else:
        monkeypatch.setattr(cli, "build_startup_runtime", error)
    assert await cli.main() == 1
    rename.assert_not_called()
    assert "secret-startup-value" not in capsys.readouterr().err


@pytest.mark.parametrize("interactive", [False, True])
async def test_step_exhaustion_never_starts_another_turn_or_renews_grant(offline_cli, monkeypatch, tmp_path, capsys, interactive):
    import copy
    from src.agent.agent import Agent
    from src.cli import terminal_input
    cli = offline_cli.cli
    output = headless_args(cli, monkeypatch, tmp_path, "--yolo", "--target", "http://127.0.0.1:8081",
        "--http-lab-grant", "http://127.0.0.1:8081,autonomous,60,2,1,1,1,4096,8192", "--accept-unknown-http-effects")
    cli.sys.argv[cli.sys.argv.index("--max-steps") + 1] = "1"
    if interactive:
        cli.sys.argv.remove("--non-interactive")
        cli.sys.argv.append("--interactive")
        monkeypatch.setattr(terminal_input, "has_terminal", lambda: True)
    read = AsyncMock(side_effect=AssertionError("No Continue read without safe same-turn resume"))
    monkeypatch.setattr(terminal_input, "read_terminal_line", read)
    original_run = Agent.run
    turns = []
    async def observe(agent, *args, **kwargs):
        rights = agent.engagement_state.http_permissions
        before = copy.deepcopy((rights.grants, rights._budgets, rights._constraints))
        turns.append(agent.store.id)
        try:
            return await original_run(agent, *args, **kwargs)
        finally:
            assert (rights.grants, rights._budgets, rights._constraints) == before
            assert agent.get_max_steps() == 1
    monkeypatch.setattr(Agent, "run", observe)
    offline_cli.client.scripted = [
        ChatResponse(message=Message("assistant", "", tool_calls=[ToolCall("status", FunctionCall("permissions_status", "{}"))]), finish_reason="tool_calls"),
        ChatResponse(message=Message("assistant", "Budget summary"), finish_reason="stop"),
    ]
    assert await cli.main() == 5
    rows = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
    assert rows[-1]["status"] == "budget_exhausted"
    diagnostic = next(row for row in rows if row["event"] == "budget_exhausted")
    assert diagnostic["step_limit"] == 1
    assert diagnostic["continuation"] == "unavailable" and diagnostic["turn_restarted"] is False
    assert len(turns) == 1 and len(offline_cli.client.requests) == 2  # outer step + final synthesis
    read.assert_not_awaited()
    if interactive:
        assert "Continue unavailable" in capsys.readouterr().err


async def test_agent_panic_stderr_and_existing_file_logger_remain_private(offline_cli, monkeypatch, tmp_path, capsys):
    from src.agent.agent import Agent
    cli = offline_cli.cli
    output = headless_args(cli, monkeypatch, tmp_path, "--log", str(tmp_path / "kagent.log"))
    offline_cli.cfg.api_key = "plain-sensitive-provider-value"
    monkeypatch.setattr(cli.logger, "init", real_log_init)
    monkeypatch.setattr(Agent, "run_inner", AsyncMock(side_effect=RuntimeError("plain-sensitive-provider-value")))
    assert await cli.main() == 1
    captured = capsys.readouterr()
    assert "plain-sensitive-provider-value" not in captured.out + captured.err
    assert "plain-sensitive-provider-value" not in (tmp_path / "kagent.log").read_text()
    assert "plain-sensitive-provider-value" not in (output / "events.jsonl").read_text()


async def test_output_loss_stops_and_still_closes_private_logs(offline_cli, monkeypatch, tmp_path):
    import io
    cli = offline_cli.cli
    output = headless_args(cli, monkeypatch, tmp_path)
    class BrokenOutput(io.StringIO):
        writes = 0
        def write(self, value):
            self.writes += 1
            if self.writes > 1:
                raise BrokenPipeError("output closed")
            return len(value)
    monkeypatch.setattr(cli.sys, "stdout", BrokenOutput())
    offline_cli.client.scripted = [ChatResponse(message=Message("assistant", "Fixture complete"), finish_reason="stop")]
    assert await cli.main() == 1
    rows = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
    assert rows[-1]["status"] == "error"
    assert len(offline_cli.client.requests) <= 1
    with (output / "events.jsonl").open("a") as stream:
        stream.write("")
