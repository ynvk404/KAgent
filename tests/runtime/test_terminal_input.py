"""PTY and official bridge fixtures; never controls a running pentest."""
import asyncio
import io
import os
import pty
import termios
from unittest.mock import Mock

import pytest

from src.cli import terminal_input as terminal
from src.permission.permission import Decision, PermissionRequest, OperatorInputUnavailable, PermissionReviewStale, YoloPrompter
from src.tools.common.ask import Question, Option
from src.ui.bridges.ask_bridge import BridgedAskPrompter
from src.ui.bridges.perm_bridge import BridgedPrompter
from tests.runtime.test_cli_exit_diagnostics import offline_cli
from tests.runtime.test_prompt_file_headless import headless_args


@pytest.fixture
def tty(monkeypatch):
    master, slave = pty.openpty()
    stream = os.fdopen(os.dup(slave), "r", encoding="utf-8")
    monkeypatch.setattr(terminal.sys, "stdin", stream)
    monkeypatch.setattr(terminal, "has_terminal", lambda: True)
    original = termios.tcgetattr(slave)
    yield master, slave, original
    stream.close()
    os.close(master)
    os.close(slave)


async def wait_reading(slave):
    async def poll():
        while termios.tcgetattr(slave)[3] & termios.ECHO:
            await asyncio.sleep(0.001)
    await asyncio.wait_for(poll(), 2)


async def test_pty_utf8_input_is_hidden_and_echo_restored(tty):
    master, slave, original = tty
    task = asyncio.create_task(terminal.read_terminal_line())
    await wait_reading(slave)
    os.write(master, "Trả lời\n".encode())
    assert await asyncio.wait_for(task, 2) == "Trả lời"
    assert termios.tcgetattr(slave) == original
    # Nothing is echoed to the peer; use nonblocking to verify.
    os.set_blocking(master, False)
    with pytest.raises(BlockingIOError):
        os.read(master, 1000)


@pytest.mark.parametrize("abort", ["cancel", "eof", "partial_eof", "invalid_utf8", "too_long"])
async def test_pty_failures_restore_terminal_and_remove_reader(tty, abort):
    master, slave, original = tty
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(terminal.read_terminal_line(limit=8))
    await wait_reading(slave)
    fd = terminal.sys.stdin.fileno()
    if abort == "cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        os.write(master, {"eof": b"\x04", "partial_eof": b"private\x04", "invalid_utf8": b"\xff\n", "too_long": b"123456789\n"}[abort])
        with pytest.raises((EOFError, UnicodeDecodeError)):
            await asyncio.wait_for(task, 2)
    assert termios.tcgetattr(slave) == original
    assert not loop.remove_reader(fd)


async def test_yolo_ask_user_waits_for_explicit_answer_via_official_bridge(tty, capsys):
    master, slave, _ = tty
    frontend = terminal.TerminalInput(lambda: ("provider-secret",))
    bridge = BridgedAskPrompter(frontend.publish_ask)
    task = asyncio.create_task(bridge.ask(Question("Choose provider-secret", [Option("First"), Option("Second")])) )
    await wait_reading(slave)
    assert not task.done()
    os.write(master, b"\n")  # Blank must not select the first option.
    await asyncio.sleep(0.03)
    assert not task.done()
    os.write(master, b"2\n")
    assert await asyncio.wait_for(task, 2) == "Second"
    assert "provider-secret" not in capsys.readouterr().err
    await frontend.close()


async def test_forced_yolo_review_uses_callback_no_session_or_lab_grant(tty):
    master, slave, _ = tty
    frontend = terminal.TerminalInput(lambda: ())
    bridge = BridgedPrompter(frontend.publish_permission)
    prompter = YoloPrompter(bridge, True)
    request = PermissionRequest("fixture", "Review", "Bounded action", force_operator=True,
                                offer_http_lab=True, no_session_cache=True)
    task = asyncio.create_task(prompter.ask(request))
    await wait_reading(slave)
    assert not task.done()
    os.write(master, b"1\n")
    assert await asyncio.wait_for(task, 2) == Decision.ALLOW_ONCE
    await frontend.close()


async def test_stale_review_cancels_reader_without_approval(tty):
    _, slave, original = tty
    frontend = terminal.TerminalInput(lambda: ())
    bridge = BridgedPrompter(frontend.publish_permission)
    current = [True]
    request = PermissionRequest("fixture", "Review", "Bounded action", force_operator=True,
                                is_current=lambda: current[0])
    task = asyncio.create_task(bridge.ask(request))
    await wait_reading(slave)
    current[0] = False
    with pytest.raises(PermissionReviewStale):
        await asyncio.wait_for(task, 2)
    await frontend.close()
    assert termios.tcgetattr(slave) == original


async def test_eof_marks_needs_operator_never_resolves(tty):
    master, slave, original = tty
    frontend = terminal.TerminalInput(lambda: ())
    bridge = BridgedAskPrompter(frontend.publish_ask)
    task = asyncio.create_task(bridge.ask(Question("Test identity?")))
    await wait_reading(slave)
    os.write(master, b"\x04")
    with pytest.raises(OperatorInputUnavailable):
        await asyncio.wait_for(task, 2)
    assert frontend.needed.is_set() and frontend.tool == "ask_user"
    await frontend.close()
    assert termios.tcgetattr(slave) == original


async def test_lost_tty_and_oversize_review_fail_closed(monkeypatch):
    frontend = terminal.TerminalInput(lambda: ())
    monkeypatch.setattr(terminal, "has_terminal", lambda: False)
    bridge = BridgedAskPrompter(frontend.publish_ask)
    with pytest.raises(OperatorInputUnavailable):
        await bridge.ask(Question("Test identity?"))
    await frontend.close()
    assert frontend.needed.is_set()
    with pytest.raises(OperatorInputUnavailable):
        frontend.safe("x" * 16385)
    assert "\x1b" not in frontend.safe("\x1b[31m--password secretvalue")
    assert "secretvalue" not in frontend.safe("\x1b[31m--password secretvalue")


async def test_actual_headless_interactive_agent_continues_and_redacts_answer(tty, offline_cli, monkeypatch, tmp_path, capsys):
    import json
    from src.llm.core.types import ChatResponse, Message, FunctionCall, ToolCall
    cli = offline_cli.cli
    output = headless_args(cli, monkeypatch, tmp_path)
    cli.sys.argv.remove("--non-interactive")
    cli.sys.argv.append("--interactive")
    offline_cli.client.scripted = [
        ChatResponse(message=Message("assistant", "", tool_calls=[ToolCall("ask", FunctionCall(
            "ask_user", json.dumps({"questions": [{"question": "Which identity?"}]})))]), finish_reason="tool_calls"),
        ChatResponse(message=Message("assistant", "Received operator-secret-value"), finish_reason="stop"),
    ]
    task = asyncio.create_task(cli.main())
    master, slave, original = tty
    await wait_reading(slave)
    assert not task.done()
    os.write(master, b"operator-secret-value\n")
    assert await asyncio.wait_for(task, 4) == 0
    captured = capsys.readouterr()
    assert "operator-secret-value" not in captured.out + captured.err
    assert "operator-secret-value" not in (output / "events.jsonl").read_text()
    assert len(offline_cli.client.requests) == 2
    assert termios.tcgetattr(slave) == original


@pytest.mark.parametrize("shutdown", ["eof", "sigint"])
async def test_actual_headless_interactive_input_shutdown_stops(tty, offline_cli, monkeypatch, tmp_path, shutdown):
    import json
    from src.llm.core.types import ChatResponse, Message, FunctionCall, ToolCall
    cli = offline_cli.cli
    output = headless_args(cli, monkeypatch, tmp_path)
    cli.sys.argv.remove("--non-interactive")
    cli.sys.argv.append("--interactive")
    handlers = {}
    monkeypatch.setattr(asyncio.get_running_loop(), "add_signal_handler", lambda sig, cb: handlers.update({sig: cb}))
    offline_cli.client.scripted = [ChatResponse(message=Message("assistant", "", tool_calls=[ToolCall("ask", FunctionCall(
        "ask_user", json.dumps({"questions": [{"question": "Which identity?"}]})))]), finish_reason="tool_calls")]
    task = asyncio.create_task(cli.main())
    master, slave, original = tty
    await wait_reading(slave)
    if shutdown == "eof":
        os.write(master, b"\x04")
    else:
        import signal
        handlers[signal.SIGINT]()
    assert await asyncio.wait_for(task, 4) == (3 if shutdown == "eof" else 130)
    assert json.loads((output / "events.jsonl").read_text().splitlines()[-1])["status"] == ("needs_operator" if shutdown == "eof" else "cancelled")
    assert len(offline_cli.client.requests) == 1
    assert termios.tcgetattr(slave) == original


async def test_terminal_loss_while_waiting_removes_reader(tty, monkeypatch):
    _, slave, original = tty
    task = asyncio.create_task(terminal.read_terminal_line())
    await wait_reading(slave)
    monkeypatch.setattr(terminal, "has_terminal", lambda: False)
    with pytest.raises(EOFError):
        await asyncio.wait_for(task, 1)
    assert termios.tcgetattr(slave) == original
    assert not asyncio.get_running_loop().remove_reader(terminal.sys.stdin.fileno())
