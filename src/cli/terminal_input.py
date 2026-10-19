"""POSIX terminal presentation for the existing permission/question bridges."""
from __future__ import annotations

import asyncio
import os
import sys
import termios
from typing import Callable, Any

from src.cli.headless import UnavailableInput
from src.permission.permission import Decision, OperatorInputUnavailable
from src.tools.common.approval_display import redact_approval


def has_terminal() -> bool:
    try:
        return all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr))
    except (AttributeError, OSError, ValueError):
        return False


async def read_terminal_line(limit: int = 4096) -> str:
    """No worker thread: cancellation removes the reader and restores echo."""
    fd = sys.stdin.fileno()
    if not os.isatty(fd):
        raise EOFError("terminal unavailable")
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    original = termios.tcgetattr(fd)
    hidden = original.copy()
    hidden[3] &= ~(termios.ECHO | termios.ECHONL)

    def ready() -> None:
        if future.done():
            return
        try:
            if not os.isatty(fd):
                raise EOFError("terminal unavailable")
            line = os.read(fd, limit + 2)
            if not line or not line.endswith((b"\n", b"\r")):
                raise EOFError("terminal closed")
            answer = line.rstrip(b"\r\n")
            if len(answer) > limit or b"\x03" in answer:
                raise EOFError("terminal input aborted")
            future.set_result(answer.decode("utf-8", errors="strict"))
        except Exception as error:
            future.set_exception(error)

    try:
        # Discard typeahead: a decision must be entered after its review appears.
        termios.tcflush(fd, termios.TCIFLUSH)
        termios.tcsetattr(fd, termios.TCSANOW, hidden)
        loop.add_reader(fd, ready)
        while True:
            try:
                return await asyncio.wait_for(asyncio.shield(future), 0.2)
            except TimeoutError:
                if not os.isatty(fd) or not has_terminal():
                    raise EOFError("terminal unavailable") from None
    finally:
        loop.remove_reader(fd)
        if not future.done():
            future.cancel()
        try:
            termios.tcsetattr(fd, termios.TCSANOW, original)
        except (OSError, termios.error):
            pass  # The controlling terminal may already have disappeared.


class TerminalInput(UnavailableInput):
    """Presentation only; resolve/reject callbacks retain all authority checks."""
    def __init__(self, secrets: Callable[[], tuple[str, ...]]):
        super().__init__()
        self.secrets = secrets
        self.tasks: dict[str, asyncio.Task] = {}
        self.pending: set[asyncio.Task] = set()
        self.lock = asyncio.Lock()
        self.answers: list[str] = []

    def safe(self, text: str) -> str:
        for secret in sorted(filter(None, (*self.secrets(), *self.answers)), key=len, reverse=True):
            text = text.replace(secret, "[REDACTED]")
        text = redact_approval(text)
        # Escape sequences and terminal controls must never reach the terminal.
        text = "".join(c for c in text if c in "\n\t" or (c.isprintable() and ord(c) != 127))
        if len(text.encode("utf-8")) > 16384:
            raise OperatorInputUnavailable("review exceeds terminal display limit")
        return text

    def publish_permission(self, request: Any) -> None:
        self._publish("permission", request)

    def publish_ask(self, request: Any) -> None:
        self._publish("ask_user", request)

    def _publish(self, kind: str, request: Any) -> None:
        previous = self.tasks.pop(kind, None)
        if previous and previous is not asyncio.current_task():
            previous.cancel()
        if request is not None:
            task = asyncio.create_task(self._present(kind, request))
            self.tasks[kind] = task
            self.pending.add(task)
            task.add_done_callback(self.pending.discard)

    async def _present(self, kind: str, request: Any) -> None:
        try:
            async with self.lock:
                if not has_terminal():
                    raise EOFError("terminal unavailable")
                if kind == "permission":
                    display = f"Review [{request.tool}]\n{request.summary}\n{request.detail}\n1. Allow once\n2. Deny"
                else:
                    q = request.question
                    display = q.question
                    for i, option in enumerate(q.options, 1):
                        display += f"\n{i}. {option.label}: {option.description or ''}"
                sys.stderr.write(self.safe(display) + "\nInput (hidden; no default): ")
                sys.stderr.flush()
                while True:
                    answer = await read_terminal_line()
                    if kind == "permission":
                        if answer not in {"1", "2"}:
                            valid = False
                        else:
                            request.resolve(Decision.ALLOW_ONCE if answer == "1" else Decision.DENY)
                            return
                    elif request.question.options:
                        valid = answer.isascii() and answer.isdigit() and 1 <= int(answer) <= len(request.question.options)
                        if valid:
                            chosen = request.question.options[int(answer) - 1].label
                            self.answers.append(chosen)
                            request.resolve(chosen)
                            return
                    else:
                        valid = bool(answer.strip()) and all(c.isprintable() for c in answer)
                        if valid:
                            self.answers.append(answer)
                            request.resolve(answer)
                            return
                    sys.stderr.write("\nInvalid input; enter an explicit answer: ")
                    sys.stderr.flush()
        except asyncio.CancelledError:
            raise
        except Exception:
            self.tool = "ask_user" if kind == "ask_user" else str(request.tool)[:128]
            self.needed.set()
            request.reject(OperatorInputUnavailable("terminal input unavailable; no action approved"))

    async def close(self) -> None:
        pending = list(self.pending)
        self.tasks.clear()
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
