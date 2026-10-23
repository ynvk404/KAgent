from __future__ import annotations
import signal
import asyncio
import os
import re
import subprocess
import sys
from typing import Any
from dataclasses import replace

from src.tools.common.runtime_metadata import RuntimeMetadata, StreamCapture

from src.logger.logger import get_logger
from src.permission.permission import Prompter
from src.tools.execution.file import decode_utf8_capped
from src.tools.common.types import PermissionHints, Tool, arg_string
from src.tools.common.outcome import ToolOutput


log = get_logger("tools.shell")

DEFAULT_TIMEOUT_SECONDS = 5 * 60
MAX_TIMEOUT_SECONDS = 30 * 60
MAX_OUTPUT_BYTES = 64 * 1024
ABORT_POLL_SECONDS = 0.05
TERMINATE_GRACE_SECONDS = 1
FATAL_PARSE_STDERR_RE = re.compile(
    r"^(?:awk:.*(?:fatal:|syntax error|missing [^)\n]+)|"
    r"jq: (?:parse error|error:))",
    re.IGNORECASE | re.MULTILINE,
)

def is_windows() -> bool:
    return sys.platform == "win32"

def shell_invocation(unix_shell: str, command: str) -> tuple[str, list[str]]:
    if is_windows():
        shell = os.environ.get("PFLOW_WINDOWS_SHELL", "powershell.exe")
        return shell, ["-NoProfile", "-NonInteractive", "-Command", command]
    return unix_shell, ["-c", command]

DENY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\brm\b(?=[^|;&\n]*\s-{1,2}[a-z-]*r)(?=[^|;&\n]*\s-{1,2}[a-z-]*f)"
        r"[^|;&\n]*\s/[^/\s]*/?(?:\s|$)",
        r"\brm\b(?=[^|;&\n]*\s-{1,2}[a-z-]*r)(?=[^|;&\n]*\s-{1,2}[a-z-]*f)"
        r"""[^|;&\n]*\s["']/[^/"'\s]*/?["'](?:\s|$)""",
        r":\(\)\s*\{\s*:\|:&\s*\}",
        r"\bmkfs\b",
        r"\bdd\b[^|;&\n]*\bof=/dev/",
        r">\s*/dev/sd[a-z]",
        r"\b(?:shutdown|reboot|halt|poweroff)\b",
        r"\bfind\b[^|;&\n]*\s-delete\b",
        r"\bfind\b[^|;&\n]*\s-exec\s+rm\b",
    )
]

class ShellTool(Tool):
    def freeze_for_execution(self):
        from copy import copy
        frozen = copy(self)
        return frozen
    def __init__(self, shell: str = "/bin/sh", tool_name: str = "shell"):
        self.shell_path = shell
        self.tool_name = tool_name

    def name(self) -> str:
        return self.tool_name

    def description(self) -> str:
        launcher = 'PowerShell' if is_windows() else '/bin/sh -c'
        portability = ('Use PowerShell Select-String and ConvertFrom-Json.' if is_windows() else
                       'For macOS/BSD portability prefer grep -E; avoid GNU-only grep -P.')
        return (
            f'Run a local command via {launcher}, in the project cwd. '
            'Direct subprocess with account filesystem/network rights; no OS sandbox or HTTP attestation. '
            f'{portability} Use the built-in http tool for target requests and native discovery for bounded service/path discovery. '
            'YOLO auto-approves covered commands; OFF requires per-command review. '
            'No interactive commands; retain concise output. Inspect exit, stderr and stdout separately; '
            'pipelines can hide failures. Reuse local artifacts after parser failure. '
            'Do not replace unavailable integrations with arbitrary commands without operator intent.'
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": (
                        "Shell command to execute. Will run via PowerShell -Command."
                        if is_windows()
                        else "Shell command to execute. Will run via /bin/sh -c."
                    ),
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Optional timeout in seconds (default 300, max 1800).",
                },
            },
            "required": ["command"],
            "additionalProperties": False,
        }

    def validate_args(self, args: dict[str, Any]) -> None:
        if set(args) - {'command', 'timeout_seconds'}:
            raise ValueError('shell accepts only command and timeout_seconds; external scanner jobs are unavailable')
        if not arg_string(args, 'command'):
            raise ValueError('command is required')

    def requires_permission(self) -> bool:
        return True

    def permission_hints(self, args: dict[str, Any]) -> PermissionHints:
        return {
            "noSessionCache": True,
            "riskTier": "high-impact",
            "cacheKey": arg_string(args, "command") or "",
            "sessionScopeDisplay": f"this exact {self.tool_name} command only",
        }

    def summarize(self, args: dict[str, Any]) -> dict[str, str]:
        cmd = arg_string(args, "command") or ""
        first_line = cmd.split("\n", 1)[0]
        truncated = f"{first_line[:117]}..." if len(first_line) > 120 else first_line
        timeout = args.get("timeout_seconds")
        effective_timeout = (min(timeout, MAX_TIMEOUT_SECONDS)
                             if isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and timeout > 0
                             else DEFAULT_TIMEOUT_SECONDS)
        return {"summary": f"{self.tool_name}: {truncated}",
                "detail": f"{cmd}\n\nTimeout: {effective_timeout:g}s"}

    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> ToolOutput:
        from src.permission.runtime.execution import guard_process
        self.validate_args(args)
        policy = guard_process(prompter, self, args)
        cmd_str = arg_string(args, "command") or ""

        if not cmd_str:
            raise ValueError("command is required")

        for pattern in DENY_PATTERNS:
            if pattern.search(cmd_str):
                raise ValueError(f"command blocked by denylist (matched {pattern.pattern})")

        timeout_arg = args.get("timeout_seconds")
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS
        if (
            isinstance(timeout_arg, (int, float))
            and not isinstance(timeout_arg, bool)
            and timeout_arg > 0
        ):
            timeout_seconds = min(timeout_arg, MAX_TIMEOUT_SECONDS)

        cmd, argv = shell_invocation(self.shell_path, cmd_str)
        from src.paths import project_root
        return await run_with_capture(cmd, argv, timeout_seconds, signal,
                                      cwd=policy.root if policy is not None else project_root())

class BashTool(ShellTool):
    def __init__(self) -> None:
        super().__init__("/bin/bash", "BashTool")

    def description(self) -> str:
        if is_windows():
            return (
                "Run a command via PowerShell on the local machine (no /bin/bash "
                "on Windows; this falls back to the same PowerShell host as the "
                "shell tool). Same gating as the shell tool (per-command "
                "permission, denylist, output truncation)."
            )
        return (
            "Run /bin/bash -c; same per-command permission, denylist and output truncation as shell. "
            "Prefer for bash features: [[ ]] tests, process substitution <(...), arrays or $'...' quoting."
        )

async def run_with_capture(
    cmd: str,
    argv: list[str],
    timeout_seconds: float,
    abort_signal: Any,
    *, cwd=None,
) -> ToolOutput:
    from src.permission.runtime.execution import current_policy
    policy = current_policy()
    source_owner = policy.observations.owner_provider() if policy else None
    def recorded(output: ToolOutput) -> ToolOutput:
        from src.permission.runtime.observations import ObservationPersistenceError
        output.truncated = stdout_buf.total > MAX_OUTPUT_BYTES or stderr_buf.total > MAX_OUTPUT_BYTES
        state = ("cancelled" if output.status == "cancelled" else
                 "timeout" if output.error_kind == "timeout" else "exit")
        code = proc.returncode
        metadata = RuntimeMetadata(
            process=state,
            exit_code=(code if code >= 0 else 128 - code) if state == "exit" and code is not None else None,
            termination_signal=-code if state == "exit" and code is not None and code < 0 else None,
            stdout=StreamCapture(stdout_buf.total, min(stdout_buf.total, MAX_OUTPUT_BYTES), stdout_buf.eof),
            stderr=StreamCapture(stderr_buf.total, min(stderr_buf.total, MAX_OUTPUT_BYTES), stderr_buf.eof),
            capture_envelope_bytes=len(output.encode("utf-8")),
            delivery="complete", retention="unavailable",
        )
        text = str(output)
        if policy is not None:
            try:
                key = policy.observations.capture_output("shell", output, owner=source_owner,
                    completed=output.status == "success", truncated=output.truncated)
            except ObservationPersistenceError as exc:
                metadata = replace(metadata, persistence=exc.persistence)
            else:
                item = policy.observations._items[key]
                input_bytes = (item.source_details or {})["retention_input_bytes"]
                metadata = replace(metadata,
                    retention="complete" if len(item.body) == input_bytes else "partial",
                    retention_input_bytes=input_bytes, retained_bytes=len(item.body), observation_id=key,
                    persistence="persisted" if policy.observations.storage is not None else "memory-only",
                    response_hash_basis="bounded-rendered-envelope-utf8")
                text += f"\n[runtime observation: {key}]"
        return ToolOutput(text, status=output.status, error_kind=output.error_kind,
                          truncated=output.truncated,
                          runtime_metadata=replace(metadata, delivered_bytes=len(text.encode("utf-8"))))
    if _is_aborted(abort_signal):
        raise RuntimeError("aborted")

    kwargs: dict[str, Any] = {}
    if is_windows():
        kwargs["creationflags"] = getattr(
            subprocess,
            "CREATE_NEW_PROCESS_GROUP",
            0
        )
    else:
        kwargs["start_new_session"] = True

    try:
        proc = await asyncio.create_subprocess_exec(
            cmd,
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            **kwargs,
        )

    except OSError as exc:
        # Preserve the original exception type (including FileNotFoundError).
        # This fact comes from the spawn boundary, never an error-text parser.
        setattr(exc, "runtime_metadata", RuntimeMetadata(process="not_started", delivery="unavailable"))
        raise

    stdout_buf = HeadTailBuffer(MAX_OUTPUT_BYTES)
    stderr_buf = HeadTailBuffer(MAX_OUTPUT_BYTES)

    async def pump(stream: asyncio.StreamReader, buf: HeadTailBuffer) -> None:
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                buf.eof = True
                break
            buf.push(chunk)

    assert proc.stdout is not None
    assert proc.stderr is not None
    stdout_task = asyncio.create_task(pump(proc.stdout, stdout_buf))
    stderr_task = asyncio.create_task(pump(proc.stderr, stderr_buf))

    timed_out = False
    abort_requested = False

    # The command is finished only when its output pipes close too. A child
    # can inherit them after the group leader exits; proc.wait() alone may
    # already return while those readers still wait indefinitely.
    completion = asyncio.gather(proc.wait(), stdout_task, stderr_task)
    termination: asyncio.Task[None] | None = None

    async def terminate() -> None:
        kill_process_group(proc.pid)
        try:
            await asyncio.wait_for(asyncio.shield(completion), TERMINATE_GRACE_SECONDS)
        except asyncio.TimeoutError:
            pass
        finally:
            # The leader may have exited while a descendant ignored TERM.
            kill_process_group(proc.pid, signal.SIGKILL)
        await completion

    async def terminate_owned() -> None:
        nonlocal termination
        if termination is None:
            termination = asyncio.create_task(terminate())
        cancelled = False
        while not termination.done():
            try:
                await asyncio.shield(termination)
            except asyncio.CancelledError:
                # Repeated cancellation cannot release the command's receipt
                # while its process group and pipe readers are still draining.
                cancelled = True
        termination.result()
        if cancelled:
            raise asyncio.CancelledError

    async def watch_abort() -> None:
        nonlocal abort_requested
        if abort_signal is None:
            return
        while not completion.done():
            if getattr(abort_signal, "aborted", False):
                abort_requested = True
                await terminate_owned()
                return
            await asyncio.sleep(ABORT_POLL_SECONDS)

    watch_task = asyncio.create_task(watch_abort())

    try:
        await asyncio.wait_for(asyncio.shield(completion), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        timed_out = True
        await terminate_owned()
    except asyncio.CancelledError:
        await terminate_owned()
        raise
    finally:
        watch_task.cancel()
        try:
            await watch_task
        except asyncio.CancelledError:
            pass

    stdout = stdout_buf.render()
    stderr = stderr_buf.render()

    if abort_requested or _is_aborted(abort_signal):
        return recorded(ToolOutput(
            f"exit: cancelled\nstdout:\n{stdout}\nstderr:\n{stderr}",
            status="cancelled",
            error_kind="cancelled",
        ))

    if timed_out:
        return recorded(ToolOutput(
            f"exit: timeout after {timeout_seconds}s\nstdout:\n{stdout}\nstderr:\n{stderr}",
            status="error", error_kind="timeout",
        ))

    code = proc.returncode or 0
    exit_code = code if code >= 0 else 128 - code

    result = f"exit: {exit_code}\nstdout:\n{stdout}"
    if stderr:
        result += f"\nstderr:\n{stderr}"
    if exit_code != 0 or FATAL_PARSE_STDERR_RE.search(stderr):
        return recorded(ToolOutput(result, status="error", error_kind="tool_exception"))
    return recorded(ToolOutput(result, status="success"))

def _is_aborted(signal: Any) -> bool:
    return signal is not None and getattr(signal, "aborted", False)

def kill_process_group(pid: int | None, sig=signal.SIGTERM) -> None:
    if not pid:
        return

    if is_windows():
        try:
            subprocess.run(
                ["taskkill", "/pid", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            log.warning("shell: could not kill process tree %s", pid, exc_info=True)
        return

    killpg = getattr(os, "killpg", None)

    if killpg is not None:
        try:
            killpg(pid, sig)
            return
        except ProcessLookupError:
            return
        except OSError:
            log.debug(
                "shell: could not signal process group %s; "
                "falling back to the process itself",
                pid,
                exc_info=True,
            )

    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        pass
    except OSError:
        log.warning("shell: could not kill process %s", pid, exc_info=True)

class HeadTailBuffer:
    def __init__(self, cap: int):
        self.cap = cap
        self.half = cap // 2
        self.head: list[bytes] = []
        self.head_len = 0
        self.tail: list[bytes] = []
        self.tail_len = 0
        self.total = 0
        self.eof = False

    def push(self, chunk: bytes) -> None:
        self.total += len(chunk)
        rest = chunk

        if self.head_len < self.half:
            room = self.half - self.head_len
            if len(rest) <= room:
                self.head.append(rest)
                self.head_len += len(rest)
                return
            self.head.append(rest[:room])
            self.head_len += room
            rest = rest[room:]

        self.tail.append(rest)
        self.tail_len += len(rest)

        while len(self.tail) > 1 and self.tail_len - len(self.tail[0]) >= self.half:
            dropped = self.tail.pop(0)
            self.tail_len -= len(dropped)

    def render(self) -> str:
        head_buf = b"".join(self.head)
        tail_full = b"".join(self.tail)
        tail_buf = tail_full[-self.half :] if len(tail_full) > self.half else tail_full
        retained = len(head_buf) + len(tail_buf)

        if self.total <= retained:
            return (head_buf + tail_buf).decode("utf-8", errors="replace")

        head_str = decode_utf8_capped(head_buf, len(head_buf))
        tail_str = _decode_utf8_tail(tail_buf)
        return f"{head_str}\n[... truncated {self.total - retained} bytes ...]\n{tail_str}"

def _decode_utf8_tail(buf: bytes) -> str:
    start = 0
    while start < len(buf) and start < 3 and 0x80 <= buf[start] < 0xC0:
        start += 1
    return buf[start:].decode("utf-8", errors="replace")
