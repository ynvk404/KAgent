from __future__ import annotations
import signal
import asyncio
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

from src.logger.logger import get_logger
from src.permission.permission import Prompter
from .file import decode_utf8_capped
from .types import Tool, arg_string
from .outcome import ToolOutput

log = get_logger("tools.shell")

DEFAULT_TIMEOUT_SECONDS = 5 * 60
MAX_TIMEOUT_SECONDS = 30 * 60
MAX_OUTPUT_BYTES = 64 * 1024
ABORT_POLL_SECONDS = 0.05
TERMINATE_GRACE_SECONDS = 1

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

@dataclass
class PortabilityPattern:
    re: re.Pattern[str]
    message: str

PORTABILITY_PATTERNS: list[PortabilityPattern] = [
    PortabilityPattern(
        re.compile(r"\bgrep\s+(?:-[A-Za-z]*P[A-Za-z]*|--perl-regexp)\b"),
        "grep -P/--perl-regexp is GNU-only. Use grep -E, awk, sed, perl -ne, or jq instead.",
    ),
    PortabilityPattern(
        re.compile(r"\bsed\s+-[A-Za-z]*r[A-Za-z]*\b"),
        "sed -r is GNU-only. Use sed -E for portable extended regular expressions.",
    ),
    PortabilityPattern(
        re.compile(r"\bbase64\s+[^|;&\n]*-[A-Za-z]*w\d*[A-Za-z]*\b"),
        'base64 -w is GNU-only. Omit wrapping flags or use tr -d "\\n".',
    ),
    PortabilityPattern(
        re.compile(r"\breadlink\s+-[A-Za-z]*f[A-Za-z]*\b"),
        "readlink -f is GNU-only. Use python3 os.path.realpath snippet instead.",
    ),
    PortabilityPattern(
        re.compile(r"\bdate\s+[^|;&\n]*-[A-Za-z]*d[A-Za-z]*\b"),
        "date -d is GNU-only. Use portable shell date handling or python3.",
    ),
    PortabilityPattern(
        re.compile(r"\bxargs\s+-[A-Za-z]*r[A-Za-z]*\b"),
        "xargs -r is GNU-only. Guard input explicitly before xargs.",
    ),
    PortabilityPattern(
        re.compile(r"\bstat\s+-c\b"),
        "stat -c is GNU-only. Use stat -f on macOS/BSD or python3 os.stat.",
    ),
    PortabilityPattern(
        re.compile(r"\bsort\s+-[A-Za-z]*V[A-Za-z]*\b"),
        "sort -V is GNU-only. Use plain sort or python3 version-sort.",
    ),
    PortabilityPattern(
        re.compile(r"(^|[|;&\s])timeout\s+\d"),
        "timeout is not available on macOS. Use tool timeout_seconds argument or python3.",
    ),
]

GREP_P_RE = re.compile(
    r"(^|[\n|;&(])([ \t]*)grep\s+"
    r"((?:(?:-[A-Za-z]+|--perl-regexp)\s+)*)"
    r"""((?:'[^']*')|(?:"[^"]*")|(?:\\.|[^\s|;&])+)"""
    r"([^|;&\n]*)"
)

class ShellTool(Tool):
    def __init__(self, shell: str = "/bin/sh", tool_name: str = "shell"):
        self.shell_path = shell
        self.tool_name = tool_name

    def name(self) -> str:
        return self.tool_name

    def description(self) -> str:
        if is_windows():
            return "\n".join(
                (
                    "Run a shell command via PowerShell on the local machine. "
                    "Primary use case is curl/Invoke-WebRequest plus standard "
                    "utilities for HTTP testing, file inspection, and one-liners. "
                    "The user will be prompted to approve each command. Capture "
                    "concise output — pipe through `Select-Object -First` for "
                    "huge outputs. Do not run interactive commands. Authorized "
                    "engagements only.",
                    "Write PowerShell-compatible commands. Unix-only tools "
                    "(grep, sed, awk, jq) may be absent; prefer PowerShell "
                    "equivalents (Select-String, -replace, ConvertFrom-Json) "
                    "unless you know the tool is installed.",
                    "",
                    "Default to curl/Invoke-WebRequest for HTTP work; only use "
                    "specialized scanners (ffuf, nuclei, sqlmap, etc.) when the "
                    "user explicitly asks for them.",
                )
            )
        return "\n".join(
            (
                "Run a shell command via /bin/sh -c on the local machine. "
                "Primary use case is curl + standard Unix utilities (jq, grep, "
                "awk, sed, head, sort, uniq) for HTTP testing, file inspection, "
                "and bash one-liners. The user will be prompted to approve each "
                "command. Capture concise output — pipe through `head` for huge "
                "outputs. Do not run interactive commands. Authorized "
                "engagements only.",
                "Write portable macOS/BSD + Linux commands. Avoid GNU-only "
                "flags such as `grep -P`; prefer `grep -E`, `awk`, `sed`, "
                "`perl -ne`, or `jq` for extraction.",
                "",
                "Default to curl for HTTP work; only use specialized scanners "
                "(ffuf, nuclei, sqlmap, etc.) when the user explicitly asks for "
                "them.",
            )
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
        }

    def requires_permission(self) -> bool:
        return True

    def permission_hints(self, args: dict[str, Any]) -> dict[str, str]:
        return {
            "cacheKey": rewrite_portable_command(arg_string(args, "command") or ""),
            "sessionScopeDisplay": f"this exact {self.tool_name} command only",
        }

    def summarize(self, args: dict[str, Any]) -> dict[str, str]:
        cmd = rewrite_portable_command(arg_string(args, "command") or "")
        first_line = cmd.split("\n", 1)[0]
        truncated = f"{first_line[:117]}..." if len(first_line) > 120 else first_line
        return {"summary": f"{self.tool_name}: {truncated}", "detail": cmd}

    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str:
        original_cmd = arg_string(args, "command") or ""
        cmd_str = rewrite_portable_command(original_cmd)

        if not cmd_str:
            raise ValueError("command is required")

        for pattern in DENY_PATTERNS:
            if pattern.search(original_cmd) or pattern.search(cmd_str):
                raise ValueError(f"command blocked by denylist (matched {pattern.pattern})")

        if not is_windows():
            for guard in PORTABILITY_PATTERNS:
                if guard.re.search(cmd_str):
                    raise ValueError(f"command blocked for portability: {guard.message}")

        timeout_arg = args.get("timeout_seconds")
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS
        if (
            isinstance(timeout_arg, (int, float))
            and not isinstance(timeout_arg, bool)
            and timeout_arg > 0
        ):
            timeout_seconds = min(timeout_arg, MAX_TIMEOUT_SECONDS)

        cmd, argv = shell_invocation(self.shell_path, cmd_str)
        return await run_with_capture(cmd, argv, timeout_seconds, signal)

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
            "Run a bash command via /bin/bash -c on the local machine. Same "
            "gating as the shell tool (per-command permission, denylist, "
            "output truncation). Prefer this over `shell` when you need bash "
            "features like [[ ]] tests, process substitution <(...), arrays, "
            "or $'...' quoting."
        )

def rewrite_portable_command(command: str) -> str:
    if is_windows():
        return command

    def replace(m: re.Match[str]) -> str:
        sep, lead, raw_flags, raw_pattern, rest = m.groups()

        flags = [f for f in raw_flags.strip().split() if f]
        short_flags = "".join(
            f[1:] for f in flags if re.fullmatch(r"-[A-Za-z]+", f)
        )
        has_perl_regexp = "--perl-regexp" in flags or "P" in short_flags
        if not has_perl_regexp:
            return m.group(0)

        unsupported_flags = re.sub(r"[Piovh]", "", short_flags)
        has_unsupported_long = any(
            f.startswith("--") and f != "--perl-regexp" for f in flags
        )
        if unsupported_flags or has_unsupported_long:
            return m.group(0)

        pattern = unquote_shell_token(raw_pattern)
        if pattern is None:
            return m.group(0)

        file_args = rest.strip()
        if re.search(r"(?:^|\s)-", file_args):
            return m.group(0)

        regex_flags = "i" if "i" in short_flags else ""
        negate = "v" in short_flags
        extract_only = "o" in short_flags

        prelude = "BEGIN { $p = $ENV{PF_GREP_PAT} } "
        if extract_only:
            code = f'{prelude}while (/$p/{regex_flags}g) {{ print "$&\\n" }}'
        elif negate:
            code = f"{prelude}print unless /$p/{regex_flags}"
        else:
            code = f"{prelude}print if /$p/{regex_flags}"

        perl = f"PF_GREP_PAT={shell_quote(pattern)} perl -ne {shell_quote(code)}"
        return f"{sep}{lead}{perl}{' ' + file_args if file_args else ''}"

    return GREP_P_RE.sub(replace, command)

def unquote_shell_token(token: str) -> str | None:
    if not token:
        return None
    if token.startswith("'") and token.endswith("'"):
        return token[1:-1]
    if token.startswith('"') and token.endswith('"'):
        return re.sub(r'\\(["\\$`])', r"\1", token[1:-1])
    return re.sub(r"\\(.)", r"\1", token)

def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"

async def run_with_capture(
    cmd: str,
    argv: list[str],
    timeout_seconds: float,
    signal: Any,
) -> str:
    if _is_aborted(signal):
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

    proc = await asyncio.create_subprocess_exec(
        cmd,
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **kwargs,
    )

    stdout_buf = HeadTailBuffer(MAX_OUTPUT_BYTES)
    stderr_buf = HeadTailBuffer(MAX_OUTPUT_BYTES)

    async def pump(stream: asyncio.StreamReader, buf: HeadTailBuffer) -> None:
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            buf.push(chunk)

    assert proc.stdout is not None
    assert proc.stderr is not None
    stdout_task = asyncio.create_task(pump(proc.stdout, stdout_buf))
    stderr_task = asyncio.create_task(pump(proc.stderr, stderr_buf))

    timed_out = False

    async def watch_abort() -> None:
        if signal is None:
            return
        while proc.returncode is None:
            if getattr(signal, "aborted", False):
                kill_process_group(proc.pid)
                return
            await asyncio.sleep(ABORT_POLL_SECONDS)

    watch_task = asyncio.create_task(watch_abort())

    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        timed_out = True
        kill_process_group(proc.pid)
        try:
            await asyncio.wait_for(proc.wait(), timeout=TERMINATE_GRACE_SECONDS)
        except asyncio.TimeoutError:
            kill_process_group(proc.pid, signal.SIGKILL)
            await proc.wait()
    except asyncio.CancelledError:
        kill_process_group(proc.pid)
        try:
            await asyncio.wait_for(proc.wait(), timeout=TERMINATE_GRACE_SECONDS)
        except asyncio.TimeoutError:
            kill_process_group(proc.pid, signal.SIGKILL)
            await proc.wait()
        stdout_task.cancel()
        stderr_task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        raise
    finally:
        watch_task.cancel()
        try:
            await watch_task
        except asyncio.CancelledError:
            pass

    await asyncio.gather(stdout_task, stderr_task)

    stdout = stdout_buf.render()
    stderr = stderr_buf.render()

    if timed_out:
        return ToolOutput(
            f"exit: timeout after {timeout_seconds}s\nstdout:\n{stdout}\nstderr:\n{stderr}",
            status="error", error_kind="timeout",
        )

    code = proc.returncode or 0
    exit_code = code if code >= 0 else 128 - code

    result = f"exit: {exit_code}\nstdout:\n{stdout}"
    if stderr:
        result += f"\nstderr:\n{stderr}"
    return result

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
