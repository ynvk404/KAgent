from __future__ import annotations
import signal
import asyncio
import os
import re
import subprocess
import sys
from typing import Any, TYPE_CHECKING
from dataclasses import replace

from src.tools.common.runtime_metadata import RuntimeMetadata, StreamCapture

from src.logger.logger import get_logger
from src.permission.permission import Prompter
from src.tools.execution.file import decode_utf8_capped
from src.tools.common.types import PermissionHints, Tool, arg_string
from src.tools.common.outcome import ToolOutput

if TYPE_CHECKING:
    from src.permission.runtime.execution import ExecutionPolicy
    from src.tools.execution.scanners import ScannerBinding, ScannerPlan

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
        frozen.scanner_plan = None
        return frozen
    def __init__(self, shell: str = "/bin/sh", tool_name: str = "shell", *, scanner_binding: ScannerBinding | None = None):
        self.shell_path = shell
        self.tool_name = tool_name
        self.scanner_binding = scanner_binding
        self.scanner_plan: ScannerPlan | None = None

    def name(self) -> str:
        return self.tool_name

    def description(self) -> str:
        if is_windows():
            return "\n".join(
                (
                    "Run an arbitrary command via PowerShell on the local machine. "
                    "Use the built-in http tool for target requests whenever it "
                    "can express them. Bound execution requires an enforcing worker; "
                    "Use PowerShell for local OS utilities or HTTP details the "
                    "native tool cannot express. "
                    "YOLO auto-approves covered commands; OFF uses normal review. Capture "
                    "concise output — pipe through `Select-Object -First` for "
                    "huge outputs. Do not run interactive commands. Authorized "
                    "engagements only.",
                    "Write PowerShell-compatible commands. Unix-only tools "
                    "(grep, sed, awk, jq) may be absent; prefer PowerShell "
                    "equivalents (Select-String, -replace, ConvertFrom-Json) "
                    "unless you know the tool is installed.",
                    "",
                    "Prefer the built-in http tool for ordinary HTTP probes. Use "
                    "semantic discovery tools for bounded path/service discovery; "
                    "generic-shell scanners require an explicit user request.",
                )
            )
        return "\n".join(
            (
                "Run /bin/sh -c for OS utilities or HTTP details the built-in http tool "
                "cannot express; prefer http otherwise. Bound execution: isolated worker "
                "and scoped HTTP broker. YOLO auto-approves covered commands; OFF requires review. "
                "Authorized engagements only; no interactive commands; concise output (`head` for large output).",
                "Worker cwd /work: read-only project, no host paths. Write shell output only to "
                "/work/artifacts/worker. For other permitted project artifacts use file_write/file_edit "
                "with normal permission checks.",
                "Use installed worker utilities; host executable availability does not imply worker compatibility. "
                "For macOS/BSD portability prefer grep -E when available; avoid GNU-only grep -P. "
                "Check the parser and its dependencies before extraction. "
                "Reuse downloaded artifacts after parser failure. Inspect download status, parser exit, stderr "
                "and useful stdout separately; a pipeline can hide a missing dependency. grep no-match is distinct from failure.",
                "Use semantic tools for bounded path/service discovery; "
                "generic-shell scanners require an explicit user request.",
                "On Linux/WSL, shell(scanner=nmap|ffuf, typed fields) uses an exact reviewed "
                "trusted-host job, without a shell. Check permissions_status for build/wordlist readiness; "
                "HTTP grants/quotas do not authorize or limit scanner traffic. No fallback command.",
            )
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                **({} if self.tool_name != "shell" else {
                    "scanner": {"type": "string", "enum": ["nmap", "ffuf"],
                        "description": "One trusted Linux scanner job per exact-plan approval; may create many connections. HTTP quotas do not limit scanner traffic."},
                    "target": {"type": "string", "description": "Nmap: one numeric IP."},
                    "ports": {"type": ["string", "array"], "items": {"type": "integer"},
                        "description": "Nmap: explicit TCP ports/ranges, e.g. 80,443,8000-8100."},
                    "url": {"type": "string", "description": "ffuf: exact active origin, one FUZZ in path."},
                    "wordlist_id": {"type": "string", "description": "ffuf: choose an existing file's ID from permissions_status. No arbitrary file paths or generated wordlists."},
                    "threads": {"type": "integer", "minimum": 1, "maximum": 256, "default": 40},
                    "rate": {"type": "number", "exclusiveMinimum": 0,
                        "description": "Optional native scanner rate; omit for native defaults. ffuf requires integer."},
                    "request_timeout_seconds": {"type": "integer", "minimum": 1, "default": 10},
                    "calibration": {"type": "boolean"},
                    "match_status": {"type": "string"},
                    "filter_status": {"type": "string"},
                    "filter_size": {"type": "array", "items": {"type": "integer", "minimum": 0}},
                }),
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
            "required": ["command"] if self.tool_name != "shell" else [],
            "additionalProperties": False,
            **({} if self.tool_name != "shell" else {"oneOf": [
                {"required": ["command"]}, {"required": ["scanner"]}]}),
        }

    def validate_args(self, args: dict[str, Any]) -> None:
        if "scanner" in args:
            from src.tools.execution.scanners import validate_scanner_args
            if self.tool_name != "shell":
                raise ValueError("scanner form is only available on shell")
            validate_scanner_args(args)
        elif not arg_string(args, "command"):
            raise ValueError("command is required")

    async def prepare_scanner(self, args: dict[str, Any], policy: ExecutionPolicy | None, signal: Any) -> None:
        from src.permission.runtime.execution import ExecutionBlocked
        self.validate_args(args)
        if policy is None or self.scanner_binding is None or self.scanner_binding.policy is not policy:
            raise ExecutionBlocked("blocked: controller scanner binding unavailable")
        # Preserve generic validation/revoke gates before DNS or resource access.
        if policy.generic_validation is not None:
            policy.generic_validation.validate_tool(self, args)
        if "*" in policy.revoked or self.name() in policy.revoked:
            raise ExecutionBlocked("blocked: tool/session-revoked")
        try:
            self.scanner_plan = await self.scanner_binding.prepare(args, signal)
        except ExecutionBlocked:
            raise
        except OSError as exc:
            raise ExecutionBlocked("blocked: scanner preparation resource/resolution unavailable") from exc

    def validate_scanner(self, policy: ExecutionPolicy, args: dict[str, Any]) -> None:
        from src.permission.runtime.execution import ExecutionBlocked
        if self.scanner_binding is None or self.scanner_binding.policy is not policy or self.scanner_plan is None:
            raise ExecutionBlocked("blocked: scanner requires a controller-prepared plan")
        from src.tools.execution.scanners import arguments_digest
        if self.scanner_plan.arguments_digest != arguments_digest(args):
            raise ExecutionBlocked("blocked: scanner arguments differ from prepared plan")
        self.scanner_binding.validate(self.scanner_plan)

    def requires_permission(self) -> bool:
        return True

    def permission_hints(self, args: dict[str, Any]) -> PermissionHints:
        if "scanner" in args:
            return {"noSessionCache": True, "riskTier": "high-impact",
                    "cacheKey": self.scanner_plan.digest if self.scanner_plan else "unprepared-scanner",
                    "sessionScopeDisplay": "this exact reviewed scanner plan only"}
        return {
            "noSessionCache": True,
            "riskTier": "high-impact",
            "cacheKey": arg_string(args, "command") or "",
            "sessionScopeDisplay": f"this exact {self.tool_name} command only",
        }

    def summarize(self, args: dict[str, Any]) -> dict[str, str]:
        if "scanner" in args:
            return {"summary": f"shell: trusted {args['scanner']} scanner job (exact plan)",
                    "detail": self.scanner_plan.display() if self.scanner_plan else "Scanner plan unavailable"}
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
        if "scanner" in args:
            from src.permission.runtime.execution import policy_for, ExecutionBlocked
            self.validate_args(args)
            policy = policy_for(prompter)
            if policy is None:
                raise ExecutionBlocked("blocked: scanner requires a bound execution policy")
            policy.revalidate_active(self, args, signal)
            assert self.scanner_binding is not None
            return await self.scanner_binding.runtime.run(self.scanner_binding, self, args, signal)
        worker = guard_process(prompter, self, args)
        cmd_str = arg_string(args, "command") or ""

        if not cmd_str:
            raise ValueError("command is required")

        for pattern in (DENY_PATTERNS if worker is None else []):
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
        if worker is not None:
            from src.permission.worker.broker import BrokerCollector, broker_directory
            collector = BrokerCollector()
            async with broker_directory(signal, collector=collector) as broker:
                cmd, argv = await worker.prepare(cmd, argv, broker=broker, signal=signal)
                from src.permission.runtime.execution import policy_for
                policy = policy_for(prompter)
                if policy is not None:
                    policy.revalidate_active(self, args, signal)
                output = await run_with_capture(cmd, argv, timeout_seconds, signal)
            # Handler cancellation, response capture and reservation release are
            # finished before publishing the final shell diagnostics. The shell
            # observation/hash continues to describe only its original output.
            if output.runtime_metadata is not None:
                output.runtime_metadata = replace(output.runtime_metadata, http=collector.snapshot())
            return output
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
            "Run /bin/bash -c; same per-command permission, denylist and output truncation as shell. "
            "Prefer for bash features: [[ ]] tests, process substitution <(...), arrays or $'...' quoting."
        )

def rewrite_portable_command(command: str) -> str:
    """Compatibility helper: execute the reviewed command without translation."""
    return command


async def run_with_capture(
    cmd: str,
    argv: list[str],
    timeout_seconds: float,
    abort_signal: Any,
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

    async def watch_abort() -> None:
        nonlocal abort_requested
        if abort_signal is None:
            return
        while proc.returncode is None:
            if getattr(abort_signal, "aborted", False):
                abort_requested = True
                kill_process_group(proc.pid)
                try:
                    await asyncio.wait_for(
                        proc.wait(),
                        timeout=TERMINATE_GRACE_SECONDS,
                    )
                except asyncio.TimeoutError:
                    kill_process_group(proc.pid, signal.SIGKILL)
                    await proc.wait()
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
