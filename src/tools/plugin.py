from __future__ import annotations

import asyncio
import json
import signal as signal_module
import os
from copy import deepcopy
from typing import Any

from src.config.config import PluginConfig
from src.permission.permission import Prompter
from src.tools.types import PermissionHints, Tool

PLUGIN_TIMEOUT_SECONDS = 5 * 60
MAX_OUTPUT_BYTES = 128 * 1024

class CommandPluginTool:
    def __init__(self, cfg: PluginConfig):
        self.cfg = cfg

    def freeze_for_execution(self):
        return CommandPluginTool(deepcopy(self.cfg))

    def name(self) -> str:
        return self.cfg.name

    def description(self) -> str:
        return (
            self.cfg.description
            or "External command plugin. Receives JSON arguments on stdin and returns stdout."
        )

    def schema(self) -> dict[str, Any]:
        return self.cfg.schema or {
            "type": "object",
            "additionalProperties": True,
        }

    def requires_permission(self) -> bool:
        # A command plugin is an arbitrary external process; its configured
        # permission flag cannot prove the action is routine or read-only.
        return True

    def permission_hints(self, args: dict[str, Any]) -> PermissionHints:
        return {"noSessionCache": True, "riskTier": "high-impact"}

    def summarize(
        self,
        args: dict[str, Any],
    ) -> dict[str, str]:
        return {
            "summary": f"plugin: {self.cfg.name}",
            "detail": (
                f"{self.cfg.command} {' '.join(self.cfg.args)}"
                f"\nstdin:\n"
                f"{json.dumps(args, indent=2)}"
            ),
        }

    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str:
        from src.permission.execution import guard_process
        worker = guard_process(prompter, self, args)
        if not self.cfg.command:
            raise RuntimeError(
                f"plugin {self.cfg.name} has no command"
            )

        command, argv = self.cfg.command, self.cfg.args
        if worker is not None:
            from src.permission.worker_broker import broker_directory
            async with broker_directory(signal) as broker:
                command, argv = await worker.prepare(command, argv, broker=broker, signal=signal)
                return await run_plugin(command, argv, args, signal)
        return await run_plugin(
            command,
            argv,
            args,
            signal,
        )

async def run_plugin(
    command: str,
    argv: list[str],
    args: dict[str, Any],
    signal: Any,
) -> str:
    proc = await asyncio.create_subprocess_exec(
        command,
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=os.name != "nt",
    )

    payload = json.dumps(args).encode()

    totals = [0, 0]

    async def pump(stream, index: int) -> bytes:
        retained = bytearray()
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return bytes(retained)
            totals[index] += len(chunk)
            retained.extend(chunk[:max(0, MAX_OUTPUT_BYTES - len(retained))])

    async def bounded_communicate() -> tuple[bytes, bytes]:
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
        out_task = asyncio.create_task(pump(proc.stdout, 0))
        err_task = asyncio.create_task(pump(proc.stderr, 1))
        try:
            try:
                proc.stdin.write(payload)
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                proc.stdin.close()
            stdout, stderr = await asyncio.gather(out_task, err_task)
            await proc.wait()
            return stdout, stderr
        finally:
            for task in (out_task, err_task):
                task.cancel()
            await asyncio.gather(out_task, err_task, return_exceptions=True)

    communicate_task = asyncio.create_task(bounded_communicate())

    async def _watch_abort() -> None:
        while not communicate_task.done():
            if getattr(signal, "aborted", False) or getattr(signal, "is_set", lambda: False)():
                return
            await asyncio.sleep(0.05)

    abort_task: asyncio.Task[None] = asyncio.ensure_future(_watch_abort())

    async def stop_process() -> None:
        if proc.returncode is None:
            try:
                if os.name != "nt":
                    os.killpg(proc.pid, signal_module.SIGKILL)
                else:
                    proc.kill()
            except ProcessLookupError:
                pass
        # communicate owns the pipe readers; let it drain the killed process.
        try:
            await asyncio.wait_for(asyncio.shield(communicate_task), 3)
        except asyncio.TimeoutError:
            communicate_task.cancel()
            await asyncio.gather(communicate_task, return_exceptions=True)

    try:
        done, _pending = await asyncio.wait(
            {communicate_task, abort_task},
            timeout=PLUGIN_TIMEOUT_SECONDS,
            return_when=asyncio.FIRST_COMPLETED,
        )

        timed_out = not done
        aborted = (not timed_out) and communicate_task not in done

        if timed_out or aborted:
            await stop_process()
            if timed_out:
                raise RuntimeError(
                    f"plugin timed out after {PLUGIN_TIMEOUT_SECONDS}s"
                )
            raise asyncio.CancelledError()
    except asyncio.CancelledError:
        await stop_process()
        raise
    finally:
        abort_task.cancel()
        await asyncio.gather(abort_task, return_exceptions=True)

    stdout, stderr = communicate_task.result()

    stdout = truncate(stdout, totals[0])
    stderr = truncate(stderr, totals[1])

    if proc.returncode == 0:
        if stderr:
            return f"{stdout}\nstderr:\n{stderr}"

        return stdout

    sig_suffix = ""

    if proc.returncode is not None and proc.returncode < 0:
        try:
            sig_name = signal_module.Signals(-proc.returncode).name
        except ValueError:
            sig_name = str(-proc.returncode)
        sig_suffix = f" (signal: {sig_name})"

    raise RuntimeError(
        f"plugin exited {proc.returncode}{sig_suffix}"
        + (f": {stderr.strip()}" if stderr else "")
    )

def truncate(
    data: bytes,
    total: int,
) -> str:
    text = data.decode(
        "utf-8",
        errors="replace",
    )

    if total <= MAX_OUTPUT_BYTES:
        return text

    return (
        text[:MAX_OUTPUT_BYTES]
        + f"\n[... truncated {total - MAX_OUTPUT_BYTES} bytes ...]"
    )

__all__ = [
    "CommandPluginTool",
    "run_plugin",
    "truncate",
    "PLUGIN_TIMEOUT_SECONDS",
    "MAX_OUTPUT_BYTES",
]
