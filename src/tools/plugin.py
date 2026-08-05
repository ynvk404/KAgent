from __future__ import annotations

import asyncio
import json
import signal as signal_module
from typing import Any

from src.config.config import PluginConfig
from src.permission.permission import Prompter
from src.tools.types import Tool

PLUGIN_TIMEOUT_SECONDS = 5 * 60
MAX_OUTPUT_BYTES = 128 * 1024

class CommandPluginTool:
    def __init__(self, cfg: PluginConfig):
        self.cfg = cfg

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
        return self.cfg.requires_permission

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
        if not self.cfg.command:
            raise RuntimeError(
                f"plugin {self.cfg.name} has no command"
            )

        return await run_plugin(
            self.cfg.command,
            self.cfg.args,
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
    )

    payload = json.dumps(args).encode()

    communicate_task: asyncio.Task[tuple[bytes, bytes]] = asyncio.ensure_future(
        proc.communicate(payload)
    )

    async def _watch_abort() -> None:
        while not communicate_task.done():
            if getattr(signal, "aborted", False):
                return
            await asyncio.sleep(0.05)

    abort_task: asyncio.Task[None] = asyncio.ensure_future(_watch_abort())

    done, _pending = await asyncio.wait(
        {communicate_task, abort_task},
        timeout=PLUGIN_TIMEOUT_SECONDS,
        return_when=asyncio.FIRST_COMPLETED,
    )

    timed_out = not done
    aborted = (not timed_out) and communicate_task not in done

    if timed_out or aborted:
        communicate_task.cancel()
        abort_task.cancel()

        proc.kill()
        await proc.wait()

        if timed_out:
            raise RuntimeError(
                f"plugin timed out after {PLUGIN_TIMEOUT_SECONDS}s"
            )

        raise asyncio.CancelledError()

    abort_task.cancel()

    stdout, stderr = communicate_task.result()

    stdout = truncate(stdout, len(stdout))
    stderr = truncate(stderr, len(stderr))

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