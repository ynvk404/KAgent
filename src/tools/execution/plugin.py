from __future__ import annotations

import asyncio
import json
import signal as signal_module
import os
from copy import deepcopy
from typing import Any

from src.config.config import PluginConfig
from src.permission.permission import Prompter
from src.tools.common.types import PermissionHints, Tool

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

    def validate_args(self, args: dict[str, Any]) -> None:
        from src.permission.runtime.execution import ExecutionBlocked
        raise ExecutionBlocked('unavailable: command plugins require the removed isolated executor; host execution is not enabled')

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
        from src.permission.runtime.execution import ExecutionBlocked
        raise ExecutionBlocked('unavailable: command plugins require the removed isolated executor; host execution is not enabled')

async def run_plugin(command, argv, args, signal):
    from src.permission.runtime.execution import ExecutionBlocked
    raise ExecutionBlocked('unavailable: command plugin execution has been removed; no host fallback')
