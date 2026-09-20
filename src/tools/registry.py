from __future__ import annotations

import json
from typing import Any, cast

from src.permission.permission import (
    Decision,
    PermissionRequest,
    Prompter,
    UserControlledRefusal,
)
from .types import (
    Tool,
    ToolSummary,
    PermissionHints,
    SummarizableTool,
    PermissionHintTool,
    ActionPermissionTool,
    ArgumentValidatingTool,
)
from src.llm.types import ToolSpec

class Registry:
    def __init__(self) -> None:
        self.tools: dict[str, Tool] = {}

    def register(
        self,
        tool: Tool,
    ) -> None:
        self.tools[tool.name()] = tool

    def get(
        self,
        name: str,
    ) -> Tool | None:
        return self.tools.get(name)

    def names(self) -> list[str]:
        return sorted(
            self.tools.keys()
        )

    def as_llm_tools(
        self,
    ) -> list[ToolSpec]:
        return [
            cast(
                ToolSpec,
                {
                    "type": "function",
                    "function": {
                        "name": tool.name(),
                        "description": tool.description(),
                        "parameters": tool.schema(),
                    },
                },
            )
            for tool in self.tools.values()
        ]

    def schema_metrics(self) -> dict[str, Any]:
        """Return deterministic approximate schema costs for diagnostics/tests."""
        rows = []
        for spec in self.as_llm_tools():
            body = json.dumps(spec, ensure_ascii=False, separators=(",", ":"))
            serialized = cast(dict[str, Any], cast(Any, spec))
            function = cast(dict[str, Any], serialized["function"])
            rows.append(
                {
                    "name": function["name"],
                    "characters": len(body),
                    "approx_tokens": len(body) // 4,
                }
            )
        rows.sort(key=lambda item: (-item["characters"], item["name"]))
        total_characters = len(
            json.dumps(self.as_llm_tools(), ensure_ascii=False, separators=(",", ":"))
        )
        return {
            "tool_count": len(rows),
            "characters": total_characters,
            "approx_tokens": total_characters // 4,
            "tools": rows,
        }

    async def execute(
        self,
        name: str,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str:
        tool = self.tools.get(name)

        if tool is None:
            raise RuntimeError(
                f"unknown tool: {name}"
            )

        if isinstance(tool, ArgumentValidatingTool):
            tool.validate_args(args)

        requires_permission = (
            tool.requires_permission_for(args)
            if isinstance(tool, ActionPermissionTool)
            else tool.requires_permission()
        )

        if requires_permission:
            summary = summarize(
                tool,
                args,
            )

            hints: PermissionHints = {}

            if isinstance(
                tool,
                PermissionHintTool,
            ):
                hints = tool.permission_hints(
                    args
                )

            request = PermissionRequest(
                tool=tool.name(),
                summary=summary["summary"],
                detail=summary["detail"],
                no_session_cache=hints.get(
                    "noSessionCache",
                    False,
                ),
                cache_key=hints.get(
                    "cacheKey",
                ),
            )

            decision = await prompter.ask(
                request,
                signal,
            )

            if decision == Decision.DENY:
                raise UserControlledRefusal(
                    f"permission denied by user for {tool.name()}"
                )

        return await tool.run(
            args,
            signal,
            prompter,
        )

def summarize(
    tool: Tool,
    args: dict[str, Any],
) -> ToolSummary:
    if isinstance(
        tool,
        SummarizableTool,
    ):
        return tool.summarize(
            args
        )

    return {
        "summary": tool.name(),
        "detail": json.dumps(args),
    }
