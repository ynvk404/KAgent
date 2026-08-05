"""
Tool registry.

Port từ:
agent/src/tools/registry.ts
"""

from __future__ import annotations

import json
from typing import Any, cast

from permission.permission import (
    Decision,
    PermissionRequest,
    Prompter,
)

from .types import (
    Tool,
    ToolSummary,
    PermissionHints,
    SummarizableTool,
    PermissionHintTool,
)

from llm.types import ToolSpec


class Registry:
    """
    Registry quản lý tools.

    - Register tools
    - Export tool schema cho LLM
    - Execute tool với permission gating
    """

    def __init__(self) -> None:
        self.tools: dict[str, Tool] = {}


    def register(
        self,
        tool: Tool,
    ) -> None:
        """
        Đăng ký tool.
        """

        self.tools[tool.name()] = tool


    def get(
        self,
        name: str,
    ) -> Tool | None:
        """
        Lấy tool theo tên.
        """

        return self.tools.get(name)


    def names(self) -> list[str]:
        """
        Danh sách tool name.
        """

        return sorted(
            self.tools.keys()
        )


    def as_llm_tools(
        self,
    ) -> list[ToolSpec]:
        """
        Convert registry thành LLM function tools.
        """

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


    async def execute(
        self,
        name: str,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str:
        """
        Execute tool với permission check.
        """

        tool = self.tools.get(name)

        if tool is None:
            raise RuntimeError(
                f"unknown tool: {name}"
            )


        if tool.requires_permission():

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
                raise PermissionError(
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
    """
    Sinh permission summary.
    """

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