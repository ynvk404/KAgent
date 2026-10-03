from __future__ import annotations

import json
import asyncio
from copy import deepcopy
from typing import Any, cast

from src.permission.permission import (
    Decision,
    PermissionRequest,
    Prompter,
    UserControlledRefusal,
)
from src.tools.common.types import (
    Tool,
    ToolSummary,
    PermissionHints,
    SummarizableTool,
    PermissionHintTool,
    ActionPermissionTool,
    ArgumentValidatingTool,
    AuthorizedExecutionTool,
    ContextReductionPolicy,
    ContextReductionTool,
)
from src.llm.core.types import ToolSpec
from src.permission.execution import ExecutionPolicy, ExecutionReceipt, policy_for
from src.permission.invocations import permission_invocation
from src.tools.common.approval_display import redact_approval as redact


class InvalidToolArguments(ValueError):
    """A tool's explicit pre-dispatch argument check rejected the call."""


class _ExecutionPrompter(Prompter):
    """Coalesce a nested gate with this invocation's exact registry approval."""

    def __init__(
        self,
        inner: Prompter,
        tool_name: str,
        cache_key: str | None,
    ) -> None:
        self._inner = inner
        self._tool_name = tool_name
        self._cache_key = cache_key

    @property
    def execution_policy(self):
        return policy_for(self._inner)

    async def ask(self, request: PermissionRequest, signal: Any = None) -> Decision:
        if (
            self._cache_key is not None
            and request.tool == self._tool_name
            and request.cache_key == self._cache_key
        ):
            # The wrapper is created only for the current tool invocation, so
            # this is one-shot composition, not session authorization.
            return Decision.ALLOW_ONCE
        return await self._inner.ask(request, signal)

    def clear_session_cache(self) -> None:
        clear = getattr(self._inner, "clear_session_cache", None)
        if callable(clear):
            clear()

class Registry:
    def __init__(self) -> None:
        self.tools: dict[str, Tool] = {}

    def register(
        self,
        tool: Tool,
    ) -> None:
        name = tool.name()
        if name in self.tools:
            raise ValueError(f"duplicate tool registration: {name}")
        self.tools[name] = tool

    def get(
        self,
        name: str,
    ) -> Tool | None:
        return self.tools.get(name)

    def names(self) -> list[str]:
        return sorted(
            self.tools.keys()
        )

    def context_reduction_policy(self, name: str | None) -> ContextReductionPolicy:
        tool = self.tools.get(name) if name is not None else None
        if (
            isinstance(tool, ContextReductionTool)
            and tool.context_reduction_policy() == "preserve"
        ):
            return "preserve"
        return "adaptive"

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

    @permission_invocation
    async def execute(
        self, name: str, args: dict[str, Any], signal: Any, prompter: Prompter,
    ) -> str:
        tool = self.tools.get(name)
        if tool is None:
            raise RuntimeError(f"unknown tool: {name}")
        freeze = getattr(tool, "freeze_for_execution", None)
        if callable(freeze):
            tool = cast(Tool, freeze())
        args = deepcopy(args)
        policy = policy_for(prompter)
        if policy is not None and type(tool).__module__ == 'src.tools.common.browser_capture':
            tool = cast(Tool, getattr(tool, 'bind_execution_policy')(policy))
        receipt = policy.prepare(tool, args) if policy is not None else None
        try:
            return await self._execute(tool, args, signal, prompter, policy, receipt)
        finally:
            if policy is not None and receipt is not None:
                policy.finish_review(receipt)

    async def _execute(
        self,
        tool: Tool,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
        policy: ExecutionPolicy | None,
        receipt: ExecutionReceipt | None,
    ) -> str:

        # Approval and dispatch use the same private snapshot, even if the
        # caller changes nested arguments while the operator is reviewing.
        args = deepcopy(args)

        if isinstance(tool, ArgumentValidatingTool):
            try:
                tool.validate_args(args)
            except (TypeError, ValueError) as err:
                raise InvalidToolArguments(str(err)) from err

        if isinstance(tool, AuthorizedExecutionTool):
            # Native HTTP uses operator grants/exact receipts rather than the
            # generic phase hints and origin permission cache. Direct tool calls
            # use the same gate; this is not an unguarded dispatch path.
            token = policy.start(receipt, tool, args, signal) if policy and receipt else None
            try:
                return await tool.run_authorized(args, signal, prompter)
            finally:
                if token is not None and policy is not None:
                    policy.stop(token)

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
                summary=redact(summary["summary"]),
                detail=redact(summary["detail"]),
                no_session_cache=hints.get(
                    "noSessionCache",
                    False,
                ),
                cache_key=hints.get(
                    "cacheKey",
                ),
                session_scope_display=hints.get(
                    "sessionScopeDisplay",
                ),
                risk_tier=hints.get(
                    "riskTier",
                    "routine",
                ),
                yolo_auto_approve=hints.get(
                    "yoloAutoApprove",
                    False,
                ),
            )

            decision = (Decision.ALLOW_ONCE if policy is not None and policy.yolo
                        else await prompter.ask(request, signal))

            if decision == Decision.DENY:
                if policy is not None and receipt is not None:
                    policy.finish_review(receipt, denied=True)
                raise UserControlledRefusal(
                    f"permission denied by user for {tool.name()}"
                )

            run_prompter: Prompter = _ExecutionPrompter(
                prompter,
                tool.name(),
                request.cache_key,
            )
        else:
            run_prompter = prompter

        token = policy.start(receipt, tool, args, signal) if policy and receipt else None
        try:
            return await tool.run(args, signal, run_prompter)
        finally:
            if token is not None and policy is not None:
                policy.stop(token)

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
