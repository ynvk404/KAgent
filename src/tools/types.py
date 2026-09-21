from __future__ import annotations

from typing import Any, Literal, Optional, Protocol, TypedDict, runtime_checkable

ContextReductionPolicy = Literal["adaptive", "preserve"]

class PermissionHints(TypedDict, total=False):
    noSessionCache: bool
    cacheKey: str
    sessionScopeDisplay: str

class ToolSummary(TypedDict):
    summary: str
    detail: str

@runtime_checkable
class Tool(Protocol):
    def name(self) -> str:
        ...

    def description(self) -> str:
        ...

    def schema(self) -> dict[str, Any]:
        ...

    def requires_permission(self) -> bool:
        ...

    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Any,
    ) -> str:
        ...

@runtime_checkable
class SummarizableTool(Protocol):
    def summarize(
        self,
        args: dict[str, Any],
    ) -> ToolSummary:
        ...

@runtime_checkable
class PermissionHintTool(Protocol):
    def permission_hints(
        self,
        args: dict[str, Any],
    ) -> PermissionHints:
        ...


@runtime_checkable
class ActionPermissionTool(Protocol):
    """Optional argument-aware override for a tool's permission requirement."""

    def requires_permission_for(self, args: dict[str, Any]) -> bool:
        ...


@runtime_checkable
class ArgumentValidatingTool(Protocol):
    """Optional tool-side validation that runs before permission is requested."""

    def validate_args(self, args: dict[str, Any]) -> None:
        ...


@runtime_checkable
class ContextReductionTool(Protocol):
    """Optional policy for tool results copied into the LLM working context."""

    def context_reduction_policy(self) -> ContextReductionPolicy:
        ...

def arg_string(
    args: dict[str, Any],
    key: str,
) -> str:
    value = args.get(key)
    if isinstance(value, str):
        return value
    return ""

def arg_bool(
    args: dict[str, Any],
    key: str,
) -> bool:
    value = args.get(key)
    if isinstance(value, bool):
        return value
    return False

def arg_number(
    args: dict[str, Any],
    key: str,
) -> Optional[float]:
    value = args.get(key)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value != float("inf") and value != float("-inf"):
            return float(value)
    return None
