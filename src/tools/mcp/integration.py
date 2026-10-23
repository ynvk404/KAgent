"""Retired process MCP adapter. Config/history remain readable; execution is unavailable."""
from __future__ import annotations
from copy import deepcopy
from typing import Any
from src.config.config import MCPServerConfig
from src.permission.runtime.execution import ExecutionBlocked
from src.tools.common.types import PermissionHints

UNAVAILABLE = 'unavailable: MCP requires the removed isolated executor; host execution is not enabled'

class MCPSession:
    """Compatibility surface for stored configuration and non-executing consumers."""
    def __init__(self, server_name: str = '', *args: Any, **kwargs: Any):
        self.server_name = server_name
        self.closed = True
        self.deployment = None

    @staticmethod
    async def open(server: MCPServerConfig, **kwargs: Any):
        raise ExecutionBlocked(UNAVAILABLE)

    async def list_tools(self):
        raise ExecutionBlocked(UNAVAILABLE)

    async def call_tool(self, *args: Any, **kwargs: Any):
        raise ExecutionBlocked(UNAVAILABLE)

    async def close(self):
        self.closed = True


class MCPTool:
    """Legacy tool objects fail closed even when constructed outside the CLI."""
    def __init__(self, session: Any, tool_name: str, remote_name: str, desc: str, schema_obj: dict[str, Any]):
        self._session, self._tool_name, self._remote_name = session, tool_name, remote_name
        self._desc, self._schema_obj = desc, schema_obj
        self._execution_policy: Any = None
        self._server: Any = None

    @property
    def cfg(self):
        return self._server

    def freeze_for_execution(self):
        from copy import copy
        frozen = copy(self)
        frozen._server = deepcopy(self._server)
        return frozen

    def name(self):
        return self._tool_name

    def description(self):
        return UNAVAILABLE

    def schema(self):
        return self._schema_obj

    def requires_permission(self):
        return True

    def validate_args(self, args: dict[str, Any]) -> None:
        raise ExecutionBlocked(UNAVAILABLE)

    def permission_hints(self, args: dict[str, Any]) -> PermissionHints:
        return {'noSessionCache': True, 'riskTier': 'high-impact'}

    def summarize(self, args: dict[str, Any]):
        return {'summary': UNAVAILABLE, 'detail': UNAVAILABLE}

    async def run(self, args: Any, signal: Any, prompter: Any):
        raise ExecutionBlocked(UNAVAILABLE)


async def discover_mcp_tools(server: MCPServerConfig, **kwargs: Any) -> dict[str, Any]:
    raise ExecutionBlocked(UNAVAILABLE)


def extract_mcp_text(content: Any) -> str:
    blocks = content if isinstance(content, list) else [content]
    parts: list[str] = []
    for block in blocks:
        if hasattr(block, "model_dump"):
            block = block.model_dump()
        if (
            isinstance(block, dict)
            and block.get("type") == "text"
            and isinstance(block.get("text"), str)
        ):
            parts.append(block["text"])
    return "\n".join(parts)
