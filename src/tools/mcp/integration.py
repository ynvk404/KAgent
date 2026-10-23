"""Retired process MCP adapter. Config/history remain readable; execution is unavailable."""
from __future__ import annotations
from copy import deepcopy
import re
from typing import Any, Optional
from src.config.config import MCPServerConfig
from src.permission.runtime.execution import ExecutionBlocked
from src.tools.common.types import PermissionHints

UNAVAILABLE = 'unavailable: MCP requires the removed isolated executor; host execution is not enabled'

def display_tool_name(tool_name: str) -> str:
    parts = [p for p in tool_name.split("_") if p and p != "mcp"]
    deduped: list[str] = []
    for p in parts:
        if deduped and deduped[-1].lower() == p.lower():
            continue
        deduped.append(p)
    return " ".join(p.capitalize() for p in deduped) or tool_name


def primary_tool_arg(tool_name: str, args: dict[str, Any]) -> Optional[str]:
    for key in ("url", "path", "command", "query"):
        val = args.get(key)
        if isinstance(val, str):
            return val
    if len(args) == 1:
        (only_val,) = args.values()
        if isinstance(only_val, str):
            return only_val
    return None


HANDSHAKE_TIMEOUT_S = 15.0
CLOSE_DEADLINE_S = 3.0
MCP_RESULT_CHAR_CAP = 128 * 1024
MCP_CALL_TIMEOUT_S = 120.0
MCP_MAX_CONTENT_BLOCKS = 200
MCP_MAX_DEPTH = 32


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


def bound_content(content: Any, cap: int, depth: int = 0) -> Any:
    if depth >= MCP_MAX_DEPTH:
        if isinstance(content, str):
            return content[:cap] if len(content) > cap else content
        if isinstance(content, (dict, list)):
            return "[... max depth exceeded ...]"
        return content

    if isinstance(content, str):
        return content[:cap] if len(content) > cap else content

    if isinstance(content, list):
        head = [
            bound_content(block, cap, depth + 1)
            for block in content[:MCP_MAX_CONTENT_BLOCKS]
        ]
        if len(content) > MCP_MAX_CONTENT_BLOCKS:
            head.append(
                {
                    "type": "text",
                    "text": f"[... {len(content) - MCP_MAX_CONTENT_BLOCKS} more content blocks truncated ...]",
                }
            )
        return head

    if isinstance(content, dict):
        return {k: bound_content(v, cap, depth + 1) for k, v in content.items()}

    if hasattr(content, "model_dump"):
        return bound_content(content.model_dump(), cap, depth + 1)

    return content


def truncate_string(s: str, cap: int) -> str:
    if len(s) <= cap:
        return s
    return f"{s[:cap]}\n[... truncated {len(s) - cap} chars ...]"


def format_mcp_error(tool_name: str, remote_name: str, content: Any) -> str:
    text = extract_mcp_text(content).strip()
    label = display_tool_name(tool_name)

    if text:
        text = re.sub(r"^Error:\s*", "", text, flags=re.IGNORECASE)
        return f"{label} failed: {text}"

    return f"{label} failed: {remote_name} returned an MCP error"


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




def sanitize(s: str) -> str:
    out = ''.join(ch if re.match(r'[A-Za-z0-9_]', ch) else '_' for ch in s)
    return re.sub(r'^_+|_+$', '', out)
