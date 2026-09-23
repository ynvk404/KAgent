from __future__ import annotations

import asyncio
import io
import json
import re
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncContextManager,
    Optional,
    Protocol,
    TextIO,
    cast,
    runtime_checkable,
)

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from src.config.config import MCPServerConfig
from src.logger.logger import get_logger

_log = get_logger("mcp")


def warn(message: str, **fields: Any) -> None:
    if fields:
        _log.warning("%s %s", message, json.dumps(fields, default=str))
    else:
        _log.warning(message)


@runtime_checkable
class Prompter(Protocol):
    ...


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

    def summarize(self, args: dict[str, Any]) -> dict[str, str]:
        ...

    async def run(
        self,
        args: dict[str, Any],
        cancel_event: Optional[asyncio.Event],
        prompter: Prompter,
    ) -> str:
        ...


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

    def __init__(
        self,
        server_name: str,
        session: ClientSession,
        exit_stack: AsyncExitStack,
        stderr_task: Optional[asyncio.Task] = None,
    ) -> None:
        self.server_name = server_name
        self._session = session
        self._exit_stack = exit_stack
        self._stderr_task = stderr_task
        self._closed = False

    @staticmethod
    async def open(server: MCPServerConfig) -> "MCPSession":
        if not server.command:
            raise ValueError(f"mcp server {server.name} has no command")

        params = StdioServerParameters(
            command=server.command,
            args=server.args,
            env=server.env,
        )

        exit_stack = AsyncExitStack()
        try:
            errlog = cast(TextIO, _StderrLogWriter(server.name))

            read, write = await exit_stack.enter_async_context(
                stdio_client(params, errlog=errlog)
            )
            client_session = await exit_stack.enter_async_context(
                ClientSession(read, write)
            )

            async def handshake() -> None:
                await client_session.initialize()

            try:
                await asyncio.wait_for(handshake(), timeout=HANDSHAKE_TIMEOUT_S)
            except asyncio.TimeoutError:
                await exit_stack.aclose()
                raise

            return MCPSession(server.name, client_session, exit_stack)
        except Exception:
            await exit_stack.aclose()
            raise

    def is_closed(self) -> bool:
        return self._closed

    async def list_tools(self) -> list[dict[str, Any]]:
        resp = await self._session.list_tools()
        tools = []
        for t in resp.tools:
            tools.append(
                {
                    "name": t.name,
                    "description": getattr(t, "description", None),
                    "inputSchema": getattr(t, "inputSchema", None),
                }
            )
        return tools

    async def call_tool(
        self,
        name: str,
        args: dict[str, Any],
        cancel_event: Optional[asyncio.Event] = None,
    ) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError(f"mcp session {self.server_name} is closed")

        call = self._session.call_tool(name, arguments=args)

        async def cancellable_call():
            if cancel_event is None:
                return await call
            call_task = asyncio.ensure_future(call)
            cancel_task = asyncio.ensure_future(cancel_event.wait())
            try:
                done, _pending = await asyncio.wait(
                    {call_task, cancel_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if cancel_task in done and call_task not in done:
                    raise asyncio.CancelledError("mcp call cancelled")
                return call_task.result()
            finally:
                for task in (call_task, cancel_task):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(call_task, cancel_task, return_exceptions=True)

        result = await asyncio.wait_for(cancellable_call(), timeout=MCP_CALL_TIMEOUT_S)
        return {
            "isError": bool(getattr(result, "isError", False)),
            "content": getattr(result, "content", None),
        }

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        async def close_op() -> None:
            try:
                await self._exit_stack.aclose()
            except Exception as err:
                warn(
                    "mcp: error while closing session",
                    server=self.server_name,
                    err=str(err),
                )
            if self._stderr_task:
                self._stderr_task.cancel()

        try:
            await asyncio.wait_for(close_op(), timeout=CLOSE_DEADLINE_S)
        except asyncio.TimeoutError:
            warn("mcp: close deadline exceeded; abandoning child", server=self.server_name)


class MCPTool:

    def __init__(
        self,
        session: MCPSession,
        tool_name: str,
        remote_name: str,
        desc: str,
        schema_obj: dict[str, Any],
    ) -> None:
        self._session = session
        self._tool_name = tool_name
        self._remote_name = remote_name
        self._desc = desc
        self._schema_obj = schema_obj

    def name(self) -> str:
        return self._tool_name

    def description(self) -> str:
        if self._desc:
            return f"MCP {self._session.server_name}: {self._desc}"
        return f"MCP tool from {self._session.server_name}"

    def schema(self) -> dict[str, Any]:
        return self._schema_obj

    def requires_permission(self) -> bool:
        return True

    def summarize(self, args: dict[str, Any]) -> dict[str, str]:
        primary = primary_tool_arg(self._tool_name, args)
        if primary is not None:
            return {"summary": display_tool_name(self._tool_name), "detail": primary}
        return {
            "summary": f"mcp: {self._tool_name}",
            "detail": json.dumps(args, indent=2),
        }

    async def run(
        self,
        args: dict[str, Any],
        cancel_event: Optional[asyncio.Event],
        _p: Prompter,
    ) -> str:
        result = await self._session.call_tool(self._remote_name, args, cancel_event)
        if result["isError"]:
            raise RuntimeError(
                format_mcp_error(self._tool_name, self._remote_name, result["content"])
            )
        bounded = bound_content(result["content"], MCP_RESULT_CHAR_CAP)
        return truncate_string(json.dumps(bounded, default=str), MCP_RESULT_CHAR_CAP)


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


async def discover_mcp_tools(server: MCPServerConfig) -> dict[str, Any]:
    session = await MCPSession.open(server)
    try:
        remote = await session.list_tools()
        tools: list[MCPTool] = []
        for t in remote:
            if not t.get("name"):
                continue
            schema = t.get("inputSchema") or {
                "type": "object",
                "additionalProperties": True,
            }
            wrapped = MCPTool(
                session,
                f"mcp_{sanitize(server.name)}_{sanitize(t['name'])}",
                t["name"],
                t.get("description") or "",
                schema,
            )
            tools.append(wrapped)
        return {"session": session, "tools": tools}
    except Exception:
        await session.close()
        raise


class _StderrLogWriter(io.TextIOBase):

    def __init__(self, server_name: str) -> None:
        super().__init__()
        self._server_name = server_name
        self._buffer = ""

    def writable(self) -> bool:
        return True

    def write(self, data: Any) -> int:
        try:
            text = (
                data.decode("utf-8", errors="replace")
                if isinstance(data, bytes)
                else str(data)
            )
        except Exception:
            return 0
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            trimmed = line.rstrip()
            if trimmed:
                warn("mcp child stderr", server=self._server_name, line=trimmed)
        return len(text)

    def flush(self) -> None:
        if self._buffer.strip():
            warn("mcp child stderr", server=self._server_name, line=self._buffer.rstrip())
            self._buffer = ""


def sanitize(s: str) -> str:
    out = "".join(ch if re.match(r"[A-Za-z0-9_]", ch) else "_" for ch in s)
    return re.sub(r"^_+|_+$", "", out)
