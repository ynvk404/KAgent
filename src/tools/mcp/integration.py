from __future__ import annotations

import asyncio
import io
import json
import re
import tempfile
from copy import deepcopy
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
from pydantic import AnyUrl

from src.config.config import MCPServerConfig
from src.tools.mcp.browser_deployment import is_designated_browser_server, is_designated_browser_local
from src.tools.mcp.cwe_deployment import (
    CWE_MCP_SERVER_NAME,
    is_designated_cwe_server,
    require_matching_cwe_deployment,
)
from src.logger.logger import get_logger
from src.tools.common.types import PermissionHints

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
        signal: Any,
        prompter: Any,
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
    async def open(server: MCPServerConfig, *, worker: Any = None, broker: Any = None, signal: Any = None) -> "MCPSession":
        # AnyIO transport/session contexts must enter and exit in the same task.
        # The long-lived owner below avoids returning their cancel scopes into
        # a different Registry/CLI task.
        if worker is not None:
            return cast(MCPSession, await OwnedMCPSession.open(server, worker=worker, broker=broker, signal=signal))
        return await MCPSession._open(server)

    @staticmethod
    async def _open(server: MCPServerConfig, *, worker: Any = None, broker: Any = None, signal: Any = None,
                    browser_local: bool = False, discovery_only: bool = False) -> "MCPSession":
        if not server.command:
            raise ValueError(f"mcp server {server.name} has no command")

        command, argv = server.command, list(server.args)
        local_params = None
        if browser_local:
            from src.tools.mcp.browser_local import local_launch_parameters
            if worker is not None or not is_designated_browser_local(server):
                raise ValueError('blocked: invalid designated trusted-local Browser launch')
            local_params = await local_launch_parameters(server, discovery_only=discovery_only)
        elif is_designated_browser_local(server):
            raise ValueError('blocked: Browser local launch requires controller opt-in')
        if is_designated_browser_server(server) and worker is None:
            raise ValueError('blocked: designated Browser MCP requires an isolated worker')
        is_cwe_server = server.name == CWE_MCP_SERVER_NAME
        if is_cwe_server:
            if not is_designated_cwe_server(server):
                raise ValueError('blocked: invalid designated CWE MCP launch configuration')
            if worker is None:
                raise ValueError('blocked: designated CWE MCP requires an isolated worker')
        if worker is not None:
            if server.env:
                raise ValueError('blocked: MCP environment export adapter unavailable; no ambient fallback')
            cwe_deployment_path = None
            if is_cwe_server:
                cwe_deployment_path = worker.cwe_mcp_deployment_path
                if cwe_deployment_path is None:
                    raise ValueError('blocked: CWE MCP deployment path is not configured')
                from src.permission.runtime.execution import current_policy
                policy = current_policy()
                if policy is not None:
                    require_matching_cwe_deployment(policy, worker)
            command, argv = await worker.prepare(command, argv, broker=broker, signal=signal,
                                                 browser_mcp=is_designated_browser_server(server),
                                                 cwe_mcp_deployment_path=cwe_deployment_path)
        params = local_params or StdioServerParameters(command=command, args=argv,
                                       env={} if worker is not None else server.env)

        exit_stack = AsyncExitStack()
        try:
            # SDK stdio_client passes errlog to subprocess: it needs a real
            # fileno(), not a TextIOBase writer with only write().
            errlog = tempfile.TemporaryFile(mode='w+', encoding='utf-8')
            def close_stderr():
                from src.redaction.redact import apply_evidence
                errlog.seek(0)
                text = apply_evidence(errlog.read(65536))
                if text:
                    warn('mcp child stderr (bounded)', server=server.name, line=text)
                errlog.close()
            exit_stack.callback(close_stderr)

            read, write = await exit_stack.enter_async_context(
                stdio_client(params, errlog=errlog)
            )
            client_session = await exit_stack.enter_async_context(
                ClientSession(read, write)
            )

            async def handshake() -> None:
                await client_session.initialize()

            await asyncio.wait_for(handshake(), timeout=HANDSHAKE_TIMEOUT_S)

            return MCPSession(server.name, client_session, exit_stack)
        except BaseException:
            # AnyIO contexts must be closed here, in their owning task, even
            # when cancellation interrupts initialization before a session is
            # returned. GC finalizers run in a different task and cannot do it.
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
        *, meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError(f"mcp session {self.server_name} is closed")

        call = (self._session.call_tool(name, arguments=args, meta=meta) if meta is not None
                else self._session.call_tool(name, arguments=args))

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
        response = {
            "isError": bool(getattr(result, "isError", False)),
            "content": getattr(result, "content", None),
        }
        if meta is not None:
            response['_meta'] = getattr(result, 'meta', None)
        return response

    async def browser_status(self) -> dict[str, Any]:
        response = await self._session.read_resource(AnyUrl('kagent://browser/status'))
        return json.loads(response.contents[0].text)  # type: ignore[union-attr]

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
            async with asyncio.timeout(CLOSE_DEADLINE_S):
                await close_op()
        except asyncio.TimeoutError:
            warn("mcp: close deadline exceeded; abandoning child", server=self.server_name)


async def _cancel_and_drain_owner(task: asyncio.Task) -> None:
    """Cancel once; repeated caller cancellation must not interrupt teardown."""
    if not task.done() and not task.cancelling():
        task.cancel()
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
    # Retrieve exceptions without moving AnyIO teardown into another task.
    await asyncio.gather(task, return_exceptions=True)


class OwnedMCPSession:
    def __init__(self, server_name):
        self.server_name = server_name
        self.queue: asyncio.Queue = asyncio.Queue()
        self.task: asyncio.Task | None = None
        self.closed = False

    @classmethod
    async def open(cls, server, *, worker, broker, signal=None):
        proxy = cls(server.name)
        ready = asyncio.get_running_loop().create_future()

        async def owner():
            session = None
            try:
                session = await MCPSession._open(server, worker=worker, broker=broker, signal=signal)
                if ready.done():
                    raise asyncio.CancelledError
                ready.set_result(True)
                while True:
                    method, args, future = await proxy.queue.get()
                    if method == 'close':
                        break
                    if future.cancelled():
                        continue
                    try:
                        result = await getattr(session, method)(*args)
                        if not future.done():
                            future.set_result(result)
                    except Exception as exc:
                        if not future.done():
                            future.set_exception(exc)
            except BaseException as exc:
                if not ready.done():
                    ready.set_exception(exc)
            finally:
                if session is not None:
                    await session.close()

        proxy.task = asyncio.create_task(owner())
        try:
            await ready
        except BaseException:
            await _cancel_and_drain_owner(proxy.task)
            raise
        return proxy

    async def invoke(self, method, *args):
        if self.closed or self.task is None or self.task.done():
            raise RuntimeError('isolated MCP session closed')
        future = asyncio.get_running_loop().create_future()
        await self.queue.put((method, args, future))
        try:
            return await future
        except asyncio.CancelledError:
            # A cancelled RPC must not retain an isolated process/lease.
            if not self.task.cancelling():
                self.task.cancel()
            raise

    def is_closed(self):
        return self.closed

    async def list_tools(self):
        return await self.invoke('list_tools')

    async def call_tool(self, name, args, cancel_event=None):
        return await self.invoke('call_tool', name, args, cancel_event)

    async def close(self):
        if self.closed or self.task is None:
            return
        self.closed = True
        await self.queue.put(('close', (), None))
        try:
            async with asyncio.timeout(CLOSE_DEADLINE_S):
                await asyncio.shield(self.task)
        except asyncio.TimeoutError:
            await _cancel_and_drain_owner(self.task)
        except asyncio.CancelledError:
            await _cancel_and_drain_owner(self.task)
            raise


class MCPToolSession(Protocol):
    server_name: str

    async def call_tool(
        self,
        name: str,
        args: dict[str, Any],
        cancel_event: Optional[asyncio.Event] = None,
    ) -> dict[str, Any]: ...


class MCPTool:

    @property
    def cfg(self):
        return self._server

    def freeze_for_execution(self):
        from copy import copy
        frozen = copy(self)
        frozen._server = deepcopy(self._server)
        return frozen

    def __init__(
        self,
        session: MCPToolSession,
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
        self._execution_policy: Any = None
        self._server: MCPServerConfig | None = None

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

    def permission_hints(self, args: dict[str, Any]) -> PermissionHints:
        return {"noSessionCache": True, "riskTier": "high-impact"}

    def summarize(self, args: dict[str, Any]) -> dict[str, str]:
        from src.redaction.redact import redact_payload

        return {
            "summary": f"mcp: {self._session.server_name}/{self._remote_name}",
            "detail": json.dumps(redact_payload({
                "server": self._session.server_name,
                "executor": {"command": self._server.command, "args": self._server.args} if self._server else None,
                "tool": self._remote_name,
                "args": args,
            }), indent=2, ensure_ascii=False),
        }

    async def run(
        self,
        args: dict[str, Any],
        signal: Any = None,
        prompter: Any = None,
        cancel_event: Optional[asyncio.Event] = None,
        _p: Any = None,
    ) -> str:
        from src.permission.runtime.execution import policy_for, ExecutionBlocked
        policy = policy_for(prompter)
        if policy is not None:
            if self._execution_policy is not policy or self._server is None or not policy.nested_allowed():
                raise ExecutionBlocked('blocked: enforcement-unavailable; MCP worker identity/receipt unavailable')
            if is_designated_browser_local(self._server):
                binding = getattr(policy, 'browser_local', None)
                if binding is None or self._session is not binding:
                    raise ExecutionBlocked('blocked: Browser local binding identity mismatch')
                source_owner = policy.observations.owner_provider()
                result = await binding.dispatch(self, args, signal, cancel_event)
                return self._render_policy_result(result, policy, source_owner)
            if policy.worker is None:
                raise ExecutionBlocked('blocked: enforcement-unavailable; MCP worker required')
            from src.permission.worker.broker import broker_directory
            # Fresh isolated server per invocation prevents background RPCs
            # from retaining a completed request's network authority.
            source_owner = policy.observations.owner_provider()
            async with broker_directory(signal) as broker:
                session = await MCPSession.open(self._server, worker=policy.worker, broker=broker, signal=signal)
                try:
                    if not policy.nested_allowed():
                        raise ExecutionBlocked('blocked: MCP execution receipt changed during initialization')
                    if self._server.name == CWE_MCP_SERVER_NAME:
                        require_matching_cwe_deployment(policy, policy.worker)
                    result = await session.call_tool(self._remote_name, args, cancel_event)
                finally:
                    await session.close()
            return self._render_policy_result(result, policy, source_owner)
        if is_designated_browser_local(self._server):
            raise ExecutionBlocked('blocked: Browser local invocation requires current policy/receipt')
        evt = cancel_event if cancel_event is not None else (signal if isinstance(signal, asyncio.Event) else None)
        result = await self._session.call_tool(self._remote_name, args, evt)
        if result["isError"]:
            raise RuntimeError(
                format_mcp_error(self._tool_name, self._remote_name, result["content"])
            )
        bounded = bound_content(result["content"], MCP_RESULT_CHAR_CAP)
        return truncate_string(json.dumps(bounded, default=str), MCP_RESULT_CHAR_CAP)

    def _render_policy_result(self, result, policy, source_owner) -> str:
        assert self._server is not None
        if result['isError']:
            raise RuntimeError(format_mcp_error(self._tool_name, self._remote_name, result['content']))
        bounded = bound_content(result['content'], MCP_RESULT_CHAR_CAP)
        encoded = json.dumps(bounded, default=str)
        truncated = bounded != result['content'] or len(encoded) > MCP_RESULT_CHAR_CAP
        output = truncate_string(encoded, MCP_RESULT_CHAR_CAP)
        key = policy.observations.capture_output(
            'mcp:' + self._server.name + ':' + self._remote_name, output,
            owner=source_owner, truncated=truncated)
        return output + (f'\n[runtime observation: {key}]' if source_owner else '')


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


async def discover_mcp_tools(server: MCPServerConfig, *, execution_policy: Any = None,
                             browser_local: Any = None) -> dict[str, Any]:
    from src.permission.runtime.execution import ExecutionBlocked
    deployment = None
    if execution_policy is not None:
        if execution_policy.worker is None and browser_local is None:
            raise ExecutionBlocked('blocked: enforcement-unavailable; MCP isolated worker required')
        if server.name == CWE_MCP_SERVER_NAME:
            deployment = require_matching_cwe_deployment(execution_policy, execution_policy.worker)
    server = deepcopy(server)
    if browser_local is not None:
        if (not is_designated_browser_local(server) or execution_policy is None
                or getattr(execution_policy, 'browser_local', None) is not browser_local
                or browser_local.policy is not execution_policy):
            raise ExecutionBlocked('blocked: invalid controller Browser opt-in discovery')
        session = browser_local
    else:
        session = await MCPSession.open(server, worker=execution_policy.worker if execution_policy else None)
    try:
        if deployment is not None and execution_policy is not None:
            if require_matching_cwe_deployment(execution_policy, execution_policy.worker) != deployment:
                raise ExecutionBlocked('blocked: CWE deployment changed during discovery')
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
            wrapped._execution_policy = execution_policy
            wrapped._server = server
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
