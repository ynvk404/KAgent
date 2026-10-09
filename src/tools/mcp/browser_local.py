"""Controller-selected Browser exception to OfflineWorker, with neutral task ownership.

This is a trusted host process, not filesystem/network isolation. Connection
status is transport evidence only; a successful authorized tool response is
the evidence that the selected lab tab actually answered.
"""
from __future__ import annotations

import asyncio
from contextvars import Context, copy_context
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit

from mcp import StdioServerParameters

from src.permission.network.grants import check_cancelled
from src.permission.runtime.execution import ExecutionBlocked
from src.target.origin import HTTPOrigin
from src.tools.mcp import browser_deployment as deployment

READINESS_TIMEOUT_S = 15.0
RPC_TIMEOUT_S = 120.0
STATUS_TIMEOUT_S = 3.0
STATUS_POLL_S = 0.1
WINDOWS_POWERSHELL = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
WINDOWS_PORT_CHECK = (
    "$ErrorActionPreference='Stop'; try { "
    "$listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | "
    "Where-Object { $_.LocalPort -eq 9009 }); "
    "if ($listeners.Count) { Write-Output 'occupied'; exit 23 }; "
    "Write-Output 'free'; exit 0 } catch { Write-Output 'check-failed'; exit 24 }"
)
MUTATING = frozenset({'browser_navigate', 'browser_click', 'browser_type', 'browser_select_option',
                      'browser_press_key', 'browser_go_back', 'browser_go_forward'})


def validate_browser_url(raw: Any) -> HTTPOrigin:
    if (not isinstance(raw, str) or not raw or '\\' in raw
            or any(ord(char) <= 32 or ord(char) == 127 for char in raw)):
        raise ExecutionBlocked('blocked: invalid Browser URL')
    try:
        parsed = urlsplit(raw)
        if parsed.username is not None or parsed.password is not None or not parsed.netloc:
            raise ValueError('credential-bearing/relative URL')
        return HTTPOrigin.from_url(raw)
    except ValueError as exc:
        raise ExecutionBlocked('blocked: Browser requires a valid absolute HTTP(S) URL') from exc


def linux_listeners() -> list[tuple[str, str]]:
    listeners = []
    for name in ('tcp', 'tcp6'):
        for row in Path('/proc/net/' + name).read_text().splitlines()[1:]:
            fields = row.split()
            address, port = fields[1].split(':')
            if int(port, 16) == 9009 and fields[3] == '0A':
                listeners.append((address, fields[9]))
    return listeners


async def check_ports_free() -> None:
    if linux_listeners():
        raise ExecutionBlocked('blocked: WSL/Linux port 9009 already owned; no kill/adoption')
    if 'microsoft' in Path('/proc/sys/kernel/osrelease').read_text().lower():
        proc = None
        try:
            async with asyncio.timeout(10):
                proc = await asyncio.create_subprocess_exec(
                    WINDOWS_POWERSHELL, '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
                    '-Command', WINDOWS_PORT_CHECK, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    env={'PATH': '/usr/bin:/bin', 'WSL_INTEROP': os.environ.get('WSL_INTEROP', '')})
                out, _ = await proc.communicate()
            if proc.returncode != 0 or out.strip() != b'free':
                raise ExecutionBlocked('blocked: Windows port 9009 occupied or inspection failed; no listener launched')
        except (OSError, TimeoutError) as exc:
            raise ExecutionBlocked('blocked: Windows port 9009 preflight unavailable') from exc
        finally:
            if proc is not None and proc.returncode is None:
                proc.kill()
                await proc.wait()


def verify_listener_owner(status: dict[str, Any]) -> None:
    try:
        pid = status['pid']
        if type(pid) is not int or pid <= 1 or not status['listening']:
            raise ValueError('listener absent')
        if Path(f'/proc/{pid}/exe').resolve(strict=True) != Path(deployment.BROWSER_MCP_COMMAND):
            raise ValueError('unexpected owner executable')
        sockets = {path.readlink().as_posix() for path in Path(f'/proc/{pid}/fd').iterdir()
                   if path.is_symlink()}
        listeners = linux_listeners()
        if len(listeners) != 1 or listeners[0][0] != '0100007F' or 'socket:[' + listeners[0][1] + ']' not in sockets:
            raise ValueError('listener is not our unique loopback socket')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ExecutionBlocked('blocked: Browser listener ownership/loopback verification failed') from exc


async def local_launch_parameters(server, *, discovery_only: bool) -> StdioServerParameters:
    if not deployment.is_designated_browser_local(server):
        raise ExecutionBlocked('blocked: invalid designated Browser local command/argv/env')
    async with asyncio.timeout(15):
        await asyncio.to_thread(deployment.verify_browser_local_deployment)
    if not discovery_only:
        await check_ports_free()
    # Override every default inherited variable of the pinned Python MCP SDK.
    # No provider/npm/proxy/Node options are copied from the controller.
    environment = {'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'LANG': 'C.UTF-8',
                   'LOGNAME': 'kagent-browser', 'USER': 'kagent-browser', 'SHELL': '/bin/false', 'TERM': 'dumb',
                   'KAGENT_BROWSER_LOCAL': '1', 'KAGENT_BROWSER_DISCOVERY': '1' if discovery_only else '0'}
    return StdioServerParameters(
        command=deployment.BROWSER_LIMITER,
        args=['--as=' + str(deployment.BROWSER_MCP_ADDRESS_SPACE), '--cpu=120', '--fsize=16777216',
              '--nofile=128', '--nproc=1024', '--core=0', '--', server.command, *server.args],
        env=environment, cwd=str(deployment.BROWSER_LOCAL_ROOT))


class BrowserOwner:
    """All MCP/AnyIO contexts enter/exit in this one neutral asyncio task."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue = asyncio.Queue()
        self.task: asyncio.Task | None = None
        self.closed = False

    @classmethod
    async def open(cls, server, *, discovery_only=False):
        from src.tools.mcp.integration import MCPSession, _cancel_and_drain_owner
        proxy = cls()
        ready = asyncio.get_running_loop().create_future()

        async def owner():
            session = None
            current = None
            try:
                session = await MCPSession._open(server, browser_local=True, discovery_only=discovery_only)
                ready.set_result(True)
                while True:
                    method, args, kwargs, guard, current = await proxy.queue.get()
                    if method == 'close':
                        break
                    if current.cancelled():
                        continue
                    try:
                        if guard is not None:
                            guard()
                        result = await getattr(session, method)(*args, **kwargs)
                        if not current.done():
                            current.set_result(result)
                    except Exception as exc:
                        if not current.done():
                            current.set_exception(exc)
                    except asyncio.CancelledError:
                        if not current.done():
                            current.set_exception(RuntimeError('Browser owner interrupted/process disconnected'))
                        raise
                    finally:
                        guard = None  # Do not retain an invocation context while idle.
                        current, args, kwargs = None, (), {}
            except BaseException as exc:
                if not ready.done():
                    ready.set_exception(exc)
            finally:
                proxy.closed = True
                error = RuntimeError('Browser process died/closed; CPU budget may be exhausted; no automatic replay')
                if current is not None and not current.done():
                    current.set_exception(error)
                while not proxy.queue.empty():
                    *_, pending = proxy.queue.get_nowait()
                    if pending is not None and not pending.done():
                        pending.set_exception(error)
                if session is not None:
                    await session.close()

        proxy.task = asyncio.create_task(owner(), context=Context(), name='browser-mcp-owner')
        try:
            await ready
        except BaseException:
            await _cancel_and_drain_owner(proxy.task)
            raise
        return proxy

    async def request(self, method, *args, guard=None, **kwargs):
        if self.closed or self.task is None or self.task.done():
            raise RuntimeError('Browser owner unavailable; explicit reset required')
        future = asyncio.get_running_loop().create_future()
        self.queue.put_nowait((method, args, kwargs, guard, future))
        return await future

    async def close(self):
        from src.tools.mcp.integration import _cancel_and_drain_owner
        if self.task is None:
            return
        if not self.closed:
            self.closed = True
            self.queue.put_nowait(('close', (), {}, None, None))
        try:
            async with asyncio.timeout(3):
                await asyncio.shield(self.task)
        except (TimeoutError, asyncio.CancelledError):
            await _cancel_and_drain_owner(self.task)
            task = asyncio.current_task()
            if task is not None and task.cancelling():
                raise asyncio.CancelledError


class BrowserLocalBinding:
    server_name = 'browser'

    def __init__(self, policy, server, *, lab_ready: bool, lab_origin: str):
        if not deployment.is_designated_browser_local(server) or sys.platform != 'linux':
            raise ExecutionBlocked('blocked: designated Linux Browser local binding required')
        self.policy = policy
        self.server = deepcopy(server)
        self.lab_ready = lab_ready
        self.lab_origin = validate_browser_url(lab_origin).as_url() if lab_origin else ''
        self.owner: BrowserOwner | None = None
        self.retired: list[BrowserOwner] = []
        self.lock = asyncio.Lock()
        self.epoch = 0
        self.closed = False
        self.fault = ''
        self.generation = 0
        self.snapshot_generation = 0
        self.schema_identity = ''
        self.lifecycle = self._lifecycle()

    def _lifecycle(self):
        rights = self.policy.engagement.http_permissions
        return (id(self.policy.engagement), self.policy.engagement.revision, rights.epoch,
                self.policy.session_id, self.policy.root)

    def invalidate(self) -> None:
        self.epoch += 1
        self.generation = self.snapshot_generation = 0
        self.fault = ''
        if self.owner is not None:
            self.retired.append(self.owner)
            if self.owner.task is not None and not self.owner.task.done():
                self.owner.task.cancel()
            self.owner = None
        self.lifecycle = self._lifecycle()

    def validate_tool(self, tool, args) -> None:
        if (self.closed or self.policy.browser_local is not self or tool._session is not self
                or tool._execution_policy is not self.policy
                or not deployment.is_designated_browser_local(tool._server)):
            raise ExecutionBlocked('blocked: Browser local controller binding mismatch')
        if not self.lab_ready or not self.lab_origin:
            raise ExecutionBlocked('blocked: operator lab-profile/pairing confirmation required (--browser-lab-ready and --target)')
        if self._lifecycle() != self.lifecycle:
            self.invalidate()
        # Lab attestation is bound to one operator-selected origin for this CLI.
        if self.lab_origin not in {origin.as_url() for origin in self.policy.engagement.allowed_origins}:
            raise ExecutionBlocked('blocked: Browser lab origin no longer in engagement scope')
        self.policy.require_network(self.lab_origin)
        if tool._remote_name == 'browser_navigate':
            origin = validate_browser_url(args.get('url')).as_url()
            self.policy.require_network(args['url'])
            if origin != self.lab_origin:
                raise ExecutionBlocked('blocked: Browser navigate outside operator lab binding')
        if self.fault:
            raise ExecutionBlocked(self.fault)

    @staticmethod
    def _schema_identity(tools) -> str:
        return json.dumps(tools, sort_keys=True, separators=(',', ':'))

    async def list_tools(self):
        # Ephemeral schema discovery uses patched Node with no network listener.
        owner = await BrowserOwner.open(self.server, discovery_only=True)
        try:
            tools = await asyncio.wait_for(owner.request('list_tools'), 15)
            if len(tools) != 12:
                raise ExecutionBlocked('blocked: Browser tool inventory changed')
            self.schema_identity = self._schema_identity(tools)
            return tools
        finally:
            await owner.close()

    async def call_tool(self, name, args, cancel_event=None):
        raise ExecutionBlocked('blocked: Browser local tools require Registry dispatch/receipt')

    async def _drain_retired(self):
        from src.tools.mcp.integration import _cancel_and_drain_owner
        retired, self.retired = self.retired, []
        for owner in retired:
            if owner.task is not None:
                await _cancel_and_drain_owner(owner.task)

    async def dispatch(self, tool, args, signal=None, cancel_event=None):
        self.validate_tool(tool, args)
        invocation_epoch = self.epoch
        context = copy_context()

        def check():
            check_cancelled(signal)
            check_cancelled(cancel_event)
            if invocation_epoch != self.epoch or not self.policy.nested_allowed():
                raise ExecutionBlocked('blocked: Browser queued receipt revoked/stale or binding reset')
            self.validate_tool(tool, args)
            if invocation_epoch != self.epoch:
                raise ExecutionBlocked('blocked: Browser context changed before dispatch')

        async def guarded(awaitable, timeout):
            task = asyncio.ensure_future(awaitable)
            try:
                async with asyncio.timeout(timeout):
                    while not task.done():
                        await asyncio.wait({task}, timeout=0.05)
                        check()
                    check()
                    return task.result()
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        # Lock waiting occurs in the invocation's task/context, never in owner.
        acquire = asyncio.create_task(self.lock.acquire())
        try:
            await guarded(acquire, RPC_TIMEOUT_S)
        except BaseException:
            if acquire.done() and not acquire.cancelled() and acquire.exception() is None and acquire.result():
                self.lock.release()
            raise
        dispatched = False
        try:
            check()
            await self._drain_retired()
            check()
            if self.owner is None:
                async def start_owner():
                    self.owner = await BrowserOwner.open(self.server)
                await guarded(start_owner(), 30)
                assert self.owner is not None
                inventory = await guarded(self.owner.request('list_tools'), 15)
                if self._schema_identity(inventory) != self.schema_identity:
                    raise ExecutionBlocked('blocked: Browser tool schemas changed after discovery')
            deadline = asyncio.get_running_loop().time() + READINESS_TIMEOUT_S
            while True:
                state = await guarded(self.owner.request('browser_status'), STATUS_TIMEOUT_S)
                verify_listener_owner(state)
                if state['connected']:
                    break
                if asyncio.get_running_loop().time() >= deadline:
                    raise ExecutionBlocked('blocked: Browser readiness deadline; extension has not connected; no action dispatched')
                await guarded(asyncio.sleep(STATUS_POLL_S), STATUS_TIMEOUT_S)
            if self.generation != state['generation']:
                self.generation = state['generation']
                self.snapshot_generation = 0
            if args.get('ref') is not None and (not self.snapshot_generation
                    or state['snapshotGeneration'] != self.snapshot_generation):
                raise ExecutionBlocked('blocked: reconnect/stale ref; request a fresh browser_snapshot')
            meta = {'kagentBrowser': {'origin': self.lab_origin, 'generation': self.generation,
                                      'snapshotGeneration': self.snapshot_generation}}

            def before_rpc():
                nonlocal dispatched
                context.run(check)
                dispatched = True

            result = await guarded(self.owner.request('call_tool', tool._remote_name, args,
                                                      meta=meta, guard=before_rpc), RPC_TIMEOUT_S)
            result_meta = (result.get('_meta') or {}).get('kagentBrowser', {})
            if result_meta.get('generation') != self.generation:
                raise RuntimeError('Browser disconnected during operation')
            self.snapshot_generation = result_meta.get('snapshotGeneration', 0)
            if result['isError'] and tool._remote_name in MUTATING:
                from src.tools.mcp.integration import extract_mcp_text
                message = extract_mcp_text(result['content'])
                if 'outcome unknown' in message or not message.startswith('Error: Blocked:'):
                    from src.redaction.redact import apply_evidence
                    # Preserve the bounded, redacted server diagnosis; outcome
                    # uncertainty must not erase which RPC/transport failed.
                    raise RuntimeError('Browser MCP failure: ' + apply_evidence(message)[:4096])
            return result
        except BaseException as exc:
            self.invalidate()
            await self._drain_retired()
            # Do not restart/replay a dead or ambiguous persistent process.
            if (dispatched or isinstance(exc, RuntimeError)) and not isinstance(exc, ExecutionBlocked):
                self.fault = 'blocked: Browser process/operation failed; explicit reset required; no replay'
            if dispatched and tool._remote_name in MUTATING:
                from src.redaction.redact import apply_evidence
                cause = apply_evidence(str(exc))[:4096]
                raise RuntimeError('Browser mutating outcome unknown; cancellation/teardown is not rollback; '
                                   'no automatic retry. Cause: ' + cause) from exc
            raise
        finally:
            self.lock.release()

    async def close(self):
        self.closed = True
        self.invalidate()
        await self._drain_retired()

    def is_closed(self):
        return self.closed
