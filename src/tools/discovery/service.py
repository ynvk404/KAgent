from __future__ import annotations

import asyncio
import errno
import hashlib
import ipaddress
import json
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from src.engagement.state import EngagementState, OutOfScopeError
from src.permission.permission import (
    Decision, PermissionRequest, Prompter, UserControlledRefusal,
)
from src.target.origin import HTTPOrigin
from src.target.target import Target
from src.tools.discovery.common import is_aborted, normalize_host, validate_ports
from src.tools.common.outcome import ErrorKind, ToolOutput
from src.tools.http.private_host import private_host_reason
from src.tools.common.types import PermissionHints, Tool
from src.workflow.state import WorkflowState
from src.workflow.ownership import WorkflowOwner
from src.permission.runtime.execution import ExecutionBlocked
from src.permission.runtime.invocations import REVIEW_TIMEOUT_SECONDS


DEFAULT_TIMEOUT_SECONDS = 20
MAX_TIMEOUT_SECONDS = 120
MAX_PORTS = 100
MAX_CONCURRENCY = 16
MAX_RESOLVED_ADDRESSES = 16


class MissingTCPScopeError(OutOfScopeError):
    """Native-only structured context; the existing error text stays compatible."""

    def __init__(self, message: str, origin: HTTPOrigin, address: str, ports: tuple[int, ...]):
        super().__init__(message)
        self.origin = origin
        self.address = address
        self.ports = tuple(sorted(ports))


class ServiceDiscoveryTool(Tool):
    def __init__(
        self,
        target: Target,
        engagement: EngagementState,
        *,
        workflow: WorkflowState | None = None,
    ) -> None:
        self.target = target
        self.engagement = engagement
        self.workflow = workflow

    def name(self) -> str:
        return "service_discovery"

    def description(self) -> str:
        return (
            "Check TCP connectivity on the active target hostname or IP. "
            "Defaults to its HTTP URL's effective port; additional explicit ports "
            "require numeric-IP TCP scope and operator execution review. "
            "Uses native TCP connections, at most 100 ports and 16 concurrent checks. "
            "No other hosts, CIDR, "
            "host lists, UDP, NSE scripts, OS detection, service version detection, "
            "or raw scanner flags. Only the default target-port check is "
            "eligible for automatic YOLO approval; other permission gates remain active."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Optional active target hostname/IP or its exact active URL.",
                },
                "ports": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_PORTS,
                    "items": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "description": (
                        "Optional TCP port list (duplicates are checked once). Defaults to the active "
                        "URL's effective port. Every additional port requires /scope tcp-add or a runtime A/B scope review "
                        "for the selected resolved IP and operator execution review."
                    ),
                },
                "mode": {
                    "type": "string",
                    "enum": ["auto", "socket"],
                    "description": "auto and socket both use native TCP.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": MAX_TIMEOUT_SECONDS,
                    "description": (
                        f"Network scan timeout (5–{MAX_TIMEOUT_SECONDS} seconds); "
                        "DNS resolution and operator permission wait are reported separately."
                    ),
                },
            },
            "required": [],
            "additionalProperties": False,
        }

    def requires_permission(self) -> bool:
        return True

    def validate_args(self, args: dict[str, Any]) -> None:
        self._parameters(args)

    def permission_hints(self, args: dict[str, Any]) -> PermissionHints:
        try:
            origin, host, ports, mode, timeout = self._parameters(args)
            backend = self._select_backend(mode)
            default_scan = ports == (origin.port,)
            action = {
                "active_origin": origin.as_url(),
                "host": host,
                "ports": list(ports),
                "backend": backend,
                "timeout": timeout,
            }
            if not default_scan:
                action["tcp_scope_revision"] = self.engagement.revision
            digest = hashlib.sha256(
                json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            return {
                "riskTier": "routine" if default_scan else "bounded-impact",
                "yoloAutoApprove": default_scan,
                "forceOperator": not default_scan,
                "noSessionCache": not default_scan,
                "cacheKey": f"service-discovery:{digest}",
                "sessionScopeDisplay": (
                    f"TCP service discovery on {host}, ports {','.join(map(str, ports))} "
                    f"using {backend} (scan timeout {timeout}s)"
                ),
            }
        except (TypeError, ValueError):
            return {"noSessionCache": True, "riskTier": "bounded-impact"}

    def summarize(self, args: dict[str, Any]) -> dict[str, str]:
        try:
            origin, host, ports, mode, timeout = self._parameters(args)
            backend = self._select_backend(mode)
            return {
                "summary": f"service discovery: {host} ({len(ports)} TCP ports)",
                "detail": (
                    f"active origin: {origin.as_url()}\ntarget host: {host}\n"
                    f"backend: {backend}\nports: {','.join(map(str, ports))}\n"
                    f"network scan timeout: {timeout}s (DNS and permission wait excluded)\n"
                    "protocol: TCP only; scripts, UDP, OS detection, and host ranges: disabled"
                ),
            }
        except (TypeError, ValueError) as err:
            return {"summary": "service discovery: invalid arguments", "detail": str(err)}

    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> ToolOutput:
        from src.permission.runtime.execution import guard_adapter
        guard_adapter(self, args, prompter)
        owner = WorkflowOwner.capture(self, prompter)
        origin, host, ports, mode, timeout = self._parameters(args)
        backend = self._select_backend(mode)
        backend_reason = self._backend_reason(mode)

        total_started = time.monotonic()
        permission_wait_seconds = 0.0
        scan_started: float | None = None

        def make_result(
            entries: list[dict[str, Any]],
            status: str,
            reason: str | None,
            *,
            resolved_address: str | None = None,
            error_kind: ErrorKind | None = None,
        ) -> ToolOutput:
            phase_status = {
                "success": "performed",
                "observation": "performed",
                "error": "failed",
                "cancelled": "cancelled",
            }.get(status)
            coverage_reason = reason
            if status == "success" and any(
                not entry.get("_completed", True) for entry in entries
            ):
                phase_status = "failed"
                coverage_reason = coverage_reason or (
                    "scanner did not provide exact state for every requested port"
                )
            objective = owner.objective
            if (
                phase_status is not None
                and owner.current()
                and objective is not None
                and self.workflow is not None
                and self.workflow.is_next_phase("recon")
            ):
                try:
                    self.workflow.record_phase_coverage(
                        "recon", "service_discovery", phase_status,  # type: ignore[arg-type]
                        objective_id=objective.id,
                        target_origin=objective.target_origin or "",
                        reason=(coverage_reason or "service discovery did not complete")
                        if phase_status in {"failed", "cancelled"} else None,
                    )
                except ValueError:
                    pass
            return self._result(
                origin, host, backend, ports, entries, total_started, status, reason,
                backend_reason=backend_reason,
                error_kind=error_kind,
                resolved_address=resolved_address,
                permission_wait_seconds=permission_wait_seconds,
                scan_duration_seconds=(
                    max(0.0, time.monotonic() - scan_started)
                    if scan_started is not None else 0.0
                ),
                scan_started=scan_started is not None,
            )

        if is_aborted(signal):
            return make_result(
                [], "cancelled", "cancelled before resolution",
                error_kind="cancelled",
            )

        addresses, resolution_status = await self._resolve_execution_addresses(
            host, timeout, signal
        )
        if resolution_status == "cancelled":
            return make_result(
                [], "cancelled", "cancelled during DNS resolution",
                error_kind="cancelled",
            )
        if resolution_status == "timeout":
            return make_result(
                [], "error", "timeout during DNS resolution",
                error_kind="timeout",
            )
        if is_aborted(signal):
            return make_result(
                [], "cancelled", "cancelled after DNS resolution",
                error_kind="cancelled",
            )
        if not addresses:
            return make_result(
                [], "error", "dns_resolution_failed", error_kind="network"
            )
        execution_address = addresses[0]
        self._require_tcp_scope(origin, execution_address, ports)

        address_reasons: list[tuple[str, str]] = []
        for address in addresses:
            private_reason = await private_host_reason(address)
            if private_reason:
                address_reasons.append((address, private_reason))
        if is_aborted(signal):
            return make_result(
                [], "cancelled", "cancelled during address policy check",
                error_kind="cancelled",
            )
        if address_reasons:
            reason_text = "; ".join(
                f"{address}: {reason}" for address, reason in address_reasons
            )
            permission_hints = self.permission_hints(args)
            declared_target = self.target.origin() == origin
            permission_started = time.monotonic()
            decision = await prompter.ask(
                PermissionRequest(
                    tool=self.name(),
                    summary=f"service_discovery: private/internal target {host}",
                    detail=(
                        f"active target host: {host}\n"
                        f"resolved addresses: {', '.join(addresses)}\n"
                        f"selected execution address: {execution_address}\n"
                        f"private/internal address reasons: {reason_text}\n"
                        f"backend: {backend}\n"
                        f"TCP ports: {','.join(map(str, ports))}\n"
                        f"network scan timeout: {timeout}s (permission wait excluded)\n\n"
                        "The scan will connect only to the selected vetted numeric address, "
                        "not resolve the hostname again. Approve only if this exact "
                        "active target and requested ports are within the engagement scope. "
                        "Execution approval does not add TCP scope."
                    ),
                    no_session_cache=(
                        not declared_target or permission_hints.get("noSessionCache", False)
                    ),
                    cache_key=(
                        permission_hints.get("cacheKey") if declared_target else None
                    ),
                    session_scope_display=(
                        permission_hints.get("sessionScopeDisplay")
                        if declared_target else None
                    ),
                    risk_tier=(
                        permission_hints.get("riskTier", "bounded-impact")
                        if declared_target else "bounded-impact"
                    ),
                    yolo_auto_approve=(
                        declared_target and permission_hints.get("yoloAutoApprove", False)
                    ),
                    force_operator=permission_hints.get("forceOperator", False),
                ),
                signal,
            )
            permission_wait_seconds += max(0.0, time.monotonic() - permission_started)
            if decision == Decision.DENY:
                raise UserControlledRefusal(
                    f"private-host service discovery denied for {host}"
                )
        if is_aborted(signal):
            return make_result(
                [], "cancelled", "cancelled before scan",
                error_kind="cancelled",
            )

        # Use one deterministic vetted address so execution cannot re-resolve DNS.
        self._require_tcp_scope(origin, execution_address, ports)
        scan_started = time.monotonic()
        entries, status, reason = await self._scan_sockets(
            execution_address, ports, timeout, signal
        )
        return make_result(
            entries, status, reason, resolved_address=execution_address,
            error_kind=(
                "timeout" if status == "error" and reason == "timeout"
                else "network" if status == "error" and reason == "dns_resolution_failed"
                else "tool_exception" if status == "error" else None
            ),
        )

    async def _resolve_execution_addresses(
        self, host: str, timeout: int, signal: Any
    ) -> tuple[list[str], str | None]:
        if is_aborted(signal):
            return [], "cancelled"
        try:
            return [str(ipaddress.ip_address(host))], None
        except ValueError:
            pass
        if is_aborted(signal):
            return [], "cancelled"
        task = asyncio.create_task(asyncio.to_thread(
            socket.getaddrinfo,
            host,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        ))
        deadline = time.monotonic() + timeout
        try:
            while not task.done():
                if is_aborted(signal):
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return [], "cancelled"
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return [], "timeout"
                await asyncio.wait({task}, timeout=min(0.05, remaining))
            raw_results = task.result()
        except (OSError, socket.gaierror, asyncio.TimeoutError):
            return [], "failed"
        except asyncio.CancelledError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
        addresses: set[str] = set()
        try:
            for result in raw_results:
                raw_address = result[4][0]
                address = ipaddress.ip_address(raw_address)
                if getattr(address, "scope_id", None) is not None:
                    return [], "failed"
                addresses.add(str(address))
        except (IndexError, TypeError, ValueError):
            return [], "failed"
        ordered = sorted(
            addresses,
            key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))),
        )
        if not ordered or len(ordered) > MAX_RESOLVED_ADDRESSES:
            return [], "failed"
        return ordered, None

    def _parameters(
        self, args: dict[str, Any]
    ) -> tuple[HTTPOrigin, str, tuple[int, ...], str, int]:
        target_url = self.target.base_url().strip()
        if not target_url:
            raise ValueError("an active HTTP target is required")
        try:
            active_origin = HTTPOrigin.from_url(target_url)
            parsed_target = urlsplit(target_url)
        except ValueError as err:
            raise ValueError("active target must be a valid HTTP URL") from err
        if parsed_target.username is not None or parsed_target.password is not None:
            raise ValueError("credential-bearing target URLs are not supported")
        if parsed_target.query or parsed_target.fragment:
            raise ValueError("active target URL must not contain a query or fragment")
        self.engagement.require_in_scope(active_origin.as_url())
        active_host = normalize_host(active_origin.hostname)

        raw_target = args.get("target")
        if raw_target is None or raw_target == "":
            host = active_host
        elif not isinstance(raw_target, str):
            raise ValueError("target must be a hostname, IP address, or exact active URL")
        elif raw_target.strip().lower().startswith(("http://", "https://")):
            try:
                requested = HTTPOrigin.from_url(raw_target.strip())
            except ValueError as err:
                raise ValueError("target URL is invalid") from err
            requested_parts = urlsplit(raw_target.strip())
            if requested_parts.username is not None or requested_parts.password is not None:
                raise ValueError("credential-bearing target URLs are not supported")
            if requested_parts.query or requested_parts.fragment:
                raise ValueError("target URL must not contain a query or fragment")
            if requested != active_origin:
                raise ValueError("service discovery target must match the active target origin")
            host = normalize_host(requested.hostname)
        else:
            host = normalize_host(raw_target)
            if host != active_host:
                raise ValueError("service discovery target host must match the active target")

        ports_value = args.get("ports")
        ports = validate_ports(ports_value, (active_origin.port,))
        mode = args.get("mode", "auto")
        if not isinstance(mode, str) or mode not in {"auto", "socket"}:
            raise ValueError("mode must be auto or socket")
        timeout = self._bounded_int(
            args.get("timeout_seconds"), DEFAULT_TIMEOUT_SECONDS, 5,
            MAX_TIMEOUT_SECONDS, "timeout_seconds",
        )
        return active_origin, host, ports, mode, timeout

    def _require_tcp_scope(
        self, origin: HTTPOrigin, address: str, ports: tuple[int, ...]
    ) -> None:
        additional = tuple(port for port in ports if port != origin.port)
        if additional and not self.engagement.tcp_allows(address, additional):
            missing = tuple(port for port in additional if not self.engagement.tcp_allows(address, (port,)))
            raise MissingTCPScopeError(
                f"additional TCP ports are outside scope for {address}; "
                f"use /scope tcp-add {address} {','.join(map(str, additional))} "
                "to authorize them before execution",
                origin, address, missing,
            )

    @staticmethod
    def _select_backend(mode: str) -> str:
        # Adapter hook used by the shared execution policy. Scanners use typed Shell.
        return "socket"

    @staticmethod
    def _backend_reason(mode: str) -> str:
        if mode == "socket":
            return "socket backend explicitly selected"
        return "native TCP discovery"

    @staticmethod
    def _bounded_int(
        value: object,
        default: int,
        minimum: int,
        maximum: int,
        name: str,
    ) -> int:
        if value is None:
            return default
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{name} must be an integer")
        if not minimum <= value <= maximum:
            raise ValueError(f"{name} must be from {minimum} through {maximum}")
        return value

    async def _scan_sockets(
        self, host: str, ports: tuple[int, ...], timeout: float, signal: Any
    ) -> tuple[list[dict[str, Any]], str, str | None]:
        deadline = time.monotonic() + timeout
        semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

        async def check(port: int) -> dict[str, Any]:
            if is_aborted(signal):
                return {"port": port, "protocol": "tcp", "state": "unknown", "_completed": False}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"port": port, "protocol": "tcp", "state": "unknown", "_completed": False}
            async with semaphore:
                try:
                    from src.permission.network.transport import socket_budget
                    async with socket_budget(host, port, signal, self.target.base_url()):
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, port),
                            timeout=min(2.0, remaining),
                        )
                        del reader
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except (UserControlledRefusal, OutOfScopeError):
                            raise
                        except OSError:
                            pass
                    return {"port": port, "protocol": "tcp", "state": "open", "_completed": True}
                except (UserControlledRefusal, OutOfScopeError):
                    # Control failures are not TCP observations. In particular,
                    # HTTPReviewTimeout also inherits TimeoutError/OSError.
                    raise
                except ConnectionRefusedError:
                    return {"port": port, "protocol": "tcp", "state": "closed", "_completed": True}
                except asyncio.TimeoutError:
                    return {"port": port, "protocol": "tcp", "state": "filtered", "_completed": True}
                except OSError as err:
                    if isinstance(err, socket.gaierror):
                        return {
                            "port": port,
                            "protocol": "tcp",
                            "state": "unknown",
                            "reason": "dns_resolution_failed",
                            "_completed": True,
                        }
                    state = "closed" if err.errno == errno.ECONNREFUSED else "unknown"
                    return {"port": port, "protocol": "tcp", "state": state, "_completed": True}

        tasks = {
            asyncio.create_task(check(port)): port
            for port in ports
        }
        pending = set(tasks)
        results: dict[int, dict[str, Any]] = {}

        def mark_unknown(port: int) -> None:
            results[port] = {
                "port": port,
                "protocol": "tcp",
                "state": "unknown",
                "_completed": False,
            }

        try:
            while pending:
                if is_aborted(signal):
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    for task in pending:
                        mark_unknown(tasks[task])
                    return list(results.values()), "cancelled", "cancelled during socket checks"

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # Let per-connection wait_for timeouts settle before
                    # classifying anything still pending as unattempted.
                    # Both deadlines are based on the same monotonic clock;
                    # without this event-loop turn, the outer deadline can
                    # win the race and discard an exact filtered result.
                    await asyncio.sleep(0)
                    settled = {task for task in pending if task.done()}
                    for task in settled:
                        results[tasks[task]] = task.result()
                    pending.difference_update(settled)
                    if not pending:
                        break
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    for task in pending:
                        mark_unknown(tasks[task])
                    return list(results.values()), "error", "timeout"

                done, pending = await asyncio.wait(
                    pending,
                    timeout=min(0.05, remaining),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    results[tasks[task]] = task.result()
        finally:
            # A control failure from one check must not leave sibling checks or
            # their socket reservations alive after this invocation exits.
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        entries = list(results.values())
        if any(entry.get("reason") == "dns_resolution_failed" for entry in entries):
            return entries, "error", "dns_resolution_failed"
        return entries, "success", None


    @staticmethod
    def _result(
        origin: HTTPOrigin,
        host: str,
        backend: str,
        requested_ports: tuple[int, ...],
        entries: list[dict[str, Any]],
        started: float,
        status: str,
        reason: str | None,
        *,
        backend_reason: str | None = None,
        error_kind: ErrorKind | None = None,
        resolved_address: str | None = None,
        permission_wait_seconds: float = 0.0,
        scan_duration_seconds: float = 0.0,
        scan_started: bool = True,
    ) -> ToolOutput:
        entries.sort(key=lambda item: item["port"])
        completed_ports = sum(
            1 for entry in entries if entry.get("_completed", True)
        )
        public_entries = [
            {key: value for key, value in entry.items() if not key.startswith("_")}
            for entry in entries[:MAX_PORTS]
        ]
        http_origins: list[str] = []
        for entry in entries:
            if entry.get("state") != "open":
                continue
            port = entry.get("port")
            schemes: tuple[str, ...] = ()
            if port == 443:
                schemes = ("https",)
            elif port == 80:
                schemes = ("http",)
            if schemes:
                for scheme in schemes:
                    default = 443 if scheme == "https" else 80
                    host_display = f"[{host}]" if ":" in host else host
                    url = f"{scheme}://{host_display}"
                    if port != default:
                        url += f":{port}"
                    http_origins.append(url)
        truncated = len(entries) > MAX_PORTS
        payload = {
            "status": status,
            "active_origin": origin.as_url(),
            "host": host,
            "resolved_address": resolved_address,
            "backend": backend,
            "backend_reason": backend_reason,
            "requested_ports": list(requested_ports),
            "completed_ports": completed_ports,
            "completed_port_count_exact": (
                not scan_started
                or (
                    backend == "socket"
                    and len(entries) == len(requested_ports)
                    and all(isinstance(entry.get("_completed"), bool) for entry in entries)
                )
                or (
                    status == "success"
                    and len(entries) == len(requested_ports)
                    and all(entry.get("_completed", True) for entry in entries)
                )
            ),
            "ports": public_entries,
            "http_origin_suggestions": list(dict.fromkeys(http_origins)),
            "suggestions_authorized": False,
            "duration_seconds": round(time.monotonic() - started, 3),
            "permission_wait_seconds": round(permission_wait_seconds, 3),
            "scan_duration_seconds": round(scan_duration_seconds, 3),
            "scan_started": scan_started,
            "reason": reason,
            "truncated": truncated,
        }
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if status == "cancelled":
            return ToolOutput(text, status="cancelled", error_kind="cancelled")
        if status == "error":
            safe_kind = error_kind if error_kind in {"timeout", "network", "tool_exception"} else "tool_exception"
            return ToolOutput(text, status="error", error_kind=safe_kind)
        return ToolOutput(text, status="observation")


@dataclass
class TCPScopeRequest:
    id: str
    origin: str
    address: str
    ports: tuple[int, ...]
    context: tuple
    expires: float
    state: str = "pending"


class TCPScopeRequests:
    """Bounded transient state; the controller owns context, UI and mutations.

    Records are created only for structured native failures by the Agent. They
    confer no execution rights and are never restored from session messages.
    """
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.requests: dict[str, TCPScopeRequest] = {}

    def current(self, request: TCPScopeRequest, context: tuple) -> bool:
        return (self.clock() < request.expires
                and self.requests.get(request.id) is request and context == request.context)

    def issue(self, error: MissingTCPScopeError, context: tuple) -> str | None:
        for request in self.requests.values():
            if request.context != context or request.address != error.address:
                continue
            if (request.state in {"denied", "cancelled", "closed"}
                    and set(request.ports).intersection(error.ports)):
                return None
            if request.ports == error.ports:
                # Do not turn a decline/cancellation into an equivalent dialog
                # in the same operator turn, even with a new tool-call ID.
                return request.id if request.state == "pending" and self.current(request, context) else None
        if len(self.requests) >= 128:
            self.requests.pop(next(iter(self.requests)))
        request_id = "tcp_" + uuid.uuid4().hex
        self.requests[request_id] = TCPScopeRequest(
            request_id, error.origin.as_url(), error.address, error.ports,
            context, self.clock() + REVIEW_TIMEOUT_SECONDS)
        return request_id

    def claim(self, request_id: str, context: tuple) -> TCPScopeRequest:
        request = self.requests.get(request_id)
        if request is None or request.state != "pending" or not self.current(request, context):
            raise ExecutionBlocked("blocked: TCP scope request is stale, expired, or already used")
        request.state = "asking"
        return request

    def decide(self, request: TCPScopeRequest, approve: bool, context: tuple) -> None:
        if request.state != "asking" or not self.current(request, context):
            raise ExecutionBlocked("blocked: TCP scope request changed while awaiting the operator")
        # Consume before the controller mutates scope. Old answers and duplicate
        # UI events cannot apply this operator decision twice.
        request.state = "approved" if approve else "denied"

    def updated(self, request: TCPScopeRequest, context: tuple) -> None:
        if request.state != "approved":
            raise ExecutionBlocked("blocked: TCP scope request has no operator approval")
        request.context = context
        request.state = "updated"

    def close(self, request: TCPScopeRequest, state: str = "closed") -> None:
        if request.state == "asking":
            request.state = state
