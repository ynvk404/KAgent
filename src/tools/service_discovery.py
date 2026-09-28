from __future__ import annotations

import asyncio
import errno
import hashlib
import ipaddress
import json
import math
import socket
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from src.engagement.state import EngagementState
from src.permission.permission import Decision, PermissionRequest, Prompter, UserControlledRefusal
from src.target.origin import HTTPOrigin
from src.target.target import Target
from .capabilities import CapabilityInventory
from .discovery_common import is_aborted, normalize_host, validate_ports
from .outcome import ErrorKind, ToolOutput
from .private_host import private_host_reason
from .shell import run_with_capture
from .types import PermissionHints, Tool
from src.workflow.state import WorkflowState


DEFAULT_TIMEOUT_SECONDS = 20
MAX_TIMEOUT_SECONDS = 120
MAX_PORTS = 100
MAX_CONCURRENCY = 16
MAX_RESOLVED_ADDRESSES = 16
MAX_NMAP_XML_BYTES = 1024 * 1024


class ServiceDiscoveryTool(Tool):
    def __init__(
        self,
        target: Target,
        engagement: EngagementState,
        capabilities: CapabilityInventory,
        tooling_profile: Callable[[], str | None],
        workflow: WorkflowState | None = None,
    ) -> None:
        self.target = target
        self.engagement = engagement
        self.capabilities = capabilities
        self.tooling_profile = tooling_profile
        self.workflow = workflow

    def name(self) -> str:
        return "service_discovery"

    def description(self) -> str:
        return (
            "Check the active target HTTP port on its active hostname or IP. "
            "Uses native TCP connections by default; full tooling profile may select "
            "installed nmap when recon coverage is missing. No other ports, CIDR, "
            "host lists, UDP, NSE scripts, OS detection, or "
            "raw scanner flags. A scan validated against the declared active "
            "target is routine reconnaissance and is eligible for YOLO; other "
            "permission gates remain active."
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
                    "items": {"type": "integer"},
                    "description": "Optional explicit list; every port must equal the active target URL's effective port.",
                },
                "mode": {
                    "type": "string",
                    "enum": ["auto", "socket"],
                    "description": "auto selects an installed scanner only for a runtime-confirmed recon coverage gap; socket forces native TCP.",
                },
                "timeout_seconds": {
                    "type": "integer",
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
            action = {
                "active_origin": origin.as_url(),
                "host": host,
                "ports": list(ports),
                "backend": backend,
                "timeout": timeout,
            }
            digest = hashlib.sha256(
                json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            return {
                "riskTier": "routine",
                "yoloAutoApprove": True,
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
        origin, host, ports, mode, timeout = self._parameters(args)
        backend = self._select_backend(mode)
        backend_reason = self._backend_reason(mode, backend)

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
            objective = self.workflow.objective if self.workflow is not None else None
            if (
                phase_status is not None
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
                        "active target and port are within the engagement scope."
                    ),
                    no_session_cache=not declared_target,
                    cache_key=(
                        permission_hints.get("cacheKey") if declared_target else None
                    ),
                    session_scope_display=(
                        permission_hints.get("sessionScopeDisplay")
                        if declared_target else None
                    ),
                    risk_tier=(
                        "routine" if declared_target else "bounded-impact"
                    ),
                    yolo_auto_approve=declared_target,
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
        scan_started = time.monotonic()
        if backend == "nmap":
            entries, status, reason = await self._scan_nmap(
                execution_address, ports, timeout, signal
            )
        else:
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
        if ports != (active_origin.port,):
            raise ValueError(
                "service discovery is limited to the active target URL's effective port"
            )
        mode = args.get("mode", "auto")
        if not isinstance(mode, str) or mode not in {"auto", "socket"}:
            raise ValueError("mode must be auto or socket")
        timeout = self._bounded_int(
            args.get("timeout_seconds"), DEFAULT_TIMEOUT_SECONDS, 5,
            MAX_TIMEOUT_SECONDS, "timeout_seconds",
        )
        return active_origin, host, ports, mode, timeout

    def _select_backend(self, mode: str) -> str:
        if mode == "socket":
            return "socket"
        use_nmap = (
            self.tooling_profile() == "full"
            and self.capabilities.snapshot().nmap is not None
            and self.workflow is not None
            and self.workflow.needs_phase_coverage("recon", "service_discovery")
        )
        return "nmap" if use_nmap else "socket"

    def _backend_reason(self, mode: str, backend: str) -> str:
        if mode != "auto":
            return f"{backend} backend explicitly selected"
        if backend == "nmap":
            return "full profile selected installed nmap for a runtime-confirmed recon coverage gap"
        if self.tooling_profile() != "full":
            return "minimal profile defaults to native TCP discovery"
        if self.capabilities.snapshot().nmap is None:
            return "nmap unavailable; fell back to native TCP discovery"
        return "no runtime-confirmed recon coverage gap; using native TCP discovery"

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
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=min(2.0, remaining),
                    )
                    del reader
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass
                    return {"port": port, "protocol": "tcp", "state": "open", "_completed": True}
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
        except asyncio.CancelledError:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            raise
        entries = list(results.values())
        if any(entry.get("reason") == "dns_resolution_failed" for entry in entries):
            return entries, "error", "dns_resolution_failed"
        return entries, "success", None

    async def _scan_nmap(
        self,
        host: str,
        ports: tuple[int, ...],
        timeout: float,
        signal: Any,
    ) -> tuple[list[dict[str, Any]], str, str | None]:
        binary = self.capabilities.snapshot().nmap
        if binary is None:
            return [], "error", "nmap is no longer available"
        with tempfile.TemporaryDirectory(prefix="kagent-service-") as directory:
            xml_path = Path(directory) / "scan.xml"
            argv = [
                "-n", "-Pn", "-sT", "-T3", "--max-retries", "1",
                "--host-timeout", f"{max(1, math.ceil(timeout))}s", "--reason",
                "-p", ",".join(str(port) for port in ports),
                "-oX", str(xml_path),
            ]
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                return [], "error", "nmap target was not a vetted numeric address"
            if address.version == 6:
                argv.append("-6")
            argv.append(host)
            try:
                output = await run_with_capture(binary, argv, timeout, signal)
            except OSError:
                self.capabilities.mark_unavailable("nmap", binary)
                return [], "error", "nmap could not be started"
            if output.status == "cancelled" or is_aborted(signal):
                return [], "cancelled", "cancelled during nmap scan"
            if output.status == "error" and output.error_kind == "timeout":
                return [], "error", "timeout"
            if not xml_path.exists():
                return [], "error", "nmap produced no XML output"
            try:
                if xml_path.stat().st_size > MAX_NMAP_XML_BYTES:
                    return [], "error", "nmap XML output exceeded the size limit"
                root = ET.fromstring(xml_path.read_bytes())
                entries: list[dict[str, Any]] = []
                seen_ports: set[int] = set()
                for port_element in root.findall(".//port"):
                    if port_element.get("protocol") != "tcp":
                        continue
                    number_raw = port_element.get("portid")
                    state_element = port_element.find("state")
                    if number_raw is None or state_element is None:
                        continue
                    try:
                        number = int(number_raw)
                    except ValueError:
                        continue
                    if number not in ports:
                        continue
                    if number in seen_ports:
                        return [], "error", "malformed nmap XML output: duplicate port records"
                    seen_ports.add(number)
                    state = state_element.get("state")
                    state_is_valid = state in {"open", "closed", "filtered", "unknown"}
                    entry: dict[str, Any] = {
                        "port": number,
                        "protocol": "tcp",
                        "state": state if state_is_valid else "unknown",
                        "_completed": state_is_valid,
                    }
                    if not state_is_valid:
                        entry["reason"] = "Nmap omitted or returned an unsupported port state"
                    service = port_element.find("service")
                    if service is not None:
                        name = service.get("name")
                        product = service.get("product")
                        version = service.get("version")
                        if name:
                            entry["service"] = self._safe_text(name, 100)
                        if product:
                            entry["product"] = self._safe_text(product, 100)
                        if version:
                            entry["version"] = self._safe_text(version, 80)
                    entries.append(entry)

                represented = {int(item["port"]) for item in entries}
                missing = sorted(set(ports) - represented)
                aggregates: dict[str, int] = {}
                for aggregate in root.findall(".//extraports"):
                    state = aggregate.get("state")
                    try:
                        count = int(aggregate.get("count", ""))
                    except ValueError:
                        continue
                    if state in {"open", "closed", "filtered", "unknown"} and count >= 0:
                        aggregates[state] = aggregates.get(state, 0) + count
                aggregate_total = sum(aggregates.values())
                if (
                    missing
                    and len(aggregates) == 1
                    and aggregate_total == len(missing)
                ):
                    aggregate_state = next(iter(aggregates))
                    entries.extend({
                        "port": number,
                        "protocol": "tcp",
                        "state": aggregate_state,
                        "_completed": True,
                        "aggregate_state": True,
                    } for number in missing)
                else:
                    aggregate_reason = (
                        "Nmap aggregate states cannot be mapped to individual requested ports"
                        if aggregates else "Nmap did not report every requested port"
                    )
                    entries.extend({
                        "port": number,
                        "protocol": "tcp",
                        "state": "unknown",
                        "reason": aggregate_reason,
                        "_completed": False,
                    } for number in missing)
                entries.sort(key=lambda item: item["port"])
                if output.status == "error":
                    return entries, "error", "nmap returned a non-zero exit status"
                incomplete_reason = None
                if any(not entry.get("_completed", True) for entry in entries):
                    incomplete_reason = (
                        "Nmap did not provide an exact per-port state for every requested port"
                    )
                return entries, "success", incomplete_reason
            except (OSError, ET.ParseError, ValueError):
                return [], "error", "malformed nmap XML output"

    @staticmethod
    def _safe_text(value: str, limit: int) -> str:
        return "".join(char for char in value if char.isprintable())[:limit]

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
            service = str(entry.get("service", "")).lower()
            schemes: tuple[str, ...] = ()
            if port == 443 or service in {"https", "https-alt"}:
                schemes = ("https",)
            elif port == 80 or service in {"http", "http-proxy"}:
                schemes = ("http",)
            elif service in {"ssl", "ssl/http"}:
                schemes = ("https",)
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
