from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, unquote, urljoin, urlsplit

import httpx

from src.engagement.state import EngagementState
from src.permission.permission import Prompter
from src.redaction.redact import apply as redact
from src.target.origin import HTTPOrigin
from src.target.target import Target
from src.tools.common.capabilities import CapabilityInventory
from src.tools.discovery.common import (
    DiscoveryScope,
    is_aborted,
    resolve_discovery_scope,
    sleep_or_abort,
    validate_relative_path,
)
from src.tools.common.outcome import ErrorKind, ToolOutput
from src.tools.http.private_host import gate_private_request, parse_http_url
from src.tools.execution.shell import run_with_capture
from src.tools.http.request_builder import NATIVE_USER_AGENT
from src.tools.common.types import PermissionHints, Tool
from src.workflow.state import WorkflowState
from src.permission.runtime.execution import guard_adapter
from src.permission.network.transport import governed_stream


DEFAULT_MAX_REQUESTS = 120
MAX_REQUESTS = 1000
DEFAULT_RATE_LIMIT = 5
MAX_RATE_LIMIT = 10
DEFAULT_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 120
MAX_PATHS = 500
MAX_EXTENSIONS = 16
MAX_RESPONSE_BYTES = 16 * 1024
MAX_RESULT_ITEMS = 100
MAX_FFUF_JSON_BYTES = 1024 * 1024

DEFAULT_PATHS = (
    "admin", "api", "api/v1", "api/v2", "auth", "login", "logout",
    "register", "account", "profile", "users", "user", "dashboard",
    "health", "healthz", "status", "metrics", "robots.txt", "sitemap.xml",
    ".well-known/security.txt", "swagger", "swagger-ui", "swagger.json",
    "openapi.json", "api-docs", "docs", "graphql", "graphiql", "debug",
    "actuator", "actuator/health", "server-status", "backup", "backups",
    "uploads", "files", "static", "assets", "config", "version", "search",
    "checkout", "cart", "orders", "support", "contact", "forgot-password",
    "reset-password", "oauth", "callback", "webhooks", "internal",
)
_SAFE_EXTENSION_RE = re.compile(r"^[a-z0-9]{1,10}$", re.IGNORECASE)


class ContentDiscoveryTool(Tool):
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
        return "content_discovery"

    def description(self) -> str:
        return (
            "Discover a bounded list of common web paths on the active target's "
            "exact HTTP origin. Uses native HTTP by default; full tooling profile "
            "may select installed ffuf when coverage is still missing. GET only, "
            "no recursion, no raw scanner flags, redirects are not followed, and "
            "every ffuf hit is rechecked with native HTTP. Its bounded paths and "
            "request budget are validated against the active scope; routine "
            "in-scope enumeration is eligible for YOLO."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "base_url": {
                    "type": "string",
                    "description": "Optional same-origin URL path or URL; defaults to the active target.",
                },
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": f"Optional relative paths (max {MAX_PATHS}); otherwise a curated list is used.",
                },
                "extensions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": f"Optional file extensions appended to each path (max {MAX_EXTENSIONS}).",
                },
                "mode": {
                    "type": "string",
                    "enum": ["auto", "native"],
                    "description": "auto selects a runtime-approved backend; native forces built-in HTTP.",
                },
                "max_requests": {
                    "type": "integer",
                    "description": f"Total request hard cap, including two baselines and verification (3–{MAX_REQUESTS}).",
                },
                "rate_limit": {
                    "type": "integer",
                    "description": f"Requests per second (1–{MAX_RATE_LIMIT}).",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": f"Whole operation timeout in seconds (5–{MAX_TIMEOUT_SECONDS}).",
                },
            },
            "required": [],
            "additionalProperties": False,
        }

    def requires_permission(self) -> bool:
        return True

    def validate_args(self, args: dict[str, Any]) -> None:
        _, _, mode, max_requests, _, _ = self._parameters(args)
        self._select_backend(mode, max_requests)

    def permission_hints(self, args: dict[str, Any]) -> PermissionHints:
        try:
            scope, words, mode, max_requests, rate, timeout = self._parameters(args)
            backend = self._select_backend(mode, max_requests)
            action = {
                "origin": scope.origin.as_url(),
                "base_path": scope.base_path,
                "paths_sha256": hashlib.sha256(
                    "\n".join(words).encode("utf-8")
                ).hexdigest(),
                "backend": backend,
                "max_requests": max_requests,
                "rate": rate,
                "timeout": timeout,
            }
            key = hashlib.sha256(
                json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            return {
                "riskTier": "routine",
                "yoloAutoApprove": True,
                "cacheKey": f"content-discovery:{key}",
                "sessionScopeDisplay": (
                    f"content discovery on {scope.origin.as_url()}{scope.base_path or '/'} "
                    f"using {backend} ({len(words)} paths, <= {max_requests} requests, "
                    f"<= {rate}/s, {timeout}s)"
                ),
            }
        except (TypeError, ValueError):
            return {"noSessionCache": True}

    def summarize(self, args: dict[str, Any]) -> dict[str, str]:
        try:
            scope, words, mode, max_requests, rate, timeout = self._parameters(args)
            backend = self._select_backend(mode, max_requests)
            path = scope.base_path or "/"
            return {
                "summary": f"content discovery: {scope.origin.as_url()}{path}",
                "detail": (
                    f"origin: {scope.origin.as_url()}\nbase path: {path}\n"
                    f"backend: {backend}\npaths: {len(words)}\n"
                    f"maximum requests: {max_requests}\nrate limit: {rate}/s\n"
                    f"timeout: {timeout}s\nmethod: GET; recursion: disabled; redirects: not followed"
                ),
            }
        except (TypeError, ValueError) as err:
            return {"summary": "content discovery: invalid arguments", "detail": str(err)}

    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> ToolOutput:
        guard_adapter(self, args, prompter)
        scope, words, mode, max_requests, rate, timeout = self._parameters(args)
        backend = self._select_backend(mode, max_requests)
        backend_reason = self._backend_reason(mode, backend, max_requests)
        coverage_incomplete_reason: str | None = None
        scanned_paths = 0

        def make_result(*call_args: Any, **call_kwargs: Any) -> ToolOutput:
            call_kwargs["backend_reason"] = backend_reason
            call_kwargs.setdefault("requested_paths", len(words))
            call_kwargs.setdefault("scanned_paths", scanned_paths)
            status = call_kwargs.get("status")
            phase_statuses = {
                "success": "performed",
                "observation": "performed",
                "error": "failed",
                "cancelled": "cancelled",
            }
            phase_status = phase_statuses.get(status) if isinstance(status, str) else None
            coverage_reason = call_kwargs.get("reason")
            if status in {"success", "observation"} and coverage_incomplete_reason:
                phase_status = "failed"
                coverage_reason = coverage_incomplete_reason
            objective = self.workflow.objective if self.workflow is not None else None
            phase_coverage: dict[str, Any] | None = None
            if (
                phase_status is not None
                and objective is not None
                and self.workflow is not None
                and self.workflow.is_next_phase("enumeration")
            ):
                try:
                    changed = self.workflow.record_phase_coverage(
                        "enumeration",
                        "active_content_discovery",
                        phase_status,  # type: ignore[arg-type]
                        objective_id=objective.id,
                        target_origin=objective.target_origin or "",
                        reason=(str(coverage_reason or "discovery did not complete")
                                if phase_status in {"failed", "cancelled"} else None),
                    )
                    recorded = self.workflow.phase_coverage_record(
                        "enumeration", "active_content_discovery"
                    )
                    if recorded is not None:
                        phase_coverage = {
                            "phase": "enumeration",
                            "dimension": "active_content_discovery",
                            "status": recorded.status,
                            "changed": changed,
                            "source": "content_discovery",
                        }
                except ValueError:
                    pass
            result = self._result(*call_args, **call_kwargs)
            if phase_coverage is None:
                return result
            payload = json.loads(str(result))
            payload["phase_coverage"] = phase_coverage
            return ToolOutput(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                status=result.status, error_kind=result.error_kind,
                http_status=result.http_status, truncated=result.truncated,
            )

        start = time.monotonic()
        deadline = start + timeout
        if is_aborted(signal):
            return make_result(
                scope, backend, 0, 0, start, None, [], [],
                status="cancelled", reason="cancelled before discovery started",
            )
        private_reason = await gate_private_request(
            prompter,
            parse_http_url(scope.origin.as_url() + "/"),
            signal,
            self.name(),
            target=self.target,
            permission_cache_key=self.permission_hints(args).get("cacheKey"),
        )
        observations: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        requests_completed = 0
        baseline_paths = [
            f".kagent-missing-{secrets.token_hex(8)}",
            f".kagent-missing-{secrets.token_hex(8)}",
        ]
        baselines: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=timeout,
            trust_env=False,
            headers={"User-Agent": NATIVE_USER_AGENT},
        ) as client:
            for baseline_path in baseline_paths:
                if baselines and not await sleep_or_abort(1 / rate, signal):
                    return make_result(
                        scope, backend, len(baseline_paths), requests_completed,
                        start, baselines, [], [], status="cancelled",
                        reason="cancelled between wildcard baselines",
                    )
                baseline, outcome = await self._probe(
                    client, self._url_for(scope, baseline_path), signal, deadline
                )
                requests_completed += int(baseline is not None)
                if outcome == "cancelled":
                    return make_result(
                        scope, backend, len(baseline_paths), requests_completed,
                        start, baselines, [], [], status="cancelled",
                        reason="cancelled during wildcard baseline",
                    )
                if outcome == "timeout":
                    return make_result(
                        scope, backend, len(baseline_paths), requests_completed,
                        start, baselines, [], [], status="error",
                        reason="timeout during wildcard baseline", error_kind="timeout",
                    )
                if baseline is None:
                    return make_result(
                        scope, backend, len(baseline_paths), requests_completed,
                        start, baselines, [], [], status="error",
                        reason="wildcard baseline request failed", error_kind="network",
                    )
                baselines.append(baseline)

            scan_budget = max_requests - len(baselines)
            if backend == "ffuf":
                # Keep enough of the total request budget to verify every hit.
                scan_budget //= 2
            scan_words = words[:scan_budget]
            scanned_paths = len(scan_words)
            if scanned_paths < len(words):
                coverage_incomplete_reason = (
                    f"request budget covered {scanned_paths} of {len(words)} requested paths"
                )
            hits: list[str] = []
            if backend == "ffuf":
                if not await sleep_or_abort(1 / rate, signal):
                    return make_result(
                        scope, backend, len(baselines), requests_completed, start, baselines,
                        [], [], status="cancelled",
                        reason="cancelled before ffuf scan",
                    )
                hits, scan_requests, scan_error = await self._run_ffuf(
                    scope, scan_words, rate, deadline, signal
                )
                requests_completed += scan_requests or 0
                request_count_exact = scan_requests is not None
                if is_aborted(signal):
                    return make_result(
                        scope, backend, len(scan_words) + len(baselines) + len(hits), requests_completed,
                        start, baselines, [], [], status="cancelled",
                        reason="cancelled while ffuf was running",
                        request_count_exact=request_count_exact,
                    )
                for word in hits:
                    if requests_completed >= max_requests:
                        rejected.append({"path": word, "reason": "request_budget_exhausted"})
                        continue
                    if not await sleep_or_abort(1 / rate, signal):
                        break
                    url = self._url_for(scope, word)
                    observation, outcome = await self._probe(client, url, signal, deadline)
                    if observation is not None:
                        requests_completed += 1
                    if outcome == "cancelled":
                        break
                    if outcome == "timeout":
                        return make_result(
                            scope, backend, len(scan_words) + len(baselines) + len(hits),
                            requests_completed, start, baselines, observations,
                            rejected, status="error", reason="operation timeout",
                            error_kind="timeout",
                        )
                    if observation is None:
                        if outcome not in {"cancelled", "timeout"}:
                            coverage_incomplete_reason = "one or more verification requests did not complete"
                        rejected.append({"path": word, "reason": outcome or "verification_failed"})
                    elif self._matches_baselines(observation, baselines):
                        rejected.append({"path": word, "reason": "wildcard_or_spa_baseline"})
                    else:
                        observation["path"] = word
                        observation["verified"] = True
                        observations.append(observation)
                if is_aborted(signal):
                    return make_result(
                        scope, backend, len(scan_words) + len(baselines), requests_completed,
                        start, baselines, observations, rejected, status="cancelled",
                        reason="cancelled during hit verification",
                    )
                if scan_error:
                    return make_result(
                        scope, backend, len(scan_words) + len(baselines), requests_completed,
                        start, baselines, observations, rejected, status="error",
                        reason=scan_error,
                        request_count_exact=request_count_exact,
                        error_kind=(
                            "timeout" if scan_error.startswith("timeout")
                            else "tool_exception"
                        ),
                    )
            else:
                for word in scan_words:
                    if requests_completed >= max_requests:
                        break
                    if not await sleep_or_abort(1 / rate, signal):
                        return make_result(
                            scope, backend, len(scan_words) + len(baselines), requests_completed,
                            start, baselines, observations, rejected,
                            status="cancelled", reason="cancelled during native discovery",
                        )
                    observation, outcome = await self._probe(
                        client, self._url_for(scope, word), signal, deadline
                    )
                    if observation is not None:
                        requests_completed += 1
                    if outcome == "cancelled":
                        return make_result(
                            scope, backend, len(scan_words) + len(baselines), requests_completed,
                            start, baselines, observations, rejected,
                            status="cancelled", reason="cancelled during native request",
                        )
                    if outcome == "timeout":
                        return make_result(
                            scope, backend, len(scan_words) + len(baselines), requests_completed,
                            start, baselines, observations, rejected,
                            status="error", reason="operation timeout",
                            error_kind="timeout",
                        )
                    if observation is None:
                        if outcome not in {"cancelled", "timeout"}:
                            coverage_incomplete_reason = "one or more path requests did not complete"
                        rejected.append({"path": word, "reason": outcome or "request_failed"})
                    elif self._matches_baselines(observation, baselines):
                        rejected.append({"path": word, "reason": "wildcard_or_spa_baseline"})
                    else:
                        observation["path"] = word
                        observation["verified"] = True
                        observations.append(observation)

        requested_requests = (
            len(scan_words) + len(baselines) + len(hits)
            if backend == "ffuf"
            else len(scan_words) + len(baselines)
        )
        result_reasons = [
            reason for reason in (coverage_incomplete_reason,
                                  f"private/internal target approved: {private_reason}" if private_reason else None)
            if reason
        ]
        result = make_result(
            scope, backend, requested_requests, requests_completed, start,
            baselines, observations, rejected, status="success",
            reason="; ".join(result_reasons) if result_reasons else None,
        )
        return result

    def _parameters(
        self, args: dict[str, Any]
    ) -> tuple[DiscoveryScope, list[str], str, int, int, int]:
        raw_base = args.get("base_url")
        if raw_base is not None and not isinstance(raw_base, str):
            raise ValueError("base_url must be a string")
        scope = resolve_discovery_scope(self.target, self.engagement, raw_base)
        paths_value = args.get("paths")
        if paths_value is None:
            paths = list(DEFAULT_PATHS)
        else:
            if not isinstance(paths_value, list) or not paths_value:
                raise ValueError("paths must be a non-empty list when provided")
            if len(paths_value) > MAX_PATHS:
                raise ValueError(f"at most {MAX_PATHS} paths may be supplied")
            paths = [validate_relative_path(item) for item in paths_value]
        extensions_value = args.get("extensions", [])
        if not isinstance(extensions_value, list) or len(extensions_value) > MAX_EXTENSIONS:
            raise ValueError(f"extensions must be a list with at most {MAX_EXTENSIONS} items")
        extensions: list[str] = []
        for item in extensions_value:
            if not isinstance(item, str):
                raise ValueError("extensions must contain strings")
            extension = item.strip().lstrip(".")
            if not _SAFE_EXTENSION_RE.fullmatch(extension):
                raise ValueError("extensions must be simple alphanumeric suffixes")
            extensions.append(extension.lower())
        words = list(dict.fromkeys(paths))
        for extension in extensions:
            words.extend(f"{path}.{extension}" for path in paths)
        words = list(dict.fromkeys(words))
        mode = args.get("mode", "auto")
        if not isinstance(mode, str) or mode not in {"auto", "native"}:
            raise ValueError("mode must be auto or native")
        max_requests = self._bounded_int(
            args.get("max_requests"), DEFAULT_MAX_REQUESTS, 3, MAX_REQUESTS,
            "max_requests",
        )
        rate = self._bounded_int(
            args.get("rate_limit"), DEFAULT_RATE_LIMIT, 1, MAX_RATE_LIMIT,
            "rate_limit",
        )
        timeout = self._bounded_int(
            args.get("timeout_seconds"), DEFAULT_TIMEOUT_SECONDS, 5,
            MAX_TIMEOUT_SECONDS, "timeout_seconds",
        )
        return scope, words, str(mode), max_requests, rate, timeout

    def _select_backend(self, mode: str, max_requests: int | None = None) -> str:
        if mode == "native":
            return "native"
        use_ffuf = (
            self.tooling_profile() == "full"
            and self.capabilities.snapshot().ffuf is not None
            and self.workflow is not None
            and self.workflow.needs_phase_coverage(
                "enumeration", "active_content_discovery"
            )
        )
        # Two independent baselines, at least one scan word, and one verification.
        if max_requests is not None and max_requests < 4:
            use_ffuf = False
        return "ffuf" if use_ffuf else "native"

    def _backend_reason(self, mode: str, backend: str, max_requests: int) -> str:
        if mode != "auto":
            return f"{backend} backend explicitly selected"
        if backend == "ffuf":
            return (
                "full profile selected installed ffuf for a runtime-confirmed "
                "enumeration coverage gap"
            )
        if self.tooling_profile() != "full":
            return "minimal profile defaults to native HTTP discovery"
        if self.capabilities.snapshot().ffuf is None:
            return "ffuf unavailable; fell back to native HTTP discovery"
        if self.workflow is None or not self.workflow.needs_phase_coverage(
            "enumeration", "active_content_discovery"
        ):
            return "no runtime-confirmed enumeration coverage gap; using native HTTP discovery"
        if max_requests < 4:
            return "native selected because the request cap leaves no safe ffuf verification budget"
        return "native selected by the runtime's bounded backend policy"

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

    @staticmethod
    def _url_for(scope: DiscoveryScope, path: str) -> str:
        return scope.base_url.rstrip("/") + "/" + path.lstrip("/")

    async def _probe(
        self,
        client: httpx.AsyncClient,
        url: str,
        signal: Any,
        deadline: float,
    ) -> tuple[dict[str, Any] | None, str | None]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, "timeout"
        if is_aborted(signal):
            return None, "cancelled"
        task = asyncio.create_task(self._read_probe(client, url, remaining))
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return None, "timeout"
                done, _ = await asyncio.wait(
                    {task}, timeout=min(0.05, remaining)
                )
                if task in done:
                    return task.result(), None
                if is_aborted(signal):
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return None, "cancelled"
        except httpx.TimeoutException:
            return None, "timeout"
        except (httpx.HTTPError, OSError, asyncio.TimeoutError):
            return None, "network_error"
        except asyncio.CancelledError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise

    async def _read_probe(
        self, client: httpx.AsyncClient, url: str, timeout: float
    ) -> dict[str, Any]:
        chunks: list[bytes] = []
        observed = 0
        body_truncated = False
        async with governed_stream(client, url, timeout, response_cap=MAX_RESPONSE_BYTES) as response:
            cap = min(MAX_RESPONSE_BYTES, getattr(response, 'extensions', {}).get("policy_response_cap", MAX_RESPONSE_BYTES))
            async for chunk in response.aiter_bytes():
                room = cap + 1 - observed
                if len(chunk) >= room:
                    chunks.append(chunk[:room])
                    observed += room
                    body_truncated = True
                    break
                chunks.append(chunk)
                observed += len(chunk)
            body = b"".join(chunks)[:cap]
            content_length = self._content_length(response.headers.get("content-length"))
            location = self._safe_location(url, response.headers.get("location"))
            content_type = self._safe_header(response.headers.get("content-type"), 160)
            fingerprint = hashlib.sha256(
                self._normalize_fingerprint_body(body, url).encode("utf-8")
            ).hexdigest()[:24]
            return {
                "status": response.status_code,
                "content_type": content_type,
                "length": content_length if content_length is not None else observed,
                "fingerprint": fingerprint,
                "body_truncated": body_truncated,
                "redirect": location,
                "_signature": (
                    response.status_code,
                    content_type,
                    fingerprint,
                    location,
                ),
            }

    @staticmethod
    def _content_length(value: str | None) -> int | None:
        if value is None:
            return None
        try:
            parsed = int(value)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None

    @staticmethod
    def _safe_header(value: str | None, limit: int) -> str | None:
        if value is None:
            return None
        return "".join(char for char in value if char.isprintable())[:limit]

    @staticmethod
    def _safe_location(request_url: str, value: str | None) -> str | None:
        if not value:
            return None
        resolved = urljoin(request_url, value)
        try:
            same_origin = HTTPOrigin.from_url(resolved) == HTTPOrigin.from_url(request_url)
        except ValueError:
            same_origin = False
        if not same_origin:
            return "[external redirect not followed]"
        destination = urlsplit(resolved)
        suffix = "?[query omitted]" if destination.query else ""
        return (destination.path or "/")[:300] + suffix

    @staticmethod
    def _normalize_fingerprint_body(body: bytes, request_url: str) -> str:
        text = body.decode("utf-8", errors="replace")
        path = urlsplit(request_url).path
        candidates = sorted(
            {
                path,
                unquote(path),
                quote(path, safe="/"),
                quote(unquote(path), safe="/"),
            },
            key=len,
            reverse=True,
        )
        for candidate in candidates:
            if candidate:
                text = text.replace(candidate, "<request-path>")
        text = re.sub(
            r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b|\b[0-9a-f]{16,}\b|\b\d{10,13}\b",
            "<dynamic>",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b",
            "<timestamp>",
            text,
        )
        return text

    @staticmethod
    def _matches_baselines(
        item: dict[str, Any], baselines: list[dict[str, Any]]
    ) -> bool:
        return any(
            item.get("_signature") == baseline.get("_signature")
            for baseline in baselines
        )

    async def _run_ffuf(
        self,
        scope: DiscoveryScope,
        words: list[str],
        rate: int,
        deadline: float,
        signal: Any,
    ) -> tuple[list[str], int | None, str | None]:
        binary = self.capabilities.snapshot().ffuf
        if binary is None:
            return [], 0, "ffuf is no longer available"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return [], 0, "operation timeout before ffuf started"
        from src.permission.runtime.execution import current_policy
        policy = current_policy()
        worker = policy.worker if policy is not None else None
        with tempfile.TemporaryDirectory(prefix="kagent-content-", dir=worker.output_root if worker else None) as directory:
            root = Path(directory)
            wordlist = root / "paths.txt"
            result_file = root / "results.json"
            wordlist.write_text("\n".join(words) + "\n", encoding="utf-8")
            argv = [
                "-w", str(wordlist),
                "-u", scope.base_url.rstrip("/") + "/FUZZ",
                "-rate", str(rate),
                "-t", "1",
                "-timeout", str(min(10, max(1, int(remaining)))),
                "-maxtime", str(max(1, int(remaining))),
                "-of", "json",
                "-o", str(result_file),
                "-mc", "all",
                "-s",
                "-noninteractive",
            ]
            try:
                if worker is not None:
                    assert policy is not None
                    from src.permission.worker.broker import broker_directory
                    argv[1] = '/work/' + wordlist.relative_to(policy.root).as_posix()
                    argv[argv.index('-o') + 1] = '/work/' + result_file.relative_to(policy.root).as_posix()
                    argv += ['-x', 'http://127.0.0.1:18080']
                    async with broker_directory(signal) as broker:
                        executable, wrapped = await worker.prepare(binary, argv, broker=broker, scanner=True, signal=signal)
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            return [], 0, "operation timeout before ffuf started"
                        output = await run_with_capture(executable, wrapped, remaining, signal)
                else:
                    output = await run_with_capture(binary, argv, remaining, signal)
            except OSError:
                self.capabilities.mark_unavailable("ffuf", binary)
                return [], 0, "ffuf could not be started (missing or not executable)"
            if output.status == "cancelled" or is_aborted(signal):
                return [], None, "cancelled"
            if output.status != "success":
                if output.error_kind == "timeout":
                    return [], None, "timeout during ffuf scan; partial results are not trusted"
                diagnostic = self._safe_diagnostic(str(output))
                reason = "ffuf failed; partial results are not trusted"
                if diagnostic:
                    reason += f": {diagnostic}"
                return [], None, reason
            scan_requests = len(words)
            error: str | None = None
            try:
                if not result_file.exists():
                    raise ValueError("ffuf did not produce JSON output")
                if result_file.stat().st_size > MAX_FFUF_JSON_BYTES:
                    raise ValueError("ffuf JSON output exceeded the size limit")
                document = json.loads(result_file.read_text(encoding="utf-8"))
                raw_results = document.get("results") if isinstance(document, dict) else None
                if not isinstance(raw_results, list):
                    raise ValueError("ffuf JSON has no results list")
                allowed = set(words)
                hits: list[str] = []
                for result in raw_results:
                    if not isinstance(result, dict):
                        continue
                    inputs = result.get("input")
                    word = inputs.get("FUZZ") if isinstance(inputs, dict) else None
                    if isinstance(word, bytes):
                        word = word.decode("utf-8", errors="replace")
                    if isinstance(word, str):
                        normalized = validate_relative_path(word)
                        if normalized in allowed and normalized not in hits:
                            hits.append(normalized)
                return hits, scan_requests, error
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
                return [], scan_requests, error or "malformed or missing ffuf JSON output"

    @staticmethod
    def _safe_diagnostic(value: str) -> str:
        # Scanner output contains no user-supplied headers, but keep diagnostics
        # short and strip terminal/control characters before exposing them.
        printable = " ".join(
            "".join(char for char in line if char.isprintable()).strip()
            for line in value.splitlines()
        )
        return redact(printable)[:240]

    @staticmethod
    def _result(
        scope: DiscoveryScope,
        backend: str,
        requested: int,
        completed: int,
        started: float,
        baseline: dict[str, Any] | list[dict[str, Any]] | None,
        discovered: list[dict[str, Any]],
        rejected: list[dict[str, Any]],
        *,
        status: str,
        reason: str | None,
        backend_reason: str | None = None,
        requested_paths: int = 0,
        scanned_paths: int = 0,
        request_count_exact: bool = True,
        error_kind: ErrorKind | None = None,
    ) -> ToolOutput:
        def public_observation(item: dict[str, Any]) -> dict[str, Any]:
            return {key: value for key, value in item.items() if not key.startswith("_")}

        truncated = len(discovered) > MAX_RESULT_ITEMS or len(rejected) > MAX_RESULT_ITEMS
        if isinstance(baseline, list):
            public_baseline: Any = [public_observation(item) for item in baseline]
        else:
            public_baseline = public_observation(baseline) if baseline else None
        payload = {
            "status": status,
            "origin": scope.origin.as_url(),
            "base_path": scope.base_path or "/",
            "backend": backend,
            "backend_reason": backend_reason,
            "requested_requests": requested,
            "completed_requests": completed,
            "completed_request_count_exact": request_count_exact,
            "requested_paths": requested_paths,
            "scanned_paths": scanned_paths,
            "duration_seconds": round(time.monotonic() - started, 3),
            "wildcard_baseline": public_baseline,
            "discovered": [public_observation(item) for item in discovered[:MAX_RESULT_ITEMS]],
            "rejected": rejected[:MAX_RESULT_ITEMS],
            "reason": reason,
            "truncated": truncated,
        }
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if status == "cancelled":
            return ToolOutput(text, status="cancelled", error_kind="cancelled", truncated=truncated)
        if status == "error":
            return ToolOutput(
                text,
                status="error",
                error_kind=error_kind if error_kind in {"timeout", "network", "tool_exception"} else "tool_exception",
                truncated=truncated,
            )
        return ToolOutput(text, status="observation", truncated=truncated)
