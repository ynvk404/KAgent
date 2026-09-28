from __future__ import annotations

import httpx

from src.engagement.state import EngagementState
from src.permission.permission import Prompter
from src.target.target import Target
from src.target.origin import HTTPOrigin
from .private_host import (
    gate_private_request,
    parse_http_url,
)
from .types import (
    Tool,
    PermissionHints,
    arg_string,
)
from .outcome import ToolOutput

RESPONSE_BYTE_CAP = 16 * 1024
MAX_RESPONSE_BYTE_CAP = 64 * 1024
REQUEST_TIMEOUT = 60

class HTTPTool(Tool):
    def __init__(
        self,
        target: Target,
        engagement: EngagementState,
    ):
        self.target = target
        self.engagement = engagement

    def name(self) -> str:
        return "http"

    def description(self) -> str:
        return (
            "Send a single HTTP/HTTPS request in the declared phase: "
            "recon, validation, or impact. Recon and benign validation "
            "inside the active engagement scope are eligible for YOLO; "
            "impact requests require prior explicit ask_user authorization "
            "and always receive a fresh per-request permission prompt. "
            "The url can be absolute (https://app/api/x) "
            "or a path (/api/x); paths resolve against the active "
            "/target base URL. Useful for poking endpoints, "
            "testing IDOR, header injection, auth bypass. "
            "Choose validation for bounded differentials and harmless proof, "
            "including POST probes; choose impact before controlled effect "
            "or data-access checks. "
            "TLS verification is disabled. "
            "Does not follow redirects (you'll see 30x responses). "
            "Authorized targets only."
        )

    def schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "description": (
                        "HTTP method "
                        "(GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD). "
                        "Defaults to GET."
                    ),
                },
                "phase": {
                    "type": "string",
                    "enum": ["recon", "validation", "impact"],
                    "description": (
                        "Required action intent. Use recon for observation, "
                        "validation for bounded benign proof (including POST), "
                        "and impact only after explicit ask_user authorization for "
                        "controlled exploitation or impact checks. "
                        "YOLO only auto-approves recon and validation."
                    ),
                },
                "url": {
                    "type": "string",
                    "description": "Full URL including scheme.",
                },
                "headers": {
                    "type": "object",
                    "description": (
                        "Request headers as a flat object {name: value}."
                    ),
                    "additionalProperties": {
                        "type": "string",
                    },
                },
                "body": {
                    "type": "string",
                    "description": "Raw request body (optional).",
                },
                "max_response_bytes": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_RESPONSE_BYTE_CAP,
                    "description": (
                        f"Maximum response-body bytes returned (default {RESPONSE_BYTE_CAP}; "
                        "use 0 for status and headers only)."
                    ),
                },
            },
            "required": [
                "url",
                "phase",
            ],
        }

    def requires_permission(self) -> bool:
        return True

    def validate_args(self, args: dict) -> None:
        phase = args.get("phase")
        if phase not in {"recon", "validation", "impact"}:
            raise ValueError("phase must be recon, validation, or impact")
        raw_url = arg_string(args, "url")
        if not raw_url:
            raise ValueError("url is required")
        response_cap = args.get("max_response_bytes", RESPONSE_BYTE_CAP)
        if (
            isinstance(response_cap, bool)
            or not isinstance(response_cap, int)
            or not 0 <= response_cap <= MAX_RESPONSE_BYTE_CAP
        ):
            raise ValueError(
                f"max_response_bytes must be an integer from 0 to {MAX_RESPONSE_BYTE_CAP}"
            )
        resolved = self.resolve_url(raw_url)
        parse_http_url(resolved)
        self._require_scope(resolved)

    def permission_hints(
        self,
        args: dict,
    ) -> PermissionHints:
        phase = args.get("phase")
        try:
            resolved = self.resolve_url(arg_string(args, "url"))
            origin = HTTPOrigin.from_url(resolved)

            hints: PermissionHints = {
                "cacheKey": origin.as_url(),
                "sessionScopeDisplay": f"HTTP requests to {origin.as_url()}",
            }

        except Exception:

            hints = {
                "cacheKey": arg_string(
                    args,
                    "url",
                ),
                "sessionScopeDisplay": "this exact HTTP request origin",
            }

        if phase == "recon":
            hints["riskTier"] = "routine"
            hints["yoloAutoApprove"] = True
        elif phase == "validation":
            hints["riskTier"] = "bounded-impact"
            hints["yoloAutoApprove"] = True
        elif phase == "impact":
            hints["noSessionCache"] = True
            hints["riskTier"] = "high-impact"
        return hints

    def summarize(
        self,
        args: dict,
    ) -> dict:
        method = (
            arg_string(args, "method")
            or "GET"
        ).upper()

        url = arg_string(
            args,
            "url",
        )

        body = arg_string(
            args,
            "body",
        )

        headers = args.get(
            "headers",
            {},
        )

        phase = arg_string(args, "phase")
        detail = f"phase: {phase or 'unspecified'}\n{method} {url}"

        if isinstance(headers, dict) and headers:
            detail += "\nheaders:"
            for k, v in headers.items():
                detail += f"\n  {k}: {v}"

        if body:

            preview = (
                body[:400] + "..."
                if len(body) > 400
                else body
            )

            detail += (
                "\nbody:\n"
                + preview
            )

        return {
            "summary": f"http: {method} {url}",
            "detail": detail,
        }

    async def run(
        self,
        args: dict,
        signal,
        prompter: Prompter,
    ) -> ToolOutput:

        method = (
            arg_string(args, "method")
            or "GET"
        ).upper()

        raw_url = arg_string(
            args,
            "url",
        )

        body = arg_string(
            args,
            "body",
        )
        response_cap = args.get("max_response_bytes", RESPONSE_BYTE_CAP)

        if not raw_url:
            raise Exception("url is required")

        resolved = self.resolve_url(raw_url)
        self._require_scope(resolved)

        private_reason = await gate_private_request(
            prompter,
            parse_http_url(resolved),
            signal,
            "http",
            target=self.target,
            permission_cache_key=HTTPOrigin.from_url(resolved).as_url(),
        )

        headers: dict[str, str] = {}

        hdrs = args.get("headers")

        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                if isinstance(v, str):
                    headers[k] = v

        if not any(
            k.lower() == "user-agent"
            for k in headers
        ):
            headers["user-agent"] = (
                "kagent/0.1"
            )

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=REQUEST_TIMEOUT,
        ) as client:

            async with client.stream(
                method=method,
                url=resolved,
                headers=headers,
                content=body if body else None,
            ) as response:

                chunks = []
                total = 0
                truncated = False

                async for chunk in response.aiter_bytes():
                    remaining = response_cap + 1 - total
                    if len(chunk) >= remaining:
                        chunks.append(chunk[:remaining])
                        total += remaining
                        truncated = total > response_cap
                        break
                    chunks.append(chunk)
                    total += len(chunk)

                content = b"".join(chunks)[:response_cap]

                output = (
                    f"HTTP/1.1 "
                    f"{response.status_code} "
                    f"{response.reason_phrase}\n"
                )

                for k, v in response.headers.items():
                    output += (
                        f"{k}: {v}\n"
                    )

                output += "\n"
                output += content.decode(
                    errors="replace"
                )
                if truncated:
                    output += f"\n[response body truncated at {response_cap} bytes]"

        if private_reason:
            output = (
                "note: private/internal host approved "
                f"for this request (reason: {private_reason})\n\n"
                + output
            )

        return ToolOutput(
            output, status="observation", http_status=response.status_code,
            truncated=truncated,
        )

    def _require_scope(self, url: str) -> None:
        self.engagement.require_in_scope(url)

    def resolve_url(
        self,
        raw: str,
    ) -> str:

        if raw.lower().startswith(
            (
                "http://",
                "https://",
            )
        ):
            return raw

        if self.target.empty():
            raise Exception(
                f'url "{raw}" is a path with no active target; '
                "set one with /target https://host "
                "or pass a full URL"
            )

        base = (
            self.target
            .base_url()
            .rstrip("/")
        )

        path = (
            raw
            if raw.startswith("/")
            else "/" + raw
        )

        return base + path
