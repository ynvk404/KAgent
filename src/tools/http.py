"""
HTTP Tool

Port từ:
Chức năng:
- Gửi HTTP/HTTPS request
- Hỗ trợ GET, POST, PUT, DELETE...
- Không follow redirect
- Disable TLS verify (pentest convention)
- Kiểm tra SSRF qua privateHost
- Trả HTTP response về cho LLM
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from src.permission.permission import Prompter
from src.target.target import Target
from .private_host import (
    gate_private_request,
    parse_http_url,
)
from .types import (
    Tool,
    arg_string,
)

RESPONSE_BYTE_CAP = 64 * 1024 
#64 x 128 x 256
REQUEST_TIMEOUT = 60


class HTTPTool(Tool):

    def __init__(
        self,
        target: Target,
    ):
        self.target = target

    # --------------------------------------------------
    # Tool name
    # --------------------------------------------------

    def name(self) -> str:
        return "http"

    # --------------------------------------------------
    # Description
    # --------------------------------------------------

    def description(self) -> str:
        return (
            "Send a single HTTP/HTTPS request. "
            "The url can be absolute (https://app/api/x) "
            "or a path (/api/x); paths resolve against the active "
            "/target base URL. Useful for poking endpoints, "
            "testing IDOR, header injection, auth bypass. "
            "TLS verification is disabled. "
            "Does not follow redirects (you'll see 30x responses). "
            "Authorized targets only."
        )

    # --------------------------------------------------
    # JSON Schema
    # --------------------------------------------------

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
            },
            "required": [
                "url",
            ],
        }

    # --------------------------------------------------
    # Permission
    # --------------------------------------------------

    def requires_permission(self) -> bool:
        return True

    # --------------------------------------------------
    # Permission cache key
    # --------------------------------------------------

    def permission_hints(
        self,
        args: dict,
    ) -> dict:

        try:
            parsed = urlparse(
                self.resolve_url(
                    arg_string(args, "url")
                )
            )

            return {
                "cacheKey": (
                    f"{parsed.scheme}://{parsed.netloc}"
                )
            }

        except Exception:

            return {
                "cacheKey": arg_string(
                    args,
                    "url",
                )
            }

    # --------------------------------------------------
    # Permission summary
    # --------------------------------------------------

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

        detail = f"{method} {url}"

        if headers:
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

    # --------------------------------------------------
    # Execute
    # --------------------------------------------------

    async def run(
        self,
        args: dict,
        signal,
        p: Prompter,
    ) -> str:

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

        if not raw_url:
            raise Exception("url is required")

        resolved = self.resolve_url(raw_url)

        private_reason = await gate_private_request(
            p,
            parse_http_url(resolved),
            signal,
            "http",
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

                async for chunk in response.aiter_bytes():

                    remaining = (
                        RESPONSE_BYTE_CAP
                        - total
                    )

                    if remaining <= 0:
                        break

                    if len(chunk) > remaining:
                        chunks.append(
                            chunk[:remaining]
                        )
                        total += remaining
                        break

                    chunks.append(chunk)
                    total += len(chunk)

                content = b"".join(chunks)

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

        if private_reason:
            output = (
                "note: private/internal host approved "
                f"for this request (reason: {private_reason})\n\n"
                + output
            )

        return output

    # --------------------------------------------------
    # Resolve URL
    # --------------------------------------------------

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