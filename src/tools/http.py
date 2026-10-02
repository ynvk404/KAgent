from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any
import asyncio
import httpx
from src.engagement.state import EngagementState
from src.permission.permission import Prompter, UserControlledRefusal, YoloPrompter
from src.permission.http_grants import EffectiveHTTP, check_cancelled
from src.permission.execution import policy_for
from src.permission.network import pin_request
from src.target.target import Target
from .private_host import gate_private_request, parse_http_url
from .types import Tool, PermissionHints, arg_string
from .outcome import ToolOutput

RESPONSE_BYTE_CAP = 16 * 1024
MAX_RESPONSE_BYTE_CAP = 64 * 1024
REQUEST_TIMEOUT = 60


class HTTPTool(Tool):
    def __init__(self, target: Target, engagement: EngagementState):
        self.target = target
        self.engagement = engagement
        self.permissions = engagement.http_permissions
        self.permissions.bind_target(lambda: target.revision)

    def name(self) -> str:
        return 'http'

    def description(self) -> str:
        return (
            'Send one HTTP/HTTPS request within engagement scope. Phase is an annotation, '
            'never authorization. Operator autonomous lab grants cover new endpoints, '
            'parameters and payloads, including SQLi/XSS, login and mutations, within '
            'their exact origin and limits. Without a grant, an exact request requires '
            'operator approval. Operator YOLO activation grants bounded scoped autonomy '
            'without manual grant commands. Scope alone is not authority. Confirm-each '
            'prompts in ordinary mode and resumes after YOLO is turned off. Blocked/pending authorization must wait for operator action; '
            'do not retry it with different phase/wording/payload. Relative paths resolve '
            'against /target. TLS verification is disabled; redirects are not followed. '
            'Raw HTTP cannot establish safe server-side effects or test-only resources.'
        )

    def schema(self) -> dict:
        return {
            'type': 'object',
            'properties': {
                'method': {'type': 'string', 'description': 'HTTP method, defaults to GET; does not determine permission.'},
                'phase': {'type': 'string', 'enum': ['recon', 'validation', 'impact'],
                          'description': 'Workflow annotation only; cannot open or downgrade permissions.'},
                'url': {'type': 'string', 'description': 'Absolute HTTP/S URL or target-relative path.'},
                'headers': {'type': 'object', 'additionalProperties': {'type': 'string'}},
                'body': {'type': 'string', 'description': 'Raw request body; payloads are preserved.'},
                'max_response_bytes': {'type': 'integer', 'minimum': 0, 'maximum': MAX_RESPONSE_BYTE_CAP,
                                       'description': f'Decoded body retained, default {RESPONSE_BYTE_CAP}; 0 for headers/status.'},
            },
            'required': ['url', 'phase'],
        }

    def requires_permission(self) -> bool:
        return True

    def validate_args(self, args: dict) -> None:
        if args.get('phase') not in {'recon', 'validation', 'impact'}:
            raise ValueError('phase must be recon, validation, or impact')
        if not arg_string(args, 'url'):
            raise ValueError('url is required')
        cap = args.get('max_response_bytes', RESPONSE_BYTE_CAP)
        if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= MAX_RESPONSE_BYTE_CAP:
            raise ValueError(f'max_response_bytes must be an integer from 0 to {MAX_RESPONSE_BYTE_CAP}')
        resolved = self.resolve_url(arg_string(args, 'url'))
        parse_http_url(resolved)
        self._require_scope(resolved)

    def permission_hints(self, args: dict) -> PermissionHints:
        return {'noSessionCache': True, 'riskTier': 'high-impact', 'yoloAutoApprove': False}

    def prepare(self, args: dict) -> tuple[EffectiveHTTP, httpx.Request]:
        self.permissions.sync_target()
        raw_url = arg_string(args, 'url')
        if not raw_url:
            raise ValueError('url is required')
        cap = args.get('max_response_bytes', RESPONSE_BYTE_CAP)
        if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= MAX_RESPONSE_BYTE_CAP:
            raise ValueError('invalid response byte cap')
        resolved = self.resolve_url(raw_url)
        self._require_scope(resolved)
        headers = {k: v for k, v in args.get('headers', {}).items() if isinstance(v, str)} if isinstance(args.get('headers'), dict) else {}
        if not any(k.lower() == 'user-agent' for k in headers):
            headers['user-agent'] = 'kagent/0.1'
        # Prepare the actual HTTPX Request once, including Host/Content-Length.
        # send(request) does not merge client defaults/cookies after approval.
        request = httpx.Request((arg_string(args, 'method') or 'GET').upper(), resolved,
                                headers=headers, content=arg_string(args, 'body').encode('utf-8'))
        if request.url.username or request.url.password:
            # HTTPX otherwise derives BasicAuth during send(), after approval.
            # Materialize it now and remove credentials from the displayed URL.
            request = next(httpx.BasicAuth(request.url.username, request.url.password).auth_flow(request))
            request.url = request.url.copy_with(username=None, password=None)
        action = EffectiveHTTP(request.method, str(request.url), tuple(request.headers.raw), request.content,
                               cap, self.target.revision, self.engagement.revision, self.permissions.epoch)
        self._require_scope(action.url)
        return action, request

    def summarize(self, args: dict) -> dict:
        action, _ = self.prepare(args)
        return {'summary': f'http: {action.method} {action.url}',
                'detail': f"phase (annotation): {arg_string(args, 'phase')}\n" + action.preview()}

    async def run_authorized(self, args: dict[str, Any], signal: Any, prompter: Prompter) -> ToolOutput:
        return await self.run(args, signal, prompter)

    async def run(self, args: dict, signal: Any, prompter: Prompter) -> ToolOutput:
        if isinstance(prompter, YoloPrompter):
            prompter.bind_http_permissions(self.permissions)
        args = deepcopy(args)
        action, request = self.prepare(args)
        policy = policy_for(prompter)
        if policy is not None:
            if not policy.nested_allowed():
                raise UserControlledRefusal('blocked: http-executor-without-receipt')
            request, address = await pin_request(policy, request)
            action = replace(action, transport_address=address)
        receipt = await self.permissions.authorize(action, prompter, signal, lambda: self.target.revision)
        # Independent gate: generic Registry approval cannot coalesce this gate.
        try:
            private_reason = await gate_private_request(
                prompter, parse_http_url(action.url), signal, 'http', target=self.target,
            )
        except (UserControlledRefusal, asyncio.CancelledError):
            self.permissions.pause_private(action.origin)
            raise
        check_cancelled(signal)
        transport_options: dict[str, Any] = {'trust_env': False} if policy is not None else {}
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=REQUEST_TIMEOUT, **transport_options) as client:
            reservation = await self.permissions.reserve_when_ready(action, receipt, signal, lambda: self.target.revision)
            response = None
            try:
                if policy is not None and not policy.nested_allowed():
                    from src.permission.execution import ExecutionBlocked
                    raise ExecutionBlocked("blocked: policy-changed-before-http-send")
                reservation.start()
                # No suspension between reservation and starting send.
                response = await client.send(request, stream=True)
                check_cancelled(signal)
                chunks: list[bytes] = []
                total = 0
                truncated = False
                async for chunk in response.aiter_bytes():
                    check_cancelled(signal)
                    remaining = action.response_cap + 1 - total
                    if len(chunk) >= remaining:
                        chunks.append(chunk[:remaining])
                        total += remaining
                        truncated = total > action.response_cap
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                content = b''.join(chunks)[:action.response_cap]
                output = f'HTTP/1.1 {response.status_code} {response.reason_phrase}\n'
                for k, v in response.headers.items():
                    output += f'{k}: {v}\n'
                output += '\n' + content.decode(errors='replace')
                if truncated:
                    output += f'\n[response body truncated at {action.response_cap} bytes]'
                if private_reason:
                    output = f'note: private/internal host independently approved (reason: {private_reason})\n\n' + output
                if policy is not None:
                    observation = policy.observations.capture(action, response.status_code, content, complete=not truncated)
                    output += f'\n[runtime observation: {observation}]'
                return ToolOutput(output, status='observation', http_status=response.status_code, truncated=truncated)
            finally:
                try:
                    if response is not None:
                        await response.aclose()
                finally:
                    reservation.release()

    def _require_scope(self, url: str) -> None:
        self.engagement.require_in_scope(url)

    def resolve_url(self, raw: str) -> str:
        if raw.lower().startswith(('http://', 'https://')):
            return raw
        if self.target.empty():
            raise ValueError(f'url "{raw}" is a path with no active target; set /target or pass a full URL')
        return self.target.base_url().rstrip('/') + (raw if raw.startswith('/') else '/' + raw)
