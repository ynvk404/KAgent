from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any
import asyncio
import ipaddress
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
import httpx
from src.engagement.state import EngagementState
from src.permission.permission import Prompter, UserControlledRefusal, YoloPrompter
from src.permission.network.grants import EffectiveHTTP, HTTPPending, check_cancelled
from src.permission.runtime.execution import policy_for
from src.permission.runtime.invocations import permission_invocation
from src.permission.network.transport import pin_request
from src.target.target import Target
from src.target.origin import HTTPOrigin
from src.workflow.state import WorkflowPhase, WorkflowState, normalize_target_origin
from src.tools.http.private_host import gate_private_request, parse_http_url, PrivateHostDeclined
from src.tools.common.types import Tool, PermissionHints, arg_string
from src.tools.common.outcome import ToolOutput
from src.tools.http.context import HTTPContextStore
from src.tools.http.request_builder import NATIVE_USER_AGENT, RequestDiff, build_captured_request, origin_headers, validate_host
from src.browser.store import CaptureStore
from src.redact.redact import apply_evidence as redact_evidence

RESPONSE_BYTE_CAP = 16 * 1024
MAX_RESPONSE_BYTE_CAP = 64 * 1024
REQUEST_TIMEOUT = 60


class _NavigationParser(HTMLParser):
    """Inspect only the bounded captured HTML, without retaining field values."""

    def __init__(self):
        super().__init__()
        self.found = False

    def handle_starttag(self, tag, attrs):
        relevant = {'a': 'href', 'script': 'src', 'form': 'action'}
        if tag in relevant and any(key == relevant[tag] and value for key, value in attrs):
            self.found = True


class HTTPTool(Tool):
    def __init__(self, target: Target, engagement: EngagementState,
                 workflow: WorkflowState | None = None,
                 capture_store: CaptureStore | None = None,
                 context_store: HTTPContextStore | None = None,
                 validation_registry=None):
        self.evidence_store: Any = None
        self.target = target
        self.workflow = workflow
        self.engagement = engagement
        self.capture_store = capture_store
        self.context_store = context_store or HTTPContextStore()
        self.validation_registry = validation_registry
        self.permissions = engagement.http_permissions
        self.permissions.bind_target(lambda: target.revision)
        self.context_store.sync_target(target.revision, engagement.revision, self.permissions.epoch)

    def name(self) -> str:
        return 'http'

    def description(self) -> str:
        return (
            'Send scoped HTTP/S. Phase labels workflow, never permission. Exact requests '
            'need approval unless an exact-origin lab grant or bounded YOLO policy applies. '
            'Blocked requests must await operator action; do not reword or retry to bypass. '
            'Relative paths use /target. TLS verification is disabled. Redirects require '
            'max_redirects and separate approval per hop; cross-origin redirects stop. '
            'Use candidate_id with mutation_value to replay one captured input.'
        )

    def schema(self) -> dict:
        return {
            'type': 'object',
            'properties': {
                'method': {'type': 'string'},
                'phase': {'type': 'string', 'enum': ['recon', 'validation', 'impact'],
                          'description': 'Workflow annotation; never permission.'},
                'url': {'type': 'string'},
                'headers': {'type': 'object', 'additionalProperties': {'type': 'string'}},
                'body': {'type': 'string'},
                'candidate_id': {'type': 'string', 'description': 'Captured baseline candidate; omit url/method/body.'},
                'mutation_value': {'type': 'string', 'description': 'Replacement input value.'},
                'input_path': {'type': 'string'},
                'old_value': {'type': 'string'},
                'occurrence': {'type': 'integer', 'minimum': 0},
                'auth_context_ref': {'type': 'string'},
                'profile': {'type': 'string', 'enum': ['native', 'browser-like']},
                'browser_context': {'type': 'string', 'enum': ['navigation', 'fetch']},
                'browser_user_agent': {'type': 'string'},
                'max_redirects': {'type': 'integer', 'minimum': 0, 'maximum': 5},
                'max_response_bytes': {'type': 'integer', 'minimum': 0, 'maximum': MAX_RESPONSE_BYTE_CAP,
                                       'description': f'Decoded byte cap; default {RESPONSE_BYTE_CAP}.'},
            },
            'required': ['phase'],
        }

    def requires_permission(self) -> bool:
        return True

    def validate_args(self, args: dict) -> None:
        if args.get('phase') not in {'recon', 'validation', 'impact'}:
            raise ValueError('phase must be recon, validation, or impact')
        if not arg_string(args, 'url') and not arg_string(args, 'candidate_id'):
            raise ValueError('url or candidate_id is required')
        cap = args.get('max_response_bytes', RESPONSE_BYTE_CAP)
        if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= MAX_RESPONSE_BYTE_CAP:
            raise ValueError(f'max_response_bytes must be an integer from 0 to {MAX_RESPONSE_BYTE_CAP}')
        if arg_string(args, 'candidate_id'):
            self._resolve_baseline(args)
        else:
            resolved = self.resolve_url(arg_string(args, 'url'))
            parse_http_url(resolved)
            self._require_scope(resolved)
        if isinstance(args.get('max_redirects', 0), bool) or not isinstance(args.get('max_redirects', 0), int) or not 0 <= args.get('max_redirects', 0) <= 5:
            raise ValueError('max_redirects must be from 0 through 5')

    def permission_hints(self, args: dict) -> PermissionHints:
        return {'noSessionCache': True, 'riskTier': 'high-impact', 'yoloAutoApprove': False}

    def prepare(self, args: dict) -> tuple[EffectiveHTTP, httpx.Request]:
        action, request, _ = self._prepare_with_diff(args)
        return action, request

    def _prepare_with_diff(self, args: dict) -> tuple[EffectiveHTTP, httpx.Request, RequestDiff | None]:
        self.permissions.sync_target()
        self.context_store.sync_target(self.target.revision, self.engagement.revision, self.permissions.epoch)
        if arg_string(args, 'candidate_id'):
            request, diff = self._resolve_baseline(args)
            assert self.workflow is not None
            candidate = self.workflow.candidates[arg_string(args, 'candidate_id')]
            self.context_store.add_identity(request, candidate.auth_context_ref)
            cap = args.get('max_response_bytes', RESPONSE_BYTE_CAP)
            if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= MAX_RESPONSE_BYTE_CAP:
                raise ValueError('invalid response byte cap')
            action = EffectiveHTTP(request.method, str(request.url), tuple(request.headers.raw), request.content,
                                   cap, self.target.revision, self.engagement.revision, self.permissions.epoch,
                                   redirect_limit=args.get('max_redirects', 0))
            return action, request, diff
        raw_url = arg_string(args, 'url')
        if not raw_url:
            raise ValueError('url is required')
        cap = args.get('max_response_bytes', RESPONSE_BYTE_CAP)
        if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= MAX_RESPONSE_BYTE_CAP:
            raise ValueError('invalid response byte cap')
        resolved = self.resolve_url(raw_url)
        self._require_scope(resolved)
        profile = args.get('profile', 'native')
        if profile not in {'native', 'browser-like'}:
            raise ValueError('profile must be native or browser-like')
        if profile == 'browser-like' and (args.get('browser_context') not in {'navigation', 'fetch'}
                                          or not arg_string(args, 'browser_user_agent')):
            raise ValueError('browser-like profile needs context and captured browser_user_agent')
        if profile == 'browser-like' and not (self.capture_store and any(
            snapshot.user_agent == arg_string(args, 'browser_user_agent')
            and HTTPOrigin.from_url(snapshot.url) == HTTPOrigin.from_url(resolved)
            for snapshot in self.capture_store.list_snapshots()
        )):
            raise ValueError('browser-like profile needs a same-origin browser snapshot')
        headers = {k: v for k, v in args.get('headers', {}).items() if isinstance(v, str)} if isinstance(args.get('headers'), dict) else {}
        validate_host(httpx.Headers(headers), resolved)
        headers = dict(origin_headers(list(headers.items())))
        if profile == 'browser-like' and any(key.lower() == 'user-agent' and value != arg_string(args, 'browser_user_agent') for key, value in headers.items()):
            raise ValueError('browser-like User-Agent conflicts with captured snapshot')
        if not any(k.lower() == 'user-agent' for k in headers):
            if profile == 'browser-like':
                context = args.get('browser_context')
                ua = arg_string(args, 'browser_user_agent')
                headers['user-agent'] = ua
                headers.setdefault('Accept', 'text/html,application/xhtml+xml,*/*;q=0.8' if context == 'navigation' else 'application/json, */*;q=0.8')
            else:
                headers['user-agent'] = NATIVE_USER_AGENT
        # Prepare the actual HTTPX Request once, including Host/Content-Length.
        # send(request) does not merge client defaults/cookies after approval.
        request = httpx.Request((arg_string(args, 'method') or 'GET').upper(), resolved,
                                headers=headers, content=arg_string(args, 'body').encode('utf-8'))
        if request.url.username or request.url.password:
            # HTTPX otherwise derives BasicAuth during send(), after approval.
            # Materialize it now and remove credentials from the displayed URL.
            request = next(httpx.BasicAuth(request.url.username, request.url.password).auth_flow(request))
            request.url = request.url.copy_with(username=None, password=None)
        self.context_store.add_identity(request, arg_string(args, 'auth_context_ref') or None)
        action = EffectiveHTTP(request.method, str(request.url), tuple(request.headers.raw), request.content,
                               cap, self.target.revision, self.engagement.revision, self.permissions.epoch,
                               redirect_limit=args.get('max_redirects', 0))
        self._require_scope(action.url)
        return action, request, None

    def _resolve_baseline(self, args: dict) -> tuple[httpx.Request, RequestDiff]:
        if self.workflow is None or self.capture_store is None:
            raise ValueError('captured replay is unavailable in this runtime')
        candidate_id = arg_string(args, 'candidate_id')
        candidate = self.workflow.candidates.get(candidate_id)
        if candidate is None or not candidate.baseline_request_ref:
            raise ValueError('candidate has no captured baseline reference')
        if 'url' in args or 'method' in args or 'body' in args or 'headers' in args:
            raise ValueError('captured replay does not accept replacement url/method/headers/body')
        if 'mutation_value' not in args or not isinstance(args['mutation_value'], str):
            raise ValueError('captured replay requires mutation_value')
        ref = candidate.baseline_request_ref
        row = self.capture_store.resolve_baseline(ref)
        if row is None:
            raise ValueError('captured baseline is unavailable or unbound; recapture required; validation is inconclusive')
        self._require_scope(row.url or '')
        if candidate.target is None or HTTPOrigin.from_url(row.url or '') != HTTPOrigin.from_url(candidate.target):
            raise ValueError('captured baseline origin differs from candidate')
        identity = candidate.auth_context_ref
        if 'auth_context_ref' in args and arg_string(args, 'auth_context_ref') != (identity or ''):
            raise ValueError('replay identity differs from candidate')
        if getattr(row, 'auth_context_ref', None) not in (None, identity):
            raise ValueError('captured baseline identity differs from candidate')
        if self.workflow.objective is not None and self.workflow.objective.mode == 'whole_target':
            linked = [item for item in self.workflow.attack_surface_inputs.values() if candidate_id in item.candidate_ids]
            if not linked or any(
                item.baseline_request_ref != ref
                or item.auth_context_ref != candidate.auth_context_ref
                or item.source_ref != candidate.source_ref
                for item in linked
            ):
                raise ValueError('baseline provenance is not linked to candidate input')
        occurrence = args.get('occurrence', 0)
        if isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 0:
            raise ValueError('occurrence must be a non-negative integer')
        request, diff = build_captured_request(row, candidate, args['mutation_value'], occurrence=occurrence,
                                               input_path=arg_string(args, 'input_path') or None,
                                               old_value=arg_string(args, 'old_value') if 'old_value' in args else None)
        if 'cookie' in request.headers or 'authorization' in request.headers:
            if not identity or getattr(row, 'auth_context_ref', None) != identity:
                raise ValueError('captured credentials have no verified identity binding; recapture required')
        runtime_cookie = self.context_store.cookie_for(request, identity)
        if 'cookie' in request.headers and runtime_cookie != request.headers['cookie']:
            raise ValueError('runtime session cookie is missing or differs from captured baseline; recapture required')
        if 'authorization' in request.headers and self.context_store.authorization_for(request, identity) != request.headers['authorization']:
            raise ValueError('runtime authorization is missing or differs from captured baseline; recapture required')
        return request, diff

    def summarize(self, args: dict) -> dict:
        action, _, request_diff = self._prepare_with_diff(args)
        diff = request_diff.summary() + '\n' if request_diff else ''
        return {'summary': f'http: {action.method} {action.url}',
                'detail': f"phase (annotation): {arg_string(args, 'phase')}\n" + diff + action.preview()}

    async def run_authorized(self, args: dict[str, Any], signal: Any, prompter: Prompter) -> ToolOutput:
        return await self.run(args, signal, prompter)

    @permission_invocation
    async def run(self, args: dict, signal: Any, prompter: Prompter) -> ToolOutput:
        if signal is None:
            return await self._run_invocation(args, signal, prompter)
        check_cancelled(signal)
        invocation = asyncio.create_task(self._run_invocation(deepcopy(args), signal, prompter))
        try:
            while not invocation.done():
                await asyncio.wait({invocation}, timeout=0.05)
                check_cancelled(signal)
            return invocation.result()
        finally:
            invocation.cancel()
            await asyncio.gather(invocation, return_exceptions=True)

    async def _run_invocation(self, args, signal, prompter) -> ToolOutput:
        policy = policy_for(prompter)
        boundary = policy.generic_validation if policy is not None else None
        # A restored generic status cannot obtain compatibility-mode HTTP.
        if policy is None and self.workflow is not None:
            from src.workflow.validation_route import GENERIC_VALIDATOR, resolve_validation_route
            objective = self.workflow.objective
            for candidate in self.workflow.candidates.values():
                latest = self.workflow.latest_result(candidate.id)
                belongs = bool(objective and (
                    candidate.id == objective.candidate_id if objective.mode == 'candidate_validation'
                    else candidate.objective_id == objective.id))
                saved_generic = bool(latest and latest.skill_name == GENERIC_VALIDATOR)
                if ((belongs or objective is None) and saved_generic
                        or belongs and resolve_validation_route(self.validation_registry, candidate.candidate_class).kind != 'expert'):
                    raise UserControlledRefusal('blocked: generic runtime policy unavailable')
        probe = None
        failure = None
        if boundary is not None:
            action, request = self.prepare(args)
            probe = boundary.begin_http(self, args, action, request)
        try:
            return await self._execute_invocation(args, signal, prompter, probe)
        except HTTPPending:
            # Bounded scheduler pressure has not sent a request and is not a
            # terminal denial or vulnerability conclusion.
            raise
        except UserControlledRefusal as exc:
            failure = exc
            raise
        finally:
            if boundary is not None:
                boundary.end_http(probe)
                if failure is not None:
                    boundary.record_blocker(probe, failure)

    async def _execute_invocation(self, args, signal, prompter, generic_probe=None) -> ToolOutput:
        if isinstance(prompter, YoloPrompter):
            prompter.bind_http_permissions(self.permissions)
        args = deepcopy(args)
        action, request, diff = self._prepare_with_diff(args)
        policy = policy_for(prompter)
        identity = (self.workflow.candidates[arg_string(args, 'candidate_id')].auth_context_ref
                    if diff is not None and self.workflow is not None else arg_string(args, 'auth_context_ref') or None)
        supplied_headers = args.get('headers')
        explicit_cookie = bool(diff is not None and 'cookie' in request.headers)
        if isinstance(supplied_headers, dict):
            explicit_cookie = explicit_cookie or any(key.lower() == 'cookie' for key in supplied_headers)
        max_redirects = args.get('max_redirects', 0)
        if isinstance(max_redirects, bool) or not isinstance(max_redirects, int) or not 0 <= max_redirects <= 5:
            raise ValueError('max_redirects must be from 0 through 5')
        seen: set[tuple[str, str]] = set()
        outputs: list[str] = []
        for hop in range(max_redirects + 1):
            redirect_key = (request.method, action.url)
            if redirect_key in seen:
                outputs.append('[redirect loop stopped]')
                break
            seen.add(redirect_key)
            if policy is not None:
                if not policy.nested_allowed():
                    raise UserControlledRefusal('blocked: http-executor-without-receipt')
                request, address = await pin_request(policy, request)
                action = replace(action, transport_address=address)
            receipt = await self.permissions.authorize(action, prompter, signal, lambda: self.target.revision)
            try:
                result, location, cookie_updated = await self._dispatch(action, request, receipt, policy, signal, prompter, identity, generic_probe, args)
            finally:
                self.permissions.discard_receipt(receipt)
            outputs.append(f'[hop {hop}]\n{result}' if max_redirects else str(result))
            if not location or hop >= max_redirects:
                if location and hop >= max_redirects and max_redirects:
                    outputs.append('[redirect hop limit reached]')
                break
            if (action.target_revision, action.scope_revision, action.epoch) != (
                    self.target.revision, self.engagement.revision, self.permissions.epoch):
                outputs.append('[HTTP context changed; redirect not followed]')
                break
            if explicit_cookie:
                outputs.append('[redirect explicit Cookie has unknown path provenance; recapture required before following]')
                break
            try:
                next_url = urljoin(action.url, location)
                parsed_next = urlsplit(next_url)
            except ValueError:
                outputs.append('[malformed redirect Location not followed]')
                break
            if parsed_next.username or parsed_next.password:
                outputs.append('[redirect containing URL credentials not followed]')
                break
            try:
                self._require_scope(next_url)
                next_origin = HTTPOrigin.from_url(next_url)
            except (ValueError, PermissionError):
                outputs.append('[redirect outside scope not followed]')
                break
            if next_origin != HTTPOrigin.from_url(action.url):
                outputs.append('[cross-origin redirect not followed; credentials retained locally]')
                break
            method = request.method
            body = request.content
            if result.http_status == 303 and method != 'HEAD' or result.http_status in {301, 302} and method == 'POST':
                method, body = 'GET', b''
            headers = [(k, v) for k, v in origin_headers(list(request.headers.multi_items()))
                       if k.lower() != 'cookie'
                       and not (method == 'GET' and k.lower() in {'content-type', 'content-encoding'})]
            request = httpx.Request(method, next_url, headers=headers, content=body)
            self.context_store.add_identity(request, identity)
            action = EffectiveHTTP(request.method, str(request.url), tuple(request.headers.raw), request.content,
                                   action.response_cap, self.target.revision, self.engagement.revision, self.permissions.epoch,
                                   redirect_limit=max_redirects - hop - 1)
        prefix = diff.summary() + '\n' if diff else ''
        return ToolOutput(redact_evidence(prefix + '\n'.join(outputs)), status='observation', http_status=result.http_status,
                          truncated=result.truncated)

    async def _dispatch(self, action, request, receipt, policy, signal, prompter, identity=None, generic_probe=None, generic_args=None) -> tuple[ToolOutput, str | None, bool]:
        # Independent gate: generic Registry approval cannot coalesce this gate.
        try:
            private_reason = await gate_private_request(
                prompter, parse_http_url(action.url), signal, 'http', target=self.target,
            )
        except PrivateHostDeclined:
            check_cancelled(signal)
            self.permissions.pause_private(action.origin)
            raise
        check_cancelled(signal)
        transport_options: dict[str, Any] = {'trust_env': False} if policy is not None else {}
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=REQUEST_TIMEOUT, **transport_options) as client:
            reservation = await self.permissions.reserve_when_ready(action, receipt, signal, lambda: self.target.revision)
            response = None
            try:
                if policy is not None and not policy.nested_allowed():
                    from src.permission.runtime.execution import ExecutionBlocked
                    raise ExecutionBlocked("blocked: policy-changed-before-http-send")
                if generic_probe is not None:
                    assert policy is not None
                    policy.generic_validation.recheck_http(self, generic_args, action, generic_probe)
                elif policy is not None:
                    # A deferred generic boundary may become active while an
                    # expert request awaits DNS/permission/scheduling. Admission
                    # before those awaits cannot authorize that later send.
                    policy.validate(self, generic_args)
                reservation.start()
                # No suspension between reservation and starting send.
                import time
                evidence_store = policy.observations if policy else getattr(self, "evidence_store", None)
                source_owner = evidence_store.owner_provider() if evidence_store else None
                sent_at = time.monotonic()
                response = await client.send(request, stream=True)
                check_cancelled(signal)
                self.permissions.sync_target()
                self.context_store.sync_target(self.target.revision, self.engagement.revision, self.permissions.epoch)
                self.context_store.extract(
                    request, response, identity, action.url,
                    generation=(action.target_revision, action.scope_revision, action.epoch),
                )
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
                version = getattr(response, 'http_version', None)
                output = f'{version or "HTTP"} {response.status_code} {response.reason_phrase}\n'
                for k, v in response.headers.items():
                    output += f'{k}: {v}\n'
                output += (f'final URL: {action.url}\n'
                           f'decoded body bytes retained before redaction: {len(content)}\n'
                           f'wire Content-Length: {response.headers.get("content-length", "unknown")}\n'
                           f'Content-Encoding: {response.headers.get("content-encoding", "identity")}\n')
                output += '\n' + content.decode(errors='replace')
                if truncated:
                    output += f'\n[response body truncated at {action.response_cap} decoded bytes]'
                if private_reason:
                    output = f'note: private/internal host independently approved (reason: {private_reason})\n\n' + output
                if evidence_store is not None:
                    observation = evidence_store.capture(action, response.status_code, content, complete=not truncated,
                        validation_binding=(generic_probe[0], generic_probe[2]) if generic_probe else None,
                        owner=source_owner or {}, response_headers=response.headers.items(),
                        elapsed_ms=(time.monotonic() - sent_at) * 1000)
                    self._attest_phase_coverage(action, response, content, observation)
                    output += f'\n[runtime observation: {observation}]'
                output = redact_evidence(output)
                return (ToolOutput(output, status='observation', http_status=response.status_code, truncated=truncated),
                        response.headers.get('location') if response.status_code in {301, 302, 303, 307, 308} else None,
                        'set-cookie' in response.headers)
            finally:
                try:
                    if response is not None:
                        await response.aclose()
                finally:
                    reservation.release()

    def _attest_phase_coverage(self, action, response, content: bytes, observation: str) -> None:
        """Coverage describes executed operations, never inferred application behavior.

        Even an HTTP error or a capped body attests reachability/metadata. HTML
        navigation needs a parsed navigation reference within captured bytes.
        Only the first observation for a dimension is retained so duplicate
        requests cannot manufacture semantic progress with fresh observation IDs.
        """
        state = self.workflow
        objective = state.objective if state is not None else None
        if (state is None or objective is None or objective.mode != 'whole_target'
                or normalize_target_origin(action.url) != objective.target_origin
                or normalize_target_origin(self.target.base_url()) != objective.target_origin):
            return
        phase: WorkflowPhase
        if state.is_next_phase('recon'):
            dimensions = ['reachability']
            try:
                ipaddress.ip_address(action.transport_address)
            except ValueError:
                pass
            else:
                dimensions.append('target_resolution')
            if response.headers:
                dimensions.append('http_fingerprint')
            phase = 'recon'
        elif state.is_next_phase('enumeration'):
            if (action.method != 'GET'
                    or not 200 <= response.status_code < 300
                    or response.headers.get('content-type', '').split(';')[0].strip().lower()
                    not in {'text/html', 'application/xhtml+xml'}):
                return
            parser = _NavigationParser()
            parser.feed(content.decode(errors='replace'))
            if not parser.found:
                return
            dimensions = ['html_navigation']
            phase = 'enumeration'
        else:
            return
        for dimension in dimensions:
            existing = state.phase_coverage_record(phase, dimension)
            if existing is not None and existing.status == 'performed':
                continue
            state.record_phase_coverage(
                phase, dimension, 'performed', objective_id=objective.id,
                target_origin=objective.target_origin or '',
                reason=f'runtime HTTP observation: {observation}',
            )

    def _require_scope(self, url: str) -> None:
        self.engagement.require_in_scope(url)

    def resolve_url(self, raw: str) -> str:
        if raw.lower().startswith(('http://', 'https://')):
            return raw
        if self.target.empty():
            raise ValueError(f'url "{raw}" is a path with no active target; set /target or pass a full URL')
        return self.target.base_url().rstrip('/') + (raw if raw.startswith('/') else '/' + raw)
