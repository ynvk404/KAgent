from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any
import asyncio
import ipaddress
import hashlib
import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, parse_qsl
import httpx
from src.engagement.state import EngagementState
from src.permission.permission import Prompter, UserControlledRefusal, PermissionPolicyBlocked, YoloPrompter
from src.permission.network.grants import CaptureSource, CaptureReplayPending, EffectiveHTTP, HTTPPending, check_cancelled
from src.permission.runtime.execution import policy_for
from src.permission.runtime.invocations import permission_invocation
from src.permission.network.transport import pin_request
from src.target.target import Target
from src.target.origin import HTTPOrigin
from src.workflow.state import WorkflowPhase, WorkflowState, normalize_target_origin
from src.workflow.ownership import invocation as workflow_invocation, current as workflow_current
from src.tools.http.private_host import gate_private_request, parse_http_url, PrivateHostDeclined
from src.tools.common.types import Tool, PermissionHints, arg_string
from src.tools.common.outcome import ToolOutput
from src.tools.common.arguments import string_fields
from src.tools.common.approval_display import redact_approval
from src.tools.http.context import HTTPContextStore
from src.tools.http.request_builder import NATIVE_USER_AGENT, RequestDiff, build_captured_baseline, build_captured_request, origin_headers, validate_host
from src.browser.store import CaptureStore
from src.redaction.redact import apply_evidence as redact_evidence
from src.redaction.redact import http_credential_redactor, redact_request_context

RESPONSE_BYTE_CAP = 16 * 1024
MAX_RESPONSE_BYTE_CAP = 64 * 1024
REQUEST_TIMEOUT = 60
REQUEST_PREVIEW_CHARS = 4000


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
        self.dispatch_attempts = 0
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
            'Scoped HTTP/S; relative paths use /target; TLS verification disabled. Phase never grants permission. '
            'Exact requests need approval unless an exact-origin lab grant or bounded YOLO applies. '
            'If blocked, await operator action; never reword/retry to bypass. '
            'Redirects: max_redirects and per-hop approval; stop cross-origin/captured redirects. '
            'candidate_id replays captured baselines; mutation_value varies one input. '
            'Captured credentials need bounded operator approval even in YOLO. '
            'Terminal evidence: complete responses within configured limits, not marker prefixes. '
            'Reuse complete captures; never add truncated sources to sufficient manifests.'
        )

    def schema(self) -> dict:
        return {
            'type': 'object',
            'properties': {
                'method': {'type': 'string', 'minLength': 1,
                        'pattern': r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"},
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
                                    'default': RESPONSE_BYTE_CAP,
                                    'description': 'Decoded byte cap; omit for default. Body/content/size comparisons need >0; '
                                    'zero requires evidence_mode=metadata-only. '
                                    'Truncated captures cannot support terminal evidence.'},
                'evidence_mode': {'type': 'string', 'enum': ['body', 'metadata-only'],
                                'default': 'body', 'description': 'body: content/size comparisons or timing probes needing response content.'},
            },
            'required': ['phase'],
        }

    def requires_permission(self) -> bool:
        return True

    def _validate_input_types(self, args: dict) -> None:
        # Direct adapter callers historically omit the workflow phase;
        # Registry dispatch still enforces its required published field.
        string_fields(args, optional=(
            'phase', 'url', 'candidate_id', 'method', 'body', 'mutation_value',
            'input_path', 'old_value', 'auth_context_ref', 'profile',
            'browser_context', 'browser_user_agent', 'evidence_mode',
        ))
        if 'method' in args and not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", args['method']):
            raise ValueError('method must be a non-empty HTTP token')
        if 'headers' in args:
            headers = args['headers']
            if not isinstance(headers, dict):
                raise ValueError('headers must be an object with string names and values')
            if any(not isinstance(key, str) or not isinstance(value, str)
                for key, value in headers.items()):
                raise ValueError('headers must contain only string names and values')

    def validate_args(self, args: dict) -> None:
        self._validate_input_types(args)
        if args.get('phase') not in {'recon', 'validation', 'impact'}:
            raise ValueError('phase must be recon, validation, or impact')
        if not arg_string(args, 'url') and not arg_string(args, 'candidate_id'):
            raise ValueError('url or candidate_id is required')
        cap = args.get('max_response_bytes', RESPONSE_BYTE_CAP)
        if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= MAX_RESPONSE_BYTE_CAP:
            raise ValueError(f'max_response_bytes must be an integer from 0 to {MAX_RESPONSE_BYTE_CAP}')
        self._validate_capture_mode(args, cap)
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

    @staticmethod
    def _validate_capture_mode(args: dict, cap: int) -> None:
        mode = args.get('evidence_mode', 'body')
        if not isinstance(mode, str) or mode not in {'body', 'metadata-only'}:
            raise ValueError('evidence_mode must be body or metadata-only')
        if cap == 0 and mode == 'body':
            raise ValueError('Body-dependent evidence requires max_response_bytes > 0. Omit it to use the default.')

    def prepare(self, args: dict) -> tuple[EffectiveHTTP, httpx.Request]:
        action, request, _ = self._prepare_with_diff(args)
        return action, request

    def _prepare_with_diff(self, args: dict) -> tuple[EffectiveHTTP, httpx.Request, RequestDiff | None]:
        self._validate_input_types(args)
        self._validate_capture_mode(args, args.get('max_response_bytes', RESPONSE_BYTE_CAP))
        self.permissions.sync_target()
        self.context_store.sync_target(self.target.revision, self.engagement.revision, self.permissions.epoch)
        if arg_string(args, 'candidate_id'):
            request, diff, source = self._resolve_baseline(args)
            cap = args.get('max_response_bytes', RESPONSE_BYTE_CAP)
            if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= MAX_RESPONSE_BYTE_CAP:
                raise ValueError('invalid response byte cap')
            action = EffectiveHTTP(request.method, str(request.url), tuple(request.headers.raw), request.content,
                                cap, self.target.revision, self.engagement.revision, self.permissions.epoch,
                                redirect_limit=args.get('max_redirects', 0), capture_source=source)
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
        headers = dict(args.get('headers', {}))
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
        request = httpx.Request(args.get('method', 'GET').upper(), resolved,
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

    def captured_baseline(self, candidate):
        """Shared expert/generic provenance checks; raw data stays in runtime."""
        if self.workflow is None or self.capture_store is None:
            raise ValueError('captured replay is unavailable in this runtime')
        if candidate is None or not candidate.baseline_request_ref:
            raise ValueError('candidate has no captured baseline reference')
        candidate_id = candidate.id
        ref = candidate.baseline_request_ref
        row = self.capture_store.resolve_baseline(ref)
        if row is None:
            raise ValueError('Captured baseline is unavailable or unbound. Capture the request again. Validation remains inconclusive.')
        self._require_scope(row.url or '')
        if candidate.target is None or HTTPOrigin.from_url(row.url or '') != HTTPOrigin.from_url(candidate.target):
            raise ValueError('captured baseline origin differs from candidate')
        identity = candidate.auth_context_ref
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
        baseline = build_captured_baseline(row, candidate)
        credentials = [(key.hex(), value.hex()) for key, value in baseline.headers.raw
                    if redact_evidence(f'{key.decode("ascii")}: {value.decode("latin1")}')
                    != f'{key.decode("ascii")}: {value.decode("latin1")}']
        source = CaptureSource(ref, row.source, row.id, HTTPOrigin.from_url(str(baseline.url)),
                            identity, candidate.source_ref,
                            hashlib.sha256(json.dumps(credentials).encode()).hexdigest() if credentials else '')
        return row, baseline, source

    def _resolve_baseline(self, args: dict) -> tuple[httpx.Request, RequestDiff | None, CaptureSource]:
        candidate = self.workflow.candidates.get(arg_string(args, 'candidate_id')) if self.workflow else None
        if candidate is None:
            raise ValueError('candidate has no captured baseline reference')
        if any(key in args for key in ('url', 'method', 'body', 'headers')):
            raise ValueError('captured replay does not accept replacement url/method/headers/body')
        if 'auth_context_ref' in args and arg_string(args, 'auth_context_ref') != (candidate.auth_context_ref or ''):
            raise ValueError('replay identity differs from candidate')
        row, baseline, source = self.captured_baseline(candidate)
        if 'mutation_value' not in args:
            if any(key in args for key in ('occurrence', 'input_path', 'old_value')):
                raise ValueError('captured replay selectors require mutation_value')
            return baseline, None, source
        if not isinstance(args['mutation_value'], str):
            raise ValueError('captured replay requires a string mutation_value')
        occurrence = args.get('occurrence', 0)
        if isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 0:
            raise ValueError('occurrence must be a non-negative integer')
        request, diff = build_captured_request(row, candidate, args['mutation_value'], occurrence=occurrence,
                                            input_path=arg_string(args, 'input_path') or None,
                                            old_value=arg_string(args, 'old_value') if 'old_value' in args else None)
        return request, diff, source

    def _recheck_capture(self, args, action, request) -> None:
        if action.capture_source is None:
            return
        try:
            fresh, _ = self.prepare(args)
        except (ValueError, TypeError) as exc:
            raise CaptureReplayPending('pending: captured baseline unavailable or changed before dispatch; recapture/review required') from exc
        fresh = replace(fresh, transport_address=action.transport_address)
        expected_url = httpx.URL(action.url)
        if action.transport_address:
            expected_url = expected_url.copy_with(host=action.transport_address)
        if (fresh.digest != action.digest or request.method != action.method
                or request.url != expected_url or tuple(request.headers.raw) != action.headers
                or request.content != action.body):
            raise CaptureReplayPending('pending: captured effective request changed; new execution authorization required')
        self.permissions.check_capture(action, reserved=True)

    def summarize(self, args: dict) -> dict:
        try:
            self._validate_input_types(args)
        except ValueError as exc:
            # Standalone presentation callers historically tolerate malformed
            # headers. Show an explicitly invalid proposal without preparing
            # a request or modifying identity/context state. Registry never
            # reaches this branch because it validates before review.
            return {'summary': 'http: invalid arguments', 'detail': redact_approval(
                f'invalid arguments: {exc}\n'
                f'proposed request (not prepared): {arg_string(args, "method") or "GET"} '
                f'{arg_string(args, "url")}\n'
                f'native default user-agent: {NATIVE_USER_AGENT}')}
        action, _, request_diff = self._prepare_with_diff(args)
        diff = request_diff.summary() + '\n' if request_diff else ''
        return {'summary': action.redact_preview(f'http: {action.method} {action.url}'),
                'detail': f"phase (annotation): {arg_string(args, 'phase')}\n" + diff + action.preview()}

    async def run_authorized(self, args: dict[str, Any], signal: Any, prompter: Prompter) -> ToolOutput:
        return await self.run(args, signal, prompter)

    @permission_invocation
    @workflow_invocation
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
        self._validate_input_types(args)
        policy = policy_for(prompter)
        boundary = policy.generic_validation if policy is not None else None
        # A restored generic status cannot obtain compatibility-mode HTTP.
        if policy is None and self.workflow is not None:
            from src.workflow.validation.route import GENERIC_VALIDATOR, resolve_validation_route
            objective = self.workflow.objective
            for candidate in self.workflow.candidates.values():
                latest = self.workflow.latest_result(candidate.id)
                belongs = bool(objective and (
                    candidate.id == objective.candidate_id if objective.mode == 'candidate_validation'
                    else candidate.objective_id == objective.id))
                saved_generic = bool(latest and latest.skill_name == GENERIC_VALIDATOR)
                if ((belongs or objective is None) and saved_generic
                        or belongs and resolve_validation_route(self.validation_registry, candidate.candidate_class).kind != 'expert'):
                    raise PermissionPolicyBlocked('blocked: generic runtime policy unavailable')
        probe = None
        failure = None
        if boundary is not None:
            action, request = self.prepare(args)
            probe = boundary.begin_http(self, args, action, request)
        try:
            return await self._execute_invocation(args, signal, prompter, probe)
        except CaptureReplayPending as exc:
            # A capture needing repair/review blocks only this request. Raising
            # UserControlledRefusal would terminate the Agent's entire batch.
            return ToolOutput(str(exc), status='pending', error_kind='permission_pending')
        except HTTPPending:
            # Scheduler pressure has not sent a request and is not a
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
                    if action.capture_source is not None and self.workflow is not None else arg_string(args, 'auth_context_ref') or None)
        supplied_headers = args.get('headers')
        explicit_cookie = bool(diff is not None and 'cookie' in request.headers)
        if isinstance(supplied_headers, dict):
            explicit_cookie = explicit_cookie or any(key.lower() == 'cookie' for key in supplied_headers)
        max_redirects = args.get('max_redirects', 0)
        if isinstance(max_redirects, bool) or not isinstance(max_redirects, int) or not 0 <= max_redirects <= 5:
            raise ValueError('max_redirects must be from 0 through 5')
        seen: set[tuple[str, str]] = set()
        outputs: list[str] = []
        sources: list[tuple[str, str]] = []
        body_ranges: list[tuple[int, int]] = []
        for hop in range(max_redirects + 1):
            redirect_key = (request.method, action.url)
            if redirect_key in seen:
                outputs.append('[redirect loop stopped]')
                break
            seen.add(redirect_key)
            if policy is not None:
                if not policy.nested_allowed():
                    raise PermissionPolicyBlocked('blocked: http-executor-without-receipt')
                request, address = await pin_request(policy, request)
                action = replace(action, transport_address=address)
            with self.permissions.reviewed_dispatch(action):
                receipt = await self.permissions.authorize(action, prompter, signal, lambda: self.target.revision)
            try:
                result, location, cookie_updated = await self._dispatch(action, request, receipt, policy, signal, prompter, identity, generic_probe, args)
            finally:
                self.permissions.discard_receipt(receipt)
            hop_prefix = f'[hop {hop}]\n' if max_redirects else ''
            offset = sum(len(part) + 1 for part in outputs) + len(hop_prefix)
            body_ranges.extend((start + offset, end + offset) for start, end in result.http_body_ranges)
            sources.extend(result.http_sources)
            outputs.append(hop_prefix + str(result))
            if not location or hop >= max_redirects:
                if location and hop >= max_redirects and max_redirects:
                    outputs.append('[redirect hop limit reached]')
                break
            if (action.target_revision, action.scope_revision, action.epoch) != (
                    self.target.revision, self.engagement.revision, self.permissions.epoch):
                outputs.append('[HTTP context changed; redirect not followed]')
                break
            if action.capture_source is not None:
                outputs.append('[captured redirect not followed; recapture required to retain credential provenance]')
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
        safe_prefix = redact_evidence(prefix)
        text = safe_prefix + '\n'.join(outputs)
        output = ToolOutput(text if sources else redact_evidence(text), status='observation',
                            http_status=result.http_status, truncated=result.truncated)
        if sources and policy is not None:
            output.http_sources = tuple(sources)
            output.http_body_ranges = tuple((a + len(safe_prefix), b + len(safe_prefix))
                                            for a, b in body_ranges)
            output.http_session = policy.session_id or self.permissions.session_id
            output.http_stamp = policy.stamp()
        return output

    async def _dispatch(self, action, request, receipt, policy, signal, prompter, identity=None, generic_probe=None, generic_args=None) -> tuple[ToolOutput, str | None, bool]:
        # Independent gate: generic Registry approval cannot coalesce this gate.
        active_check = policy.active_review_check() if policy is not None else lambda: True
        try:
            private_reason = await gate_private_request(
                prompter, parse_http_url(action.url), signal, 'http', target=self.target,
                is_current=lambda: active_check() and self.permissions.review_is_current(receipt, action, self.target.revision),
            )
        except PrivateHostDeclined:
            check_cancelled(signal)
            self.permissions.pause_private(action.origin)
            raise
        check_cancelled(signal)
        receipt = self.permissions.dispatch_receipt(receipt, action, signal, self.target.revision)
        evidence_store = policy.observations if policy else getattr(self, "evidence_store", None)
        def check_response_current() -> None:
            # Admission authorizes this dispatch, not publication after an
            # awaited send/body read has crossed a scope or ownership change.
            check_cancelled(signal)
            self.permissions.sync_target()
            if evidence_store is None:
                # Legacy standalone callers can receive redacted historical
                # traffic without publishing an observation. Cookie/context
                # extraction separately checks the captured request generation.
                return
            if (action.epoch != self.permissions.epoch
                    or action.target_revision != self.target.revision
                    or action.scope_revision != self.engagement.revision
                    or receipt.policy_revision != self.permissions.revision
                    or self.workflow is not None and not workflow_current(self)):
                raise PermissionPolicyBlocked('blocked: HTTP response owner/scope/permission changed')
            if policy is not None:
                policy.revalidate_active(self, generic_args, signal)

        transport_options: dict[str, Any] = {'trust_env': False} if policy is not None or action.capture_source is not None else {}
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=REQUEST_TIMEOUT, **transport_options) as client:
            reservation = await self.permissions.reserve_when_ready(action, receipt, signal, lambda: self.target.revision)
            response = None
            dispatch_fact = None
            captured_observation = None
            dispatch_cancelled = False
            dispatch_state = policy.generic_validation.state if policy and policy.generic_validation else None
            try:
                if policy is not None and not policy.nested_allowed():
                    from src.permission.runtime.execution import ExecutionBlocked
                    raise ExecutionBlocked("blocked: policy-changed-before-http-send")
                self._recheck_capture(generic_args, action, request)
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
                source_owner = evidence_store.owner_provider() if evidence_store else None
                sent_at = time.monotonic()
                # This is the native transport handoff. Retries and followed
                # redirects each enter here again; failed sends still count.
                if dispatch_state is not None:
                    from src.workflow.assessment import begin_dispatch
                    from src.permission.runtime.execution import _active
                    execution = _active.get()
                    dispatch_fact = begin_dispatch(dispatch_state, source_owner,
                                                action.invocation_id or receipt.id, action.digest,
                                                execution[1].id if execution and execution[0] is policy else None)
                self.dispatch_attempts += 1
                response = await client.send(request, stream=True)
                check_response_current()
                self.context_store.sync_target(self.target.revision, self.engagement.revision, self.permissions.epoch)
                if action.capture_source is None:
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
                check_response_current()
                content = b''.join(chunks)[:action.response_cap]
                from src.permission.runtime.execution import _active, invocation_digest
                execution = _active.get()
                trusted_http = bool(type(self) is HTTPTool and policy is not None
                    and self.engagement is policy.engagement and policy.nested_allowed()
                    and execution is not None and execution[0] is policy
                    and isinstance(generic_args, dict)
                    and execution[1].digest == invocation_digest(self, generic_args)
                    and action.epoch == self.permissions.epoch
                    and action.target_revision == self.target.revision
                    and action.scope_revision == self.engagement.revision)
                redact = (http_credential_redactor(request.headers.multi_items(), response.headers.multi_items())
                        if action.capture_source else redact_evidence)
                version = getattr(response, 'http_version', None)
                output = f'{version or "HTTP"} {response.status_code} {redact(response.reason_phrase)}\n'
                for k, v in response.headers.items():
                    # Header names supply the credential context; the body does
                    # not pass through this header/request export guard.
                    output += redact(f'{k}: {v}') + '\n'
                output += (f'final URL: {redact(action.url)}\n'
                        f'decoded body bytes retained before redaction: {len(content)}\n'
                        f'wire Content-Length: {response.headers.get("content-length", "unknown")}\n'
                        f'Content-Encoding: {response.headers.get("content-encoding", "identity")}\n')
                header_length = len(output)
                output += '\n'
                body_start = len(output)
                output += content.decode(errors='replace') if trusted_http else redact(content.decode(errors='replace'))
                body_end = len(output)
                if truncated:
                    output += f'\n[response body truncated at {action.response_cap} decoded bytes]'
                if evidence_store is not None:
                    # The effective, authorized request includes replay/context
                    # changes. Model arguments alone are not a capture of it.
                    request_text = redact(
                        f'{action.method} {action.url}\n'
                        + '\n'.join(f'{k.decode("ascii")}: {v.decode("latin1")}'
                                    for k, v in action.headers)
                        + '\n\n' + redact_request_context(action.body.decode(errors='replace'),
                                                            request.headers.get('content-type')))
                    if policy is not None:
                        for secret in policy.internal_secret_values():
                            if secret:
                                request_text = request_text.replace(secret, '[INTERNAL SECRET OMITTED]')
                    request_preview = request_text[:REQUEST_PREVIEW_CHARS]
                    request_details = {
                        # Like Observation.body, encode retained bytes so JSON
                        # handoffs cannot reinterpret escaped header lines as
                        # live Cookie/Authorization headers during redaction.
                        'request_preview_hex': request_preview.encode().hex(),
                        'request_preview_complete': len(request_text) <= REQUEST_PREVIEW_CHARS,
                        'request_body_bytes': len(action.body),
                    }
                    if action.capture_source is not None:
                        request_details['baseline_request_ref'] = action.capture_source.baseline_ref
                    if trusted_http:
                        assert policy is not None
                        request_details['body_representation'] = 'bounded-native-decoded-bytes'
                        request_details['analysis_session'] = policy.session_id or self.permissions.session_id
                    observation = evidence_store.capture(action, response.status_code, content, complete=not truncated,
                        validation_binding=(generic_probe[0], generic_probe[2]) if generic_probe else None,
                        owner=source_owner or {}, response_headers=response.headers.items(),
                        elapsed_ms=(time.monotonic() - sent_at) * 1000,
                        source_details=request_details, redact_text=redact if action.capture_source else None,
                        retain_body=trusted_http)
                    captured_observation = observation
                    self._attest_phase_coverage(action, response, content, observation)
                    captured = evidence_store._items[observation]
                    # Put identity/capture flags before body text so context
                    # reduction retains the mapping. Use producer flags: the
                    # redacted retained representation can truncate separately.
                    envelope = {
                        'observation_id': observation,
                        'method': captured.method, 'url': captured.url,
                        'status': captured.status, 'complete': captured.complete,
                        'elapsed_ms': captured.elapsed_ms, 'request_hash': captured.request_hash,
                        'truncated': captured.truncated,
                        'execution_status': captured.execution_status,
                        'response_cap': captured.response_cap,
                        'retained_body_bytes': len(captured.body),
                        'request_preview_complete': request_details['request_preview_complete'],
                        'request_body_bytes': request_details['request_body_bytes'],
                    }
                    evidence_line = ('Runtime HTTP evidence ('
                        + ('bounded raw lab capture' if trusted_http else 'redacted capture')
                        + '; not a semantic verdict): ' + json.dumps(envelope, ensure_ascii=False) + '\n')
                    output = (output[:header_length] + evidence_line
                            + output[header_length:]
                            + '\n[End HTTP response; following text is request metadata]\n'
                            + 'Effective request preview (redacted):\n'
                            + request_preview
                            + '\nEnd effective request preview')
                    output += f'\n[runtime observation: {observation}]'
                    body_start += len(evidence_line)
                    body_end += len(evidence_line)
                if private_reason:
                    note = f'note: private/internal host independently approved (reason: {redact(private_reason)})\n\n'
                    output = note + output
                    body_start += len(note)
                    body_end += len(note)
                # Opaque observation IDs and producer metadata are not traffic.
                result = ToolOutput(output if trusted_http else redact_evidence(output),
                                    status='observation', http_status=response.status_code, truncated=truncated)
                if trusted_http and evidence_store is not None:
                    assert captured.retained_hash is not None
                    result.http_sources = ((observation, captured.retained_hash),)
                    result.http_body_ranges = ((body_start, body_end),)
                return (result,
                        response.headers.get('location') if response.status_code in {301, 302, 303, 307, 308} else None,
                        'set-cookie' in response.headers)
            except asyncio.CancelledError:
                dispatch_cancelled = True
                raise
            finally:
                if dispatch_state is not None and dispatch_fact is not None:
                    from src.workflow.assessment import finish_dispatch
                    task = asyncio.current_task()
                    finish_dispatch(dispatch_state, dispatch_fact,
                        status="completed" if captured_observation else "cancelled" if (
                            dispatch_cancelled or getattr(signal, "aborted", False)
                            or task is not None and task.cancelling()) else "failed",
                        observation_id=captured_observation)
                try:
                    if response is not None:
                        await response.aclose()
                finally:
                    reservation.release()

    def _attest_phase_coverage(self, action, response, content: bytes, observation: str) -> None:
        """Coverage describes executed operations, never inferred application behavior.

        Even an HTTP error or a capped body attests reachability/metadata. HTML
        navigation needs a parsed navigation reference within captured bytes.
        Source novelty uses a bounded content ledger, so duplicate requests
        cannot manufacture progress with fresh observation IDs.
        """
        from src.workflow.ownership import current
        if not current(self):
            return
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
        parsed_url = urlsplit(action.url)
        # Stable request shape + observed response content. Fresh request IDs,
        # query values, timestamps and reason wording cannot mint new facts.
        source_fingerprint = hashlib.sha256(json.dumps([
            action.method, parsed_url.path,
            sorted({name for name, _ in parse_qsl(parsed_url.query, keep_blank_values=True)}),
            response.status_code, response.headers.get('content-type', '').split(';')[0].strip().lower(),
            hashlib.sha256(content).hexdigest(),
        ], separators=(',', ':')).encode()).hexdigest()
        for dimension in dimensions:
            existing = state.phase_coverage_record(phase, dimension)
            if (existing is not None and existing.status == 'performed'
                    and (source_fingerprint in existing.source_fingerprints
                         or len(existing.source_fingerprints) >= 128)):
                continue
            state.record_phase_coverage(
                phase, dimension, 'performed', objective_id=objective.id,
                target_origin=objective.target_origin or '',
                reason=f'runtime HTTP observation: {observation}',
                source_fingerprint=source_fingerprint,
            )

    def _require_scope(self, url: str) -> None:
        self.engagement.require_in_scope(url)

    def resolve_url(self, raw: str) -> str:
        if raw.lower().startswith(('http://', 'https://')):
            return raw
        if self.target.empty():
            raise ValueError(f'URL "{raw}" is a relative path with no active target. Set /target or pass a full URL.')
        return self.target.base_url().rstrip('/') + (raw if raw.startswith('/') else '/' + raw)
