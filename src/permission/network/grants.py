"""Ephemeral operator HTTP rights. No phase, payload or method classifiers.

All state mutations and reserve/start/release are synchronous on the owning
asyncio event loop: there is no await between validation and reservation.
This manager is neither serialized nor exposed as an LLM tool.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
import uuid
from contextlib import contextmanager, asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, asdict, replace, field
from typing import Any, Callable, Literal, TYPE_CHECKING

from src.permission.permission import Decision, PermissionRequest, Prompter, UserControlledRefusal, PermissionReviewStale
from src.target.origin import HTTPOrigin
from src.tools.common.approval_display import redact_approval
from src.redaction.redact import http_credential_redactor
from src.permission.runtime.invocations import review_id, on_review_end, permission_invocation, capture_review, ReviewGuard, REVIEW_TIMEOUT_SECONDS

if TYPE_CHECKING:
    from src.engagement.state import EngagementState

WARNING = (
    "Accept unknown HTTP effects on this origin. This does NOT guarantee prevention "
    "of bulk delete, email, changes to real data or other server-side effects. "
    "The operator must establish that this lab is disposable. "
    "No local read/export, shell/MCP, egress or sandbox rights are granted."
)

# Trusted native invocation mode, scoped by exact manager/action identity.
# It selects ticket timing, never grants authority or callback ownership.
_review_dispatch: ContextVar[tuple[Any, str] | None] = ContextVar('http_review_dispatch', default=None)


class HTTPBlocked(UserControlledRefusal):
    """A blocked/pending authorization result, with no automatic dialog retry."""
    explicit_denial = False
    error_kind = 'policy_block'

    def __init__(self, message: str, *, explicit_denial: bool = False):
        super().__init__(message)
        self.explicit_denial = explicit_denial
        if explicit_denial:
            self.error_kind = 'permission_denied'


class HTTPPending(HTTPBlocked):
    """Transient rate/concurrency pressure; bounded scheduling, no new approval."""
    error_kind = 'permission_pending'


class HTTPReviewTimeout(HTTPPending, TimeoutError):
    error_kind = 'permission_timeout'


class HTTPReviewStale(HTTPBlocked):
    error_kind = 'permission_stale'


class CaptureReplayPending(HTTPBlocked):
    """Capture repair/review needed; no send or terminal validation conclusion."""
    error_kind = 'permission_pending'


def check_cancelled(signal: Any) -> None:
    if signal is not None and (
        getattr(signal, "aborted", False) or getattr(signal, "is_set", lambda: False)()
    ):
        raise asyncio.CancelledError()


@dataclass(frozen=True, slots=True)
class HTTPLimits:
    seconds: float | None = 1200
    requests: int | None = 500
    rate: float = 3
    burst: int = 3
    concurrency: int = 2
    request_bytes: int = 128 * 1024
    response_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        for name in ("seconds", "rate"):
            value = getattr(self, name)
            if name == "seconds" and value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be positive and finite")
        for name in ("requests", "burst", "concurrency", "request_bytes", "response_bytes"):
            value = getattr(self, name)
            if name == "requests" and value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    @classmethod
    def session(cls, **resources: Any) -> HTTPLimits:
        """Explicit operator session grant; resource controls still apply."""
        return cls(seconds=None, requests=None, **resources)

    def display(self) -> str:
        lifetime = f"expires in {self.seconds:g}s" if self.seconds is not None else "session lifetime"
        quota = f"requests <= {self.requests}" if self.requests is not None else "no request quota"
        return (
            f"{lifetime}; {quota}; "
            f"token bucket {self.rate:g}/s, burst {self.burst}; concurrency <= {self.concurrency}; "
            f"request URL + headers + body <= {self.request_bytes} bytes; "
            f"decoded response body retained <= {self.response_bytes} bytes. "
            "These are application limits, not total wire-byte/server-resource guarantees."
        )


@dataclass(frozen=True, slots=True)
class CaptureSource:
    """Immutable runtime provenance, never credential bytes or durable rights."""
    baseline_ref: str
    source: str
    source_id: str
    origin: HTTPOrigin
    identity: str | None
    source_ref: str | None
    credential_digest: str


@dataclass(frozen=True, slots=True)
class EffectiveHTTP:
    method: str
    url: str
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes
    response_cap: int
    target_revision: int
    scope_revision: int
    epoch: str
    transport_address: str = ""
    invocation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    redirect_limit: int = 0
    capture_source: CaptureSource | None = None

    @property
    def origin(self) -> HTTPOrigin:
        return HTTPOrigin.from_url(self.url)

    @property
    def digest(self) -> str:
        material = [self.method, self.url, [(k.hex(), v.hex()) for k, v in self.headers],
                    self.body.hex(), self.response_cap, False, self.redirect_limit, 60]
        material.append(self.transport_address)
        if self.capture_source is not None:
            material.append(asdict(self.capture_source))
        return hashlib.sha256(json.dumps(material, separators=(",", ":")).encode()).hexdigest()

    @property
    def size(self) -> int:
        return len(self.url.encode()) + len(self.method.encode()) + sum(len(k) + len(v) + 4 for k, v in self.headers) + len(self.body)

    def preview(self) -> str:
        headers = "\n".join(f"{k.decode('ascii')}: {v.decode('latin1')}" for k, v in self.headers)
        return self.redact_preview(
            f"{self.method} {self.url}\n{headers}\n\n{self.body.decode('utf-8', errors='replace')}\n\n"
            f"response body cap: {self.response_cap}; timeout: 60s; redirects: "
            f"{'off' if self.redirect_limit == 0 else f'explicit follow-up, at most {self.redirect_limit} hops'}; "
            f"TLS verification: off; socket: {self.transport_address or 'library DNS'}"
        )

    def redact_preview(self, text: str) -> str:
        if self.capture_source is not None:
            text = http_credential_redactor((k.decode('ascii'), v.decode('latin1'))
                                           for k, v in self.headers)(text)
        return redact_approval(text)


@dataclass(frozen=True, slots=True)
class HTTPGrant:
    id: str
    session_id: str
    engagement_id: str
    origin: HTTPOrigin
    mode: Literal["autonomous", "confirm-each"]
    limits: HTTPLimits
    created_at: float
    expires_at: float | None
    revision: int
    issuer: str = "operator"
    activation: Literal["manual", "yolo"] = "manual"


@dataclass(slots=True)
class _Budget:
    limits: HTTPLimits
    expires_at: float | None
    tokens: float
    updated_at: float
    used: int = 0
    active: int = 0

    def expired(self, now: float) -> bool:
        return self.expires_at is not None and now >= self.expires_at

    def exhausted(self, *, reserved: bool = False) -> bool:
        cap = self.limits.requests
        return cap is not None and (self.used > cap if reserved else self.used >= cap)


@dataclass(frozen=True, slots=True)
class HTTPReceipt:
    id: str
    session_id: str
    epoch: str
    digest: str
    origin: HTTPOrigin
    scope_revision: int
    target_revision: int
    policy_revision: int
    expires_at: float
    grant_id: str | None
    invocation_id: str = ''
    review_guard: ReviewGuard | None = field(default=None, kw_only=True, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class HTTPReviewTicket(HTTPReceipt):
    """Reviewed action awaiting independent gates; never a dispatch receipt."""


@dataclass(slots=True)
class HTTPReservation:
    budget: _Budget
    release_slot: Callable[[], None]
    started: bool = False
    released: bool = False
    capture_budget: _Budget | None = None

    def start(self) -> None:
        if self.released or self.started:
            raise HTTPBlocked("blocked: reservation already used")
        self.started = True

    def release(self) -> None:
        if not self.released:
            self.budget.active -= 1
            self.release_slot()
            if not self.started:
                self.budget.used -= 1
                self.budget.tokens = min(self.budget.limits.burst, self.budget.tokens + 1)
                if self.capture_budget is not None:
                    self.capture_budget.used -= 1
            self.released = True


class HTTPPermissions:
    def __init__(self, engagement: EngagementState, *, clock: Callable[[], float] = time.monotonic):
        self.engagement = engagement
        self.clock = clock
        self.review_timeout = REVIEW_TIMEOUT_SECONDS
        self._review_cleanups: dict[str, Callable[[], None]] = {}
        self.session_id = uuid.uuid4().hex
        self.epoch = uuid.uuid4().hex
        self.revision = 0
        self.denied = False
        self.grants: dict[HTTPOrigin, HTTPGrant] = {}
        self._budgets: dict[str, _Budget] = {}
        self._grant_versions: dict[HTTPOrigin, int] = {}
        self._denial_versions: dict[HTTPOrigin, int] = {}
        self._exact_budgets: dict[HTTPOrigin, _Budget] = {}
        self._receipts: dict[str, HTTPReceipt] = {}
        self._pending: set[HTTPOrigin] = set()
        # Locks are fair on the owning event loop. Reference counts include
        # owners and waiters so idle origins leave no persistent queue state.
        self._review_locks: dict[HTTPOrigin, tuple[asyncio.Lock, int]] = {}
        self._suppressed: set[HTTPOrigin] = set()
        self._declined_actions: dict[tuple[str, str], HTTPOrigin] = {}
        self._revoked: set[HTTPOrigin] = set()
        self._blocked_gate: set[HTTPOrigin] = set()
        self._grant_pending: set[HTTPOrigin] = set()
        self._inflight: dict[HTTPOrigin, int] = {}
        self._yolo_enabled = False
        self._target_revision: Callable[[], int] | None = None
        self._bound_target = 0
        # Controller opt-in: retained restrictions never restore authorization.
        self.constraint_journal: Callable[[], None] | None = None
        self._constraints: dict[HTTPOrigin, _Budget] = {}
        self._capture_grants: dict[CaptureSource, _Budget] = {}
        self._capture_pending: set[CaptureSource] = set()

    def constraint_state(self) -> list[dict[str, Any]]:
        rows = dict(self._constraints)
        rows.update(self._exact_budgets)
        rows.update({origin: self._budgets[grant.id] for origin, grant in self.grants.items()})
        return [{"origin": origin.as_url(), "limits": asdict(budget.limits), "used": budget.used,
                 "deadline": (time.time() + budget.expires_at - self.clock()
                              if budget.expires_at is not None else None)} for origin, budget in rows.items()]

    def restore_constraints(self, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            origin = HTTPOrigin.from_url(row["origin"])
            limits = HTTPLimits(**row["limits"])
            deadline = row.get("deadline")
            remaining = float(deadline) - time.time() if deadline is not None else limits.seconds
            if limits.seconds is not None and remaining is not None:
                remaining = min(limits.seconds, remaining)
            budget = _Budget(limits, self.clock() + remaining if remaining is not None else None,
                             0, self.clock(), max(0, int(row["used"])))
            self._constraints[origin] = budget
            grant = self.grants.get(origin)
            if grant is not None:
                self._budgets[grant.id] = budget
                self.grants[origin] = replace(grant, limits=limits, expires_at=budget.expires_at)
        self.revision += 1
        self._clear_receipts()

    def bind_target(self, getter: Callable[[], int]) -> None:
        self._target_revision = getter
        self._bound_target = getter()

    def sync_target(self) -> None:
        if self._target_revision is not None and self._target_revision() != self._bound_target:
            self.reset(preserve_denial=True)
            self._bound_target = self._target_revision()
            self._refresh_yolo()

    def set_yolo(self, enabled: bool) -> None:
        """Operator toggle activates session HTTP rights; resource gates remain."""
        self.sync_target()
        if self._yolo_enabled != enabled:
            self._yolo_enabled = enabled
            self.revision += 1
            self._clear_receipts()
            if not enabled:
                # Switching modes does not turn YOLO grants into manual rights
                # or a sticky revoke. Explicit manual grants remain unchanged.
                for origin, grant in list(self.grants.items()):
                    if grant.activation == "yolo":
                        if self.constraint_journal is not None:
                            self._constraints[origin] = self._budgets[grant.id]
                        del self.grants[origin]
        self._refresh_yolo()

    def _refresh_yolo(self) -> None:
        if not self._yolo_enabled or self.denied:
            return
        for origin in sorted(self.engagement.allowed_origins):
            # Never refill expired/exhausted grants or override operator
            # limits/confirm-each/revocation merely because YOLO remains on.
            if origin not in self.grants and origin not in self._revoked:
                self.activate(origin.as_url(), HTTPLimits.session(), activation="yolo")

    def reset(self, *, preserve_denial: bool = False) -> None:
        # Old in-flight reservations retain their own budget for safe release.
        if self.constraint_journal is not None and preserve_denial:
            self._constraints.update(self._exact_budgets)
            self._constraints.update({origin: self._budgets[grant.id] for origin, grant in self.grants.items()})
        elif not preserve_denial:
            self._constraints.clear()
        self.epoch = uuid.uuid4().hex
        self.revision += 1
        denied = self.denied if preserve_denial else False
        self.denied = denied
        self.grants.clear()
        self._budgets.clear()
        self._exact_budgets.clear()
        self._clear_receipts()
        self._suppressed.clear()
        self._capture_grants.clear()
        self._declined_actions.clear()
        if not preserve_denial:
            self._revoked.clear()
        self._blocked_gate.clear()
        # Pending asks keep their origin until their finally; old approvals
        # cannot cross epochs and cannot cause another concurrent dialog.

    def scope_changed(self) -> None:
        self.revision += 1
        self._clear_receipts()
        self._capture_grants.clear()
        for origin in list(self.grants):
            if origin not in self.engagement.allowed_origins:
                self.revoke(self.grants[origin].id)
        self._refresh_yolo()

    def deny_session(self) -> None:
        for grant in list(self.grants.values()):
            self.revoke(grant.id)
        self.denied = True
        self.revision += 1
        self._clear_receipts()
        self._capture_grants.clear()


    def retry(self, url: str) -> None:
        """Explicit operator reopening, not a model retry or session approval."""
        origin = self.engagement.require_in_scope(url)
        self.denied = False
        self._suppressed.discard(origin)
        self._declined_actions = {digest: value for digest, value in self._declined_actions.items() if value != origin}
        self._revoked.discard(origin)
        self._blocked_gate.discard(origin)
        self._capture_grants = {source: budget for source, budget in self._capture_grants.items()
                                if source.origin != origin or
                                (not budget.expired(self.clock()) and not budget.exhausted())}
        budget = self._exact_budgets.get(origin)
        if budget is not None and (budget.expired(self.clock()) or budget.exhausted()):
            # Only this explicit operator command renews the exact-only safety
            # envelope. No exact receipt is issued and existing lab grant
            # expiry/quota is unchanged. Selected YOLO may reopen a revoked
            # origin below, following this explicit operator retry.
            del self._exact_budgets[origin]
        self.revision += 1
        self._clear_receipts()
        self._refresh_yolo()

    def activate(self, url: str, limits: HTTPLimits, mode: str = "autonomous", *, activation: Literal["manual", "yolo"] = "manual") -> HTTPGrant:
        """Trusted UI/CLI callback only; never reachable from tool arguments."""
        self.sync_target()
        if self.denied:
            raise HTTPBlocked("blocked: session deny; operator must explicitly retry first")
        origin = self.engagement.require_in_scope(url)
        if mode not in {"autonomous", "confirm-each"}:
            raise ValueError("mode must be autonomous or confirm-each")
        now = self.clock()
        selected_mode: Literal["autonomous", "confirm-each"] = "autonomous" if mode == "autonomous" else "confirm-each"
        # Adding rights for one origin does not stale another origin's queued
        # review/receipt. Replacement still retires this origin's receipts.
        version = self._grant_versions.get(origin, 0) + 1
        self._grant_versions[origin] = version
        self._clear_receipts(origin)
        carried = self._constraints.get(origin) if activation == "yolo" else None
        if carried is not None:
            # Current operator YOLO activation supplies authority. Retained
            # constraints preserve finite limits and accounting without turning
            # an unconstrained dimension back into an implicit fixed ceiling.
            limits = carried.limits
        grant = HTTPGrant(uuid.uuid4().hex, self.session_id, self.epoch, origin, selected_mode, limits,
                          now, carried.expires_at if carried else (now + limits.seconds if limits.seconds is not None else None),
                          version, activation=activation)
        self.grants[origin] = grant
        self._budgets[grant.id] = carried if carried else _Budget(limits, grant.expires_at, limits.burst, now)
        if self.constraint_journal is not None:
            self._constraints[origin] = self._budgets[grant.id]
        self._suppressed.discard(origin)
        self._revoked.discard(origin)
        return grant

    def pause_private(self, origin: HTTPOrigin) -> None:
        self._blocked_gate.add(origin)

    def revoke(self, grant_id: str) -> None:
        for origin, grant in list(self.grants.items()):
            if grant.id == grant_id:
                del self.grants[origin]
                self._revoked.add(origin)
                self._suppressed.add(origin)
                self.revision += 1
                self._clear_receipts()
                self._capture_grants = {source: budget for source, budget in self._capture_grants.items()
                                        if source.origin != origin}
                return
        raise ValueError("unknown active grant id")

    def summary(self) -> str:
        """Operator-facing state only; do not renew grants or consume budgets."""
        rows = [f"YOLO: {'on' if self._yolo_enabled else 'off'}",
                f"HTTP session deny: {'on' if self.denied else 'off'}"]
        now = self.clock()
        grants: list[str] = []
        active = 0
        for origin, grant in sorted(self.grants.items()):
            budget = self._budgets[grant.id]
            review_blocked = (origin in self._suppressed and grant.mode == "confirm-each"
                              and not self._yolo_enabled)
            if self.denied or origin in self._revoked or origin in self._blocked_gate or review_blocked:
                state = "blocked"
            elif budget.expired(now):
                state = "expired"
            elif budget.exhausted():
                state = "exhausted"
            else:
                state = "active"
                active += 1
            quota = (f"{max(0, grant.limits.requests - budget.used)} requests left"
                     if grant.limits.requests is not None else "no request quota")
            lifetime = (f"{max(0, grant.expires_at - now):.0f}s left"
                        if grant.expires_at is not None else "session lifetime")
            grants.extend((
                f"{origin.as_url()}: {state}; {grant.mode}",
                f"  {quota}; {lifetime}; {self._inflight.get(origin, 0)}/{grant.limits.concurrency} running",
                f"  Revoke ID: {grant.id}",
            ))
        rows.append(f"HTTP grants: {active} active" if grants else "HTTP grants: none")
        rows.extend(grants)
        if self._suppressed:
            rows.append("HTTP retry needed: " + ", ".join(o.as_url() for o in sorted(self._suppressed)))
        if self._blocked_gate:
            rows.append("Private-host review blocked: " + ", ".join(o.as_url() for o in sorted(self._blocked_gate)))
        if grants:
            rows.append("HTTP grants do not approve scanner jobs.")
        return "\n".join(rows)

    def status(self) -> str:
        rows = [f"HTTP runtime session {self.session_id}; YOLO: {self._yolo_enabled}; session deny: {self.denied}", WARNING]
        for origin, grant in self.grants.items():
            budget = self._budgets[grant.id]
            quota = (f"remaining {max(0, grant.limits.requests-budget.used)} requests"
                     if grant.limits.requests is not None else f"{budget.used} requests used; no request quota")
            lifetime = (f"{max(0, grant.expires_at-self.clock()):.1f}s remaining"
                        if grant.expires_at is not None else "session lifetime")
            rows.append(f"{grant.id} operator/{grant.activation} {origin.as_url()} {grant.mode}; "
                        f"{quota}; {lifetime}; origin active {self._inflight.get(origin, 0)}; {grant.limits.display()}")
        if self._suppressed:
            rows.append("Pending/operator retry needed: " + ", ".join(o.as_url() for o in self._suppressed))
        if self._blocked_gate:
            rows.append("Private-host review declined/pending: " + ", ".join(o.as_url() for o in self._blocked_gate))
        if not self.grants:
            rows.append("No active broad HTTP grants. YOLO activates scoped autonomy where policy permits; "
                        "revocation/session deny require operator retry. Otherwise approve exact requests.")
        return "\n".join(rows)

    def _check(self, action: EffectiveHTTP, target_revision: int) -> None:
        self.engagement.require_in_scope(action.url)
        if self.denied:
            raise HTTPBlocked("blocked: HTTP denied for session; use /permissions retry <origin>")
        if action.epoch != self.epoch or action.target_revision != target_revision or action.scope_revision != self.engagement.revision:
            raise HTTPBlocked("pending: target/scope/session changed; approval invalidated")

    @property
    def revoked_origins(self) -> frozenset[HTTPOrigin]:
        return frozenset(self._revoked)

    def origin_authority(self, origin: HTTPOrigin) -> tuple[str, int, str | None]:
        """Read-only invalidation identity, not permission or request accounting.

        The version also observes replacement from no grant to a grant. Callers
        retain their own operation approval; usage/tokens/inflight are excluded.
        """
        grant = self.grants.get(origin)
        return self.epoch, self._grant_versions.get(origin, 0), grant.id if grant else None

    def revocation_state(self) -> dict[str, Any]:
        return {"denied": self.denied, "origins": [o.as_url() for o in sorted(self._revoked)]}

    def restore_revocations(self, raw: dict[str, Any]) -> None:
        self.denied = raw.get("denied") is True
        self._revoked |= {HTTPOrigin.from_url(url) for url in raw.get("origins", [])}
        for origin in list(self.grants):
            if self.denied or origin in self._revoked:
                del self.grants[origin]
        self.revision += 1
        self._clear_receipts()

    @property
    def target_revision(self) -> int:
        self.sync_target()
        return self._target_revision() if self._target_revision is not None else 0

    def authorize_adapter(self, action: EffectiveHTTP) -> HTTPReceipt:
        """Controller transport entrypoint after the independent operation receipt.

        Not exposed as a tool. Ordinary discovery approval covers its prepared
        operation, rather than asking again for every baseline/verification.
        """
        self.sync_target()
        self._check(action, self.target_revision)
        if action.origin in self._revoked or action.origin in self._blocked_gate:
            raise HTTPBlocked("blocked: origin revoked/private gate declined")
        grant = self.grants.get(action.origin)
        try:
            self._capacity(action, self._budget(action, grant))
        except HTTPPending:
            pass
        return self._mint(action, grant)

    def _budget(self, action: EffectiveHTTP, grant: HTTPGrant | None) -> _Budget:
        now = self.clock()
        if grant is not None:
            return self._budgets[grant.id]
        if action.origin not in self._exact_budgets:
            limits = HTTPLimits()
            self._exact_budgets[action.origin] = self._constraints.get(action.origin) or _Budget(
                limits, now + limits.seconds if limits.seconds is not None else None, limits.burst, now)
        return self._exact_budgets[action.origin]

    def _capacity(self, action: EffectiveHTTP, budget: _Budget) -> None:
        now = self.clock()
        limits = budget.limits
        if budget.expired(now):
            raise HTTPBlocked("blocked: authorization/exact-action execution envelope expired; operator grant required")
        if budget.exhausted():
            raise HTTPBlocked("blocked: request budget exhausted; operator grant required")
        if action.size > limits.request_bytes or action.response_cap > limits.response_bytes:
            raise HTTPBlocked("blocked: request/response byte limit exceeded; operator must change limits")
        if self._inflight.get(action.origin, 0) >= limits.concurrency:
            raise HTTPPending("pending: concurrency limit reached")
        budget.tokens = min(limits.burst, budget.tokens + max(0, now-budget.updated_at)*limits.rate)
        budget.updated_at = now
        if budget.tokens < 1:
            raise HTTPPending("pending: rate limit reached")

    def _mint(self, action: EffectiveHTTP, grant: HTTPGrant | None,
              review_guard: ReviewGuard | None = None) -> HTTPReceipt:
        fields = (uuid.uuid4().hex, self.session_id, self.epoch, action.digest, action.origin,
                  action.scope_revision, action.target_revision, self.revision,
                  review_guard.expires if review_guard else self.clock() + 60,
                  grant.id if grant else None, action.invocation_id)
        receipt = (HTTPReviewTicket(*fields, review_guard=review_guard) if review_guard
                   else HTTPReceipt(*fields))
        # Bound ephemeral receipt storage; expired receipts cannot be reused.
        for old in list(self._receipts.values()):
            if (old.expires_at <= self.clock()
                    or old.review_guard is not None and not old.review_guard.is_current()):
                self.discard_receipt(old)
        if len(self._receipts) >= 1024:
            raise HTTPBlocked("pending: too many outstanding receipts")
        self._receipts[receipt.id] = receipt
        if review_guard is not None:
            self._review_cleanups[receipt.id] = review_guard.on_close(lambda: self.discard_receipt(receipt))
        return receipt

    def review_is_current(self, ticket: HTTPReceipt, action: EffectiveHTTP, target_revision: int) -> bool:
        try:
            self._check_receipt(action, ticket, None, target_revision)
            return True
        except (HTTPBlocked, ValueError):
            return False

    def dispatch_receipt(self, ticket: HTTPReceipt, action: EffectiveHTTP, signal: Any,
                         target_revision: int) -> HTTPReceipt:
        """Mint the dispatch lifetime after independent private-host review."""
        self._check_receipt(action, ticket, signal, target_revision)
        if not isinstance(ticket, HTTPReviewTicket):
            return ticket
        receipt = HTTPReceipt(ticket.id, ticket.session_id, ticket.epoch, ticket.digest, ticket.origin,
                              ticket.scope_revision, ticket.target_revision, ticket.policy_revision,
                              self.clock() + 60, ticket.grant_id, ticket.invocation_id,
                              review_guard=ticket.review_guard)
        self._receipts[receipt.id] = receipt
        return receipt

    def _review_guard(self, prompter: Prompter, signal: Any, condition: Callable[[], bool]) -> ReviewGuard:
        policy = getattr(prompter, 'execution_policy', None)
        stamp = policy.stamp() if policy is not None else None
        return capture_review(signal=signal, clock=self.clock,
                              timeout=policy.review_timeout if policy is not None else self.review_timeout,
                              condition=lambda: condition() and (policy is None or policy.stamp() == stamp))

    @contextmanager
    def reviewed_dispatch(self, action: EffectiveHTTP):
        """Keep the existing authorize API compatible with controller wrappers."""
        token = _review_dispatch.set((self, action.invocation_id))
        try:
            try:
                yield
            except HTTPReviewTimeout:
                raise
            except TimeoutError as exc:
                # authorize() performs review, never transport I/O. Preserve
                # TimeoutError compatibility while identifying this boundary.
                raise HTTPReviewTimeout('pending: HTTP permission review timed out; no dispatch') from exc
        finally:
            _review_dispatch.reset(token)

    def discard_receipt(self, receipt: HTTPReceipt) -> None:
        """Retire only this invocation's unused receipt, never other decisions."""
        known = self._receipts.get(receipt.id)
        if known is not None and known.invocation_id == receipt.invocation_id and known.digest == receipt.digest:
            del self._receipts[receipt.id]
        cleanup = self._review_cleanups.pop(receipt.id, None)
        if cleanup is not None:
            cleanup()

    def _clear_receipts(self, origin: HTTPOrigin | None = None) -> None:
        for receipt in list(self._receipts.values()):
            if origin is None or receipt.origin == origin:
                self.discard_receipt(receipt)

    def check_capture(self, action: EffectiveHTTP, *, reserved: bool = False) -> _Budget | None:
        source = action.capture_source
        if source is None or not source.credential_digest:
            return None
        budget = self._capture_grants.get(source)
        if source.origin != action.origin or budget is None:
            raise CaptureReplayPending("pending: captured credential authorization required")
        # reserve() already accounted for this request before the final check.
        if budget.expired(self.clock()) or budget.exhausted(reserved=reserved):
            raise CaptureReplayPending("pending: captured credential authorization expired/exhausted; use /permissions retry <origin> for review")
        return budget

    async def _authorize_capture(self, action: EffectiveHTTP, budget: _Budget,
                                 prompter: Prompter, signal: Any,
                                 target_revision: Callable[[], int]) -> None:
        source = action.capture_source
        if source is None or not source.credential_digest:
            return
        if source in self._capture_grants:
            self.check_capture(action)
            return
        key = (review_id(), "capture:" + hashlib.sha256(repr(source).encode()).hexdigest())
        if key in self._declined_actions or source in self._capture_pending:
            raise CaptureReplayPending("pending: captured credential review declined or already open")
        # Separate from HTTP autonomy: neither ingestion nor YOLO grants use of
        # an unseen credential. One review approves this bounded source only.
        revision = self.revision
        grant_version = self._grant_versions.get(action.origin, 0)
        guard = self._review_guard(prompter, signal, lambda: (
            action.epoch == self.epoch and action.scope_revision == self.engagement.revision
            and action.target_revision == target_revision() and revision == self.revision
            and grant_version == self._grant_versions.get(action.origin, 0)))
        self._capture_pending.add(source)
        try:
            decision = await prompter.ask(PermissionRequest(
                tool="http_capture_credentials",
                summary=f"Authorize captured credentials for {source.origin.as_url()}",
                detail=(f"source: {source.source}; baseline: {source.baseline_ref}\n"
                        "Use only this immutable capture and its identity for input mutations. "
                        "No redirects or shared HTTP context import. Rights end on target/scope/session reset.\n"
                        + "Capture use inherits the reviewed HTTP lifetime and request limit.\nCurrent HTTP execution limits: "
                        + budget.limits.display() + "\n\n" + action.preview()),
                no_session_cache=True, risk_tier="high-impact", force_operator=True,
                is_current=guard.is_current), signal)
            check_cancelled(signal)
            self.sync_target()
            self._check(action, target_revision())
            if not guard.is_current():
                raise HTTPReviewStale("pending: capture policy changed during review")
            if decision != Decision.ALLOW_ONCE:
                self._declined_actions[key] = action.origin
                def clear_capture_decline() -> None:
                    self._declined_actions.pop(key, None)
                on_review_end(clear_capture_decline)
                raise CaptureReplayPending("pending: operator declined captured credential use; no dispatch")
            # Bound memory without silently renewing expired/exhausted rights.
            if len(self._capture_grants) >= 1024:
                raise HTTPBlocked("pending: capture authorization capacity reached; reset required")
            now = self.clock()
            self._capture_grants[source] = _Budget(budget.limits, budget.expires_at, 0, now)
        finally:
            self._capture_pending.discard(source)

    def revoke_capture(self, baseline_ref: str) -> None:
        """Trusted operator callback; never a model tool or persisted approval."""
        self._capture_grants = {source: budget for source, budget in self._capture_grants.items()
                                if source.baseline_ref != baseline_ref}
        self.revision += 1
        self._clear_receipts()

    async def review_grant(self, url: str, limits: HTTPLimits, mode: str, prompter: Prompter,
                           signal: Any = None, *, is_current: Callable[[], bool] | None = None) -> HTTPGrant | None:
        self.sync_target()
        origin = self.engagement.require_in_scope(url)
        if mode not in {"autonomous", "confirm-each"}:
            raise ValueError("mode must be autonomous or confirm-each")
        if self.denied:
            raise HTTPBlocked("blocked: session deny; operator retry required")
        if origin in self._grant_pending:
            raise HTTPBlocked("pending: equivalent lab grant review already open")
        epoch, revision, scope = self.epoch, self.revision, self.engagement.revision
        grant_version = self._grant_versions.get(origin, 0)
        guard = self._review_guard(prompter, signal, lambda: (
            (epoch, revision, scope) == (self.epoch, self.revision, self.engagement.revision)
            and grant_version == self._grant_versions.get(origin, 0)
            and (is_current is None or is_current())))
        self._grant_pending.add(origin)
        try:
            decision = await prompter.ask(PermissionRequest(
                tool="http_lab_grant", summary=f"Activate {mode} HTTP lab grant for {origin.as_url()}",
                detail=f"issuer: operator; session: {self.session_id}\n{limits.display()}\n\n{WARNING}",
                no_session_cache=True, risk_tier="high-impact", is_current=guard.is_current), signal)
        finally:
            self._grant_pending.discard(origin)
        check_cancelled(signal)
        self.sync_target()
        if not guard.is_current():
            raise HTTPBlocked("pending: policy changed during grant review; operator must review again")
        if decision != Decision.ALLOW_ONCE:
            self._suppressed.add(origin)
            return None
        return self.activate(origin.as_url(), limits, mode)

    @permission_invocation
    async def authorize(self, action: EffectiveHTTP, prompter: Prompter, signal: Any,
                        target_revision: Callable[[], int]) -> HTTPReceipt:
        try:
            async with self._review_slot(action, prompter, signal, target_revision):
                return await self._authorize_active(action, prompter, signal, target_revision)
        except HTTPReviewTimeout:
            raise
        except TimeoutError as exc:
            raise HTTPReviewTimeout('pending: HTTP permission review timed out; no dispatch') from exc

    @asynccontextmanager
    async def _review_slot(self, action, prompter, signal, target_revision):
        self.sync_target()
        self._check(action, target_revision())
        origin = action.origin
        if sum(count for _, count in self._review_locks.values()) >= 1024:
            raise HTTPPending('pending: HTTP review queue capacity reached')
        lock, count = self._review_locks.get(origin, (asyncio.Lock(), 0))
        self._review_locks[origin] = lock, count + 1
        # Queue lease is separate from active human review. Policy and owning
        # turn still bound the wait, and all rights are reread after acquisition.
        guard = self._review_guard(prompter, signal, lambda: (
            action.epoch == self.epoch and action.scope_revision == self.engagement.revision
            and action.target_revision == target_revision()))
        denial_version = self._denial_versions.get(origin, 0)
        acquisition = asyncio.create_task(lock.acquire())
        try:
            while not acquisition.done() or origin in self._grant_pending:
                check_cancelled(signal)
                self.sync_target()
                self._check(action, target_revision())
                if not guard.owner_is_current():
                    raise HTTPBlocked('blocked: HTTP review owner ended')
                if self.clock() >= guard.expires:
                    raise HTTPReviewTimeout('pending: HTTP review queue deadline reached; no dispatch')
                if not guard.is_current():
                    raise HTTPBlocked('blocked: HTTP review queue policy changed')
                if acquisition.done():
                    await asyncio.sleep(0.05)
                else:
                    await asyncio.wait({acquisition}, timeout=0.05)
            acquisition.result()
            check_cancelled(signal)
            if not guard.is_current():
                raise HTTPReviewStale('blocked: stale HTTP queue owner')
            if denial_version != self._denial_versions.get(origin, 0):
                raise HTTPBlocked('blocked: queued HTTP review declined; operator retry required')
            yield
        finally:
            acquisition.cancel()
            joined = asyncio.gather(acquisition, return_exceptions=True)
            interrupted = False
            while not joined.done():
                try:
                    await asyncio.shield(joined)
                except asyncio.CancelledError:
                    interrupted = True
            joined.result()
            if not acquisition.cancelled() and acquisition.exception() is None:
                lock.release()
            _, remaining = self._review_locks[origin]
            if remaining == 1:
                del self._review_locks[origin]
            else:
                self._review_locks[origin] = lock, remaining - 1
            if interrupted:
                raise asyncio.CancelledError

    async def _authorize_active(self, action: EffectiveHTTP, prompter: Prompter, signal: Any,
                                target_revision: Callable[[], int]) -> HTTPReceipt:
        defer_dispatch = _review_dispatch.get() == (self, action.invocation_id)
        self.sync_target()
        check_cancelled(signal)
        self._check(action, target_revision())
        origin = action.origin
        guard = self._review_guard(prompter, signal, lambda: (
            action.epoch == self.epoch and action.scope_revision == self.engagement.revision
            and action.target_revision == target_revision()))
        decline_key = (review_id(), action.digest)
        if origin in self._blocked_gate:
            raise HTTPBlocked("pending: private-host permission declined; operator retry required")
        grant = self.grants.get(origin)
        if origin in self._revoked:
            raise HTTPBlocked("blocked: grant revoked; operator retry/new grant required")
        budget = self._budget(action, grant)
        try:
            self._capacity(action, budget)
        except HTTPPending:
            pass  # Dispatch scheduler waits at most 30s, without asking again.
        if decline_key in self._declined_actions:
            raise HTTPBlocked("pending: exact action declined in this turn; operator retry required")
        if grant is not None and (grant.mode == "autonomous" or self._yolo_enabled):
            await self._authorize_capture(action, budget, prompter, signal, target_revision)
            if not guard.is_current():
                raise HTTPReviewStale('blocked: stale HTTP review owner')
            return self._mint(action, grant, guard if defer_dispatch else None)
        if origin in self._suppressed:
            raise HTTPBlocked("pending: lab grant review previously declined; operator /permissions retry required")
        self._pending.add(origin)
        revision = self.revision
        grant_version = self._grant_versions.get(origin, 0)
        def review_current() -> bool:
            return (guard.is_current() and revision == self.revision
                    and grant_version == self._grant_versions.get(origin, 0))
        try:
            decision = await prompter.ask(PermissionRequest(
                tool="http", summary=action.redact_preview(f"Approve exact HTTP request: {action.method} {action.url}"),
                detail=action.preview() + "\n\n" +
                       ("Once-only execution envelope: " if grant is None else "Current execution limits: ") +
                       budget.limits.display() +
                       "\n\n" + WARNING,
                no_session_cache=True, risk_tier="high-impact", offer_http_lab=grant is None,
                session_scope_display=f"HTTP {origin.as_url()}; all endpoints, methods and payloads; "
                                      "active session; no request quota or fixed grant TTL",
                is_current=review_current), signal)
            check_cancelled(signal)
            self._check(action, target_revision())
            if not review_current():
                if self.clock() >= guard.expires:
                    raise HTTPReviewTimeout('pending: HTTP permission review expired; no dispatch')
                raise HTTPReviewStale("pending: authorization policy changed during review")
            if decision == Decision.ALLOW_SESSION and grant is None:
                grant = self.activate(origin.as_url(), replace(budget.limits, seconds=None, requests=None))
            elif decision == Decision.GRANT_LAB and grant is None:
                grant = await self.review_grant(origin.as_url(), HTTPLimits(), "autonomous", prompter, signal,
                                                is_current=review_current)
                self._check(action, target_revision())
                if grant is None:
                    raise HTTPBlocked("blocked: operator declined lab grant; no dispatch")
            elif decision != Decision.ALLOW_ONCE:
                self._denial_versions[origin] = self._denial_versions.get(origin, 0) + 1
                self._declined_actions[decline_key] = origin
                def clear_decline() -> None:
                    self._declined_actions.pop(decline_key, None)
                on_review_end(clear_decline)
                raise HTTPBlocked("blocked: permission denied by user for http; equivalent reviews suppressed for this turn",
                                  explicit_denial=True)
            try:
                self._capacity(action, self._budget(action, grant))
            except HTTPPending:
                pass
            await self._authorize_capture(action, self._budget(action, grant), prompter, signal, target_revision)
            if not guard.is_current():
                if self.clock() >= guard.expires:
                    raise HTTPReviewTimeout('pending: HTTP permission review expired; no dispatch')
                raise HTTPReviewStale('blocked: stale HTTP review owner')
            return self._mint(action, grant, guard if defer_dispatch else None)
        except PermissionReviewStale as exc:
            if self.clock() >= guard.expires:
                raise HTTPReviewTimeout('pending: HTTP permission review expired; no dispatch') from exc
            raise
        finally:
            self._pending.discard(origin)

    def _check_receipt(self, action: EffectiveHTTP, receipt: HTTPReceipt, signal: Any,
                       target_revision: int) -> HTTPGrant | None:
        self.sync_target()
        check_cancelled(signal)
        self._check(action, target_revision)
        known = self._receipts.get(receipt.id)
        if known is not receipt or receipt.session_id != self.session_id or receipt.epoch != self.epoch:
            raise HTTPBlocked("blocked: unknown/replayed receipt")
        if (receipt.digest != action.digest or receipt.invocation_id != action.invocation_id or receipt.origin != action.origin or
            receipt.scope_revision != action.scope_revision or receipt.target_revision != action.target_revision or
            receipt.policy_revision != self.revision or self.clock() >= receipt.expires_at):
            raise HTTPBlocked("blocked: receipt changed/expired/policy invalidated")
        if isinstance(receipt, HTTPReviewTicket) and (receipt.review_guard is None or not receipt.review_guard.is_current()):
            raise HTTPReviewStale('blocked: stale HTTP review owner')
        if receipt.review_guard is not None and not receipt.review_guard.owner_is_current():
            raise HTTPReviewStale('blocked: stale HTTP review owner')
        grant = self.grants.get(action.origin)
        if action.origin in self._revoked or (receipt.grant_id is not None and (grant is None or grant.id != receipt.grant_id)):
            raise HTTPBlocked("blocked: grant revoked/replaced")
        if receipt.grant_id is None and grant is not None:
            raise HTTPBlocked("blocked: grant changed; new authorization required")
        return grant

    def reserve(self, action: EffectiveHTTP, receipt: HTTPReceipt, signal: Any, target_revision: int) -> HTTPReservation:
        """Atomic check + consume + reserve on the single runtime event loop."""
        grant = self._check_receipt(action, receipt, signal, target_revision)
        if isinstance(receipt, HTTPReviewTicket):
            raise HTTPBlocked('blocked: review-ticket-is-not-dispatch-receipt')
        budget = self._budget(action, grant)
        self._capacity(action, budget)
        capture_budget = self.check_capture(action)
        self.discard_receipt(receipt)
        budget.used += 1
        budget.tokens -= 1
        budget.active += 1
        origin = action.origin
        self._inflight[origin] = self._inflight.get(origin, 0) + 1
        if capture_budget is not None:
            capture_budget.used += 1

        if self.constraint_journal is not None:
            try:
                self.constraint_journal()
            except BaseException:
                budget.used -= 1
                budget.tokens += 1
                budget.active -= 1
                self._inflight[origin] -= 1
                if capture_budget is not None:
                    capture_budget.used -= 1
                raise

        def release_slot() -> None:
            remaining = self._inflight[origin] - 1
            if remaining:
                self._inflight[origin] = remaining
            else:
                del self._inflight[origin]

        return HTTPReservation(budget, release_slot, capture_budget=capture_budget)

    async def reserve_when_ready(self, action: EffectiveHTTP, receipt: HTTPReceipt, signal: Any, target_revision: Callable[[], int]) -> HTTPReservation:
        """Bounded scheduler for already-authorized work, not permission retry.

        No slot/quota held while waiting. Every wake checks revocation/scope,
        receipt lifetime and budgets anew; terminal failures never retry.
        """
        deadline = time.monotonic() + 30
        try:
            for _ in range(600):
                try:
                    return self.reserve(action, receipt, signal, target_revision())
                except HTTPPending:
                    if time.monotonic() >= deadline:
                        break
                    await asyncio.sleep(0.05)
            raise HTTPReviewTimeout("pending: rate/concurrency scheduling deadline reached; no automatic retry/dialog")
        finally:
            self.discard_receipt(receipt)
