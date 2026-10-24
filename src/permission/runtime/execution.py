"""Controller-owned execution policy; tool output/args are never authority.

An approval is separate from resource validation. Shell runs directly with a current receipt. Worker-dependent plugins/MCP are unavailable.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, asdict, is_dataclass, field, replace
import hashlib
import json
import os
import stat
from pathlib import Path
import time
import uuid
import math
from typing import Any, TYPE_CHECKING, Callable

from src.tools.common.outcome import annotate_error
from src.permission.permission import UserControlledRefusal
from src.permission.network.grants import check_cancelled
from src.permission.runtime.invocations import review_id, on_review_end, capture_review, ReviewGuard, REVIEW_TIMEOUT_SECONDS

if TYPE_CHECKING:
    from src.engagement.state import EngagementState


class ExecutionBlocked(UserControlledRefusal):
    explicit_denial = False
    error_kind = 'policy_block'


@dataclass(frozen=True)
class ExecutionReceipt:
    id: str
    digest: str
    revision: tuple[str, int, int, int]
    expires: float
    review_id: str = 'library'
    validation_binding: tuple[str, str] | None = None
    review_guard: ReviewGuard | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class ExecutionReview(ExecutionReceipt):
    """Immutable review ticket; cannot dispatch until exchanged for a receipt."""


_active: ContextVar[tuple["ExecutionPolicy", ExecutionReceipt] | None] = ContextVar("execution_receipt", default=None)


def file_resource_identity(path: str | Path) -> tuple:
    resolved = Path(path).expanduser().resolve()
    try:
        info = resolved.stat()
        return str(resolved), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
    except FileNotFoundError:
        return str(resolved), 'absent'


def invocation_digest(tool: Any, args: dict[str, Any]) -> str:
    config = getattr(tool, "cfg", None)
    resource = None
    if type(tool).__module__ == "src.tools.execution.file" and args.get("path"):
        resource = list(file_resource_identity(args['path']))
    material = [tool.name(), type(tool).__module__, args,
                asdict(config) if is_dataclass(config) and not isinstance(config, type) else None,
                getattr(tool, "shell_path", None), resource]
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str,
                                     separators=(",", ":")).encode()).hexdigest()


class ExecutionPolicy:
    def __init__(self, engagement: EngagementState, root: Path, *, protected: tuple[Path, ...] = (),
                 clock=time.monotonic, max_calls: int | None = None, concurrency: int = 16,
                 cwe_mcp_deployment_path: str | Path | None = None,
                 review_timeout: float = REVIEW_TIMEOUT_SECONDS):
        self.engagement = engagement
        self.root = root.resolve()
        self.protected = tuple(p.resolve() for p in protected)
        # Preserve the configured spelling so local catalog validation can reject
        # symlinked and noncanonical roots instead of resolving them away.
        self.cwe_mcp_deployment_path = (Path(cwe_mcp_deployment_path).expanduser()
                                        if cwe_mcp_deployment_path else None)
        self.clock = clock
        if isinstance(review_timeout, bool) or not math.isfinite(review_timeout) or review_timeout <= 0:
            raise ValueError('review_timeout must be positive and finite')
        self.review_timeout = review_timeout
        if max_calls is not None and (type(max_calls) is not int or max_calls <= 0):
            raise ValueError('max_calls must be a positive integer or None')
        if type(concurrency) is not int or concurrency <= 0:
            raise ValueError('concurrency must be a positive integer')
        self.max_calls = max_calls
        self.concurrency = concurrency
        self.used = 0
        self.active = 0
        self.revision = 0
        self.yolo = False
        self.revoked: set[str] = set()
        self._receipts: dict[str, ExecutionReceipt] = {}
        self._active_receipts: dict[str, ExecutionReceipt] = {}
        self._review_cleanups: dict[str, Any] = {}
        self._denied: set[tuple[str, str]] = set()
        self._pending: set[str] = set()
        self.input_questions: dict[str, str | None] = {}
        self.journal: Path | None = None
        self.session_id: str | None = None
        self.generic_validation: Any = None
        from src.permission.runtime.observations import ObservationStore
        self.observations = ObservationStore()
        # Actual controller-managed credential slots; never payload guesses.
        # The CLI closure reads current configuration after provider switches.
        self.internal_secret_values: Callable[[], tuple[str, ...]] = lambda: ()
        self.vetted_ips: dict[str, tuple[str, ...]] = {}
        from src.engagement.state import EngagementState
        from src.permission.network.grants import HTTPLimits
        research = EngagementState()
        research.add_origin("https://html.duckduckgo.com")
        self.research_permissions = research.http_permissions
        self.research_permissions.activate("https://html.duckduckgo.com", HTTPLimits(response_bytes=1024 * 1024))
        self.engagement.http_permissions.constraint_journal = self.persist
        self.research_permissions.constraint_journal = self.persist

    def stamp(self) -> tuple[str, int, int, int]:
        self.engagement.http_permissions.sync_target()
        profile = hashlib.sha256(json.dumps([str(self.root), [str(p) for p in self.protected],
                                              self.max_calls, self.concurrency,
                                              str(self.cwe_mcp_deployment_path or ""),
                                              "direct-shell-v1"],
                                             separators=(",", ":")).encode()).hexdigest()
        return profile, self.revision, self.engagement.revision, self.engagement.http_permissions.revision

    def set_yolo(self, enabled: bool) -> None:
        if self.yolo != enabled:
            self.yolo = enabled
            self.revision += 1
            self._clear_reviews()

    def revoke(self, tool: str = "*") -> None:
        self.revoked.add(tool)
        self.revision += 1
        self._clear_reviews()
        self.persist()

    def restore_tool(self, tool: str) -> None:
        self.revoked.discard(tool)
        self.revision += 1
        self._clear_reviews()
        self.persist()

    def load_journal(self, path: Path) -> None:
        """Trusted controller storage only, never loaded from memory/summary."""
        self.journal = path
        self.session_id = path.stem
        path.parent.mkdir(parents=True, exist_ok=True)
        self.observations.attach_storage(path.parent.parent / "observations" / path.name)
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.revoked = set(raw.get("revoked_tools", []))
            self.engagement.http_permissions.restore_revocations(raw.get("http", {}))
            self.engagement.http_permissions.restore_constraints(raw.get("http_constraints", []))
            self.research_permissions.restore_constraints(raw.get("research_constraints", []))
            self.used = max(self.used, int(raw.get("used_calls", 0)))
            limit = raw.get("max_calls", self.max_calls)
            self.max_calls = max(1, int(limit)) if limit is not None else None
            self.concurrency = max(1, int(raw.get("concurrency", self.concurrency)))
            self.revision += 1
            self._clear_reviews()

    def persist(self) -> None:
        if self.journal is None:
            return
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        temp = self.journal.with_name(self.journal.name + ".tmp")
        data = {"revoked_tools": sorted(self.revoked), "http": self.engagement.http_permissions.revocation_state(),
                "http_constraints": self.engagement.http_permissions.constraint_state(),
                "research_constraints": self.research_permissions.constraint_state(), "used_calls": self.used,
                "max_calls": self.max_calls, "concurrency": self.concurrency}
        with open(temp, "w", encoding="utf-8") as stream:
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        temp.chmod(0o600)
        temp.replace(self.journal)

    def retry(self) -> None:
        """Explicit operator action; never called from tool arguments."""
        self._denied.clear()
        self.input_questions.clear()
        self.revision += 1
        self._clear_reviews()

    def refresh_network(self) -> None:
        self.vetted_ips.clear()
        self.revision += 1
        self._clear_reviews()

    def require_path(self, path: str | Path, *, write: bool = False) -> Path:
        resolved = Path(path).expanduser().resolve()
        boundary = self.generic_validation
        if write and boundary is not None and boundary.restricted():
            candidates = [c for c in boundary.candidates() if c.status == "validating"]
            if len(candidates) != 1:
                raise ExecutionBlocked("blocked: generic proof write requires one active candidate")
            candidate = boundary.require(candidates[0].id)
            expected = boundary.proof_path(candidate)
            if Path(path).expanduser().absolute() != expected or resolved != expected:
                raise ExecutionBlocked("blocked: generic write restricted to candidate proof.md")
        if not resolved.is_relative_to(self.root):
            raise ExecutionBlocked("blocked: file-outside-profile; operator must change resource roots")
        if any(resolved.is_relative_to(p) for p in self.protected):
            raise ExecutionBlocked("blocked: protected-control-plane")
        if write and resolved.is_relative_to(self.root / "artifacts/findings"):
            raise ExecutionBlocked("blocked: canonical-finding-store; use verified finding workflow")
        if write and resolved.is_relative_to(self.root / "findings"):
            raise ExecutionBlocked("blocked: persisted-finding-store; use verified finding workflow")
        if write and self.cwe_mcp_deployment_path is not None:
            deployment = self.cwe_mcp_deployment_path.resolve()
            if resolved.is_relative_to(deployment):
                raise ExecutionBlocked("blocked: CWE adapter control-plane; use explicit setup maintenance")
        if write and (
            resolved.is_relative_to(self.root / "cwe-mcp-deployment")
            or resolved.is_relative_to(Path(__file__).resolve().parents[3] / "components")
        ):
            # The controller imports the reviewed wire contract; the isolated
            # server executes its audited deployment. Model file tools cannot
            # replace either trust anchor, even with a one-shot approval/YOLO.
            # Explicit external setup/maintenance still owns these files. This
            # adds no mounts, network rights or general MCP permission changes.
            raise ExecutionBlocked("blocked: CWE adapter control-plane; use explicit setup maintenance")
        if resolved.exists():
            kind = resolved.stat().st_mode
            if not (stat.S_ISREG(kind) or stat.S_ISDIR(kind)):
                raise ExecutionBlocked("blocked: unsupported-file-resource-type")
        # A second pathname to an inode outside a root is not a trustworthy import.
        if resolved.is_file() and resolved.stat().st_nlink > 1:
            raise ExecutionBlocked("blocked: ambiguous-hardlink; import a separate lab copy")
        return resolved

    def require_network(self, url: str, *, research: bool = False) -> None:
        rights = self.engagement.http_permissions
        if rights.denied or "*" in self.revoked:
            raise ExecutionBlocked("blocked: network/session-revoked")
        if research:
            from src.target.origin import HTTPOrigin
            if HTTPOrigin.from_url(url).as_url() != "https://html.duckduckgo.com":
                raise ExecutionBlocked("blocked: research-destination-outside-profile")
            return
        origin = self.engagement.require_in_scope(url)
        if origin in rights.revoked_origins:
            raise ExecutionBlocked("blocked: origin-revoked")

    def require_evidence(self, artifact: Any, root: Path) -> Path:
        """Allow one controller-managed snapshot, never an arbitrary .kagent read."""
        if not self.nested_allowed() or root.resolve() != self.root:
            raise ExecutionBlocked("blocked: evidence-without-current-receipt")
        source = artifact.source_path
        if not source:
            raise ExecutionBlocked("blocked: managed-evidence-source-missing; re-import required")
        self.require_path(source)
        key = hashlib.sha256(artifact.candidate_id.encode()).hexdigest()[:24]
        path = root / artifact.path
        expected_id = "ev_" + hashlib.sha256(
            f"{artifact.candidate_id}\0{artifact.path}\0{artifact.sha256}".encode()).hexdigest()[:20]
        suffixes = {(self.root / ".kagent/evidence" / key / f"{artifact.sha256}.proof"),
                    (self.root / ".kagent/evidence" / key / "sensitive" / f"{artifact.sha256}.proof")}
        if path not in suffixes or artifact.id != expected_id:
            raise ExecutionBlocked("blocked: unmanaged-evidence-identity")
        if path.resolve() != path or not path.is_file() or path.stat().st_nlink != 1:
            raise ExecutionBlocked("blocked: evidence-resource-changed")
        return path

    def validate(self, tool: Any, args: dict[str, Any]) -> None:
        name = tool.name()
        if self.generic_validation is not None and type(tool).__module__ in {
                "src.tools.http.http_tool", "src.tools.http.web", "src.tools.execution.shell",
                "src.tools.execution.plugin", "src.tools.mcp.integration",
                "src.tools.discovery.content", "src.tools.discovery.service"}:
            boundary = self.generic_validation
            attempt = boundary.state.attempts.get(boundary.durable_attempt, {})
            if attempt.get("status") == "active" and attempt.get("probing_stopped"):
                raise ExecutionBlocked("blocked: probing stopped; finalize the owned validation attempt")
        if self.generic_validation is not None:
            try:
                self.generic_validation.validate_tool(tool, args)
            except (TypeError, ValueError) as exc:
                raise ExecutionBlocked(f"blocked: {exc}") from exc
        if "*" in self.revoked or name in self.revoked:
            raise ExecutionBlocked("blocked: tool/session-revoked")
        module = type(tool).__module__
        if module in {'src.tools.mcp.integration', 'src.tools.execution.plugin'}:
            raise ExecutionBlocked('unavailable: this adapter requires the removed isolated executor; host execution is not enabled')
        if module == 'src.tools.execution.shell' and 'scanner' in args:
            raise ExecutionBlocked('unavailable: external scanner jobs have been removed')
        if module not in {"src.tools.http.http_tool", "src.tools.http.web", "src.tools.execution.file", "src.tools.execution.search",
                          "src.tools.discovery.content", "src.tools.discovery.service", "src.tools.workflow.workflow_tool",
                          "src.tools.workflow.finding", "src.tools.workflow.coverage", "src.tools.skills.payloads", "src.tools.skills.skill_file",
                          "src.tools.skills.paths", "src.tools.common.ask", "src.tools.common.browser_capture", "src.skills.load_skill",
                          "src.tools.execution.shell", "src.tools.execution.plugin", "src.tools.mcp.integration", "src.tools.common.permission_status",
                          "src.tools.common.tool_result"}:
            raise ExecutionBlocked("blocked: enforcement-unavailable; unregistered capability adapter")
        if module == "src.tools.common.tool_result":
            from types import SimpleNamespace
            tool.validate_rights(args, SimpleNamespace(execution_policy=self), receipt=False)
        if module == "src.tools.execution.file":
            self.require_path(args.get("path", ""), write="Read" not in type(tool).__name__)
        elif module == "src.tools.execution.search":
            self.require_path(args.get("path") or self.root)
        elif module == "src.tools.http.http_tool":
            self.require_network(tool.prepare(args)[0].url)
        elif module == 'src.tools.workflow.finding':
            self.engagement.require_in_scope(args.get('url', ''))
        elif module == "src.tools.http.web":
            self.require_network(args.get("url", "https://html.duckduckgo.com"), research=name == "web_search")
        elif module in {"src.tools.discovery.content", "src.tools.discovery.service"}:
            self.require_network(tool.target.base_url())
            tool.validate_args(args)

    def prepare(self, tool: Any, args: dict[str, Any], *, reviewing: bool = False,
                signal: Any = None) -> ExecutionReceipt:
        check_cancelled(signal)
        self.validate(tool, args)
        digest = invocation_digest(tool, args)
        for old in list(self._receipts.values()):
            if not self.review_is_current(old):
                self.finish_review(old)
        if (review_id(), digest) in self._denied:
            raise ExecutionBlocked("blocked: invocation-declined; operator retry required")
        if digest in self._pending:
            raise ExecutionBlocked("pending: equivalent invocation review already open")
        if self.max_calls is not None and self.used >= self.max_calls:
            raise annotate_error(ExecutionBlocked("blocked: session-call-budget-exhausted"), "session")
        if len(self._receipts) >= 1024:
            raise ExecutionBlocked("pending: receipt-capacity")
        guard = capture_review(signal=signal, clock=self.clock,
                               timeout=self.review_timeout if reviewing else 60)
        receipt_type = ExecutionReview if reviewing else ExecutionReceipt
        receipt = receipt_type(uuid.uuid4().hex, digest, self.stamp(), guard.expires,
                               review_id(), review_guard=guard)
        if (tool.name() == "file_write" and self.generic_validation is not None
                and self.generic_validation.restricted()):
            boundary = self.generic_validation
            candidate = next(c for c in boundary.candidates() if c.status == "validating")
            receipt = replace(receipt, validation_binding=(candidate.id, boundary.snapshot(candidate.id)))
        self._receipts[receipt.id] = receipt
        self._pending.add(digest)
        self._review_cleanups[receipt.id] = guard.on_close(lambda: self.finish_review(receipt))
        return receipt

    def _clear_reviews(self) -> None:
        for receipt in list(self._receipts.values()):
            self.finish_review(receipt)

    def finish_review(self, receipt: ExecutionReceipt, *, denied: bool = False) -> None:
        # An old invocation's finally cannot remove a fresh sibling's pending
        # digest after its own ticket was consumed/retired.
        if self._receipts.pop(receipt.id, None) is not None:
            self._pending.discard(receipt.digest)
        cleanup = self._review_cleanups.pop(receipt.id, None)
        if cleanup is not None:
            cleanup()
        if denied:
            key = (receipt.review_id, receipt.digest)
            self._denied.add(key)
            on_review_end(lambda: self._denied.discard(key))

    def dispatch_receipt(self, review: ExecutionReceipt, tool: Any, args: dict[str, Any],
                         signal: Any) -> ExecutionReceipt:
        """Exchange one still-current review for one short dispatch receipt."""
        check_cancelled(signal)
        self.validate(tool, args)
        if not self.review_is_current(review) or review.review_id != review_id():
            raise ExecutionBlocked('blocked: stale execution review')
        if review.digest != invocation_digest(tool, args):
            raise ExecutionBlocked('blocked: execution-arguments-changed')
        if not isinstance(review, ExecutionReview):
            return review
        receipt = ExecutionReceipt(review.id, review.digest, review.revision, self.clock() + 60,
                                   review.review_id, review.validation_binding, review.review_guard)
        self._receipts[receipt.id] = receipt
        return receipt

    def start(self, receipt: ExecutionReceipt, tool: Any, args: dict[str, Any], signal: Any):
        check_cancelled(signal)
        if isinstance(receipt, ExecutionReview):
            raise ExecutionBlocked('blocked: review-ticket-is-not-dispatch-receipt')
        if receipt.validation_binding is not None:
            try:
                if self.generic_validation is None:
                    raise ValueError("generic runtime restriction unavailable")
                self.generic_validation.unchanged(*receipt.validation_binding)
            except ValueError as exc:
                raise ExecutionBlocked(f"blocked: {exc}") from exc
        self.validate(tool, args)
        digest = invocation_digest(tool, args)
        if receipt.digest != digest:
            raise ExecutionBlocked("blocked: execution-arguments-changed")
        if (not self.review_is_current(receipt)
                or receipt.review_id != review_id() or self.clock() >= receipt.expires):
            raise ExecutionBlocked("blocked: stale/replayed-execution-receipt")
        if ((self.max_calls is not None and self.used >= self.max_calls)
                or self.active >= self.concurrency):
            raise ExecutionBlocked("pending: execution-budget/concurrency")
        # Admission remains distinct from transport handoff. It links pending
        # adapters to the owner so disposition cannot race an admitted action.
        if self.generic_validation is not None and type(tool).__module__ in {
                "src.tools.http.http_tool",
                "src.tools.execution.shell", "src.tools.execution.plugin", "src.tools.mcp.integration",
                "src.tools.discovery.content", "src.tools.discovery.service", "src.tools.http.web"}:
            from src.workflow.assessment import source_owner, invalidate_effect_declaration
            owner = source_owner(self)
            if owner is not None:
                state = self.generic_validation.state
                effects = state.attempts[owner["id"]].get("effects")
                if effects is None or len(effects["admissions"]) >= 256:
                    raise ExecutionBlocked("blocked: attempt bookkeeping unavailable")
                if type(tool).__module__ != "src.tools.http.http_tool":
                    invalidate_effect_declaration(effects)
                effects["admissions"].append({"invocation_id": receipt.id, "tool": tool.name()})
                state.mark_committed()
        self.finish_review(receipt)
        self.used += 1
        self.persist()
        self.active += 1
        self._active_receipts[receipt.id] = receipt
        return _active.set((self, receipt))

    def stop(self, token) -> None:
        entry = _active.get()
        _active.reset(token)
        if entry is not None and entry[0] is self:
            self._active_receipts.pop(entry[1].id, None)
        self.active -= 1

    def nested_allowed(self) -> bool:
        entry = _active.get()
        return bool(entry is not None and entry[0] is self and self.execution_is_current(entry[1]))

    def execution_is_current(self, receipt: ExecutionReceipt) -> bool:
        # A consumed receipt authorizes its running operation, not another
        # dispatch. Its short dispatch TTL no longer measures execution time.
        return (self._active_receipts.get(receipt.id) is receipt and receipt.revision == self.stamp()
                and (receipt.review_guard is None or receipt.review_guard.owner_is_current()))

    def active_review_check(self):
        """Capture invocation identity before awaiting; callbacks have other contexts."""
        entry = _active.get()
        return lambda: bool(entry is not None and entry[0] is self and self.execution_is_current(entry[1]))

    def revalidate_active(self, tool: Any, args: dict[str, Any], signal: Any) -> None:
        check_cancelled(signal)
        self.validate(tool, args)
        entry = _active.get()
        if not self.nested_allowed() or entry is None or entry[1].digest != invocation_digest(tool, args):
            raise ExecutionBlocked('blocked: execution-resource/arguments-changed')

    def bind_validation_context(self, state, skills, target) -> None:
        if self.validation_context_matches(state, skills, target):
            return
        if self.generic_validation is not None and self.generic_validation.in_flight:
            raise ExecutionBlocked("blocked: generic validation context changed during probe")
        from src.permission.runtime.generic_validation import GenericValidationBoundary
        self.generic_validation = GenericValidationBoundary(self, state, skills, target)
        from src.workflow.assessment import source_owner
        self.observations.owner_provider = lambda: source_owner(self)

    def validation_context_matches(self, state, skills, target) -> bool:
        return bool(self.generic_validation is not None
                    and self.generic_validation.matches(state, skills, target))

    def review_is_current(self, receipt: ExecutionReceipt, tool: Any = None,
                          args: dict[str, Any] | None = None) -> bool:
        """UI callback check; do not consult the callback task's review context."""
        try:
            return (self._receipts.get(receipt.id) is receipt and receipt.revision == self.stamp()
                    and self.clock() < receipt.expires
                    and (receipt.review_guard is None or receipt.review_guard.is_current())
                    and (tool is None or args is None or receipt.digest == invocation_digest(tool, args)))
        except Exception:
            return False

    def status(self) -> str:
        limit = str(self.max_calls) if self.max_calls is not None else 'no session quota'
        return (f"Execution profile: {self.root}; YOLO: {self.yolo}; calls: {self.used}/{limit}; "
                f"active: {self.active}/{self.concurrency}; revoked: {', '.join(sorted(self.revoked)) or '(none)'}\n"
                "Shell: direct subprocess in project cwd; account filesystem/network rights, no OS isolation. Plugins/MCP requiring the removed executor are unavailable.\n"
                "Read and export assumptions: lab root is operator-approved input; no general context egress guarantee.")


def policy_for(prompter: Any) -> ExecutionPolicy | None:
    policy = getattr(prompter, "execution_policy", None)
    return policy if isinstance(policy, ExecutionPolicy) else None


def default_execution_policy(engagement: EngagementState, root: Path, *,
                             cwe_mcp_deployment_path: str | Path | None = None) -> ExecutionPolicy:
    """Shared CLI/test factory: protected storage is never relaxed by a fixture."""
    runtime = Path(__file__).resolve().parents[3]
    return ExecutionPolicy(engagement, root, protected=(runtime / "src", runtime / "skills",
        runtime / "AGENTS.md", root / ".git", root / ".kagent"),
        cwe_mcp_deployment_path=cwe_mcp_deployment_path)


def guard_process(prompter: Any, tool: Any, args: dict[str, Any]):
    if type(tool).__module__ != 'src.tools.execution.shell':
        raise ExecutionBlocked('unavailable: direct execution is supported only for the native shell adapter')
    policy = policy_for(prompter)
    if policy is not None:
        if not policy.nested_allowed():
            raise ExecutionBlocked("blocked: process-without-execution-receipt")
        entry = _active.get()
        digest = invocation_digest(tool, args)
        if entry is None or entry[1].digest != digest:
            raise ExecutionBlocked("blocked: effective-process-action-changed")
        policy.revalidate_active(tool, args, None)
        return policy
    return None


def current_policy() -> ExecutionPolicy | None:
    entry = _active.get()
    return entry[0] if entry is not None else None


def guard_adapter(tool: Any, args: dict[str, Any], prompter: Any) -> None:
    policy = policy_for(prompter)
    if policy is not None:
        policy.validate(tool, args)
        if not policy.nested_allowed():
            raise ExecutionBlocked("blocked: executor-without-receipt")
