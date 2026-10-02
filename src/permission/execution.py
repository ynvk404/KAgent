"""Controller-owned execution policy; tool output/args are never authority.

An approval is separate from resource validation. Bound process tools need the
isolated worker and supported broker transport; never ambient host fallback.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, asdict, is_dataclass
import hashlib
import json
import os
import stat
from pathlib import Path
import time
import uuid
from typing import Any, TYPE_CHECKING

from src.permission.permission import UserControlledRefusal
from src.permission.http_grants import check_cancelled

if TYPE_CHECKING:
    from src.engagement.state import EngagementState


class ExecutionBlocked(UserControlledRefusal):
    pass


@dataclass(frozen=True)
class ExecutionReceipt:
    id: str
    digest: str
    revision: tuple[str, int, int, int]
    expires: float


_active: ContextVar[tuple["ExecutionPolicy", ExecutionReceipt] | None] = ContextVar("execution_receipt", default=None)


def invocation_digest(tool: Any, args: dict[str, Any]) -> str:
    config = getattr(tool, "cfg", None)
    resource = None
    if type(tool).__module__ == "src.tools.file" and args.get("path"):
        path = Path(args["path"]).expanduser().resolve()
        try:
            info = path.stat()
            resource = [str(path), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]
        except FileNotFoundError:
            resource = [str(path), "absent"]
    material = [tool.name(), type(tool).__module__, args,
                asdict(config) if is_dataclass(config) and not isinstance(config, type) else None,
                getattr(tool, "shell_path", None), resource]
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str,
                                     separators=(",", ":")).encode()).hexdigest()


class ExecutionPolicy:
    def __init__(self, engagement: EngagementState, root: Path, *, protected: tuple[Path, ...] = (),
                 clock=time.monotonic, max_calls: int = 10000, concurrency: int = 16):
        self.engagement = engagement
        self.root = root.resolve()
        self.protected = tuple(p.resolve() for p in protected)
        self.clock = clock
        self.max_calls = max_calls
        self.concurrency = concurrency
        self.used = 0
        self.active = 0
        self.revision = 0
        self.yolo = False
        self.revoked: set[str] = set()
        self._receipts: dict[str, ExecutionReceipt] = {}
        self._denied: set[str] = set()
        self._pending: set[str] = set()
        self.input_questions: dict[str, str | None] = {}
        self.journal: Path | None = None
        self.worker: Any = None
        from src.permission.observations import ObservationStore
        self.observations = ObservationStore()
        self.vetted_ips: dict[str, tuple[str, ...]] = {}
        from src.engagement.state import EngagementState
        from src.permission.http_grants import HTTPLimits
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
                                              id(self.worker), self.worker.summary() if self.worker else None],
                                             separators=(",", ":")).encode()).hexdigest()
        return profile, self.revision, self.engagement.revision, self.engagement.http_permissions.revision

    def set_yolo(self, enabled: bool) -> None:
        if self.yolo != enabled:
            self.yolo = enabled
            self.revision += 1
            self._receipts.clear()

    def revoke(self, tool: str = "*") -> None:
        self.revoked.add(tool)
        self.revision += 1
        self._receipts.clear()
        self.persist()

    def restore_tool(self, tool: str) -> None:
        self.revoked.discard(tool)
        self.revision += 1
        self._receipts.clear()
        self.persist()

    def load_journal(self, path: Path) -> None:
        """Trusted controller storage only, never loaded from memory/summary."""
        self.journal = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.observations.attach_storage(path.parent.parent / "observations" / path.name)
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.revoked = set(raw.get("revoked_tools", []))
            self.engagement.http_permissions.restore_revocations(raw.get("http", {}))
            self.engagement.http_permissions.restore_constraints(raw.get("http_constraints", []))
            self.research_permissions.restore_constraints(raw.get("research_constraints", []))
            self.used = max(self.used, int(raw.get("used_calls", 0)))
            self.max_calls = max(1, int(raw.get("max_calls", self.max_calls)))
            self.concurrency = max(1, int(raw.get("concurrency", self.concurrency)))
            self.revision += 1
            self._receipts.clear()

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
        self._receipts.clear()

    def refresh_network(self) -> None:
        self.vetted_ips.clear()
        self.revision += 1
        self._receipts.clear()

    def require_path(self, path: str | Path, *, write: bool = False) -> Path:
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_relative_to(self.root):
            raise ExecutionBlocked("blocked: file-outside-profile; operator must change resource roots")
        if any(resolved.is_relative_to(p) for p in self.protected):
            raise ExecutionBlocked("blocked: protected-control-plane")
        if write and resolved.is_relative_to(self.root / "artifacts/findings"):
            raise ExecutionBlocked("blocked: canonical-finding-store; use verified finding workflow")
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
        if "*" in self.revoked or name in self.revoked:
            raise ExecutionBlocked("blocked: tool/session-revoked")
        module = type(tool).__module__
        if module == "src.tools.mcp_integration" and (self.worker is None or getattr(tool, '_execution_policy', None) is not self):
            raise ExecutionBlocked('blocked: enforcement-unavailable; MCP isolated executor identity unavailable')
        if module in {"src.tools.shell", "src.tools.plugin"} and self.worker is None:
            raise ExecutionBlocked("blocked: enforcement-unavailable; isolated filesystem/network/process adapter required")
        if module not in {"src.tools.http", "src.tools.web", "src.tools.file", "src.tools.search",
                          "src.tools.content_discovery", "src.tools.service_discovery", "src.tools.workflow",
                          "src.tools.finding", "src.tools.coverage", "src.tools.payloads", "src.tools.skill_file",
                          "src.tools.skill_paths", "src.tools.ask", "src.tools.browser_capture", "src.skills.load_skill",
                          "src.tools.shell", "src.tools.plugin", "src.tools.mcp_integration", "src.tools.permission_status"}:
            raise ExecutionBlocked("blocked: enforcement-unavailable; unregistered capability adapter")
        if module == "src.tools.file":
            self.require_path(args.get("path", ""), write="Read" not in type(tool).__name__)
        elif module == "src.tools.search":
            self.require_path(args.get("path") or self.root)
        elif module == "src.tools.http":
            self.require_network(tool.resolve_url(args.get("url", "")))
        elif module == 'src.tools.finding':
            self.engagement.require_in_scope(args.get('url', ''))
        elif module == "src.tools.web":
            self.require_network(args.get("url", "https://html.duckduckgo.com"), research=name == "web_search")
        elif module in {"src.tools.content_discovery", "src.tools.service_discovery"}:
            self.require_network(tool.target.base_url())
            if module.endswith("content_discovery"):
                _, _, mode, cap, _, _ = tool._parameters(args)
                backend = tool._select_backend(mode, cap)
            else:
                _, _, _, mode, _ = tool._parameters(args)
                backend = tool._select_backend(mode)
            if backend == 'ffuf' and (self.worker is None or not tool.target.base_url().startswith('http://')):
                raise ExecutionBlocked('blocked: ffuf requires isolated plaintext HTTP broker (native backend available)')
            if backend == "nmap":
                raise ExecutionBlocked("blocked: enforcement-unavailable; scanner process adapter required (native backend available)")

    def prepare(self, tool: Any, args: dict[str, Any]) -> ExecutionReceipt:
        self.validate(tool, args)
        digest = invocation_digest(tool, args)
        if digest in self._denied:
            raise ExecutionBlocked("blocked: invocation-declined; operator retry required")
        if digest in self._pending:
            raise ExecutionBlocked("pending: equivalent invocation review already open")
        if self.used >= self.max_calls:
            raise ExecutionBlocked("blocked: session-call-budget-exhausted")
        self._receipts = {key: value for key, value in self._receipts.items() if value.expires > self.clock()}
        if len(self._receipts) >= 1024:
            raise ExecutionBlocked("pending: receipt-capacity")
        receipt = ExecutionReceipt(uuid.uuid4().hex, digest, self.stamp(), self.clock() + 60)
        self._receipts[receipt.id] = receipt
        self._pending.add(digest)
        return receipt

    def finish_review(self, receipt: ExecutionReceipt, *, denied: bool = False) -> None:
        self._pending.discard(receipt.digest)
        if denied:
            self._denied.add(receipt.digest)
        self._receipts.pop(receipt.id, None)

    def start(self, receipt: ExecutionReceipt, tool: Any, args: dict[str, Any], signal: Any):
        check_cancelled(signal)
        self.validate(tool, args)
        digest = invocation_digest(tool, args)
        if receipt.digest != digest:
            raise ExecutionBlocked("blocked: execution-arguments-changed")
        if self._receipts.get(receipt.id) != receipt or receipt.revision != self.stamp() or self.clock() >= receipt.expires:
            raise ExecutionBlocked("blocked: stale/replayed-execution-receipt")
        if self.used >= self.max_calls or self.active >= self.concurrency:
            raise ExecutionBlocked("pending: execution-budget/concurrency")
        del self._receipts[receipt.id]
        self._pending.discard(receipt.digest)
        self.used += 1
        self.persist()
        self.active += 1
        return _active.set((self, receipt))

    def stop(self, token) -> None:
        _active.reset(token)
        self.active -= 1

    def nested_allowed(self) -> bool:
        entry = _active.get()
        return entry is not None and entry[0] is self and entry[1].revision == self.stamp()

    def status(self) -> str:
        return (f"Execution profile: {self.root}; YOLO: {self.yolo}; calls: {self.used}/{self.max_calls}; "
                f"active: {self.active}/{self.concurrency}; revoked: {', '.join(sorted(self.revoked)) or '(none)'}\n"
                f"Worker: {self.worker.summary() if self.worker is not None else 'enforcement-unavailable'}; local stdio MCP/HTTP ffuf need compatible configuration; nmap/remote MCP unavailable.\n"
                "Read and export assumptions: lab root is operator-approved input; no general context egress guarantee.")


def policy_for(prompter: Any) -> ExecutionPolicy | None:
    policy = getattr(prompter, "execution_policy", None)
    return policy if isinstance(policy, ExecutionPolicy) else None


def default_execution_policy(engagement: EngagementState, root: Path) -> ExecutionPolicy:
    """Shared CLI/test factory: protected storage is never relaxed by a fixture."""
    runtime = Path(__file__).resolve().parents[2]
    return ExecutionPolicy(engagement, root, protected=(runtime / "src", runtime / "skills",
        runtime / "AGENTS.md", root / ".git", root / ".kagent"))


def guard_process(prompter: Any, tool: Any, args: dict[str, Any]):
    policy = policy_for(prompter)
    if policy is not None:
        if policy.worker is None:
            raise ExecutionBlocked("blocked: enforcement-unavailable; isolated process adapter required")
        if not policy.nested_allowed():
            raise ExecutionBlocked("blocked: process-without-execution-receipt")
        entry = _active.get()
        digest = invocation_digest(tool, args)
        if entry is None or entry[1].digest != digest:
            raise ExecutionBlocked("blocked: effective-process-action-changed")
        return policy.worker
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
