"""Selective admission and continuation for token-saving tool text only."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
import re
from typing import Any, TYPE_CHECKING, cast
import uuid

from src.llm.core.types import Message
from src.paths import project_root
from src.permission.runtime.execution import policy_for, ExecutionBlocked
from src.session.tool_results import (
    ToolResultStore, ResultReference, ResultUnavailable, digest_text, load_references,
)
from src.tools.execution.file import FileReadTool, FileReadToolAlias
from src.tools.execution.shell import ShellTool, BashTool
from src.tools.http.http_tool import HTTPTool
from src.tools.http.web import WebFetchTool, WebSearchTool

if TYPE_CHECKING:
    from src.agent.agent import Agent


@dataclass
class PendingResult:
    message: Message
    original: str
    provenance: dict[str, Any]


def source_provenance(agent: Agent, name: str, args: dict[str, Any]) -> dict[str, Any] | None:
    """Exact reviewed adapters, not names supplied by a plugin/model.

    Search spans an unknown set of separately gated files, and arbitrary MCP
    tools may return semantic receipts. Neither is eligible without a trusted
    per-result source contract. No command, credential, or full URL is saved.
    """
    tool = agent.tools.get(name)
    if tool is None or agent.tools.context_reduction_policy(name) == "preserve":
        return None
    source: dict[str, Any] = {"module": type(tool).__module__, "class": type(tool).__name__,
                              "policy_required": policy_for(agent.prompter) is not None}
    if type(tool) in (ShellTool, BashTool):
        source.update(kind="shell", adapter=digest_text(str(cast(ShellTool, tool).shell_path)))
        policy = policy_for(agent.prompter)
        if policy is not None:
            source["resource_profile"] = shell_profile(policy)
    elif type(tool) in (FileReadTool, FileReadToolAlias):
        path = args.get("path")
        if not isinstance(path, str) or not path:
            return None
        resolved = Path(path).expanduser().resolve()
        root = agent.result_retention.store.project if agent.result_retention.store else project_root()
        # Do not turn reads of managed state, findings or known proof sources
        # into generic token-saving results. This is retention exclusion only;
        # it neither opens nor changes the underlying file-read permission gate.
        if any(resolved.is_relative_to(root / directory) for directory in (
            ".kagent", "artifacts/findings", "artifacts/generic-validation", "findings",
        )):
            return None
        for evidence in agent.workflow.evidence.values():
            if resolved == (root / evidence.path).resolve() or (
                evidence.source_path and resolved == Path(evidence.source_path).resolve()
            ):
                return None
        source.update(kind="file", path=str(resolved))
    elif type(tool) is HTTPTool:
        # Workflow/validation HTTP receipts remain inline. Bounded recon text
        # may be retained; capture/observations are untouched by this branch.
        if args.get("phase") != "recon" or args.get("candidate_id"):
            return None
        from src.target.origin import HTTPOrigin
        source.update(kind="http", origin=HTTPOrigin.from_url(tool.resolve_url(args.get("url", ""))).as_url())
    elif type(tool) is WebFetchTool:
        from src.target.origin import HTTPOrigin
        source.update(kind="http", origin=HTTPOrigin.from_url(args.get("url", "")).as_url())
    elif type(tool) is WebSearchTool:
        source.update(kind="research", origin="https://html.duckduckgo.com")
    else:
        return None
    return source


def shell_profile(policy: Any) -> str:
    # Stable resource restrictions, not an approval or a process identity.
    return digest_text(json.dumps([str(policy.root), [str(path) for path in policy.protected],
        policy.worker.summary() if policy.worker else None,
        str(policy.cwe_mcp_deployment_path or "")], separators=(",", ":")))


def reference_header(ref: ResultReference) -> str:
    # This controller envelope is distinct from untrusted output markers.
    return ("Retained tool result (preview; not evidence or authorization): "
            + json.dumps(asdict(ref), ensure_ascii=False, separators=(",", ":"))
            + "\nUse read_tool_result for an omitted character range. If unavailable/denied, "
              "report that limitation; do not infer unseen content or repeat the action.\n")


def retained_preview(ref: ResultReference, original: str, budget: int) -> str:
    from .agent import MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR, MIDTURN_ELISION_PREFIX, MIDTURN_WINDOW_WEIGHTS
    from .output_bounds import bound_distributed_content
    header = reference_header(ref)
    minimum = max(1, MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR - len(header))
    return header + bound_distributed_content(original, max(minimum, budget - len(header)),
        minimum_retained_length=minimum, elision_prefix=MIDTURN_ELISION_PREFIX,
        weights=MIDTURN_WINDOW_WEIGHTS)


class ResultRetention:
    def __init__(self, agent: Agent):
        self.agent = agent
        policy = policy_for(agent.prompter)
        root = policy.root if policy is not None else project_root()
        self.store: ToolResultStore | None = None
        if agent.store is not None and agent.store.id:
            try:
                self.store = ToolResultStore(root, agent.store.id)
            except (OSError, ValueError):
                pass
        self.scope: dict[str, str] = {}
        self.revision = agent.target.revision
        self.references: dict[str, ResultReference] = {}
        self.pending: dict[int, PendingResult] = {}
        self.refresh_scope()

    def refresh_scope(self) -> None:
        target = digest_text(self.agent.target.base_url())
        if (self.revision != self.agent.target.revision
                or self.scope.get("target") != target):
            self.scope = {"generation": uuid.uuid4().hex, "target": target,
                          "project": self.store.project_id if self.store else ""}
            self.revision = self.agent.target.revision
            self.references.clear()
            self.pending.clear()

    def restore(self, messages: list[Message]) -> None:
        self.pending.clear()
        self.references.clear()
        if not messages or self.store is None:
            return
        scope = messages[0].tool_result_scope
        if (isinstance(scope, dict) and scope.get("project") == self.store.project_id
                and scope.get("target") == digest_text(self.agent.target.base_url())
                and isinstance(scope.get("generation"), str)
                and re.fullmatch(r"[0-9a-f]{32}", scope["generation"])):
            self.scope = dict(scope)
            self.revision = self.agent.target.revision
            for message in messages:
                if message.tool_result_scope != self.scope:
                    continue
                for ref in load_references(message.tool_result_refs):
                    self.references[ref.result_ref] = ref
                    if len(self.references) > self.store.max_results:
                        self.references.clear()
                        return

    def attach(self, message: Message) -> Message:
        self.refresh_scope()
        return replace(message, tool_result_scope=dict(self.scope),
                       tool_result_refs=[asdict(ref) for ref in self.references.values()] or None)

    def continuation(self) -> str:
        self.refresh_scope()
        if not self.references:
            return ""
        rows = [f"{ref.tool_name}: {ref.result_ref}; retained characters={ref.char_length}"
                for ref in self.references.values()]
        return ("\n\nToken-saving tool result index (not evidence or rights; availability is checked on reread):\n"
                + "\n".join(rows)
                + "\nUse read_tool_result with character offsets for omitted regions. "
                  "Do not infer unseen output or rerun an action when retrieval fails.")

    def remember(self, message: Message, args: dict[str, Any], execution: Any) -> None:
        self.refresh_scope()
        if self.store is None or message.tool_status not in {"success", "observation"}:
            return
        try:
            provenance = source_provenance(self.agent, message.name or "", args)
            if (provenance is not None and execution.retention_generation == self.scope["generation"]
                    and execution.retention_provenance == provenance):
                self.pending[id(message)] = PendingResult(message, message.content, provenance)
        except Exception:
            # Optimization must never change the successful execution outcome.
            return

    def admit(self, working: list[Message], tools_tokens: int) -> None:
        from .agent import (approximate_message_tokens, MIDTURN_MIN_SAFETY_TOKENS,
                            MIDTURN_SAFETY_RATIO, MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR,
                            _proportional_reductions, _BoundedToolResult)
        self.refresh_scope()
        agent = self.agent
        threshold = agent.auto_compact_threshold
        total = tools_tokens + approximate_message_tokens(working)
        if self.store is None or threshold <= 0 or total < threshold:
            return
        target = max(0, threshold - max(MIDTURN_MIN_SAFETY_TOKENS, round(threshold * MIDTURN_SAFETY_RATIO)))
        floor = MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR
        candidates = [i for i, msg in enumerate(working)
                      if msg.role == "tool" and len(msg.content) > floor
                      and agent.tools.context_reduction_policy(msg.name) == "adaptive"]
        reductions = _proportional_reductions([len(working[i].content) - floor for i in candidates],
                                             max(0, total - target) * 4)
        for i, reduction in zip(candidates, reductions):
            msg = working[i]
            pending = self.pending.get(id(msg))
            if pending is None or msg.tool_result_refs or reduction <= 0:
                continue
            # Estimate the exact envelope using a fixed-width ID/hash before
            # publication. Admission pays for both reference and schema cost.
            prototype = ResultReference("tr_" + "0" * 32, "0" * 64,
                len(pending.original.encode("utf-8")), len(pending.original), msg.name or "",
                msg.tool_call_id or "", msg.tool_status or "success", msg.tool_error_kind,
                msg.tool_http_status, msg.tool_truncated, pending.provenance["kind"], "0" * 64)
            header = reference_header(prototype)
            budget = max(floor, len(msg.content) - reduction)
            represented = retained_preview(prototype, pending.original, budget)
            reader = agent.tools.get("read_tool_result")
            schema_cost = len(json.dumps(reader.schema())) if reader is not None else 0
            if len(pending.original) - len(represented) <= max(len(header), schema_cost):
                continue
            try:
                ref = self.store.put(pending.original, generation=self.scope["generation"],
                    provenance=pending.provenance, tool_name=prototype.tool_name,
                    tool_call_id=prototype.tool_call_id, status=prototype.status,
                    error_kind=prototype.error_kind, http_status=prototype.http_status,
                    truncated=prototype.truncated)
            except Exception:
                continue
            if ref is None:
                continue
            replacement = replace(msg, content=retained_preview(ref, pending.original, budget),
                                  tool_result_refs=[asdict(ref)], tool_result_scope=dict(self.scope))
            working[i] = replacement
            agent.history[:] = [replacement if entry is msg else entry for entry in agent.history]
            self.references[ref.result_ref] = ref
            self.pending.pop(id(msg), None)
            self.pending[id(replacement)] = PendingResult(replacement, pending.original, pending.provenance)
            agent._bounded_results.pop(id(msg), None)
            agent._bounded_results[id(replacement)] = _BoundedToolResult(replacement, pending.original)

    def lookup(self, result_ref: str) -> ResultReference:
        from src.session.tool_results import valid_ref
        if not valid_ref(result_ref):
            raise ResultUnavailable("invalid tool result reference")
        self.refresh_scope()
        ref = self.references.get(result_ref)
        if ref is None or self.store is None:
            raise ResultUnavailable("tool result reference unavailable in this session/project/target generation")
        return ref

    def validate_capability(self, ref: ResultReference) -> None:
        # Check the owning controller's live skill/generic boundary directly on
        # the original capability, never recursively on the derivative reader.
        if ref.tool_name == "read_tool_result" or not self.agent.is_tool_allowed(ref.tool_name).ok:
            raise ExecutionBlocked("blocked: tool result source capability unavailable")

    def validate_source(self, ref: ResultReference, provenance: dict[str, Any], prompter: Any,
                        *, require_receipt: bool) -> None:
        self.validate_capability(ref)
        policy = policy_for(prompter)
        tool = self.agent.tools.get(ref.tool_name)
        if (tool is None or type(tool).__module__ != provenance.get("module")
                or type(tool).__name__ != provenance.get("class")
                or (provenance.get("policy_required") and policy is None)):
            raise ExecutionBlocked("blocked: tool result source rights unavailable")
        if policy is not None:
            if self.store is None or policy.root != self.store.project:
                raise ExecutionBlocked("blocked: tool result project rights mismatch")
            if require_receipt and not policy.nested_allowed():
                raise ExecutionBlocked("blocked: tool result requires a current execution receipt")
            if "*" in policy.revoked or ref.tool_name in policy.revoked:
                raise ExecutionBlocked("blocked: tool result source revoked")
        if ref.source_kind == "file":
            if type(tool) not in (FileReadTool, FileReadToolAlias) or not isinstance(provenance.get("path"), str):
                raise ExecutionBlocked("blocked: tool result file provenance invalid")
            if policy is not None:
                policy.require_path(provenance["path"])
        elif ref.source_kind == "shell":
            if type(tool) not in (ShellTool, BashTool) or digest_text(str(cast(ShellTool, tool).shell_path)) != provenance.get("adapter"):
                raise ExecutionBlocked("blocked: tool result process adapter changed")
            if policy is not None:
                policy.validate(tool, {})
                if shell_profile(policy) != provenance.get("resource_profile"):
                    raise ExecutionBlocked("blocked: tool result process resource profile changed")
        elif ref.source_kind in {"http", "research"}:
            if type(tool) not in (HTTPTool, WebFetchTool, WebSearchTool):
                raise ExecutionBlocked("blocked: tool result network provenance invalid")
            if policy is not None:
                policy.require_network(provenance.get("origin", ""), research=ref.source_kind == "research")
            elif ref.source_kind != "research":
                self.agent.engagement_state.require_in_scope(provenance.get("origin", ""))
        else:
            raise ExecutionBlocked("blocked: unsupported tool result provenance")
