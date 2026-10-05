"""An opaque, gated character-range reader; no generic filesystem capability."""
from __future__ import annotations

import json
from typing import Any, TYPE_CHECKING

from src.permission.runtime.execution import policy_for, ExecutionBlocked
from src.permission.permission import PermissionRequest, Decision, UserControlledRefusal
from src.permission.network.grants import check_cancelled
from src.session.tool_results import MAX_READ_CHARS, ResultUnavailable, read_region
from src.tools.common.types import PermissionHints
from src.tools.execution.file import gate_sensitive_path

if TYPE_CHECKING:
    from src.agent.tool_results import ResultRetention


class ReadToolResult:
    def __init__(self, retention: ResultRetention):
        self.retention = retention

    def name(self) -> str:
        return "read_tool_result"

    def description(self) -> str:
        return ("Read one bounded character range of a retained sanitized tool result by opaque result_ref. "
                "References grant no evidence or authorization. Missing/denied/corrupt results must be reported; "
                "do not infer unseen content or rerun the original action. Offsets count Unicode characters.")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {
            "result_ref": {"type": "string"},
            "start_char": {"type": "integer"},
            "max_chars": {"type": "integer", "maximum": MAX_READ_CHARS},
        }, "required": ["result_ref", "start_char", "max_chars"], "additionalProperties": False}

    def requires_permission(self) -> bool:
        return True

    def permission_hints(self, args: dict[str, Any]) -> PermissionHints:
        # Every derivative read is a new proposed action. Original approval is
        # never serialized or turned into a cache key for this capability.
        return {"noSessionCache": True, "riskTier": "high-impact",
                "cacheKey": f"result:{args.get('result_ref')}:{args.get('start_char')}:{args.get('max_chars')}"}

    def context_reduction_policy(self):
        return "preserve"

    def validate_args(self, args: dict[str, Any]) -> None:
        if set(args) != {"result_ref", "start_char", "max_chars"}:
            raise ValueError("use only result_ref, start_char and max_chars")
        ref = self.retention.lookup(args["result_ref"])
        self.retention.validate_capability(ref)
        if any(type(args[key]) is not int for key in ("start_char", "max_chars")):
            raise ValueError("tool result offsets must be integer character offsets")

    def validate_rights(self, args: dict[str, Any], prompter: Any, *, receipt: bool) -> None:
        self.validate_args(args)
        ref = self.retention.lookup(args["result_ref"])
        store = self.retention.store
        if store is None:
            raise ResultUnavailable("tool result storage unavailable")
        provenance = store.provenance(ref, self.retention.scope["generation"])
        self.retention.validate_source(ref, provenance, prompter, require_receipt=receipt)

    async def run(self, args: dict[str, Any], signal: Any, prompter: Any) -> str:
        check_cancelled(signal)
        policy = policy_for(prompter)
        if policy is not None and not policy.nested_allowed():
            raise ExecutionBlocked("blocked: tool result read without current execution receipt")
        self.validate_rights(args, prompter, receipt=True)
        if policy is None or not policy.yolo:
            decision = await prompter.ask(PermissionRequest(
                tool=self.name(), summary="Read a retained sanitized tool result range",
                detail=json.dumps(args), no_session_cache=True, risk_tier="high-impact",
                cache_key=self.permission_hints(args).get("cacheKey"),
            ), signal)
            if decision == Decision.DENY:
                raise UserControlledRefusal("retained tool result read denied")
        # A range approval may suspend while skills, policy or scope change.
        # Revalidate before proceeding to the separate sensitive-source review.
        self.validate_rights(args, prompter, receipt=True)
        ref = self.retention.lookup(args["result_ref"])
        store = self.retention.store
        assert store is not None
        generation = self.retention.scope["generation"]
        provenance = store.provenance(ref, generation)
        if ref.source_kind == "file":
            await gate_sensitive_path(prompter, provenance["path"], "read retained result", signal)
        check_cancelled(signal)
        # Scope, rights, provenance and integrity are checked again after any
        # permission suspension. Never silently resolve an old generation.
        if self.retention.lookup(ref.result_ref) != ref or generation != self.retention.scope["generation"]:
            raise ResultUnavailable("tool result target generation changed")
        self.validate_rights(args, prompter, receipt=True)
        text, current = store.resolve(ref, generation)
        if current != provenance:
            raise ResultUnavailable("tool result provenance changed")
        maximum = min(MAX_READ_CHARS, max(0, args["max_chars"]))

        def encode(size: int) -> str:
            return json.dumps({"result_ref": ref.result_ref, "sha256": ref.sha256,
                               "offset_unit": "unicode_characters", "adapter_truncated": ref.truncated,
                               **read_region(text, args["start_char"], size)}, ensure_ascii=False)

        # Preserve a valid range receipt even for heavily escaped text. The
        # response itself fits the existing output floor, without nested
        # previews or another artifact. Actual offsets describe returned text.
        low, high, best = 0, maximum, encode(0)
        while low <= high:
            size = (low + high) // 2
            encoded = encode(size)
            if len(encoded) <= MAX_READ_CHARS:
                best = encoded
                low = size + 1
            else:
                high = size - 1
        return best
