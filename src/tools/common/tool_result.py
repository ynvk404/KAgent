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


class HTTPObservationUnavailable(ExecutionBlocked):
    error_kind = "reference_unavailable"


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


class ReadHTTPObservation:
    """Session-owned HTTP range access, separate from sanitized tr_ storage."""

    def __init__(self, agent: Any):
        self.agent = agent

    def name(self) -> str:
        return "read_http_observation"

    def description(self) -> str:
        return ("Read a bounded response-body character range of an existing owned obs_ HTTP observation. "
                "Use the returned next_start_char; offsets count decoded Unicode characters. "
                "No HTTP is sent. Retrieval grants no evidence acceptance or ownership. "
                "Unavailable/revoked observations must be reported, never replaced with invented content.")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {
            "observation_id": {"type": "string"},
            "start_char": {"type": "integer", "minimum": 0},
            "max_chars": {"type": "integer", "minimum": 1, "maximum": MAX_READ_CHARS},
        }, "required": ["observation_id", "start_char", "max_chars"], "additionalProperties": False}

    def requires_permission(self) -> bool:
        return True

    def permission_hints(self, args: dict[str, Any]) -> PermissionHints:
        return {"noSessionCache": True, "riskTier": "high-impact",
                "cacheKey": f"observation:{args.get('observation_id')}:{args.get('start_char')}:{args.get('max_chars')}"}

    def context_reduction_policy(self):
        return "preserve"

    def validate_args(self, args: dict[str, Any]) -> None:
        import re
        if (set(args) != {"observation_id", "start_char", "max_chars"}
                or not isinstance(args["observation_id"], str)
                or not re.fullmatch(r"obs_[0-9a-f]{32}", args["observation_id"])
                or type(args["start_char"]) is not int or args["start_char"] < 0
                or type(args["max_chars"]) is not int or not 1 <= args["max_chars"] <= MAX_READ_CHARS):
            raise ValueError("use an obs_ ID and bounded integer character offsets")

    def validate_rights(self, args: dict[str, Any], prompter: Any, *, receipt: bool) -> None:
        self.validate_args(args)
        policy = policy_for(prompter)
        if policy is None or policy is not policy_for(self.agent.prompter):
            raise ExecutionBlocked("blocked: HTTP observation controller unavailable")
        if receipt and not policy.nested_allowed():
            raise ExecutionBlocked("blocked: HTTP observation read without current receipt")
        if "http" in policy.revoked or self.name() in policy.revoked or "*" in policy.revoked:
            raise ExecutionBlocked("blocked: HTTP observation capability revoked")
        item = policy.observations._items.get(args["observation_id"])
        state = self.agent.workflow
        objective = state.objective
        candidate = state.candidates.get(item.candidate_id) if item else None
        attempt = state.attempts.get(item.attempt_id) if item else None
        if (item is None or candidate is None or attempt is None or objective is None
                or item.source_kind not in {"native-http", "imported-capture"}
                or item.objective_id != objective.id
                or not state.candidate_belongs_to_objective(candidate, objective)
                or attempt.get("epoch") != policy.engagement.http_permissions.epoch
                or attempt.get("target_revision") != self.agent.target.revision
                or attempt.get("status") not in {"active", "completed"}
                or objective.target_origin != self.agent.target.origin().as_url()):
            raise HTTPObservationUnavailable(
                'HTTP observation ownership or scope is unavailable. Use workflow(action="list") for current owned observation IDs. Do not rerun HTTP.')
        from src.workflow.assessment import candidate_binding, resolve_sources, attempt_owner
        if candidate_binding(candidate) != item.candidate_binding:
            raise ExecutionBlocked("blocked: HTTP observation candidate binding changed")
        if attempt.get("status") == "active" and attempt_owner(state, attempt["id"],
                policy.engagement.http_permissions.epoch, self.agent.target.revision, policy.session_id) is None:
            raise ExecutionBlocked("blocked: HTTP observation active attempt changed")
        if attempt.get("status") == "completed":
            latest = state.latest_result(candidate.id)
            if (latest is None or latest.attempt_id != attempt["id"] or any(
                    a.get("candidate_id") == candidate.id and a.get("status") == "active"
                    for a in state.attempts.values())):
                raise ExecutionBlocked("blocked: HTTP observation belongs to a superseded attempt")
        session = policy.session_id or policy.engagement.http_permissions.session_id
        if (item.source_details or {}).get("analysis_session") != session:
            raise ExecutionBlocked("blocked: HTTP observation analysis session mismatch")
        policy.require_network(item.url)
        if not self.agent.is_tool_allowed("http").ok:
            raise ExecutionBlocked("blocked: HTTP observation skill capability unavailable")
        resolve_sources(policy, state, candidate, attempt, [item.id], terminal=False, negative=False)
        body = item.body.decode(errors="replace")
        # Check the source before slicing. Otherwise individually harmless
        # ranges could reconstruct a secret hidden in the original response.
        if any(secret in body for secret in self.agent._managed_http_secrets()):
            raise ExecutionBlocked("blocked: retained HTTP body contains a known internal secret")
        if args["start_char"] > len(body):
            raise ValueError("HTTP observation character offset exceeds retained body")

    async def run(self, args: dict[str, Any], signal: Any, prompter: Any) -> str:
        check_cancelled(signal)
        self.validate_rights(args, prompter, receipt=True)
        policy = policy_for(prompter)
        assert policy is not None
        if not policy.yolo:
            decision = await prompter.ask(PermissionRequest(
                tool=self.name(), summary="Read an existing HTTP observation range",
                detail=json.dumps(args), no_session_cache=True, risk_tier="high-impact",
                cache_key=self.permission_hints(args).get("cacheKey"),
            ), signal)
            if decision == Decision.DENY:
                raise UserControlledRefusal("HTTP observation range read denied")
        check_cancelled(signal)
        self.validate_rights(args, prompter, receipt=True)
        item = policy.observations._items[args["observation_id"]]
        assert item.retained_hash is not None
        text = item.body.decode(errors="replace")
        from src.tools.common.outcome import ToolOutput
        # Use the same lab HTTP outbound analysis guard as native capture. The
        # envelope stays small and body offsets describe only retained text.
        def encode(size):
            region = read_region(text, args["start_char"], size)
            body = region.pop("content")
            header = json.dumps({"observation_id": item.id, "retained_hash": item.retained_hash,
                "status": item.status, "elapsed_ms": item.elapsed_ms, "request_hash": item.request_hash,
                "offset_unit": "unicode_characters", "complete": item.complete,
                "adapter_truncated": item.truncated, "start_char": region["actual_start"],
                "end_char": region["actual_end"], "source_chars": region["total_length"],
                "next_start_char": region["next_offset"]}, ensure_ascii=False) + "\n"
            return header + body, len(header), region
        low, high = 0, args["max_chars"]
        best = encode(0)
        while low <= high:
            middle = (low + high) // 2
            value = encode(middle)
            if len(value[0]) <= MAX_READ_CHARS:
                best = value
                low = middle + 1
            else:
                high = middle - 1
        output = ToolOutput(best[0], truncated=bool(best[2]["next_offset"] is not None))
        output.http_sources = ((item.id, item.retained_hash),)
        output.http_body_ranges = ((best[1], len(output)),)
        output.http_session = policy.session_id or policy.engagement.http_permissions.session_id
        output.http_stamp = policy.stamp()
        return output
