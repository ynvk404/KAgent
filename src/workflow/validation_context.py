"""Read-only handoff derived from canonical records and current runtime stores.

This view is never stored in WorkflowState or SessionFile. Availability is an
observation, not permission, proof, a proposal, or a promise of replayability.
Executors must still validate the actual request through their existing gates.
"""
from __future__ import annotations

from dataclasses import dataclass
from email.message import Message
import json
import re
from typing import Any, TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

import httpx

from src.engagement.state import OutOfScopeError
from src.permission.permission import UserControlledRefusal
from src.tools.http.request_builder import _raw_capture
from src.workflow.state import (
    WorkflowState, candidate_origin, normalize_media_type, normalize_target_origin,
)

if TYPE_CHECKING:
    from src.tools.http.http_tool import HTTPTool


@dataclass(frozen=True)
class ValidationContext:
    """Transient snapshot; canonical records remain the only recorded truth."""

    fields: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        from copy import deepcopy
        return deepcopy(self.fields)


def without_transient_validation_context(content: str, *, truncated: bool = False) -> str:
    """Omit the view before retention/clipping, including response envelopes.

    Malformed text carrying the transient key cannot be separated reliably:
    omit that representation instead of retaining orphan availability claims.
    Valid response metadata and non-transient text remain intact.
    """
    omitted = "[Workflow response omitted: transient runtime context could not be separated safely. Retrieve canonical records and re-derive runtime availability.]"

    def carries_view(text: str) -> bool:
        # Also recognize escaped keys in malformed/partly encoded responses.
        decoded = re.sub(r"\\+u([0-9a-fA-F]{4})", lambda match: chr(int(match[1], 16)), text)
        return "validation_context" in decoded

    def clean(value: Any, depth: int, *, canonical: bool = False) -> tuple[Any, bool]:
        if depth > 32:
            raise ValueError("response nesting exceeds omission limit")
        if isinstance(value, dict):
            result = {}
            changed = "validation_context" in value
            for key, child in value.items():
                if key == "validation_context":
                    continue
                # Canonical samples/templates/signals are untrusted data, not
                # encoded tool-response envelopes. A real parameter can itself
                # be named validation_context; keep that record metadata exact.
                if canonical and (key in {"request_template", "sample_payload"} and isinstance(child, str)
                                  or key == "signals" and isinstance(child, list)
                                  and all(isinstance(item, str) for item in child)):
                    result[key] = child
                    continue
                record = (key in {"candidate", "input"} and isinstance(child, dict)
                          and isinstance(child.get("id"), str)
                          and ("candidate_class" in child or "objective_id" in child))
                result[key], child_changed = clean(child, depth + 1, canonical=record)
                changed |= child_changed
            return result, changed
        if isinstance(value, list):
            result = []
            changed = False
            for child in value:
                child, child_changed = clean(child, depth + 1)
                result.append(child)
                changed |= child_changed
            return result, changed
        if (isinstance(value, str) and carries_view(value)
                and (value.lstrip().startswith(("{", "[", '"', "```"))
                     or re.search(r'''["']validation_context["']''', value))):
            result = strip(value, depth + 1)
            return result, result != value
        return value, False

    def strip(text: str, depth: int) -> str:
        try:
            payload = json.loads(text)
        except (TypeError, ValueError):
            if not carries_view(text):
                return text
            # Preserve ordinary text/fence wrappers around complete JSON.
            for match in re.finditer(r"[\[{]", text):
                try:
                    payload, end = json.JSONDecoder().raw_decode(text, match.start())
                except ValueError:
                    continue
                prefix, suffix = text[:match.start()], text[end:]
                if carries_view(prefix) or carries_view(suffix):
                    continue
                payload, changed = clean(payload, depth + 1)
                if changed:
                    return prefix + json.dumps(payload, ensure_ascii=False, indent=2) + suffix
            return omitted
        payload, changed = clean(payload, depth + 1)
        return json.dumps(payload, ensure_ascii=False, indent=2) if changed else text

    try:
        if not carries_view(content):
            # A truncated workflow representation may have lost the owning
            # key while retaining availability/sample fragments. Its original
            # semantic boundaries cannot be recovered from text alone.
            return omitted if truncated else content
        return strip(content, 0)
    except (ValueError, RecursionError):
        return omitted


def _url(origin: str | None, endpoint: str | None) -> str | None:
    if not origin or not endpoint:
        return None
    resolved = urljoin(origin + "/", endpoint)
    if normalize_target_origin(resolved) != origin:
        raise ValueError("endpoint differs from context origin")
    return resolved


def _enriched_content_type(known: set[str]) -> set[str]:
    """Choose an existing full type only if all known parameters agree.

    Base-only metadata may be enriched; conflicting charset/boundary values
    remain ambiguous. Never synthesize a new executable Content-Type string.
    """
    if len(known) < 2 or len({normalize_media_type(value) for value in known}) != 1:
        return known
    parsed: dict[str, dict[str, str]] = {}
    combined: dict[str, str] = {}
    for value in sorted(known):
        message = Message()
        message["content-type"] = value
        params = dict((message.get_params() or [])[1:])
        if any(name in combined and combined[name] != parameter for name, parameter in params.items()):
            return known
        combined.update(params)
        parsed[value] = params
    exact = [value for value, params in parsed.items() if params == combined]
    return {min(exact)} if exact else known


def resolve_validation_context(
    state: WorkflowState, candidate_id: str, *, target: str | None = None,
    http_tool: HTTPTool | None = None,
) -> ValidationContext:
    """Resolve compatible reverse links without selecting an arbitrary input.

    Unknowns stay None. Conflicting known fields are withheld, even when a
    candidate has a value, so callers cannot mistake ambiguity for exactness.
    No marker, default method, body, selector, or controller intent is invented.
    """
    candidate = state.candidates.get(candidate_id)
    if candidate is None:
        raise ValueError("unknown candidate")
    objective = state.objective
    origin = candidate_origin(candidate.target)
    if origin is not None and candidate_origin(target) not in (None, origin):
        raise ValueError("candidate differs from active target origin")
    if objective is not None:
        if (objective.mode == "candidate_validation" and objective.candidate_id != candidate_id
                or objective.mode != "candidate_validation" and candidate.objective_id != objective.id):
            raise ValueError("candidate differs from active objective")
        if objective.target_origin is not None and origin != objective.target_origin:
            raise ValueError("candidate differs from active objective origin")

    limitations: list[str] = []
    if origin is None:
        limitations.append("target_origin_unknown")
    conflicts: set[str] = set()
    names = ("method", "endpoint", "parameter", "location", "content_type",
             "baseline_request_ref", "auth_context_ref")
    values: dict[str, set[str]] = {name: set() for name in (*names, "sample_payload")}

    def add(record: Any) -> None:
        for name in values:
            value = getattr(record, name, None)
            if value is None:
                continue
            if name == "endpoint":
                try:
                    value = _url(origin, value) if origin else value
                except ValueError:
                    conflicts.add(name)
                    continue
            elif name == "location":
                value = value.lower()
            if value is not None:
                values[name].add(value)

    add(candidate)
    linked = sorted((item for item in state.attack_surface_inputs.values()
                     if candidate_id in item.candidate_ids), key=lambda item: item.id)
    compatible = []
    for item in linked:
        try:
            state.validate_input_candidate(item.id, candidate)
        except ValueError:
            # Never expose a foreign input's sample or refs. Keep the conflict
            # explicit instead of silently falling back to candidate geometry.
            limitations.append("incompatible_linked_input")
            conflicts.update(values)
            continue
        compatible.append(item)
        add(item)
    if objective is not None and objective.mode == "whole_target" and not linked:
        limitations.append("canonical_input_not_linked")

    resolved: dict[str, Any] = {}
    for name, known in values.items():
        if name == "content_type":
            known = _enriched_content_type(known)
        if len(known) > 1:
            conflicts.add(name)
        resolved[name] = next(iter(known)) if len(known) == 1 and name not in conflicts else None
    if conflicts:
        limitations.append("ambiguous_context")
    for name in ("method", "endpoint", "parameter", "location"):
        if resolved[name] is None:
            limitations.append(f"{name}_unknown")
    # Full content types (including charset/boundary) must agree for an exact
    # request. Phase 1 normalized media compatibility alone is insufficient.
    fields: dict[str, Any] = {
        "candidate_id": candidate.id,
        "objective_id": candidate.objective_id,
        "target": candidate.target,
        "target_origin": origin,
        "input_ids": [item.id for item in compatible],
        "resolution": "ambiguous" if conflicts else "resolved" if compatible else "candidate_only",
        **resolved,
        "url": _url(origin, resolved["endpoint"]),
        "media_type": normalize_media_type(resolved["content_type"]),
        "sample_state": ("ambiguous" if "sample_payload" in conflicts else
                         "known_sanitized" if resolved["sample_payload"] is not None else "unknown"),
        "request_template": candidate.request_template,
        "template_state": ("explicit_mutation" if candidate.request_template
                           and "{INJECTION_POINT}" in candidate.request_template
                           else "known_sanitized" if candidate.request_template else "unknown"),
        "provenance": {"source_skill": candidate.source_skill, "source_ref": candidate.source_ref},
        "hypothesis": {"candidate_class": candidate.candidate_class, "test_case": candidate.test_case,
                       "signals": list(candidate.signals), "priority": candidate.priority},
        "conflicting_fields": sorted(conflicts),
        "limitations": limitations,
    }
    baseline, auth = _runtime_availability(state, candidate_id, fields, http_tool)
    fields["baseline"] = baseline
    fields["auth"] = auth
    return ValidationContext(fields)


def _availability(state: str, *, reason: str | None = None) -> dict[str, Any]:
    return {"state": state, "available": state == "available", "reason": reason}


def _runtime_availability(
    state: WorkflowState, candidate_id: str, fields: dict[str, Any], tool: HTTPTool | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    ref, identity = fields["baseline_request_ref"], fields["auth_context_ref"]
    baseline = _availability("missing" if ref is None else "unavailable", reason=None if ref is None else "runtime_missing")
    auth = _availability("unknown" if identity is None else "unavailable", reason=None if identity is None else "runtime_missing")
    if fields["resolution"] == "ambiguous":
        return (_availability("unavailable", reason="ambiguous_context"),
                _availability("unavailable", reason="ambiguous_context"))
    if tool is None:
        return baseline, auth
    if tool.workflow is not state or normalize_target_origin(tool.target.base_url()) != fields["target_origin"]:
        return (_availability("unavailable", reason="runtime_context_mismatch"),
                _availability("unavailable", reason="runtime_context_mismatch"))
    tool.permissions.sync_target()
    tool.context_store.sync_target(tool.target.revision, tool.engagement.revision, tool.permissions.epoch)
    captured_headers: httpx.Headers | None = None
    capture_identity: str | None = None
    runtime_url = fields["url"]
    if ref:
        try:
            row = tool.capture_store.resolve_baseline(ref) if tool.capture_store is not None else None
            if row is None:
                baseline = _availability("stale_or_unbound", reason="recapture_required")
            else:
                try:
                    method, url, headers, _ = _raw_capture(row)
                except (ValueError, UnicodeError, TypeError):
                    baseline = _availability("incomplete_or_unsupported", reason="recapture_required")
                else:
                    tool._require_scope(url)
                    parsed_url = urlsplit(url)
                    parsed_endpoint = urlsplit(runtime_url) if runtime_url is not None else None
                    captured_headers = httpx.Headers(headers)
                    linked = [item for item in state.attack_surface_inputs.values() if candidate_id in item.candidate_ids]
                    candidate = state.candidates[candidate_id]
                    provenance_matches = (state.objective is None or state.objective.mode != "whole_target" or
                                          bool(linked) and all(item.baseline_request_ref == ref and item.auth_context_ref == identity
                                                               and item.source_ref == candidate.source_ref for item in linked))
                    if (parsed_url.username or parsed_url.password
                            or captured_headers.get("content-encoding", "identity").lower() != "identity"):
                        baseline = _availability("incomplete_or_unsupported", reason="recapture_required")
                        captured_headers = None
                    elif (normalize_target_origin(url) != fields["target_origin"]
                            or fields["method"] is not None and method != fields["method"]
                            or parsed_endpoint is not None and
                            (parsed_url.path, parsed_url.query) != (parsed_endpoint.path, parsed_endpoint.query)
                            or fields["media_type"] is not None and
                            normalize_media_type(captured_headers.get("content-type")) != fields["media_type"]
                            or getattr(row, "auth_context_ref", None) not in (None, identity)
                            or not provenance_matches):
                        baseline = _availability("unavailable", reason="binding_mismatch")
                        captured_headers = None
                    else:
                        capture_identity = getattr(row, "auth_context_ref", None)
                        runtime_url = url
                        baseline = _availability("available")
        except (ValueError, OutOfScopeError, UserControlledRefusal):
            baseline = _availability("unavailable", reason="capture_access_denied")
    if identity and runtime_url:
        try:
            tool._require_scope(runtime_url)
            # Only query credential presence; do not prepare an action or infer
            # a missing method. Cookie path/secure/expiry rules remain active.
            request = httpx.Request(fields["method"] or "HEAD", runtime_url)
            cookie = tool.context_store.cookie_for(request, identity)
            authorization = tool.context_store.authorization_for(request, identity)
            auth = _availability("available" if cookie or authorization else "unavailable",
                                 reason=None if cookie or authorization else "live_identity_missing_or_expired")
            if captured_headers is not None and any(key in captured_headers for key in ("cookie", "authorization")):
                if (capture_identity != identity
                        or "cookie" in captured_headers and captured_headers["cookie"] != cookie
                        or "authorization" in captured_headers and captured_headers["authorization"] != authorization):
                    auth = _availability("unavailable", reason="captured_identity_not_live")
        except (ValueError, OutOfScopeError, UserControlledRefusal):
            auth = _availability("unavailable", reason="identity_context_unavailable")
    elif identity:
        auth = _availability("unavailable", reason="endpoint_unknown")
    if captured_headers is not None and any(key in captured_headers for key in ("cookie", "authorization")):
        if auth["state"] != "available":
            baseline = _availability("unavailable", reason="captured_identity_not_live")
    return baseline, auth
