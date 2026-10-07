"""Generic admissibility and controller bindings; no vulnerability interpretation.

Source snapshots are bounded redacted representations, not execution permissions.
Only producers and the optional operator transaction can assign provenance.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from typing import Any
from urllib.parse import urlsplit, urljoin
import uuid

from src.target.origin import HTTPOrigin

MAX_SOURCES = 32
MAX_MANIFEST_BYTES = 2 * 1024 * 1024


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def candidate_binding(candidate) -> str:
    row = candidate.to_dict().copy()
    # Bookkeeping/enrichment annotations do not alter request ownership.
    for key in ("status", "priority", "signals", "source_skill"):
        row.pop(key, None)
    return digest(row)


def references(value: Any, name: str, maximum: int = MAX_SOURCES) -> list[str]:
    if (not isinstance(value, list) or len(value) > maximum
            or any(not isinstance(x, str) or not x or x.strip() != x for x in value)
            or len(set(value)) != len(value)):
        raise ValueError(f"{name} must contain distinct bounded source/reference IDs")
    return value


def source_row(item) -> dict[str, Any]:
    row = asdict(item)
    row["body"] = item.body.hex()
    row.pop("retained_hash", None)
    return json.loads(json.dumps(row))


def start_attempt(state, candidate, session_id, epoch, *, requests=None, criteria=None, target_origin=None, target_revision=None):
    related = requests or []
    if not isinstance(related, list) or len(related) > 16:
        raise ValueError("related_requests must be a bounded list")
    normalized = []
    for request in related:
        if not isinstance(request, dict) or not {"role", "method", "url"} <= set(request) or set(request) - {"role", "method", "url", "required"}:
            raise ValueError("related request requires role, method, url")
        if any(not isinstance(request[k], str) or not request[k] or len(request[k]) > 2000
               for k in ("role", "method", "url")):
            raise ValueError("related request fields must be bounded strings")
        if request["method"].upper() not in {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"}:
            raise ValueError("related request method unavailable")
        if request["role"] not in {"baseline", "control", "trigger", "readback", "cleanup", "auxiliary"}:
            raise ValueError("invalid related request role")
        origin = candidate.target or target_origin or (state.objective.target_origin if state.objective else None)
        if not origin:
            raise ValueError("related request requires an exact declared target origin")
        url = urljoin(origin or "", request["url"])
        if HTTPOrigin.from_url(url) != HTTPOrigin.from_url(origin):
            raise ValueError("related request outside exact target origin")
        if "required" in request and not isinstance(request["required"], bool):
            raise ValueError("related request required must be boolean")
        from src.redact.redact import apply_evidence
        normalized.append({"role": request["role"], "method": request["method"].upper(), "url": apply_evidence(url),
                           "required": request.get("required", request["role"] != "cleanup")})
    from src.redact.redact import redact_payload
    if criteria is not None and (not isinstance(criteria, dict) or len(json.dumps(criteria)) > 6000):
        raise ValueError("attempt assessment criteria must be a bounded object")
    origin = target_origin or candidate.target or (state.objective.target_origin if state.objective else None)
    origin = HTTPOrigin.from_url(origin).as_url() if origin else None
    row = {"id": "attempt_" + uuid.uuid4().hex, "candidate_id": candidate.id,
           "candidate_binding": candidate_binding(candidate), "session_id": session_id,
           "objective_id": state.objective.id if state.objective else None,
           "epoch": epoch, "target_origin": origin, "status": "active", "related_requests": normalized,
           "criteria": redact_payload(criteria), "target_revision": target_revision,
           "result_position": sum(r.candidate_id == candidate.id for r in state.validation_results)}
    for previous in state.attempts.values():
        if previous.get("status") != "active":
            continue
        if previous.get("candidate_id") != candidate.id:
            raise ValueError("another validation attempt is active")
        ownership = ("candidate_binding", "session_id", "objective_id", "epoch", "target_origin", "target_revision", "result_position")
        if all(previous.get(key) == row[key] for key in ownership):
            if ((requests is not None and previous.get("related_requests") != normalized)
                    or (criteria is not None and previous.get("criteria") != row["criteria"])):
                raise ValueError("active attempt declaration changed; close it and start an explicit retest")
            return previous
        # Explicit start after a changed identity seals the old attempt. No
        # old sources or execution context are adopted by the new identity.
        previous["status"] = "interrupted"
    state.attempts[row["id"]] = row
    return row


def source_owner(policy) -> dict[str, Any] | None:
    boundary = policy.generic_validation
    if boundary is None:
        return None
    aid = getattr(boundary, "durable_attempt", None)
    return attempt_owner(boundary.state, aid, policy.engagement.http_permissions.epoch,
                         boundary.target.revision if boundary.target else None,
                         policy.session_id)


def attempt_owner(state, aid, epoch, target_revision, session_id=None):
    row = state.attempts.get(aid)
    if not row or row.get("status") != "active":
        return None
    candidate = state.candidates.get(row["candidate_id"])
    if (candidate is None or candidate.status != "validating"
            or candidate_binding(candidate) != row["candidate_binding"]
            or row["objective_id"] != (state.objective.id if state.objective else None)
            or row["epoch"] != epoch
            or (session_id is not None and row.get("session_id") != session_id)
            or row.get("target_revision") != target_revision
            or row.get("result_position") != sum(r.candidate_id == candidate.id for r in state.validation_results)):

        return None
    return {key: row[key] for key in ("id", "candidate_id", "candidate_binding", "session_id", "objective_id", "epoch")}


def resolve_sources(policy, state, candidate, attempt, ids, *, terminal, negative, store=None):
    rows = []
    for key in references(ids, "observation_ids"):
        source_store = policy.observations if policy else store
        item = source_store._items.get(key) if source_store is not None else None
        if item is None and key in state.selected_sources:
            from src.permission.runtime.observations import Observation
            entry = state.selected_sources[key]
            retained = entry["source"].copy()
            retained.pop("role", None)
            retained.pop("required", None)
            retained["body"] = bytes.fromhex(retained["body"])
            retained["response_headers"] = tuple(tuple(h) for h in retained.get("response_headers", []))
            item = Observation(**retained, retained_hash=entry["hash"])
        if item is None:
            raise ValueError("primary evidence reference unavailable: " + key)
        row = source_row(item)
        if not item.retained_hash or digest(row) != item.retained_hash:
            raise ValueError("source retained representation integrity mismatch")
        if not attempt or any(row.get(field) != attempt.get(field if field != "attempt_id" else "id") for field in
                              ("candidate_id", "candidate_binding", "session_id", "objective_id", "epoch", "attempt_id")):
            raise ValueError("source session/epoch/candidate/objective/attempt ownership mismatch")
        if item.source_kind in {"native-http", "imported-capture"}:
            if HTTPOrigin.from_url(item.url) != HTTPOrigin.from_url(candidate.target or attempt.get("target_origin")):
                raise ValueError("primary evidence origin mismatch")
            path = urlsplit((candidate.endpoint or "").split(" ")[-1]).path
            direct = (not path or urlsplit(item.url).path == path) and (not candidate.method or candidate.method == item.method)
            related = [r for r in attempt["related_requests"] if r["url"] == item.url and r["method"] == item.method]
            if not direct and not related:
                raise ValueError("undeclared primary request identity/role mismatch")
            row["role"] = related[0]["role"] if related else "imported" if item.source_kind == "imported-capture" else "probe"
            row["required"] = related[0].get("required", True) if related else True
            boundary = policy.generic_validation if policy else None
            if item.source_kind == "native-http" and boundary is not None and boundary.started_candidate == candidate.id and item.probe_binding != boundary.probe_identity():
                raise ValueError("generic probe binding mismatch")
        elif item.source_kind == "tool-output":
            row["role"] = "process-output"
            row["required"] = False
        else:
            raise ValueError("unsupported primary source kind")
        if terminal and row["required"] and (not item.complete or item.truncated is True or row.get("execution_status") != "completed"):
            raise ValueError("terminal assessment requires completed usable primary evidence; submit an unresolved outcome")
        rows.append({"source": row, "hash": item.retained_hash})
    if terminal and attempt:
        for request in attempt["related_requests"]:
            if request.get("required", True) and not any(entry["source"]["url"] == request["url"]
                    and entry["source"]["method"] == request["method"] for entry in rows):
                raise ValueError("declared required request lacks completed evidence; submit unresolved")
    if terminal and not rows:
        raise ValueError("terminal assessment requires usable primary evidence")
    if len(json.dumps(rows)) > MAX_MANIFEST_BYTES:
        raise ValueError("selected evidence manifest exceeds bounded storage")
    return rows


def seal(result):
    row = result.to_dict().copy()
    for key in ("assessment_binding", "coverage_synced", "cleanup_state", "cleanup_status"):
        row.pop(key, None)
    return digest(row)


def accepted_result(state, candidate, result, policy=None) -> bool:
    """Resolve a committed assessment, including honest read-only v1 compatibility."""
    if result is None or result.outcome not in {"confirmed", "not-confirmed"}:
        return False
    if result.assessment_contract_version < 2:
        # v1 remains historical. A uniquely current certificate may be displayed;
        # new Agent submissions never use this path to gain authority.
        if policy is None:
            return False
        matches = [r for r in state.validation_results if r.candidate_id == candidate.id
                   and r.evidence_refs == result.evidence_refs and r.outcome == result.outcome]
        legacy = policy.observations.result(candidate.id, tuple(result.evidence_refs),
                                           policy.engagement.http_permissions.epoch, candidate)
        return len(matches) == 1 and legacy is not None and legacy.outcome == result.outcome
    if (result.assessment_source not in {"agent", "operator"} or not result.result_id
            or not result.attempt_id or result.candidate_binding != candidate_binding(candidate)
            or result.assessment_binding != seal(result)
            or not state.evidence_matches(candidate.id, result.evidence_refs)):
        return False
    if policy and policy.session_id is not None and result.session_id != policy.session_id:
        return False
    attempt = state.attempts.get(result.attempt_id)
    if (not attempt or attempt.get("candidate_binding") != result.candidate_binding
            or attempt.get("candidate_id") != candidate.id
            or attempt.get("session_id") != result.session_id
            or attempt.get("objective_id") != result.objective_id
            or result.objective_id != (state.objective.id if state.objective else None)):
        return False
    if result.assessment.get("attempt") != {k:v for k,v in attempt.items() if k != "status"}:
        return False
    manifest = result.evidence_manifest
    if not isinstance(manifest, list) or not 0 < len(manifest) <= MAX_SOURCES:
        return False
    for entry in manifest:
        if not isinstance(entry, dict) or not isinstance(entry.get("source"), dict):
            return False
        row = entry.get("source", {}).copy()
        row.pop("role", None)
        required = row.pop("required", True)
        if digest(row) != entry.get("hash"):
            return False
        if any(row.get(key) != getattr(result, key) for key in
               ("candidate_id", "candidate_binding", "session_id", "objective_id", "attempt_id")):
            return False
        if required and (not row.get("complete") or row.get("truncated") is True or row.get("execution_status") != "completed"):
            return False
        if policy:
            item = policy.observations._items.get(row.get("id"))
            if item is not None and digest(source_row(item)) != entry["hash"]:
                return False
    if not any(entry["source"].get("source_kind") in {"native-http", "imported-capture"}
            and entry["source"].get("complete") and not entry["source"].get("truncated")
            and entry["source"].get("execution_status") == "completed" for entry in manifest):
        return False
    artifacts = result.assessment.get("artifacts", [])
    parents = {ref: state.evidence_sources.get(ref, []) for ref in result.evidence_refs}
    if result.assessment.get("artifact_sources", {ref: [] for ref in result.evidence_refs}) != parents:
        return False
    return artifacts == [state.evidence[ref].to_dict() for ref in result.evidence_refs]


def check_excerpts(assessment, manifest):
    excerpts = assessment.get("excerpts", [])
    if not isinstance(excerpts, list) or len(excerpts) > 16:
        raise ValueError("excerpts must be a bounded list")
    parents = {entry["source"]["id"]: entry["source"] for entry in manifest}
    for excerpt in excerpts:
        if not isinstance(excerpt, dict) or set(excerpt) != {"source_id", "start", "end", "sha256"}:
            raise ValueError("excerpt requires exact primary source, byte range and hash")
        source = parents.get(excerpt["source_id"])
        if source is None:
            raise ValueError("excerpt parent source unavailable")
        start, end = excerpt["start"], excerpt["end"]
        body = bytes.fromhex(source["body"])
        if (type(start) is not int or type(end) is not int or not 0 <= start < end <= len(body)
                or hashlib.sha256(body[start:end]).hexdigest() != excerpt["sha256"]):
            raise ValueError("excerpt range/hash mismatch")


def assessment_provenance(state, candidate, result, policy=None) -> dict[str, Any]:
    """Presentation view; never rewrites historical records or their v1 hashes."""
    if result.assessment_contract_version >= 2:
        return {"source": result.assessment_source or "legacy/unknown", "contract_version": 2}
    if policy is not None and accepted_result(state, candidate, result, policy):
        legacy = policy.observations.result(candidate.id, tuple(result.evidence_refs),
                                           policy.engagement.http_permissions.epoch, candidate)
        if legacy is not None:
            return {"source": "operator" if legacy.verification_source == "operator-reviewed" else "legacy-verifier", "contract_version": 1,
                    "legacy_verification_source": legacy.verification_source}
    return {"source": result.assessment_source or "legacy/unknown", "contract_version": 1}
