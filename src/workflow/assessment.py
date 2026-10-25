"""Generic admissibility and controller bindings; no vulnerability interpretation.

Source snapshots are bounded redacted representations, not execution permissions.
Producers assign live provenance; persisted historical sources remain distinct.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from typing import Any
from urllib.parse import urlsplit, urljoin
import uuid

from src.target.origin import HTTPOrigin
from src.workflow.evidence.errors import EvidenceSubmissionError

MAX_SOURCES = 32
MAX_MANIFEST_BYTES = 2 * 1024 * 1024


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def candidate_binding(candidate) -> str:
    row = candidate.to_dict().copy()
    # Bookkeeping/enrichment annotations do not alter request ownership.
    for key in ("status", "priority", "signals", "source_skill", "deferred_reason"):
        row.pop(key, None)
    return digest(row)


def references(value: Any, name: str, maximum: int = MAX_SOURCES) -> list[str]:
    if (not isinstance(value, list) or len(value) > maximum
            or any(not isinstance(x, str) or not x or x.strip() != x for x in value)
            or len(set(value)) != len(value)):
        raise EvidenceSubmissionError("INVALID_REFERENCE_LIST", f"{name} must contain distinct bounded source/reference IDs")
    return value


def source_row(item) -> dict[str, Any]:
    row = asdict(item)
    row["body"] = item.body.hex()
    row.pop("retained_hash", None)
    return json.loads(json.dumps(row))


class DuplicateRequestAssociation(ValueError):
    """A duplicate normalized association, without retaining request material."""

    code = "DUPLICATE_REQUEST_ASSOCIATION"
    field = "related_requests"
    repair_hint = (
        "Declare each normalized method and resolved/redacted URL once with one role and required value. "
        "Different bodies, payloads or identities on that route are observations, not separate associations. "
        "Use start_validation with candidate_id alone only when the Candidate already covers the primary request, "
        "current prerequisites are met, and no required supplementary association is lost. "
        "For supplementary conflicts, restate the intended role/requirement and preserve evidence obligations. "
        "Do not invent URLs, merge conflicting declarations, close another attempt or send HTTP to repair arguments."
    )

    def __init__(self, first_index: int, duplicate_index: int) -> None:
        self.indices = (first_index, duplicate_index)
        super().__init__(
            "ambiguous duplicate related request method/URL association; "
            "declare each method/URL once with one role and requirement, "
            "or use distinct actual request URLs"
        )


def request_associations(attempt) -> dict[tuple[str, str], dict[str, Any]]:
    """One exact method/URL has one role and requirement, including on resume."""
    related = attempt.get("related_requests", [])
    if not isinstance(related, list) or len(related) > 16:
        raise ValueError("related_requests must be a bounded list")
    associations = {}
    first_indices = {}
    for index, request in enumerate(related):
        if (not isinstance(request, dict) or not {"role", "method", "url"} <= set(request)
                or set(request) - {"role", "method", "url", "required"}
                or request["role"] not in {"baseline", "control", "trigger", "readback", "cleanup", "auxiliary"}
                or request["method"] not in {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"}
                or not isinstance(request["url"], str)
                or not isinstance(request.get("required", True), bool)):
            raise ValueError("invalid related request association")
        key = (request["method"], request["url"])
        if key in associations:
            raise DuplicateRequestAssociation(first_indices[key], index)
        associations[key] = request
        first_indices[key] = index
    return associations


def source_association(candidate, attempt, row, associations):
    if row.get("source_kind") == "tool-output":
        return "process-output", False
    if row.get("source_kind") not in {"native-http", "imported-capture"}:
        raise ValueError("unsupported primary source kind")
    if HTTPOrigin.from_url(row["url"]) != HTTPOrigin.from_url(candidate.target or attempt.get("target_origin")):
        raise EvidenceSubmissionError("SOURCE_ORIGIN_MISMATCH", "primary evidence origin mismatch")
    path = urlsplit((candidate.endpoint or "").split(" ")[-1]).path
    direct = (not path or urlsplit(row["url"]).path == path) and (not candidate.method or candidate.method == row["method"])
    request = associations.get((row["method"], row["url"]))
    if request is None and not direct:
        from src.redaction.redact import apply as redact
        # Geometry only, taken from actual source metadata. Query/fragment,
        # authority credentials, headers and bodies never enter diagnostics.
        def label(method, url):
            verb = method if method in {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"} else "unknown"
            safe_path = redact(urlsplit(url).path or '/')
            safe_path = ''.join(c for c in safe_path if ord(c) >= 32 and ord(c) != 127)[:240]
            return f'{verb} {safe_path}'
        producer = row.get('producer') if row.get('producer') in {'http', 'scoped-capture-bridge'} else 'unknown'
        raise EvidenceSubmissionError("SOURCE_REQUEST_MISMATCH", "undeclared primary request identity/role mismatch; "
            f"expected primary: {label(candidate.method, candidate.endpoint or '/')}; "
            f"actual: {label(row['method'], row['url'])}; producer={producer}; no related request association")
    if request is not None:
        return request["role"], request.get("required", True)
    return ("imported" if row["source_kind"] == "imported-capture" else "probe"), True


def usable_source(row) -> bool:
    return (row.get("complete") is True and row.get("truncated") is not True
            and row.get("execution_status") == "completed")


def source_usability(row) -> dict[str, Any]:
    """Capture eligibility only; never a vulnerability or effects assessment."""
    reasons = []
    if row.get('truncated') is True:
        reasons.append('truncated')
    if row.get('complete') is not True:
        reasons.append('incomplete')
    if row.get('execution_status') != 'completed':
        reasons.append('execution unfinished')
    return {'terminal_usable': usable_source(row), 'unusable_reasons': reasons}


def require_cleanup_evidence(rows):
    """A declaration cannot substitute for an owned action and later readback."""
    sources = [entry["source"] for entry in rows if usable_source(entry["source"])]
    if not any(cleanup.get("role") == "cleanup" and readback.get("role") == "readback"
               and readback.get("observed_at", -1) >= cleanup.get("observed_at", float("inf"))
               for cleanup in sources for readback in sources):
        raise ValueError("cleanup succeeded requires owned cleanup action and subsequent verification readback")


class EvidenceAdmissibilityError(EvidenceSubmissionError):
    """A manifest repair error, distinct from a missing validation step."""

    def __init__(self, message: str, observation_id: str):
        super().__init__("UNUSABLE_PRIMARY_SOURCE", message, offending_observation_ids=[observation_id])


def require_usable_source(row):
    if usable_source(row):
        return
    reasons = []
    if row.get("truncated") is True:
        reasons.append("truncated")
    if row.get("complete") is not True:
        reasons.append("incomplete")
    if row.get("execution_status") != "completed":
        reasons.append("execution unfinished")
    # Fixed guidance and controller ID only; never echo captured secrets.
    raise EvidenceAdmissibilityError(
        f"evidence-admissibility: source {row['id']} unusable ({', '.join(reasons)}). "
        "Terminal assessment requires completed usable primary evidence. "
        "Read this rejection; select only usable observations supporting the assessment. "
        "When proof or parents change, correct the source proof and dependent claims/excerpts, "
        "then record_evidence again with the correct observation_ids for a new immutable snapshot. "
        "Replace evidence_refs only after registering a corrected snapshot; "
        "never remove a cited proof parent without correcting dependent proof. "
        "Retry at most twice after the initial submission using existing evidence. "
        "Do not edit registered snapshots in place. "
        "Do not add probes just to repair a manifest when existing evidence suffices. "
        "If evidence is insufficient, submit insufficient-evidence; continue validation only "
        "for a separately identified missing validation step.", row['id']
    )


def check_source_requirements(candidate, attempt, rows, *, terminal):
    associations = request_associations(attempt)
    for entry in rows:
        row = entry["source"]
        role, required = source_association(candidate, attempt, row, associations)
        if row.get("role") != role or row.get("required", True) is not required:
            raise ValueError("primary source association mismatch")
        if terminal and required:
            require_usable_source(row)
    if terminal:
        for key, request in associations.items():
            if request.get("required", True) and not any(
                    entry["source"].get("source_kind") in {"native-http", "imported-capture"}
                    and (entry["source"].get("method"), entry["source"].get("url")) == key
                    and usable_source(entry["source"]) for entry in rows):
                raise EvidenceSubmissionError("MISSING_VALIDATION_STEP",
                    "declared required request lacks completed evidence; submit unresolved", validation_step=True)


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
        from src.redaction.redact import apply_evidence
        normalized.append({"role": request["role"], "method": request["method"].upper(), "url": apply_evidence(url),
                           "required": request.get("required", request["role"] != "cleanup")})
    request_associations({"related_requests": normalized})
    from src.redaction.redact import redact_payload
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
    # Effects belong to the attempt, not to a rejected evidence submission.
    # Absence on a historical attempt remains unknown; hydration never invents it.
    row["effects"] = {"dispatches": [], "admissions": [], "declaration": None}
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
    from src.workflow.evidence.recovery import carry_continuation_budget
    carry_continuation_budget(state, row)
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


def invalidate_effect_declaration(effects):
    declaration = effects["declaration"]
    if declaration is not None and declaration["mutation_performed"] is not True:
        # A bounded no-write interpretation does not cover a later action.
        effects["declaration"] = None
    elif declaration is not None and declaration["cleanup_state"] in {"succeeded", "not-required"}:
        declaration.update(cleanup_state="unknown", cleanup_status="Further target action has not been assessed for cleanup")


def begin_dispatch(state, owner, invocation_id, request_hash, admission_id):
    """Synchronous transport handoff facts; no payload, permission or effect claim."""
    if owner is None:
        return None
    attempt = state.attempts.get(owner["id"])
    if attempt is None or any(attempt.get(k) != v for k, v in owner.items()):
        raise ValueError("dispatch attempt ownership changed")
    effects = attempt.get("effects")
    if not isinstance(effects, dict):
        raise ValueError("dispatch attempt bookkeeping unavailable")
    if not admission_id or not any(row["invocation_id"] == admission_id for row in effects["admissions"]):
        raise ValueError("dispatch admission linkage unavailable")
    dispatches = effects["dispatches"]
    if len(dispatches) >= 256:
        raise ValueError("bounded attempt dispatch journal exhausted")
    fact = {"invocation_id": invocation_id, "admission_id": admission_id, "request_hash": request_hash,
            "status": "dispatched", "observation_id": None}
    invalidate_effect_declaration(effects)
    dispatches.append(fact)
    state.mark_committed()
    return fact


def finish_dispatch(state, fact, *, status, observation_id=None):
    if fact is not None:
        fact.update(status=status, observation_id=observation_id)
        state.mark_committed()


def require_idle_attempt(attempt, policy):
    # Finalization requires settled transport facts, including without a live
    # policy (for example restored bookkeeping). Read-only projections do not.
    if any(row['status'] == 'dispatched' for row in attempt['effects']['dispatches']):
        raise ValueError("attempt dispatch still in flight")
    if policy and any(row["invocation_id"] in policy._active_receipts
                      for row in attempt["effects"]["admissions"]):
        raise ValueError("attempt action still in flight")


def attempt_effects(state, attempt, observations=None):
    """Return conservative result fields from current, bounded attempt facts."""
    effects = attempt.get("effects")
    if not isinstance(effects, dict) or set(effects) != {"dispatches", "admissions", "declaration"}:
        raise ValueError("attempt bookkeeping unavailable")
    dispatches, other = effects["dispatches"], effects["admissions"]
    if not isinstance(dispatches, list) or len(dispatches) > 256 or not isinstance(other, list) or len(other) > 256:
        raise ValueError("attempt bookkeeping unavailable")
    if any(not isinstance(row, dict) or not isinstance(row.get("invocation_id"), str)
           or not isinstance(row.get("tool"), str) for row in other):
        raise ValueError("attempt admission bookkeeping unavailable")
    for row in dispatches:
        if (not isinstance(row, dict) or not isinstance(row.get("invocation_id"), str)
                or not isinstance(row.get("request_hash"), str)
                or row.get("status") not in {"dispatched", "completed", "failed", "cancelled"}):
            raise ValueError("attempt bookkeeping unavailable")
    declaration = effects["declaration"]
    # A fresh/retested attempt cannot erase an acknowledged write whose
    # cleanup is still unresolved. Carry bookkeeping, never old source rights.
    prior_write = None
    prior_unresolved = False
    for previous in reversed(list(state.attempts.values())):
        if (previous is attempt or previous.get("candidate_binding") != attempt["candidate_binding"]
                or previous.get("target_origin") != attempt["target_origin"]):
            continue
        result = next((r for r in reversed(state.validation_results) if r.attempt_id == previous["id"]), None)
        prior = ({k: getattr(result, k) for k in ("mutation_performed", "cleanup_state", "cleanup_status")}
                 if result else previous.get("effects", {}).get("declaration"))
        facts = previous.get("effects", {})
        if ((not facts and result is None or facts.get("dispatches")
             or any(row["tool"] != "http" for row in facts.get("admissions", [])))
                and (result is None or result.cleanup_state not in {"not-required", "succeeded"})):
            prior_unresolved = True
        if prior and prior.get("mutation_performed") is True:
            if prior.get("cleanup_state") not in {"not-required", "succeeded"}:
                prior_write = prior
            break
    if prior_write and (declaration is None or declaration.get("mutation_performed") is not True):
        return {k: prior_write[k] for k in ("mutation_performed", "cleanup_state", "cleanup_status")}
    if declaration is not None:
        if not isinstance(declaration, dict):
            raise ValueError("attempt declaration unavailable")
        return {k: declaration[k] for k in ("mutation_performed", "cleanup_state", "cleanup_status")}
    has_sources = any(entry.get("source", {}).get("attempt_id") == attempt["id"]
                      for entry in state.selected_sources.values())
    has_sources = has_sources or bool(observations and any(
        item.attempt_id == attempt["id"] for item in observations._items.values()))
    # HTTP admission is not a transport handoff; finished pre-dispatch
    # failures have no target effect. Other adapters only attest admission.
    if not dispatches and not any(row["tool"] != "http" for row in other) and not has_sources:
        if prior_unresolved:
            return {"mutation_performed": None, "cleanup_state": "unknown",
                    "cleanup_status": "Prior attempt effects/cleanup remain unresolved; no current action dispatched"}
        return {"mutation_performed": False, "cleanup_state": "not-required",
                "cleanup_status": "No target action dispatched in this attempt"}
    return {"mutation_performed": None, "cleanup_state": "unknown",
            "cleanup_status": "Target effects and cleanup have not been established"}


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
    associations = request_associations(attempt) if attempt else {}
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
            raise EvidenceSubmissionError("PRIMARY_REFERENCE_UNAVAILABLE", "primary evidence reference unavailable")
        row = source_row(item)
        if not item.retained_hash or digest(row) != item.retained_hash:
            raise EvidenceSubmissionError("SOURCE_INTEGRITY_MISMATCH", "source retained representation integrity mismatch")
        if not attempt or any(row.get(field) != attempt.get(field if field != "attempt_id" else "id") for field in
                              ("candidate_id", "candidate_binding", "session_id", "objective_id", "epoch", "attempt_id")):
            raise EvidenceSubmissionError("SOURCE_OWNERSHIP_MISMATCH", "source session/epoch/candidate/objective/attempt ownership mismatch")
        if item.source_kind in {"native-http", "imported-capture"}:
            row["role"], row["required"] = source_association(candidate, attempt, row, associations)
            boundary = policy.generic_validation if policy else None
            if item.source_kind == "native-http" and boundary is not None and boundary.started_candidate == candidate.id and item.probe_binding != boundary.probe_identity():
                raise ValueError("generic probe binding mismatch")
        elif item.source_kind == "tool-output":
            row["role"] = "process-output"
            row["required"] = False
        else:
            raise ValueError("unsupported primary source kind")
        rows.append({"source": row, "hash": item.retained_hash})
    if attempt:
        check_source_requirements(candidate, attempt, rows, terminal=terminal)
    if terminal and not rows:
        raise EvidenceSubmissionError("MISSING_PRIMARY_OBSERVATIONS", "terminal assessment requires usable primary evidence")
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
    try:
        check_source_requirements(candidate, attempt, manifest, terminal=True)
    except (ValueError, TypeError, KeyError):
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


def check_excerpts(assessment, manifest, *, terminal=False):
    excerpts = assessment.get("excerpts", [])
    if not isinstance(excerpts, list) or len(excerpts) > 16:
        raise ValueError("excerpts must be a bounded list")
    parents = {entry["source"]["id"]: entry["source"] for entry in manifest}
    for excerpt in excerpts:
        if not isinstance(excerpt, dict) or set(excerpt) != {"source_id", "start", "end", "sha256"}:
            raise ValueError("excerpt requires exact primary source, byte range and hash")
        source = parents.get(excerpt["source_id"])
        if source is None:
            raise EvidenceSubmissionError("EXCERPT_PARENT_UNAVAILABLE", "excerpt parent source unavailable")
        # Optional request metadata may be retained, but citing its body makes
        # completeness relevant even when the request was not required.
        if terminal:
            require_usable_source(source)
        start, end = excerpt["start"], excerpt["end"]
        body = bytes.fromhex(source["body"])
        if (type(start) is not int or type(end) is not int or not 0 <= start < end <= len(body)
                or hashlib.sha256(body[start:end]).hexdigest() != excerpt["sha256"]):
            raise EvidenceSubmissionError("EXCERPT_MISMATCH", "excerpt range/hash mismatch")


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
