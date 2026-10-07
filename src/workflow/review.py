"""Transient snapshots for detecting state changes during operator review."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from src.workflow.state import WorkflowState


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def review_snapshot(state: WorkflowState, candidate_id: str) -> str:
    """Compare complete review state without changing legacy fingerprints.

    Result position also distinguishes a forced identical retest. New reports
    may retain this digest as their historical confirmation binding. It grants
    no proof/classification authority and never reconstructs legacy bindings.
    """
    candidate = state.candidates[candidate_id]
    identity = candidate.to_dict()
    identity.pop("status")  # Workflow's record_result changes status itself.
    result = state.latest_result(candidate_id)
    refs = result.evidence_refs if result else [
        item.id for item in state.evidence.values() if item.candidate_id == candidate_id
    ]
    return digest({
        "candidate": identity,
        "result": result.to_dict() if result else None,
        "position": sum(r.candidate_id == candidate_id for r in state.validation_results),
        "evidence": [state.evidence[ref].to_dict() if ref in state.evidence else None for ref in refs],
    })


def confirmation_binding(state: WorkflowState, candidate_id: str) -> str:
    result = state.latest_result(candidate_id)
    if result is not None and result.assessment_contract_version >= 2:
        return result.assessment_binding or ""
    return review_snapshot(state, candidate_id)
