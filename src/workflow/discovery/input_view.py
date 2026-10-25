"""Read-only bounded projection of existing workflow inputs, not a second store."""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from src.workflow.state import INPUT_DISPOSITIONS, AttackSurfaceInput, WorkflowState

INPUT_PAGE_BYTES = 16 * 1024
DEFAULT_INPUT_LIMIT = 20
MAX_INPUT_LIMIT = 25


def input_provenance(state: WorkflowState, item: AttackSurfaceInput) -> dict[str, Any]:
    """Explicit uncertainty from existing references, without body reads or new authority."""
    documents = [link.source_id for link in state.discovery_provenance.values()
                 if link.input_id == item.id and link.locator.startswith('manual:')]
    request_linked = bool(item.baseline_request_ref or item.source_ref and any(
        source.retained_ref == item.source_ref and source.kind in {'http', 'capture'}
        for source in state.discovery_sources.values()))
    kind = ('request-linked' if request_linked else
            'manual-document-attribution' if documents else 'unverified')
    return {'kind': kind, 'document_source_ids': sorted(set(documents))[:8],
            'authentication_requirement': 'unknown',
            'note': ('References do not verify field consumption or an authentication prerequisite. '
                     'Verify exact method, field, media type and documented type before analysis; '
                     'a GET error does not establish POST semantics. Missing credentials alone are not an exclusion.')}


def ordered_inputs(state: WorkflowState) -> list[AttackSurfaceInput]:
    priority = {"pending": 0, "blocked": 1, "analyzed": 2, "dropped": 3}
    return sorted(state.objective_inputs(), key=lambda row: (priority[row.disposition], row.id))


def input_summary(item: AttackSurfaceInput) -> dict[str, Any]:
    # Full samples, templates, transitions and link arrays belong to get_input.
    return {"id": item.id, "method": item.method, "endpoint": (item.endpoint or "")[:200] or None,
            "parameter": (item.parameter or "")[:200] or None, "location": item.location,
            "input_type": item.input_type, "content_type": item.content_type,
            "disposition": item.disposition,
            "disposition_reason": (item.disposition_reason or "")[:200] or None}


def input_page(state: WorkflowState, args: dict[str, Any]) -> dict[str, Any]:
    disposition = args.get("input_disposition")
    if disposition is not None and disposition not in INPUT_DISPOSITIONS:
        raise ValueError("input_disposition must be pending/analyzed/dropped/blocked")
    limit = args.get("input_limit", DEFAULT_INPUT_LIMIT)
    if type(limit) is not int or not 1 <= limit <= MAX_INPUT_LIMIT:
        raise ValueError("input_limit must be an integer from 1 through 25")
    rows = ordered_inputs(state)
    objective = state.objective
    # Disposition affects membership/order even when an explicit filter is used.
    # Unrelated candidates, observations or committed revisions do not stale it.
    snapshot = [state.generation, objective.id if objective else None,
                objective.target_origin if objective else None, disposition,
                [(row.id, row.disposition) for row in rows]]
    binding = hashlib.sha256(json.dumps(snapshot, separators=(",", ":")).encode()).hexdigest()
    selected = [row for row in rows if disposition is None or row.disposition == disposition]
    offset = 0
    cursor = args.get("input_cursor")
    if cursor is not None:
        try:
            if not isinstance(cursor, str) or len(cursor) > 256:
                raise ValueError
            token = json.loads(base64.b64decode(cursor.encode("ascii"), altchars=b"-_", validate=True))
            if (not isinstance(token, list) or len(token) != 2 or token[0] != binding
                    or type(token[1]) is not int or not 0 < token[1] < len(selected)):
                raise ValueError
            offset = token[1]
        except (ValueError, TypeError, UnicodeError):
            raise ValueError("stale/invalid input cursor or filter mismatch; restart list(view=inputs) without input_cursor") from None

    counts = {name: sum(row.disposition == name for row in rows) for name in sorted(INPUT_DISPOSITIONS)}
    count = min(limit, len(selected) - offset)
    while True:
        end = offset + count
        next_cursor = (base64.urlsafe_b64encode(json.dumps([binding, end], separators=(",", ":")).encode()).decode()
                       if end < len(selected) else None)
        page = {"ok": True, "input_counts": {"total": len(rows), **counts},
                "inputs_filtered_total": len(selected), "inputs_returned": count,
                "inputs_complete": next_cursor is None, "next_input_cursor": next_cursor,
                "attack_surface_inputs": [input_summary(row) for row in selected[offset:end]]}
        if len(json.dumps(page, ensure_ascii=True, separators=(",", ":")).encode()) <= INPUT_PAGE_BYTES:
            return page
        count -= 1
        if count < 1:
            raise ValueError("input summary exceeds byte budget; use get_input for exact ID details")
