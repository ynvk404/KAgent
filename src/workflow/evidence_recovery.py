"""Attempt-scoped repair accounting. It grants no execution or result authority."""
from __future__ import annotations

from copy import deepcopy
import json
from typing import Any


MAX_EVIDENCE_RECOVERY_RETRIES = 2
MAX_EVIDENCE_REJECTIONS = 1 + MAX_EVIDENCE_RECOVERY_RETRIES
# Each repair may need separate proof-write, registration and result turns.
# This bounds terminal repair only; normal validation and max_steps are unchanged.
MAX_TERMINAL_REPAIR_TURNS = 3 * MAX_EVIDENCE_RECOVERY_RETRIES


def restored_budgets(value, attempts) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    budgets = {aid: deepcopy(row) for aid, row in value.items() if aid in attempts
               and isinstance(row, dict) and row.get("candidate_id") == attempts[aid].get("candidate_id")
               and all(type(row.get(k)) is int and 0 <= row[k] <= limit for k, limit in (
                   ("rejections", MAX_EVIDENCE_REJECTIONS + 1),
                   ("repair_turns", MAX_TERMINAL_REPAIR_TURNS + 1)))
               and type(row.get("paused")) is bool and type(row.get("closed")) is bool}
    for row in budgets.values():
        try:
            valid = isinstance(row.get("closure_args"), dict) and len(json.dumps(row["closure_args"])) <= 6000
        except (TypeError, ValueError, RecursionError):
            valid = False
        if not valid:
            # Damaged auxiliary metadata cannot grant fresh submission retries.
            row["closure_args"] = {}
    return budgets


def current_budget(state, cid, *, create=False):
    objective_id = state.objective.id if state.objective else None
    attempt = next((a for a in reversed(list(state.attempts.values()))
                    if a.get("candidate_id") == cid and a.get("objective_id") == objective_id), None)
    if attempt is None:
        return None
    aid = attempt["id"]
    if create and aid not in state.evidence_recovery:
        state.evidence_recovery[aid] = {"candidate_id": cid, "rejections": 0, "repair_turns": 0,
                                      "paused": False, "closed": False, "closure_args": {}}
    return state.evidence_recovery.get(aid)


def carry_continuation_budget(state, attempt):
    # Resume needs fresh rights/observations under the existing contract, but
    # cannot grant fresh submission retries merely by interrupting the run.
    # Explicit retests have a different objective or candidate binding.
    keys = ("candidate_id", "candidate_binding", "session_id", "objective_id", "target_origin")
    for old in reversed(list(state.attempts.values())):
        budget = state.evidence_recovery.get(old["id"])
        if budget and all(old.get(k) == attempt.get(k) for k in keys):
            state.evidence_recovery[attempt["id"]] = deepcopy(budget)
            state.evidence_recovery[attempt["id"]]["closed"] = False
            return


def closure_args(args):
    from src.redaction.redact import redact_payload
    # Only bounded non-traffic bookkeeping survives resume. No IDs are salvaged
    # or observations/parents manufactured for the unresolved closure.
    saved = {k: args[k] for k in ("skill_name", "cleanup_state", "cleanup_status")
             if isinstance(args.get(k), str) and len(args[k]) <= 2000}
    if type(args.get("mutation_performed")) is bool:
        saved["mutation_performed"] = args["mutation_performed"]
    techniques = args.get("techniques")
    if isinstance(techniques, list) and len(techniques) <= 16 and all(isinstance(t, str) and len(t) <= 200 for t in techniques):
        saved["techniques"] = techniques
    if len(json.dumps(saved)) > 6000:
        saved.pop("techniques", None)
        saved.pop("cleanup_status", None)
    safe = redact_payload(saved)
    if len(json.dumps(safe)) > 6000:
        safe.pop("techniques", None)
        safe.pop("cleanup_status", None)
        if len(json.dumps(safe)) > 6000:
            safe = {}
    return safe
