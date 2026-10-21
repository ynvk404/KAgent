"""Stable evidence rejection codes shared by submission and bounded recovery."""
from __future__ import annotations

import json


class EvidenceSubmissionError(ValueError):
    def __init__(self, code: str, message: str, *, validation_step: bool = False):
        super().__init__(message)
        self.code = code
        self.repair_kind = "validation-step" if validation_step else "manifest"

    @property
    def repair_hint(self) -> str:
        if self.code == "MISSING_VALIDATION_START":
            return ("Call start_validation for the current candidate through existing gates and use its returned attempt_id. "
                    "Do not borrow old attempt sources or infer retest authority. If validation cannot start, "
                    "submit an honest unresolved outcome without unavailable references.")
        if self.repair_kind == "validation-step":
            return ("Identify the predeclared required request still missing usable evidence. "
                    "Continue only that bounded validation step through existing gates, or submit an unresolved outcome.")
        specific = {
            "SOURCE_OWNERSHIP_MISMATCH": (
                "A source may be unowned (captured before start_validation), not necessarily from a prior attempt. "
                "It cannot be adopted or rebound. observations_total counts only the current owned inventory, "
                "not all session traffic. Repair a manifest only with sources already owned by this attempt. "),
            "EVIDENCE_REFERENCE_MISMATCH": (
                "evidence_refs requires canonical ev_... IDs from record_evidence.evidence.id for this Candidate, "
                "never evidence_path, snapshot path or obs_ IDs. Write proof first, register it, then copy the returned ID. "),
            "UNUSABLE_PRIMARY_SOURCE": (
                "A truncated/incomplete primary response cannot support a terminal result, even if its prefix is convincing. "
                "Local pagination cannot recover bytes never captured. If no sufficient usable source already exists, "
                "identify the missing bounded validation step: obtain a complete, compact, non-sensitive response "
                "through existing scope/permission/attempt gates (for example a minimal marker/count, no credentials or bulk data). "
                "Do not increase caps or retry budgets. If that step cannot be completed, record insufficient-evidence "
                "with the limitation; report it as inconclusive. "),
        }.get(self.code, "")
        return specific + ("Inspect the current candidate/attempt ledger and use only real, correctly owned references. "
                "Reuse usable observations already captured; do not recapture HTTP just to repair a submission. "
                "For changed proof/parents, correct the source file and dependent claims/excerpts, then call "
                "record_evidence again with the correct observation_ids and replace evidence_refs. "
                "Never edit registered snapshots or rebind their parents. Retry at most twice after the initial "
                "submission within this attempt's recovery budget; continuation does not reset it. "
                "If no usable primary evidence "
                "exists, submit insufficient-evidence with a reason and omit unavailable references.")

    def response(self, action: str) -> str:
        # The message and hint contain fixed diagnostics, never supplied IDs,
        # paths, response bodies or request credentials.
        return f"error: {self}\n" + json.dumps({"ok": False, "error": {
            "code": self.code, "action": action, "repair_kind": self.repair_kind,
            "message": str(self), "repair_hint": self.repair_hint,
        }})


def evidence_repair_kind(value: str) -> str | None:
    """Read the structured envelope, independent of diagnostic wording."""
    if not value.startswith("error:") or "\n" not in value:
        return None
    try:
        error = json.loads(value.split("\n", 1)[1])["error"]
        if isinstance(error.get("code"), str) and error.get("repair_kind") in {"manifest", "validation-step"}:
            return error["repair_kind"]
    except (ValueError, KeyError, TypeError, AttributeError):
        pass
    return None
