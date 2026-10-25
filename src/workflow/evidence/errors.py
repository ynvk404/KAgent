"""Stable evidence rejection codes shared by submission and bounded recovery."""
from __future__ import annotations

import json
import re

MAX_PROOF_PARENT_DIAGNOSTICS = 16
MAX_PROOF_PARENT_LINES = 8


class EvidenceSubmissionError(ValueError):
    def __init__(self, code: str, message: str, *, validation_step: bool = False,
                 missing_primary_parents: dict[str, list[int]] | None = None,
                 offending_observation_ids: list[str] | None = None):
        super().__init__(message)
        self.code = code
        self.repair_kind = "validation-step" if validation_step else "manifest"
        self.missing_primary_parents = missing_primary_parents or {}
        self.offending_observation_ids = offending_observation_ids or []

    @property
    def repair_hint(self) -> str:
        if self.code == "MISSING_VALIDATION_START":
            return ("Call start_validation for the current candidate through existing gates and use its returned attempt_id. "
                    "Do not borrow old attempt sources or infer retest authority. If validation cannot start, "
                    "submit an honest unresolved outcome without unavailable references.")
        if self.repair_kind == "validation-step":
            if self.code == 'UNRESOLVED_ORACLE':
                return ('Reassess the selected technique, payload compatibility and competing hypotheses against owned observations. '
                        'Equal intended TRUE/FALSE responses do not establish an evaluated oracle or a completed negative. '
                        'Choose a distinct evidence-supported test only when capabilities, scope and remaining limits permit; '
                        'there is no mandatory technique sequence. Otherwise submit insufficient-evidence. '
                        'For a meaningful negative, declare assessment.oracle_status=established and an observation-grounded oracle_basis; '
                        'these are Agent assessments, not runtime verification of SQL semantics.')
            return ("Identify the predeclared required request still missing usable evidence. "
                    "Continue only that bounded validation step through existing gates, or submit an unresolved outcome.")
        specific = {
            "PROOF_PARENT_MISMATCH": (
                "Compare missing_primary_parents with record_evidence.observation_ids; proof_line_numbers are "
                "1-based lines in the redacted snapshot. Explicit observation fields, headings and table rows "
                "are parent claims, including inconclusive history. Declare every cited source only after "
                "checking its current attempt ownership and usability; a diagnostic ID is not ownership proof. "
                "Keep adverse evidence. record_attempt_state only declares effects and cannot set proof parents; "
                "reordering the same IDs cannot repair a missing parent. "),
            "SOURCE_OWNERSHIP_MISMATCH": (
                "A source may be unowned (captured before start_validation), not necessarily from a prior attempt. "
                "It cannot be adopted or rebound. observations_total counts only the current owned inventory, "
                "not all session traffic. Repair a manifest only with sources already owned by this attempt. "),
            "EVIDENCE_REFERENCE_MISMATCH": (
                "evidence_refs requires canonical ev_... IDs from record_evidence.evidence.id for this Candidate, "
                "never evidence_path, snapshot path or obs_ IDs. Write proof first, register it, then copy the returned ID. "),
            "UNUSABLE_PRIMARY_SOURCE": (
                "A truncated/incomplete primary response cannot support a terminal result, even if its prefix is convincing. "
                "Unusable optional metadata may remain referenced, but required observations and terminal excerpts must be usable. "
                "If proof or dependent claims rely on an unusable source, correct the source proof and dependent confirmation IDs "
                "using complete retained replacements, then register a new snapshot. "
                "If only a proposed assessment excerpt is invalid and the registered proof and parents remain correct, "
                "correct that assessment without rewriting or rebinding the snapshot. "
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
        # Fixed prose never echoes input. The sole contextual diagnostic is a
        # bounded list of canonical observation handles and physical line numbers;
        # never include proof text, paths, payloads, credentials or other IDs.
        error: dict[str, object] = {
            "code": self.code, "action": action, "repair_kind": self.repair_kind,
            "message": str(self), "repair_hint": self.repair_hint,
        }
        if self.offending_observation_ids:
            error['offending_observation_ids'] = [ref for ref in self.offending_observation_ids
                if re.fullmatch(r'obs_[0-9a-f]{32}', ref)][:MAX_PROOF_PARENT_DIAGNOSTICS]
        if self.code == "PROOF_PARENT_MISMATCH" and self.missing_primary_parents:
            gaps = [(reference, sorted(set(line for line in lines if type(line) is int and line > 0)))
                    for reference, lines in self.missing_primary_parents.items()
                    if re.fullmatch(r"obs_[0-9a-f]{32}", reference)]
            gaps = sorted((row for row in gaps if row[1]), key=lambda row: (row[1][0], row[0]))
            error["missing_primary_parent_count"] = len(gaps)
            error["missing_primary_parents"] = [
                {"observation_id": reference, "proof_line_numbers": lines[:MAX_PROOF_PARENT_LINES]}
                for reference, lines in gaps[:MAX_PROOF_PARENT_DIAGNOSTICS]]
            error["missing_primary_parents_truncated"] = (
                len(gaps) > MAX_PROOF_PARENT_DIAGNOSTICS or
                any(len(lines) > MAX_PROOF_PARENT_LINES for _, lines in gaps))
        return f"error: {self}\n" + json.dumps({"ok": False, "error": error})


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
