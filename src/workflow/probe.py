"""Non-authoritative, transient proposals for one bounded HTTP comparison.

There are deliberately no safety claims, grants, receipts or conclusions here.
Only the controller may bind verified endpoint/action facts in the executor.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class ProbeProposal:
    candidate_id: str
    objective_id: str
    target_origin: str
    endpoint: str
    method: str
    location: str
    parameter: str
    values: tuple[str, ...]
    baseline_request_ref: str | None = None
    auth_context_ref: str | None = None
    occurrence: int = 0
    input_path: str | None = None
    observation: str = "compare-response"
    capture: str = "native-http+candidate-proof"
    stop: str = "after-comparison"

    def to_dict(self) -> dict[str, Any]:
        raw = asdict(self)
        raw["values"] = list(self.values)
        return raw

    @staticmethod
    def schema() -> dict[str, Any]:
        # Keep the shared tool-schema budget: strict field/type validation is
        # performed by parse(), while the model gets the concrete interface.
        return {
            "type": "object",
            "description": (
                "Generic start: candidate_id/objective_id/target_origin/endpoint/method/location/parameter; "
                "values:[strings]. Optional baseline_request_ref/auth_context_ref/occurrence/input_path. "
                "Defaults observation=compare-response, "
                "capture=native-http+candidate-proof, stop=after-comparison. "
                "Matching controller-verified action context required; no authority."
            ),
        }

    @classmethod
    def parse(cls, raw: Any) -> ProbeProposal:
        if not isinstance(raw, dict) or set(raw) - set(cls.__dataclass_fields__):
            raise ValueError("generic probe must be a structured proposal without safety/authority claims")
        required = ("candidate_id", "objective_id", "target_origin", "endpoint",
                    "method", "location", "parameter")
        if any(not isinstance(raw.get(key), str) or not raw[key].strip() for key in required):
            raise ValueError("generic probe requires candidate/objective/origin/endpoint/method/input")
        values = raw.get("values")
        # Representation bounds, not a request quota; repetitions use native budgets.
        if (not isinstance(values, list) or not values
                or any(not isinstance(v, str) or len(v.encode()) > 4096 for v in values)
                or len(str(raw).encode()) > 32768):
            raise ValueError("generic probe requires bounded concrete values")
        occurrence = raw.get("occurrence", 0)
        if isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 0:
            raise ValueError("generic probe occurrence must be a non-negative integer")
        for key in ("baseline_request_ref", "auth_context_ref", "input_path"):
            if raw.get(key) is not None and (not isinstance(raw[key], str) or not raw[key].strip()):
                raise ValueError(f"generic probe {key} must be a concrete reference")
        if (raw.get("observation", "compare-response") not in {"compare-response", "compare-status", "compare-header"}
                or raw.get("capture", "native-http+candidate-proof") != "native-http+candidate-proof"
                or raw.get("stop", "after-comparison") != "after-comparison"):
            raise ValueError("generic probe requires bounded comparison/capture/stop intent")
        return cls(**{**raw, "values": tuple(values)})
