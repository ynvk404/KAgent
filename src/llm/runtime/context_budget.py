"""Optional hard input policy, separate from proactive compaction thresholds."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.llm.providers import KIMI_CONTEXT_WINDOWS

if TYPE_CHECKING:
    from src.llm.core.client import Client


@dataclass(frozen=True)
class InputBudget:
    input_limit: int | None = None
    source: str = "unknown"
    reserved_output_tokens: int = 0
    safety_tokens: int = 0


def resolve_input_budget(client: Client) -> InputBudget:
    # Explicit runtime adapter override is already an input-only limit. It is
    # bound to this client instance, never inferred from a custom display name.
    explicit = getattr(client, "input_token_limit", None)
    if type(explicit) is int and explicit > 0:
        return InputBudget(explicit, "explicit-input")
    window = KIMI_CONTEXT_WINDOWS.get(client.model()) if client.name() == "kimi" else None
    if window is None:
        return InputBudget()
    maximum = getattr(client, "max_tokens", None)
    # Factory uses 2048 for Kimi. Direct adapters without an output setting
    # retain that conservative reservation instead of claiming zero output.
    output = maximum if type(maximum) is int and maximum > 0 else 2048
    safety = max(128, (window + 19) // 20)  # 5% heuristic uncertainty reservation.
    return InputBudget(max(0, window - output - safety), "kimi-context", output, safety)


class ContextCapacityError(RuntimeError):
    """Local, non-transient admission outcome; no provider request was sent."""

    def __init__(self, estimate: int, budget: InputBudget, fixed_floor: int):
        self.estimate = estimate
        self.budget = budget
        self.fixed_floor = fixed_floor
        super().__init__(
            f"context capacity: estimated request {estimate} tokens exceeds hard input "
            f"budget {budget.input_limit} ({budget.source}); nonreducible context "
            f"at least {fixed_floor} tokens. Reduce input/context or select a larger "
            "capacity; session state is preserved. Estimates are approximate."
        )
