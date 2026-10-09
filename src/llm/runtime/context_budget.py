"""Optional hard input policy, separate from proactive compaction thresholds."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.llm.providers import DEEPSEEK_CONTEXT_LIMITS, DEEPSEEK_DEFAULT_BASE_URL, KIMI_CONTEXT_WINDOWS

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
    return resolve_model_input_budget(client.name(), client.model(), getattr(client, "max_tokens", None),
                                      base_url=getattr(client, "base_url", "") or "")


def resolve_model_input_budget(provider: str, model: str, maximum: int | None = None, *,
                               base_url: str | None = None) -> InputBudget:
    """Shared reservations; absent config URL selects the factory default.

    Live clients without a URL pass an empty string, which cannot establish
    the first-party DeepSeek capacity from a provider/model label alone.
    """
    window = None
    source = "unknown"
    default_output = 2048  # Existing Kimi factory/direct-client reservation.
    if provider == "kimi":
        window = KIMI_CONTEXT_WINDOWS.get(model)
        source = "kimi-context"
    elif provider == "deepseek" and (base_url is None or base_url.rstrip("/") in {
        DEEPSEEK_DEFAULT_BASE_URL, DEEPSEEK_DEFAULT_BASE_URL + "/v1",
    }):
        limits = DEEPSEEK_CONTEXT_LIMITS.get(model)
        if limits is not None:
            window, default_output = limits
            source = "deepseek-context"
    if window is None:
        return InputBudget()
    # DeepSeek omits max_tokens when unset. Reserve the verified output ceiling
    # to cover every thinking mode without changing adapter request semantics.
    output = maximum if type(maximum) is int and maximum > 0 else default_output
    safety = max(128, (window + 19) // 20)  # 5% heuristic uncertainty reservation.
    return InputBudget(max(0, window - output - safety), source, output, safety)


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
