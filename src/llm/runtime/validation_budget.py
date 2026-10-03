"""Opt-in hard budget for a bounded live validation run; no default provider changes."""
from contextvars import ContextVar
from decimal import Decimal
import json
from pathlib import Path
import os

import httpx


class ValidationBudgetExceeded(RuntimeError):
    pass


active_validation_budget: ContextVar["ValidationBudget | None"] = ContextVar("validation_budget", default=None)


class ValidationBudget:
    # Verified official deepseek-flash peak rates, 2026-10-02. Peak prices are
    # conservative upper bounds regardless of time/holiday/cache eligibility.
    PRICE_SOURCE = "https://api-docs.deepseek.com/quick_start/pricing/"
    INPUT = Decimal("0.30") / 1_000_000
    CACHED = Decimal("0.006") / 1_000_000
    OUTPUT = Decimal("1.20") / 1_000_000

    def __init__(self, path: Path, model: str, host: str = "api.deepseek.com"):
        if model != "deepseek-flash" or host != "api.deepseek.com":
            raise ValueError("verified pricing unavailable for configured model/endpoint")
        self.path = path
        self.model = model
        self.host = host
        self.state = json.loads(path.read_text()) if path.exists() else {"attempts": [], "sessions": 0, "unknown_usage": False}
        self.attempt_limit = 5  # Explicitly lifted only after the trial is reviewed.

    @property
    def cost(self):
        return sum((Decimal(row["charged_upper_usd"]) for row in self.state["attempts"]), Decimal(0))

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(".tmp")
        with temp.open("w") as stream:
            json.dump({**self.state, "model": self.model, "price_source": self.PRICE_SOURCE}, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        temp.chmod(0o600)
        temp.replace(self.path)

    def begin_session(self):
        if self.state["sessions"] >= 3:
            raise ValidationBudgetExceeded("three live sessions exhausted")
        self.state["sessions"] += 1
        self.save()

    def continue_after_trial(self):
        if self.state["unknown_usage"]:
            raise ValidationBudgetExceeded("usage unavailable; stop after trial")
        self.attempt_limit = 60

    def reserve(self, request: httpx.Request):
        if request.url.host != self.host or request.url.scheme != "https":
            raise ValidationBudgetExceeded("unexpected validation provider destination")
        if len(self.state["attempts"]) >= min(60, self.attempt_limit):
            raise ValidationBudgetExceeded("API attempt limit reached")
        body = json.loads(request.content) if request.content else {}
        if body and body.get("model") != self.model:
            raise ValidationBudgetExceeded("model changed")
        # UTF-8 byte count plus generous framing bound; count schemas too.
        input_bound = len(request.content) + 4096
        # No configured cap: official maximum 384K, rounded up conservatively.
        output_bound = body.get("max_completion_tokens", body.get("max_tokens", 400000)) if body else 0
        if not isinstance(output_bound, int) or output_bound <= 0 and body:
            raise ValidationBudgetExceeded("unknown output bound")
        upper = self.INPUT * input_bound + self.OUTPUT * output_bound
        if self.cost + upper > Decimal("1"):
            raise ValidationBudgetExceeded("insufficient budget for next worst-case attempt")
        row = {"attempt": len(self.state["attempts"]) + 1, "session": self.state["sessions"],
               "method": request.method, "path": request.url.path,
               "reserved_upper_usd": str(upper), "charged_upper_usd": str(upper), "usage": None}
        self.state["attempts"].append(row)
        self.save()
        return row

    def settle(self, row, usage):
        if not isinstance(usage, dict) or not all(isinstance(usage.get(key), int) and usage[key] >= 0 for key in ("prompt_tokens", "completion_tokens")):
            self.state["unknown_usage"] = True
        else:
            hit = usage.get("prompt_cache_hit_tokens", 0)
            hit = hit if isinstance(hit, int) and 0 <= hit <= usage["prompt_tokens"] else 0
            cost = self.INPUT * (usage["prompt_tokens"] - hit) + self.CACHED * hit + self.OUTPUT * usage["completion_tokens"]
            row["usage"] = {key: usage[key] for key in ("prompt_tokens", "completion_tokens", "prompt_cache_hit_tokens", "prompt_cache_miss_tokens", "total_tokens") if key in usage}
            row["charged_upper_usd"] = str(cost)
            if cost > Decimal(row["reserved_upper_usd"]):
                self.state["unknown_usage"] = True
        self.save()

    def transport(self):
        return BudgetTransport(self)


class BudgetTransport(httpx.AsyncBaseTransport):
    def __init__(self, budget, inner=None):
        self.budget = budget
        self.inner = inner or httpx.AsyncHTTPTransport(trust_env=False)

    async def handle_async_request(self, request):
        row = self.budget.reserve(request)
        try:
            response = await self.inner.handle_async_request(request)
            raw = await response.aread()
            try:
                data = json.loads(raw)
                usage = data.get("usage")
            except (ValueError, AttributeError):
                usage = None
            self.budget.settle(row, usage)
            return response
        except BaseException:
            self.budget.settle(row, None)
            raise

    async def aclose(self):
        await self.inner.aclose()
