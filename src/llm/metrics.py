"""Local, metadata-only measurements for LLM requests."""

from __future__ import annotations

import json
import os
from collections import deque
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Literal


def _count(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int | None = None
    cached_input_tokens: int | None = None
    output_tokens: int | None = None
    reasoning_tokens: int | None = None
    total_tokens: int | None = None
    # Gemini candidatesTokenCount excludes thoughts; OpenAI/DeepSeek
    # completion_tokens include reasoning. Never sum these blindly.
    output_includes_reasoning: bool | None = None


def openai_chat_usage(raw: Any) -> TokenUsage | None:
    if not isinstance(raw, dict):
        return None
    prompt = raw.get("prompt_tokens_details")
    completion = raw.get("completion_tokens_details")
    cached = prompt.get("cached_tokens") if isinstance(prompt, dict) else None
    if cached is None:
        cached = raw.get("prompt_cache_hit_tokens")
    return TokenUsage(
        input_tokens=_count(raw.get("prompt_tokens")),
        cached_input_tokens=_count(cached),
        output_tokens=_count(raw.get("completion_tokens")),
        reasoning_tokens=_count(completion.get("reasoning_tokens")) if isinstance(completion, dict) else None,
        total_tokens=_count(raw.get("total_tokens")),
        output_includes_reasoning=True,
    )


def gemini_usage(raw: Any) -> TokenUsage | None:
    if not isinstance(raw, dict):
        return None
    return TokenUsage(
        input_tokens=_count(raw.get("promptTokenCount")),
        cached_input_tokens=_count(raw.get("cachedContentTokenCount")),
        output_tokens=_count(raw.get("candidatesTokenCount")),
        reasoning_tokens=_count(raw.get("thoughtsTokenCount")),
        total_tokens=_count(raw.get("totalTokenCount")),
        output_includes_reasoning=False,
    )


@dataclass(frozen=True, slots=True)
class RequestMetrics:
    request_id: str
    started_at: str
    duration_ms: float
    provider: str
    model: str
    purpose: str
    policy_id: str
    requested_reasoning_level: str | None
    effective_reasoning_level: str | None
    status: Literal["success", "error", "cancelled"]
    usage: TokenUsage | None = None
    tool_call_count: int | None = None
    retry_count: int | None = None
    retry_wait_ms: float | None = None
    compact_total_duration_ms: float | None = None


class MetricsCollector:
    """Bounded memory; explicit export writes only allowlisted metadata."""

    def __init__(self, max_records: int = 2048) -> None:
        self.records: deque[RequestMetrics] = deque(maxlen=max_records)

    def add(self, record: RequestMetrics) -> None:
        self.records.append(record)

    def set_latest_compaction_total(
        self, duration_ms: float, *, after_request_id: str | None = None
    ) -> None:
        for index in range(len(self.records) - 1, -1, -1):
            if self.records[index].request_id == after_request_id:
                return
            if self.records[index].purpose == "compaction" and self.records[index].compact_total_duration_ms is None:
                self.records[index] = replace(
                    self.records[index], compact_total_duration_ms=round(duration_ms, 2)
                )
                return

    def export_jsonl(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            for record in self.records:
                output.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")
