"""Offline comparison of metadata-only reasoning benchmark runs."""

from __future__ import annotations

import json
import math
import re
import statistics
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from src.llm.metrics import RequestMetrics


_SAFE_REF = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")


def _safe_reference(value: str) -> str:
    if not _SAFE_REF.fullmatch(value):
        raise ValueError("benchmark references must be opaque IDs, not URLs or secrets")
    return value


@dataclass(frozen=True, slots=True)
class ObservedTotal:
    value: int | None
    missing_requests: int


def _usage_total(records: list[RequestMetrics], field: str) -> ObservedTotal:
    values = [getattr(record.usage, field) if record.usage else None for record in records]
    known = [value for value in values if value is not None]
    return ObservedTotal(sum(known) if known else None, len(values) - len(known))


@dataclass(frozen=True, slots=True)
class BenchmarkRun:
    run_id: str
    scenario_id: str
    target_ref: str
    scope_ref: str
    provider: str
    model: str
    policy_id: str
    reasoning_configuration: tuple[tuple[str, str | None, str | None], ...]
    started_at: str
    request_count: int
    tool_call_count: int | None
    compact_count: int
    compact_llm_duration_ms: float | None
    compact_total_duration_ms: float | None
    retry_count: int | None
    retry_wait_ms: float | None
    total_request_duration_ms: float
    median_request_duration_ms: float | None
    p95_request_duration_ms: float | None
    input_tokens: ObservedTotal
    cached_input_tokens: ObservedTotal
    output_tokens: ObservedTotal
    reasoning_tokens: ObservedTotal
    total_tokens: ObservedTotal
    outcome_ref: str | None = None
    ground_truth_ref: str | None = None


def build_run(
    records: Iterable[RequestMetrics], *, run_id: str, scenario_id: str,
    target_ref: str, scope_ref: str, outcome_ref: str | None = None,
    ground_truth_ref: str | None = None,
) -> BenchmarkRun:
    rows = list(records)
    if not rows:
        raise ValueError("benchmark run requires at least one request")
    if len({(row.provider, row.model, row.policy_id) for row in rows}) != 1:
        raise ValueError("split runs when provider, model, or policy changes")
    durations = sorted(row.duration_ms for row in rows)
    tool_counts = [row.tool_call_count for row in rows]
    return BenchmarkRun(
        run_id=_safe_reference(run_id), scenario_id=_safe_reference(scenario_id),
        target_ref=_safe_reference(target_ref), scope_ref=_safe_reference(scope_ref),
        provider=rows[0].provider, model=rows[0].model,
        policy_id=rows[0].policy_id,
        reasoning_configuration=tuple(sorted({
            (row.purpose, row.requested_reasoning_level, row.effective_reasoning_level)
            for row in rows
        }, key=lambda item: (item[0], item[1] or "", item[2] or ""))),
        started_at=min(row.started_at for row in rows),
        request_count=len(rows),
        tool_call_count=sum(value for value in tool_counts if value is not None)
        if all(value is not None for value in tool_counts) else None,
        compact_count=sum(row.purpose == "compaction" for row in rows),
        compact_llm_duration_ms=(
            round(sum(row.duration_ms for row in rows if row.purpose == "compaction"), 2)
            if any(row.purpose == "compaction" for row in rows) else None
        ),
        compact_total_duration_ms=(
            round(sum(row.compact_total_duration_ms or 0 for row in rows), 2)
            if all(row.compact_total_duration_ms is not None for row in rows if row.purpose == "compaction")
            and any(row.purpose == "compaction" for row in rows) else None
        ),
        retry_count=(sum(row.retry_count or 0 for row in rows)
                     if all(row.retry_count is not None for row in rows) else None),
        retry_wait_ms=(round(sum(row.retry_wait_ms or 0 for row in rows), 2)
                       if all(row.retry_wait_ms is not None for row in rows) else None),
        total_request_duration_ms=round(sum(durations), 2),
        median_request_duration_ms=statistics.median(durations),
        p95_request_duration_ms=durations[math.ceil(0.95 * len(durations)) - 1],
        input_tokens=_usage_total(rows, "input_tokens"),
        cached_input_tokens=_usage_total(rows, "cached_input_tokens"),
        output_tokens=_usage_total(rows, "output_tokens"),
        reasoning_tokens=_usage_total(rows, "reasoning_tokens"),
        total_tokens=_usage_total(rows, "total_tokens"),
        outcome_ref=_safe_reference(outcome_ref) if outcome_ref else None,
        ground_truth_ref=_safe_reference(ground_truth_ref) if ground_truth_ref else None,
    )


def same_reasoning_configuration(first: BenchmarkRun, second: BenchmarkRun) -> bool:
    """Identical observed settings cannot establish a policy comparison."""
    return first.reasoning_configuration == second.reasoning_configuration


def load_request_metrics(path: str | Path) -> list[RequestMetrics]:
    """Read an explicit local export; never execute or infer missing usage."""
    from src.llm.metrics import TokenUsage

    records: list[RequestMetrics] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        raw: dict[str, Any] = json.loads(line)
        usage = raw.get("usage")
        raw["usage"] = TokenUsage(**usage) if isinstance(usage, dict) else None
        records.append(RequestMetrics(**raw))
    return records


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Summarize a local KAgent metrics export")
    parser.add_argument("metrics_jsonl")
    parser.add_argument("--compare-metrics-jsonl")
    for key in ("run_id", "scenario_id", "target_ref", "scope_ref"):
        parser.add_argument(f"--{key.replace('_', '-')}", required=True)
    args = parser.parse_args()
    run = build_run(
        load_request_metrics(args.metrics_jsonl), run_id=args.run_id,
        scenario_id=args.scenario_id, target_ref=args.target_ref,
        scope_ref=args.scope_ref,
    )
    if args.compare_metrics_jsonl:
        other = build_run(
            load_request_metrics(args.compare_metrics_jsonl),
            run_id=f"{args.run_id}-comparison", scenario_id=args.scenario_id,
            target_ref=args.target_ref, scope_ref=args.scope_ref,
        )
        result: dict[str, Any] = {
            "runs": [asdict(run), asdict(other)],
            "equivalent_reasoning_configuration": same_reasoning_configuration(run, other),
        }
    else:
        result = asdict(run)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
