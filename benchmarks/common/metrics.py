"""Metadata from production request_metrics and events, never inferred usage."""
from __future__ import annotations

from dataclasses import asdict
import math
import statistics


def llm_metrics(records, done: dict | None) -> dict:
    rows = [asdict(r) for r in records]
    total_calls = done.get('total_llm_calls') if done else None
    records_complete = type(total_calls) is int and total_calls == len(rows)
    tokens = {}
    for field in ('input_tokens', 'output_tokens', 'total_tokens'):
        known = [(r.get('usage') or {}).get(field) for r in rows]
        available = [v for v in known if v is not None]
        tokens[field] = {'total': sum(available) if rows and records_complete and len(available) == len(rows) else None,
                         'observed_sum': sum(available) if available else None,
                         'known_requests': len(available), 'requests': len(rows),
                         'complete': bool(rows) and records_complete and len(available) == len(rows)}
    return {'requests': rows, 'request_records_complete': records_complete, 'tokens': tokens,
            **{k: done.get(k) if done else None for k in (
                'agent_loop_llm_calls', 'compaction_llm_calls', 'final_synthesis_llm_calls', 'total_llm_calls')}}


def distribution(samples: list[float]) -> dict:
    if any(type(v) not in {float, int} or not math.isfinite(v) or v < 0 for v in samples):
        raise ValueError('invalid timing sample')
    ordered = sorted(samples)
    return {'n': len(samples), 'mean': statistics.mean(samples) if samples else None,
            'median': statistics.median(samples) if samples else None,
            'p95': ordered[math.ceil(.95 * len(samples)) - 1] if samples else None,
            'percentile_definition': 'nearest-rank-ceiling'}
