"""Canonical CSV tables and a separate deterministic thesis presentation."""
from __future__ import annotations

import csv
from io import StringIO

from benchmarks.common.contracts import PARTITIONS
from .aggregate import COUNTS, RATES, partition_rows, summary_rows
from .model import ReportModel
from .thesis import render_thesis_tables

CASE_FIELDS = (
    'case_id', 'vulnerability_class', 'expected_vulnerable', 'agent_outcome',
    'evaluator_partition', 'evaluator_reason', 'confusion', 'final_status', 'worker_status',
    'agent_seconds', 'wall_seconds', 'http_admitted', 'http_dispatch_attempts',
    'llm_calls', 'tool_proposed', 'tool_executed', 'tool_result_events',
    'tool_blocked', 'tool_failed', 'input_tokens', 'input_tokens_complete',
    'output_tokens', 'output_tokens_complete', 'total_tokens', 'total_tokens_complete',
)


def csv_bytes(fields: tuple[str, ...], rows: list[dict]) -> bytes:
    stream = StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def render_tables(model: ReportModel) -> dict[str, bytes]:
    summary_fields = ('class', *COUNTS, *(field for rate in RATES for field in
        (rate, f'{rate}_numerator', f'{rate}_denominator')))
    partition_fields = ('class', 'scheduled', *(part.replace('-', '_') for part in PARTITIONS))
    abnormal = [{'case_id': case['case_id'], 'partition': case['evaluator_partition'],
                 'reason': case['evaluator_reason'], 'manual_root_cause': ''}
                for case in model.cases if case['evaluator_partition'] != 'evaluable']
    return {
        'thesis-tables.md': render_thesis_tables(model),
        'summary.csv': csv_bytes(summary_fields, summary_rows(model)),
        'partitions.csv': csv_bytes(partition_fields, partition_rows(model)),
        'per-case.csv': csv_bytes(CASE_FIELDS, list(model.cases)),
        'abnormal-analysis-template.csv': csv_bytes(
            ('case_id', 'partition', 'reason', 'manual_root_cause'), abnormal),
    }
