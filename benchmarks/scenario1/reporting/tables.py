"""Canonical CSV tables and a separate deterministic thesis presentation."""
from __future__ import annotations

import csv
from io import StringIO

from .aggregate import COUNTS, RATES, groups, summary_rows
from .model import ReportModel
from .thesis import render_thesis_tables

CASE_FIELDS = (
    'case_id', 'vulnerability_class', 'expected_vulnerable',
    'execution_status', 'assessment_status', 'assessment_reason',
    'assessment_outcome', 'assessment_confusion', 'final_status', 'worker_status',
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
    abnormal = [{'case_id': case['case_id'], 'execution_status': case['execution_status'],
                 'assessment_status': case['assessment_status'], 'reason': case['assessment_reason'],
                 'manual_root_cause': ''}
                for case in model.cases if case['execution_status'] != 'completed'
                or case['assessment_status'] != 'accepted']
    files = {
        'thesis-tables.md': render_thesis_tables(model),
        'summary.csv': csv_bytes(summary_fields, summary_rows(model)),
        'per-case.csv': csv_bytes(CASE_FIELDS, list(model.cases)),
        'abnormal-analysis-template.csv': csv_bytes(
            ('case_id', 'execution_status', 'assessment_status', 'reason', 'manual_root_cause'), abnormal),
    }
    for filename, key in (('execution.csv', 'execution_status_counts'), ('assessments.csv', 'assessment_status_counts')):
        files[filename] = csv_bytes(('class', 'status', 'count', 'scheduled'), [
            {'class': label, 'status': status, 'count': count, 'scheduled': group['scheduled']}
            for label, group in groups(model) for status, count in sorted(group[key].items())])
    return files
