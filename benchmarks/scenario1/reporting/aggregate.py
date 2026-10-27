"""Presentation of the single current evaluation contract."""
from __future__ import annotations

from benchmarks.common.contracts import CLASSES
from .model import ReportModel

LABELS = (('Overall', 'overall'), ('SQLi', CLASSES[0]), ('XSS', CLASSES[1]))
RATES = ('recall', 'precision', 'fpr', 'assessment_coverage', 'completion_rate')
COUNTS = ('scheduled', 'started', 'completed', 'execution_failed', 'not_run',
          'assessment_accepted', 'TP', 'TN', 'FP', 'FN')


def groups(model: ReportModel):
    for label, key in LABELS:
        yield label, model.metrics['overall'] if key == 'overall' else model.metrics['classes'][key]


def rate_parts(group: dict, name: str) -> tuple[int, int]:
    return {
        'recall': (group['TP'], group['TP'] + group['FN']),
        'precision': (group['TP'], group['TP'] + group['FP']),
        'fpr': (group['FP'], group['FP'] + group['TN']),
        'assessment_coverage': (group['assessment_accepted'], group['scheduled']),
        'completion_rate': (group['completed'], group['scheduled']),
    }[name]


def summary_rows(model: ReportModel) -> list[dict]:
    result = []
    for label, group in groups(model):
        row = {'class': label, **{key: group[key] for key in COUNTS}}
        for rate in RATES:
            numerator, denominator = rate_parts(group, rate)
            row.update({rate: group[rate], f'{rate}_numerator': numerator,
                        f'{rate}_denominator': denominator})
        result.append(row)
    return result


def public_metrics(model: ReportModel) -> dict:
    return {label: {key: group[key] for key in (*COUNTS, *RATES,
                   'execution_status_counts', 'assessment_status_counts')}
            for label, group in groups(model)}
