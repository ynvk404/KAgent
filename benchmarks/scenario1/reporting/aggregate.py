"""Presentation of canonical evaluator counts and rates, without rescoring."""
from __future__ import annotations

from benchmarks.common.contracts import CLASSES, PARTITIONS
from .model import ReportModel

LABELS = (('Overall', 'overall'), ('SQLi', CLASSES[0]), ('XSS', CLASSES[1]))
RATES = ('recall', 'precision', 'fpr', 'evaluability')
COUNTS = ('scheduled', 'evaluable', 'TP', 'TN', 'FP', 'FN')


def groups(model: ReportModel):
    for label, key in LABELS:
        yield label, model.metrics['overall'] if key == 'overall' else model.metrics['classes'][key]


def rate_parts(group: dict, name: str) -> tuple[int, int]:
    return {
        'recall': (group['TP'], group['TP'] + group['FN']),
        'precision': (group['TP'], group['TP'] + group['FP']),
        'fpr': (group['FP'], group['FP'] + group['TN']),
        'evaluability': (group['evaluable'], group['scheduled']),
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


def partition_rows(model: ReportModel) -> list[dict]:
    return [{'class': label, 'scheduled': group['scheduled'],
             **{part.replace('-', '_'): group[part] for part in PARTITIONS}}
            for label, group in groups(model)]


def public_metrics(model: ReportModel) -> dict:
    return {label: {key: group[key] for key in (*COUNTS, *PARTITIONS, *RATES)}
            for label, group in groups(model)}
