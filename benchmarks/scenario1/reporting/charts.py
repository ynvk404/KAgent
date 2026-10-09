"""Dependency-free, deterministic SVG figures for print and Word reports."""
from __future__ import annotations

from decimal import Decimal
from html import escape
import math

from benchmarks.common.contracts import CLASSES, PARTITIONS
from .aggregate import rate_parts
from .model import ReportModel
from .thesis_charts import render_thesis_charts

# One palette for outcomes, metrics and vulnerability classes. Text/marks also
# convey meaning: color is never the only way to identify a value.
COLORS = {
    'positive': '#23664f', 'warning': '#956020', 'failure': '#a43f3f',
    'invalid': '#6b5b83', 'neutral': '#666666', 'empty': '#f1f3f5',
    'blue': '#285c79',
}
PARTITION_LABELS = ('Đánh giá được', 'Chưa có kết luận', 'Lỗi thực thi', 'Kết quả không hợp lệ', 'Chưa chạy')
PARTITION_COLORS = tuple(COLORS[key] for key in ('positive', 'warning', 'failure', 'invalid', 'neutral'))
CLASS_STYLES = (('SQLi', CLASSES[0], COLORS['blue']), ('XSS', CLASSES[1], COLORS['invalid']))
METRIC_STYLES = (('recall', 'Recall', COLORS['blue']),
                 ('precision', 'Precision', COLORS['positive']),
                 ('fpr', 'FPR', COLORS['failure']),
                 ('evaluability', 'Tỷ lệ đánh giá được', COLORS['positive']))
WIDTH = 920
CASES_PER_PAGE = 20
STYLE = (
    'text{font-family:Arial,sans-serif;fill:#171717;font-size:16px}'
    '.title{font-size:24px;font-weight:bold}.section{font-weight:bold}'
    '.small{font-size:14px}.number{font-variant-numeric:tabular-nums}'
    '.center{text-anchor:middle}.right{text-anchor:end}'
    '.axis{stroke:#666666;stroke-width:1}.grid{stroke:#d6dbe0;stroke-width:1}'
)


def _svg(height: int, body: list[str]) -> bytes:
    return ('<svg xmlns="http://www.w3.org/2000/svg" '
            f'width="{WIDTH}" height="{height}" viewBox="0 0 {WIDTH} {height}" role="img">\n'
            f'<style>{STYLE}</style>\n'
            f'<rect width="{WIDTH}" height="{height}" fill="white"/>\n'
            + '\n'.join(body) + '\n</svg>\n').encode('utf-8')


def _text(x: int | float, y: int | float, value: str, cls: str = '') -> str:
    return f'<text x="{x}" y="{y}" class="{cls}">{escape(value)}</text>'


def _rect(x: int | float, y: int | float, w: int | float, h: int | float, fill: str) -> str:
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" '
            f'fill="{fill}" stroke="#666666" stroke-width="0.8"/>')


def _line(x1: float, y1: float, x2: float, y2: float, cls: str = 'axis') -> str:
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" class="{cls}"/>'


def _designation(model: ReportModel) -> str:
    metadata = model.metadata
    kind = metadata['classification']
    if kind == 'unknown':
        return 'Official status not declared'
    return ('Official' if kind == 'official' else 'Development') + (
        ' / smoke' if metadata['classification_qualifier'] == 'smoke' else '')


def _header(model: ReportModel, title: str, subtitle: str) -> list[str]:
    return [f'<title>{escape(title)}</title>', f'<desc>{escape(subtitle)}</desc>',
            _text(32, 44, title, 'title'), _text(32, 72, _designation(model), 'small'),
            _text(32, 98, subtitle, 'small'), _line(32, 116, WIDTH - 32, 116, 'grid')]


def confusion_matrix(model: ReportModel) -> bytes:
    group = model.metrics['overall']
    body = _header(model, 'Confusion matrix',
                   f"Evaluable cases: {group['evaluable']:,} of {group['scheduled']:,} scheduled")
    body += [_text(572, 151, 'Agent assessment', 'center section'),
             _text(462, 181, 'Positive', 'center'), _text(682, 181, 'Negative', 'center'),
             _text(32, 226, 'Ground truth', 'section'),
             _text(326, 255, 'Vulnerable', 'right'), _text(326, 355, 'Safe', 'right')]
    for row, labels in enumerate((('TP', 'FN'), ('FP', 'TN'))):
        for col, label in enumerate(labels):
            x, y = 360 + col * 220, 200 + row * 100
            color = COLORS['positive'] if row == col else COLORS['failure']
            body += [_rect(x, y, 204, 88, COLORS['empty']),
                     _rect(x, y, 5, 88, color),
                     _text(x + 102, y + 29, label, 'center'),
                     _text(x + 102, y + 65, f"{group[label]:,}", 'title center number')]
    body.append(_text(32, 434, 'Only evaluable cases contribute; unresolved and failed cases are excluded.', 'small'))
    return _svg(466, body)


def class_metrics(model: ReportModel) -> bytes:
    body = _header(model, 'Validation metrics by vulnerability class',
                   'Recall, Precision, FPR dùng các case đánh giá được; Tỷ lệ đánh giá được dùng toàn bộ case đã lên lịch.')
    for class_index, (label, cls, _) in enumerate(CLASS_STYLES):
        group = model.metrics['classes'][cls]
        top = 150 + class_index * 208
        body.append(_text(32, top, label, 'section'))
        for tick in (0, 25, 50, 75, 100):
            body.append(_text(190 + 4.7 * tick, top, f'{tick}%', 'small center number'))
        for index, (rate, display_label, color) in enumerate(METRIC_STYLES):
            y = top + 18 + index * 38
            numerator, denominator = rate_parts(group, rate)
            value = group[rate]
            if rate == 'evaluability':
                body.append(f'<text x="48" y="{y + 17}"><tspan x="48" dy="-8">Tỷ lệ đánh giá</tspan>'
                            '<tspan x="48" dy="17">được</tspan></text>')
            else:
                body.append(_text(48, y + 17, display_label))
            body.append(_rect(190, y, 470, 24, COLORS['empty']))
            if value is not None and value > 0:
                body.append(_rect(190, y, round(470 * value, 4), 24, color))
            displayed = 'NA' if value is None else f'{value * 100:.1f}%'
            body.append(_text(684, y + 18, f'{displayed} ({numerator:,}/{denominator:,})', 'number'))
    body += [_text(32, 554, 'Values show percentage (numerator/denominator). NA means a zero denominator.', 'small'),
             _text(32, 578, 'Recall: TP/(TP+FN) · Precision: TP/(TP+FP) · FPR: FP/(FP+TN)', 'small')]
    return _svg(610, body)


def evaluation_partitions(model: ReportModel) -> bytes:
    body = _header(model, 'Evaluation outcome distribution by vulnerability class',
                   'All scheduled cases; patterns and labeled counts remain readable in grayscale.')
    # No text sits on a segment, including very small nonzero segments.
    marks = ('<path d="M0 8L8 0"/>', '<path d="M0 0L8 8"/>',
             '<path d="M0 4H8"/>', '<path d="M4 0V8"/>',
             '<circle cx="4" cy="4" r="1" fill="white"/>')
    body.append('<defs>')
    for index, (color, mark) in enumerate(zip(PARTITION_COLORS, marks)):
        body.append(f'<pattern id="partition-{index}" width="8" height="8" patternUnits="userSpaceOnUse">'
                    f'<rect width="8" height="8" fill="{color}"/>'
                    f'<g stroke="white" stroke-width="1">{mark}</g></pattern>')
    body.append('</defs>')
    for index, (label, cls, _) in enumerate(CLASS_STYLES):
        group = model.metrics['classes'][cls]
        if sum(group[part] for part in PARTITIONS) != group['scheduled']:
            raise ValueError('class partition total differs from scheduled')
        y = 144 + index * 64
        body += [_text(32, y + 21, label, 'section'), _rect(105, y, 500, 30, COLORS['empty'])]
        x = 105.0
        for part_index, part in enumerate(PARTITIONS):
            count = group[part]
            width = 500 * count / group['scheduled'] if group['scheduled'] else 0
            if count:
                rect = _rect(round(x, 4), y, round(width, 4), 30, f'url(#partition-{part_index})')
                body.append(rect.replace('<rect ', f'<rect data-class="{cls}" data-partition="{part}" data-count="{count}" '))
            x += width
        body.append(_text(640, y + 21, f"N scheduled = {group['scheduled']:,}", 'number'))
    # Table headers double as the legend, so labels need not be repeated.
    for index, label in enumerate(PARTITION_LABELS):
        x = 162 + index * 155
        body += [_rect(x - 9, 265, 18, 15, f'url(#partition-{index})'),
                 _text(x, 302, label, 'small center')]
    body.append(_line(32, 312, WIDTH - 32, 312, 'grid'))
    for index, (label, cls, _) in enumerate(CLASS_STYLES):
        group = model.metrics['classes'][cls]
        y = 338 + index * 36
        body.append(_text(32, y, label, 'section'))
        for part_index, part in enumerate(PARTITIONS):
            text = _text(162 + part_index * 155, y, f'{group[part]:,}', 'center number')
            body.append(text.replace('<text ', f'<text data-class="{cls}" data-partition="{part}" '))
    body += [_text(32, 406, 'Counts include zeros and sum to N scheduled in each class.', 'small'),
             _text(32, 428, 'Chưa có kết luận, lỗi thực thi, kết quả không hợp lệ và chưa chạy không được tính vào TN/FN.', 'small')]
    return _svg(450, body)


def _value(case: dict, metric: str) -> int | float | None:
    value = case.get(metric)
    if metric == 'total_tokens':
        return value if case.get('total_tokens_complete') is True and type(value) is int and value >= 0 else None
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 else None


def _format_number(value: int | float, *, seconds: bool = False) -> str:
    if value >= 1_000_000_000:
        return f'{Decimal(value):.2e}'
    return f'{value:,.1f}' if seconds else f'{value:,.0f}'


def _axis_maximum(values: list[int | float | None], *, seconds: bool) -> int | float:
    maximum = max((v for v in values if v is not None), default=0)
    if maximum <= (1 if seconds else 4):
        return 1 if seconds else 4
    if maximum > 1e300:
        return maximum
    # Four equal intervals, rounded upward to familiar decimal steps. Keep a
    # finite fallback when rounding a very large recorded duration overflows.
    step = maximum / 4
    magnitude = 10 ** math.floor(math.log10(step))
    for multiplier in (1, 2, 2.5, 5, 10):
        if multiplier * magnitude >= step:
            rounded = (multiplier * magnitude if seconds else math.ceil(multiplier * magnitude)) * 4
            return rounded if math.isfinite(rounded) else maximum
    return maximum


def _case_charts(model: ReportModel, *, metric: str, stem: str, title: str, axis: str) -> dict[str, bytes]:
    """Paginate observations in manifest order with one scale across all pages.

    Ordinals join to CSV row order; data-case holds the full sanitized pseudonym.
    No sorting by value or filtering by evaluation outcome alters that mapping.
    """
    seconds = metric == 'agent_seconds'
    values = [_value(case, metric) for case in model.cases]
    maximum = _axis_maximum(values, seconds=seconds)
    pages = max(1, (len(model.cases) + CASES_PER_PAGE - 1) // CASES_PER_PAGE)
    result = {}
    for page in range(pages):
        start = page * CASES_PER_PAGE
        cases = model.cases[start:start + CASES_PER_PAGE]
        subtitle = ('Measured Agent interval; includes retained intervals for incomplete executions.' if seconds else
                    f'Complete totals: {sum(v is not None for v in values):,}/{len(values):,} cases; other values are NA.')
        if pages > 1:
            subtitle += f' Page {page + 1}/{pages}.'
        body = _header(model, title, subtitle)
        for index, (label, _, color) in enumerate(CLASS_STYLES):
            x = 32 + index * 112
            body += [_rect(x, 136, 18, 15, color), _text(x + 26, 149, label, 'small')]
        body.append(_text(888, 149, 'Case numbers follow manifest execution order', 'small right'))
        bottom = 194 + max(1, len(cases)) * 30
        for tick in range(5):
            x = 220 + tick * 135
            tick_value = maximum * tick // 4 if type(maximum) is int and not seconds else maximum * (tick / 4)
            body += [_line(x, 178, x, bottom, 'grid'),
                     _text(x, bottom + 24, _format_number(tick_value, seconds=seconds), 'small center number')]
        body.append(_text(490, bottom + 52, axis, 'center'))
        for index, case in enumerate(cases):
            y = 190 + index * 30
            label, _, color = next(style for style in CLASS_STYLES if style[1] == case['vulnerability_class'])
            ordinal = start + index + 1
            value = values[start + index]
            incomplete = seconds and value is not None and case.get('final_status') != 'completed'
            body.append(_text(32, y + 17, f'Case {ordinal:02d} · {label}', 'number'))
            body.append(f'<g data-case="{escape(case["case_id"], quote=True)}" data-ordinal="{ordinal}" '
                        f'data-available="{str(value is not None).lower()}">')
            if value is not None and value > 0:
                body.append(_rect(220, y, round(value / maximum * 540, 4), 21, color))
            displayed = 'NA' if value is None else _format_number(value, seconds=seconds)
            body.append(_text(888, y + 17, displayed + (' *' if incomplete else ''), 'right number'))
            body.append('</g>')
        if not cases:
            body.append(_text(32, 207, 'No scheduled cases', 'small'))
        body.append(_text(32, bottom + 84, 'NA: measured Agent interval unavailable.' if seconds else
                          'NA: full token total unavailable or incomplete; partial sums are excluded.', 'small'))
        if seconds:
            body.append(_text(32, bottom + 108, '* Execution did not complete; retained Agent interval only.', 'small'))
        filename = stem if page == 0 else f'{stem}-{page + 1:02d}'
        result[f'charts/{filename}.svg'] = _svg(bottom + (140 if seconds else 116), body)
    return result


def render_charts(model: ReportModel) -> dict[str, bytes]:
    return {**render_thesis_charts(model),
            'charts/confusion-matrix.svg': confusion_matrix(model),
            'charts/class-metrics.svg': class_metrics(model),
            'charts/evaluation-partitions.svg': evaluation_partitions(model),
            **_case_charts(model, metric='agent_seconds', stem='processing-time',
                           title='Processing time by benchmark case', axis='Processing time (s)'),
            **_case_charts(model, metric='total_tokens', stem='total-tokens',
                           title='Total tokens by benchmark case', axis='Total tokens')}
