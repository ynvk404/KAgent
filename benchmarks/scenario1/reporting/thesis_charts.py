"""Three fixed-size thesis figures; captions live in thesis-tables.md."""
from __future__ import annotations

from decimal import Decimal
from html import escape
from typing import Sequence

from .aggregate import RATES, rate_parts
from .model import ReportModel
from .thesis import CLASS_LABELS, Number, class_cases, format_decimal, resource_summary

FIGURE_NAMES = ('scenario1-validation-quality', 'scenario1-processing-time-median',
                'scenario1-total-tokens-median')
CLASS_COLORS = ('#285c79', '#6b5b83')
METRIC_COLORS = ('#285c79', '#23664f', '#a43f3f', '#666666')
STYLE = ('text{font-family:Arial,sans-serif;fill:#171717;font-size:15px}'
         '.class{font-size:16px;font-weight:bold}.tick{font-size:14.2px}'
         '.number{font-variant-numeric:tabular-nums}.center{text-anchor:middle}'
         '.right{text-anchor:end}.grid{stroke:#d6dbe0;stroke-width:1}'
         '.axis{stroke:#666666;stroke-width:1}')


def _text(x: Number, y: Number, value: str, css: str = '') -> str:
    return f'<text x="{x}" y="{y}" class="{css}">{escape(value)}</text>'


def _rect(x: Number, y: Number, width: Number, height: Number, fill: str, css: str) -> str:
    return f'<rect x="{x}" y="{y}" width="{width}" height="{height}" fill="{fill}" class="{css}"/>'


def _line(x: Number, y1: Number, y2: Number, css: str) -> str:
    return f'<line x1="{x}" y1="{y1}" x2="{x}" y2="{y2}" class="{css}"/>'


def _svg(height: int, title: str, description: str, body: list[str]) -> bytes:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="16.5cm" '
            f'height="{height / 40:g}cm" viewBox="0 0 660 {height}" role="img">\n'
            f'<title>{escape(title)}</title><desc>{escape(description)}</desc>\n'
            f'<style>{STYLE}</style>\n<rect width="660" height="{height}" fill="white"/>\n'
            + '\n'.join(body) + '\n</svg>\n').encode('utf-8')


def validation_quality(model: ReportModel) -> bytes:
    body = []
    for index, (label, cls) in enumerate(CLASS_LABELS[:2]):
        group = model.metrics['classes'][cls]
        offset = index * 216
        body.append(_text(20, 28 + offset, label, 'class'))
        for tick in (0, 25, 50, 75, 100):
            body.append(_text(145 + 295 * tick / 100, 48 + offset, f'{tick}%', 'tick center number'))
        for rate, color, center in zip(RATES, METRIC_COLORS, (78, 112, 146, 190)):
            y = center + offset
            numerator, denominator = rate_parts(group, rate)
            value = group[rate]
            body.append(f'<g data-class="{cls}" data-metric="{rate}" '
                        f'data-available="{str(denominator > 0).lower()}">')
            if rate == 'evaluability':
                body.append(f'<text x="32" y="{y + 5}"><tspan x="32" dy="-8">Tỷ lệ đánh giá</tspan>'
                            '<tspan x="32" dy="17">được</tspan></text>')
            else:
                body.append(_text(32, y + 5, 'FPR' if rate == 'fpr' else rate.capitalize()))
            body.append(_rect(145, y - 9, 295, 18, '#f1f3f5', 'track'))
            if denominator and value is not None and value > 0:
                body.append(_rect(145, y - 9, round(295 * value, 4), 18, color, 'filled'))
            displayed = 'NA' if not denominator or value is None else format_decimal(value * 100) + '%'
            body += [_text(460, y + 5, f'{displayed} ({numerator}/{denominator})', 'number'), '</g>']
    return _svg(440, 'Chất lượng xác thực SQLi và XSS',
                'Canonical class rates; denominator zero is NA. See companion captions and T1.', body)


def _axis(values: Sequence[Number | None], intervals: int) -> tuple[Decimal, list[Decimal]]:
    maximum = max((Decimal(str(v)) for v in values if v is not None), default=Decimal(0))
    if maximum <= 1:
        limit = Decimal(1)
    else:
        step = maximum / intervals
        magnitude = Decimal(10) ** step.adjusted()
        nice = next(m * magnitude for m in map(Decimal, ('1', '2', '2.5', '5', '10')) if m * magnitude >= step)
        limit = nice * intervals
    return limit, [limit * i / intervals for i in range(intervals + 1)]


def resource_median(model: ReportModel, *, tokens: bool) -> bytes:
    metric, divisor = ('total_tokens', 1000) if tokens else ('agent_seconds', 1)
    values = [resource_summary(class_cases(model, cls, completed=True), metric).median
              for _, cls in CLASS_LABELS[:2]]
    displayed_values = [Decimal(str(v)) / divisor if v is not None else None for v in values]
    maximum, ticks = _axis(displayed_values, 4 if tokens else 5)
    body = []
    for tick in ticks:
        x = round(float(tick / maximum) * 400 + 110, 4)
        # Keep fractional ticks exact (e.g. 0,25), rather than labeling a
        # quarter-unit position 0,2 after value-column rounding.
        label = (format(tick.normalize(), 'f').replace('.', ',')
                 if tick < 1_000_000_000 else format_decimal(tick))
        body += [_line(x, 32, 132, 'axis' if tick == 0 else 'grid'),
                 _text(x, 153, label, 'tick center number')]
    for (label, cls), value, color, y in zip(CLASS_LABELS[:2], displayed_values, CLASS_COLORS, (58, 108)):
        body += [_text(20, y + 5, label, 'class'),
                 f'<g data-class="{cls}" data-available="{str(value is not None).lower()}">']
        if value is not None and value > 0:
            body.append(_rect(110, y - 11, round(float(value / maximum) * 400, 4), 22, color, 'filled'))
        body += [_text(630, y + 5, format_decimal(value), 'right number'), '</g>']
    axis = 'Trung vị tổng token (nghìn)' if tokens else 'Trung vị thời gian (s)'
    body.append(_text(310, 186, axis, 'center'))
    return _svg(200, axis, 'Parent-completed executions; metric-specific availability. '
                'See T2, T3 and the missing-data ledger in the companion Markdown.', body)


def render_thesis_charts(model: ReportModel) -> dict[str, bytes]:
    return {f'charts/{name}.svg': contents for name, contents in zip(FIGURE_NAMES, (
        validation_quality(model), resource_median(model, tokens=False), resource_median(model, tokens=True)))}
