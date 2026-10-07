"""Thesis presentation projections over the bound, normalized report model."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
import math
from typing import Any, Sequence

from benchmarks.common.contracts import CLASSES, PARTITIONS
from benchmarks.common.metrics import distribution
from .model import ReportModel

CLASS_LABELS = (('SQLi', CLASSES[0]), ('XSS', CLASSES[1]), ('Tổng', None))
PARTITION_LABELS = dict(zip(PARTITIONS, (
    'Đánh giá được', 'Chưa kết luận', 'Lỗi thực thi', 'Kết quả không hợp lệ', 'Chưa chạy')))
STATUS_LABELS = {
    'timeout': 'Quá thời gian', 'runtime-error': 'Lỗi thực thi',
    'provider-error': 'Lỗi nhà cung cấp', 'budget-exhausted': 'Hết ngân sách',
    'crashed': 'Sự cố', 'setup-error': 'Lỗi khởi tạo', 'not-run': 'Chưa chạy',
    'scheduled': 'Đã lên lịch', 'started': 'Đã bắt đầu',
}
Number = int | float | Decimal


def usable_value(case: dict[str, Any], metric: str) -> int | float | None:
    """Use canonical normalization rules; never substitute another measurement."""
    value = case.get(metric)
    if metric == 'agent_seconds':
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return None
        try:
            valid = math.isfinite(value) and value >= 0
        except OverflowError:
            valid = False
    else:
        valid = type(value) is int and value >= 0
        if metric == 'total_tokens':
            valid = valid and case.get('total_tokens_complete') is True
    return value if valid else None


@dataclass(frozen=True)
class ResourceSummary:
    available: int
    eligible: int
    median: Number | None
    mean: Number | None
    p95: Number | None
    minimum: Number | None
    maximum: Number | None
    total: int | float | None

    @property
    def coverage(self) -> str:
        return f'{self.available}/{self.eligible}'


def resource_summary(cases: Sequence[dict[str, Any]], metric: str) -> ResourceSummary:
    values = [v for case in cases if (v := usable_value(case, metric)) is not None]
    median = mean = p95 = None
    if values:
        try:
            stats = distribution(values)
            if not all(math.isfinite(stats[key]) for key in ('median', 'mean', 'p95')):
                raise OverflowError
            median, mean, p95 = (stats[key] for key in ('median', 'mean', 'p95'))
            if all(type(v) is int for v in values) and len(values) % 2 == 0:
                # statistics.median converts an even integer pair to float.
                # Keep the exact half-token before any presentation rounding.
                ordered_ints = sorted(values)
                mid = len(values) // 2
                pair_sum = ordered_ints[mid - 1] + ordered_ints[mid]
                with localcontext() as context:
                    context.prec = len(str(pair_sum)) + 2
                    median = Decimal(pair_sum) / 2
        except OverflowError:
            # Canonical integer counters have no upper bound. Preserve fractional
            # medians even beyond float range; p95 follows the shared definition.
            ordered = sorted(Decimal(v) for v in values)
            with localcontext() as context:
                context.prec = max(len(v.as_tuple().digits) for v in ordered) + len(str(len(values))) + 16
                mid = len(ordered) // 2
                median = ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2
                mean = sum(ordered) / len(ordered)
            p95 = ordered[math.ceil(.95 * len(ordered)) - 1]
    return ResourceSummary(len(values), len(cases), median, mean, p95,
        min(values) if values else None, max(values) if values else None,
        sum(values) if cases and len(values) == len(cases) else None)


def class_cases(model: ReportModel, cls: str | None, *, completed: bool = False) -> list[dict[str, Any]]:
    return [case for case in model.cases
            if (cls is None or case['vulnerability_class'] == cls)
            and (not completed or case.get('final_status') == 'completed')]


def format_decimal(value: Number | None, divisor: int = 1) -> str:
    if value is None:
        return 'NA'
    number = Decimal(str(value)) if type(value) is float else Decimal(value)
    with localcontext() as context:
        context.prec = max(28, len(number.as_tuple().digits) + 16)
        number /= divisor
        if 0 < number <= Decimal('0.05'):
            return '<0,1'
        if number >= 1_000_000_000:
            return f'{number:.2e}'.replace('.', ',')
        return f'{number:.1f}'.replace('.', ',')


def format_count(value: int | float | None) -> str:
    return 'NA' if value is None else f'{value:,}'.replace(',', '.')


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    return ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join('---' for _ in headers) + ' |',
            *['| ' + ' | '.join(row) + ' |' for row in rows], '']


def _metric_cell(summary: ResourceSummary, divisor: int) -> str:
    return f'{format_decimal(summary.median, divisor)}<br>{summary.coverage}'


def render_thesis_tables(model: ReportModel) -> bytes:
    kind = model.metadata['classification']
    if kind == 'development':
        context = ('Development / smoke — minh họa kiểm tra exporter, không phải kết quả luận văn chính thức.'
                   if model.metadata.get('classification_qualifier') == 'smoke' else
                   'Development — không phải kết quả luận văn chính thức.')
    elif kind == 'official':
        context = 'Official — phân loại do người vận hành khai báo; không chứng nhận tính hợp lệ khoa học.'
    else:
        context = 'Chưa khai báo trạng thái Official; không trình bày như kết quả chính thức.'
    lines = ['# Scenario 1 — Bảng và chú thích hình', '', context, '',
             '## T1A — Kết quả đánh giá', '']
    groups = [(label, model.metrics['overall'] if cls is None else model.metrics['classes'][cls])
              for label, cls in CLASS_LABELS]
    lines += _table(('Lớp', 'Tổng case', *PARTITION_LABELS.values()),
                    [[label, str(g['scheduled']), *[str(g[p]) for p in PARTITIONS]] for label, g in groups])
    lines += ['## T1B — Confusion counts', '']
    lines += _table(('Lớp', 'TP', 'TN', 'FP', 'FN'),
                    [[label, *[str(g[p]) for p in ('TP', 'TN', 'FP', 'FN')]] for label, g in groups])
    lines += ['Counts chỉ thuộc các case đánh giá được. TP/TN là đánh giá dương/âm đúng; '
              'FP/FN là đánh giá dương/âm sai. Các partition khác không được coi là TN hoặc FN.', '']
    for panel, metric, heading, divisor in (
            ('A', 'agent_seconds', 'Thời gian xử lý (s)', 1),
            ('B', 'total_tokens', 'Tổng token (nghìn)', 1000)):
        lines += [f'## T2{panel} — {heading}', '']
        rows = []
        for label, cls in CLASS_LABELS:
            stats = resource_summary(class_cases(model, cls, completed=True), metric)
            limits = ('NA' if stats.minimum is None else
                      f'{format_decimal(stats.minimum, divisor)}–{format_decimal(stats.maximum, divisor)}')
            rows.append([label, stats.coverage, *[format_decimal(v, divisor)
                for v in (stats.median, stats.mean, stats.p95)], limits])
        lines += _table(('Lớp', 'Số đo / case hoàn tất', 'Trung vị', 'Trung bình', 'p95', 'Min–max'), rows)
    lines += ['T2A/T2B chỉ lấy trạng thái kết thúc do parent ghi nhận là completed, gồm cả '
              'case chưa kết luận hoặc kết quả không hợp lệ nếu có số đo hợp lệ. Coverage độc lập '
              'cho từng metric. Tổng tính lại từ các case gộp, không lấy trung bình thống kê từng lớp. '
              'p95 dùng nearest-rank-ceiling; mẫu nhỏ có thể cho p95 bằng max.', '',
              'Khoảng thời gian đo gồm Agent chạy và xử lý công việc nền còn lại; không gồm setup, '
              'freeze/teardown hoặc overhead của parent. Tổng token chỉ dùng số đo đầy đủ và hợp lệ; '
              'không thay bằng tổng quan sát từng phần hoặc input/output token.', '']
    noncompleted = [case for case in model.cases if case.get('final_status') not in (None, 'completed')]
    missing = [case for case in model.cases if case.get('final_status') is None]
    if noncompleted:
        lines += ['## T2C — Tài nguyên execution chưa hoàn tất', '']
        rows = []
        for label, cls in CLASS_LABELS[:2]:
            statuses = sorted({case['final_status'] for case in noncompleted if case['vulnerability_class'] == cls})
            for status in statuses:
                cases = [case for case in noncompleted if case['vulnerability_class'] == cls and case['final_status'] == status]
                rows.append([f'{label} / {STATUS_LABELS[status]}', str(len(cases)),
                    _metric_cell(resource_summary(cases, 'agent_seconds'), 1),
                    _metric_cell(resource_summary(cases, 'total_tokens'), 1000)])
        lines += _table(('Lớp / trạng thái', 'Số execution', 'Trung vị thời gian giữ lại (s)',
                         'Trung vị tổng token đầy đủ (nghìn)'), rows)
        lines += ['Mỗi trạng thái parent được giữ riêng; khoảng đo giữ lại không phải thời gian đến '
                  'hoàn tất. Mỗi ô metric ghi availability n/N của đúng nhóm lớp/trạng thái.', '']
    if missing:
        lines += ['## Ledger — Không có trạng thái kết thúc', '']
        rows = []
        for label, cls in CLASS_LABELS[:2]:
            for partition in PARTITIONS:
                cases = [case for case in missing if case['vulnerability_class'] == cls
                         and case['evaluator_partition'] == partition]
                if cases:
                    rows.append([label, PARTITION_LABELS[partition], str(len(cases)),
                        _metric_cell(resource_summary(cases, 'agent_seconds'), 1),
                        _metric_cell(resource_summary(cases, 'total_tokens'), 1000)])
        lines += _table(('Lớp', 'Partition đánh giá', 'Số case', 'Trung vị thời gian giữ lại (s)',
                         'Trung vị tổng token đầy đủ (nghìn)'), rows)
        lines += ['“Không có trạng thái kết thúc” chỉ là nhãn hiển thị cho dữ liệu thiếu, không phải '
                  'trạng thái canonical mới. Chưa chạy giữ nguyên partition và tổng schedule trong T1/T3; '
                  'không mô tả như execution đã chạy. Các partition còn lại được giữ riêng; không suy diễn '
                  'thời điểm bắt đầu/kết thúc từ số đo hoặc trạng thái worker.', '']
    lines += ['## T3 — Tổng workload toàn schedule', '']
    rows = []
    for label, cls in CLASS_LABELS:
        cases = class_cases(model, cls)
        cells = []
        for metric in ('total_tokens', 'llm_calls', 'tool_executed', 'http_dispatch_attempts'):
            stats = resource_summary(cases, metric)
            cells.append(f'{format_count(stats.total)}<br>{stats.coverage}')
        rows.append([label, *cells])
    lines += _table(('Lớp', 'Tổng token', 'Lần gọi LLM', 'Lần chạy tool', 'Lần thử gửi HTTP'), rows)
    lines += ['Mỗi ô ghi full aggregate và availability n/N, N là tổng case đã lên schedule. '
              'Bao gồm số đo hợp lệ của case hoàn tất và chưa hoàn tất. Chỉ có full aggregate khi N > 0 '
              'và đủ số đo hợp lệ cho mọi case; thiếu bất kỳ số đo nào thì NA, không dùng known-case sum '
              'làm full total. Token chỉ cộng tổng đầy đủ. Missing không bằng zero.', '',
              'LLM là logical invocations; tool là policy-started invocations, gồm cả lời gọi có thể thất bại '
              'và loại harness Candidate admission. HTTP là native transport dispatch attempts, '
              'không chứng minh delivery hoặc thành công; thiếu dispatch không thay bằng admission.', '',
              'NA là không khả dụng; zero đo được vẫn là 0. Số thập phân dùng dấu phẩy, một chữ số '
              'sau dấu phẩy; số dương rất nhỏ dùng <0,1 để không biến thành zero. T3 dùng số đếm nguyên '
              'với dấu chấm phân cách nghìn. CSV giữ nguyên giá trị canonical và độ chính xác.', '',
              '## Chú thích gợi ý', '',
              f'Ngữ cảnh áp dụng cho F1/F2/F3: {context}', '',
              '**F1 — Chất lượng xác thực SQLi và XSS trong Scenario 1.** Recall, Precision và FPR '
              'tính trên các case đánh giá được; Evaluability là tỷ lệ case đánh giá được trên tổng case. '
              'Nhãn thể hiện % (n/d); FPR thấp hơn tốt hơn.', '']
    references = (' Execution chưa hoàn tất xem T2C.' if noncompleted else '') + (
        ' Case thiếu trạng thái kết thúc xem Ledger.' if missing else '')
    for metric, text in (
            ('agent_seconds', '**F2 — Trung vị thời gian xử lý của Agent theo lớp lỗ hổng.** '
             'Trung vị trên các execution hoàn tất có số đo, đơn vị giây. Khoảng đo gồm Agent chạy '
             'và xử lý công việc nền còn lại; variability xem T2A.'),
            ('total_tokens', '**F3 — Trung vị tổng token sử dụng theo lớp lỗ hổng.** '
             'Trung vị của tổng token đầy đủ trên các execution hoàn tất, đơn vị nghìn token; '
             'variability xem T2B, tổng tiêu thụ toàn schedule xem T3.')):
        coverage = []
        for label, cls in CLASS_LABELS[:2]:
            cases = class_cases(model, cls)
            stats = resource_summary(class_cases(model, cls, completed=True), metric)
            coverage.append(f'{label}: {stats.eligible}/{len(cases)} case hoàn tất, {stats.coverage} số đo')
        lines += [text + ' ' + '; '.join(coverage) + '.' + references, '']
    return ('\n'.join(lines)).encode('utf-8')
