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
    'Đánh giá được', 'Chưa có kết luận', 'Lỗi thực thi', 'Kết quả không hợp lệ', 'Chưa chạy')))
STATUS_LABELS = {
    'timeout': 'Quá thời gian', 'runtime-error': 'Lỗi thực thi',
    'provider-error': 'Lỗi dịch vụ LLM', 'budget-exhausted': 'Đạt giới hạn tài nguyên',
    'crashed': 'Tiến trình gặp sự cố', 'setup-error': 'Lỗi khởi tạo', 'not-run': 'Chưa chạy',
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
        context = ('Development / smoke — minh họa kiểm tra xuất báo cáo, không phải kết quả luận văn chính thức.'
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
    lines += ['“Đánh giá được” (Evaluable): lần chạy hoàn tất, có kết luận hợp lệ của Agent '
              'để đối chiếu với nhãn chuẩn (ground truth). “Chưa có kết luận” (Unresolved): '
              'chưa có kết luận, thiếu bằng chứng hoặc còn bị chặn/trì hoãn. “Lỗi thực thi” '
              '(Execution failed): lần chạy không hoàn tất hoặc bị gián đoạn sau khi bắt đầu. '
              '“Kết quả không hợp lệ” (Invalid result): tệp kết quả của lần chạy thiếu/hỏng '
              'hoặc kết luận không đạt kiểm tra tính hợp lệ. “Chưa chạy” (Not run): case chưa bắt đầu. '
              'Bốn nhóm sau không đủ điều kiện đưa vào TP/TN/FP/FN; không coi là TN hoặc FN.', '']
    lines += ['## T1B — Confusion counts', '']
    lines += _table(('Lớp', 'TP', 'TN', 'FP', 'FN'),
                    [[label, *[str(g[p]) for p in ('TP', 'TN', 'FP', 'FN')]] for label, g in groups])
    lines += ['Chỉ đếm các case đánh giá được: TP là xác nhận đúng lỗ hổng; TN là không xác nhận '
              'lỗ hổng trên case không có lỗ hổng theo nhãn chuẩn; FP là xác nhận nhầm lỗ hổng; '
              'FN là không xác nhận lỗ hổng trên case có lỗ hổng theo nhãn chuẩn. '
              'Kết luận hợp lệ “không xác nhận lỗ hổng” khác với “chưa có kết luận”: kết luận này '
              'được tính là TN hoặc FN khi đối chiếu với nhãn chuẩn.', '']
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
    lines += ['T2A/T2B chỉ lấy các lần chạy được tiến trình điều phối ghi nhận là hoàn tất, gồm cả '
              'case chưa có kết luận hoặc kết quả không hợp lệ nếu có số đo hợp lệ. Số đo / case hoàn tất '
              'là n/N: n case có số đo hợp lệ, N case hoàn tất; tính riêng cho thời gian và token. '
              'Tổng tính lại từ các case gộp, không lấy trung bình thống kê từng lớp. '
              'p95 là số đo ở vị trí làm tròn lên của 0,95 × n trong dãy tăng dần; '
              'mẫu nhỏ có thể cho p95 bằng giá trị lớn nhất.', '',
              'Khoảng thời gian đo gồm Agent chạy và xử lý công việc nền còn lại; không gồm khởi tạo, '
              'đóng băng/xuất kết quả hoặc chi phí điều phối tiến trình. Token là đơn vị văn bản '
              'mà mô hình xử lý; tổng token chỉ dùng số đo đầy đủ cho mọi yêu cầu LLM, '
              'không thay bằng tổng quan sát từng phần hoặc tự cộng input/output token.', '']
    noncompleted = [case for case in model.cases if case.get('final_status') not in (None, 'completed')]
    missing = [case for case in model.cases if case.get('final_status') is None]
    if noncompleted:
        lines += ['## T2C — Tài nguyên của các lần chạy chưa hoàn tất', '']
        rows = []
        for label, cls in CLASS_LABELS[:2]:
            statuses = sorted({case['final_status'] for case in noncompleted if case['vulnerability_class'] == cls})
            for status in statuses:
                cases = [case for case in noncompleted if case['vulnerability_class'] == cls and case['final_status'] == status]
                rows.append([f'{label} / {STATUS_LABELS[status]}', str(len(cases)),
                    _metric_cell(resource_summary(cases, 'agent_seconds'), 1),
                    _metric_cell(resource_summary(cases, 'total_tokens'), 1000)])
        lines += _table(('Lớp / trạng thái', 'Số lần chạy', 'Trung vị thời gian đã ghi nhận (s)',
                         'Trung vị tổng token đầy đủ (nghìn)'), rows)
        lines += ['Mỗi trạng thái kết thúc được giữ riêng; thời gian đã ghi nhận chỉ là khoảng đo '
                  'còn lưu được, không phải thời gian đến khi hoàn tất. Dưới trung vị là n/N: '
                  'n case có số đo hợp lệ, N case trong đúng nhóm lớp/trạng thái. '
                  '“Đạt giới hạn tài nguyên” là chạm giới hạn lời gọi, yêu cầu HTTP hoặc dung lượng '
                  'ngữ cảnh; “Lỗi dịch vụ LLM” là lỗi khi làm việc với dịch vụ mô hình; '
                  '“Tiến trình gặp sự cố” là sự cố của tiến trình chạy case.', '']
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
        lines += _table(('Lớp', 'Nhóm kết quả đánh giá', 'Số case', 'Trung vị thời gian đã ghi nhận (s)',
                         'Trung vị tổng token đầy đủ (nghìn)'), rows)
        lines += ['“Không có trạng thái kết thúc” chỉ là nhãn hiển thị cho dữ liệu thiếu, không phải '
                  'một trạng thái mới của lần chạy. Case chưa chạy vẫn được tính trong tổng case '
                  'đã lên lịch ở T1/T3. Các nhóm kết quả được giữ riêng; không suy diễn '
                  'thời điểm bắt đầu/kết thúc từ số đo hoặc trạng thái của tiến trình chạy case. '
                  'Dưới trung vị là n/N: n case có số đo hợp lệ, N case trong nhóm.', '']
    lines += ['## T3 — Tổng sử dụng tài nguyên của các case đã lên lịch', '']
    rows = []
    for label, cls in CLASS_LABELS:
        cases = class_cases(model, cls)
        cells = []
        for metric in ('total_tokens', 'llm_calls', 'tool_executed', 'http_dispatch_attempts'):
            stats = resource_summary(cases, metric)
            cells.append(f'{format_count(stats.total)}<br>{stats.coverage}')
        rows.append([label, *cells])
    lines += _table(('Lớp', 'Tổng token', 'Lần gọi LLM', 'Lần chạy tool', 'Lần thử gửi HTTP'), rows)
    lines += ['Mỗi ô ghi tổng số và n/N: n case có số đo hợp lệ, N case đã lên lịch. '
              'Bao gồm số đo hợp lệ của case hoàn tất và chưa hoàn tất. Chỉ có tổng số khi N > 0 '
              'và đủ số đo hợp lệ cho mọi case; thiếu bất kỳ số đo nào thì NA, không dùng tổng '
              'của riêng các case có số đo làm tổng toàn bộ. Token chỉ cộng tổng đầy đủ. '
              'Thiếu số đo không có nghĩa là 0.', '',
              'Lần gọi LLM đếm yêu cầu ở cấp ứng dụng, không tách từng lần thử lại ở tầng truyền tải; '
              'lần chạy tool đếm lời gọi đã bắt đầu thực thi sau khi được cấp phép, gồm cả lời gọi có thể thất bại '
              'và không tính thao tác tạo ứng viên kiểm thử của bộ benchmark. Lần thử gửi HTTP đếm '
              'mỗi lần chuyển yêu cầu cho bộ truyền tải, gồm cả thử lại; không chứng minh máy chủ '
              'đã nhận hoặc xử lý thành công. Số lượt được cấp phép gửi không thay cho số lần thử gửi.', '',
              'NA: không tính được tỷ lệ khi mẫu số bằng 0; không có số đo hợp lệ để tính thống kê; '
              'hoặc thiếu số đo để tính tổng toàn bộ ở T3. Tổng token chưa được ghi nhận đầy đủ '
              'cũng là NA. Giá trị 0 đo được vẫn là 0. Số thập phân dùng dấu phẩy, một chữ số '
              'sau dấu phẩy; số dương rất nhỏ dùng <0,1 để không biến thành 0. T3 dùng số đếm nguyên '
              'với dấu chấm phân cách nghìn. CSV giữ nguyên giá trị gốc và độ chính xác.', '',
              '## Chú thích gợi ý', '',
              f'Ngữ cảnh áp dụng cho F1/F2/F3: {context}', '',
              '**F1 — Chất lượng xác thực SQLi và XSS trong Scenario 1.** Recall, Precision và FPR '
              'tính trên các case đánh giá được: Recall = TP/(TP+FN), tỷ lệ xác nhận đúng trong '
              'các case có lỗ hổng theo nhãn chuẩn; Precision = TP/(TP+FP), tỷ lệ xác nhận đúng '
              'trong các case Agent xác nhận có lỗ hổng; FPR = FP/(FP+TN), tỷ lệ xác nhận nhầm '
              'trong các case không có lỗ hổng theo nhãn chuẩn. Tỷ lệ đánh giá được (Evaluability) '
              '= số case đánh giá được / tổng case đã lên lịch. '
              'Nhãn thể hiện % (tử số/mẫu số); NA khi mẫu số bằng 0. Các nhóm chưa có kết luận, lỗi '
              'thực thi, kết quả không hợp lệ và chưa chạy không được tính vào TP/TN/FP/FN (xem T1A). '
              'Recall và Precision cao hơn tốt hơn; FPR thấp hơn tốt hơn. Tỷ lệ đánh giá được '
              'thể hiện mức bao phủ, không phải độ đúng.', '']
    references = (' Các lần chạy chưa hoàn tất xem T2C.' if noncompleted else '') + (
        ' Case thiếu trạng thái kết thúc xem Ledger.' if missing else '')
    for metric, text in (
            ('agent_seconds', '**F2 — Trung vị thời gian xử lý của Agent theo lớp lỗ hổng.** '
             'Trung vị trên các lần chạy được tiến trình điều phối ghi nhận là hoàn tất và có số đo '
             'hợp lệ, kể cả case chưa có kết luận hoặc kết quả không hợp lệ. Đơn vị giây; khoảng đo gồm '
             'Agent chạy và xử lý công việc nền còn lại, không gồm khởi tạo, xuất kết quả và chi phí '
             'điều phối. Đây không phải thời gian toàn bộ benchmark. NA khi không có số đo hợp lệ; '
             'phân bố thời gian xem T2A.'),
            ('total_tokens', '**F3 — Trung vị tổng token sử dụng theo lớp lỗ hổng.** '
             'Trung vị của tổng token được ghi nhận đầy đủ cho mọi yêu cầu LLM trên các lần chạy '
             'được tiến trình điều phối ghi nhận là hoàn tất, kể cả case chưa có kết luận hoặc kết quả '
             'không hợp lệ. Đơn vị nghìn token (1 = 1.000 token); token là đơn vị văn bản mà mô hình '
             'xử lý. Số đo thiếu hoặc chưa đầy đủ không được đưa vào trung vị; NA khi không có số đo '
             'hợp lệ. Phân bố token xem T2B, tổng tiêu thụ của mọi case đã lên lịch xem T3.')):
        coverage = []
        for label, cls in CLASS_LABELS[:2]:
            cases = class_cases(model, cls)
            stats = resource_summary(class_cases(model, cls, completed=True), metric)
            coverage.append(f'{label}: {stats.eligible}/{len(cases)} case hoàn tất / đã lên lịch; '
                            f'{stats.coverage} case có số đo hợp lệ / hoàn tất')
        lines += [text + ' ' + '; '.join(coverage) + '.' + references, '']
    return ('\n'.join(lines)).encode('utf-8')
