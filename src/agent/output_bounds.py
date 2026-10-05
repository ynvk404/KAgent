"""Deterministic transforms for bounding LLM-facing tool output."""

from collections.abc import Callable


def _weighted_window_lengths(total: int, weights: tuple[int, ...]) -> list[int]:
    """Split a source budget deterministically across the ordered windows."""
    lengths = [total * weight // 100 for weight in weights]
    remainder = total - sum(lengths)
    for index in range(remainder):
        lengths[index % len(lengths)] += 1
    return lengths


def _distributed_window_ranges(
    source_length: int,
    budget: int,
    weights: tuple[int, ...],
    *,
    weighted_window_lengths: Callable[[int], list[int]] | None = None,
) -> list[tuple[int, int]]:
    get_lengths = weighted_window_lengths or (
        lambda total: _weighted_window_lengths(total, weights)
    )
    lengths = get_lengths(min(source_length, max(0, budget)))
    anchors = (0.0, 0.25, 0.5, 0.75, 1.0)
    ranges: list[tuple[int, int]] = []

    for index, (anchor, length) in enumerate(zip(anchors, lengths)):
        if length <= 0:
            continue
        if index == 0:
            start = 0
        elif index == len(anchors) - 1:
            start = source_length - length
        else:
            center = round(source_length * anchor)
            start = center - length // 2
        start = min(max(0, start), source_length - length)
        end = start + length

        if ranges and start <= ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
        else:
            ranges.append((start, end))

    return ranges


def _render_distributed_windows(
    content: str,
    source_budget: int,
    *,
    weights: tuple[int, ...],
    elision_prefix: str,
    distributed_window_ranges: (
        Callable[[int, int], list[tuple[int, int]]] | None
    ) = None,
) -> str:
    get_ranges = distributed_window_ranges or (
        lambda source_length, budget: _distributed_window_ranges(
            source_length,
            budget,
            weights,
        )
    )
    ranges = get_ranges(len(content), source_budget)
    if not ranges:
        return ""

    parts: list[str] = []
    previous_end = 0
    for start, end in ranges:
        if start > previous_end:
            parts.append(
                "\n"
                f"{elision_prefix}; characters "
                f"{previous_end}-{start} omitted; original length {len(content)}]"
                "\n"
            )
        parts.append(content[start:end])
        previous_end = end

    if previous_end < len(content):
        parts.append(
            "\n"
            f"{elision_prefix}; characters "
            f"{previous_end}-{len(content)} omitted; original length {len(content)}]"
            "\n"
        )
    return "".join(parts)


def _render_distributed_omissions(
    content: str,
    omitted: int,
    *,
    elision_prefix: str,
    proportional_reductions: Callable[[list[int], int], list[int]],
) -> str:
    """Render four ordered gaps between the five evidence anchor points."""
    source_length = len(content)
    anchors = [0, source_length // 4, source_length // 2, source_length * 3 // 4, source_length]
    capacities = [max(0, anchors[i + 1] - anchors[i] - 2) for i in range(4)]
    gap_lengths = proportional_reductions(capacities, omitted)
    gaps: list[tuple[int, int]] = []
    for index, gap_length in enumerate(gap_lengths):
        if gap_length <= 0:
            continue
        segment_start = anchors[index] + 1
        segment_end = anchors[index + 1] - 1
        start = segment_start + (segment_end - segment_start - gap_length) // 2
        gaps.append((start, start + gap_length))

    parts: list[str] = []
    previous_end = 0
    for start, end in gaps:
        parts.append(content[previous_end:start])
        parts.append(
            "\n"
            f"{elision_prefix}; characters "
            f"{start}-{end} omitted; original length {source_length}]"
            "\n"
        )
        previous_end = end
    parts.append(content[previous_end:])
    return "".join(parts)


def bound_recent_tool_result(
    content: str,
    target_length: int,
    *,
    minimum_retained_length: int,
    elision_prefix: str,
    render_windows: Callable[[str, int], str],
    render_omissions: Callable[[str, int], str],
) -> str:
    """Bound one LLM-facing result with ordered windows including marker cost."""
    target_length = max(
        minimum_retained_length,
        min(len(content), target_length),
    )
    if len(content) <= target_length or elision_prefix in content:
        return content

    low = 0
    high = len(content)
    best = ""
    while low <= high:
        source_budget = (low + high) // 2
        rendered = render_windows(content, source_budget)
        if len(rendered) <= target_length:
            if len(rendered) > len(best):
                best = rendered
            low = source_budget + 1
        else:
            high = source_budget - 1

    # When weighted windows overlap under slight pressure, filling their gaps
    # can otherwise produce a large representational cliff. A complementary
    # four-gap search keeps almost all source while retaining the same five
    # distributed evidence regions.
    low = 1
    high = len(content)
    while low <= high:
        omitted = (low + high) // 2
        rendered = render_omissions(content, omitted)
        if len(rendered) <= target_length:
            if len(rendered) > len(best):
                best = rendered
            high = omitted - 1
        else:
            low = omitted + 1

    if not best or len(best) >= len(content):
        return content
    return best


def _proportional_reductions(capacities: list[int], required: int) -> list[int]:
    """Allocate an integer reduction using stable largest remainders."""
    total_capacity = sum(capacities)
    amount = min(max(0, required), total_capacity)
    if amount == 0 or total_capacity == 0:
        return [0] * len(capacities)

    reductions = [amount * capacity // total_capacity for capacity in capacities]
    remainders = [amount * capacity % total_capacity for capacity in capacities]
    left = amount - sum(reductions)
    order = sorted(range(len(capacities)), key=lambda i: (-remainders[i], i))
    for index in order:
        if left == 0:
            break
        if reductions[index] < capacities[index]:
            reductions[index] += 1
            left -= 1
    return reductions
