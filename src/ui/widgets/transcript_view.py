from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterator
from contextlib import contextmanager

from rich.segment import Segment
from textual.geometry import Offset
from textual.message import Message
from textual.selection import Selection
from textual.strip import Strip
from textual.widgets import RichLog

from src.ui.theme import ACCENT, MUTED


class TranscriptView(RichLog):

    class Reflow(Message):
        """The transcript viewport has received its settled layout size."""

        def __init__(self, follow_tail: bool) -> None:
            super().__init__()
            self.follow_tail = follow_tail

    def on_resize(self) -> None:
        # Resizing can increase max_scroll_y before the app redraws. Compare
        # against the previous viewport so that a tail reader stays at the tail.
        follow_tail = self.auto_scroll and self.scroll_y >= max(0, len(self.lines) - self._viewport_height)
        self._viewport_height = self.size.height
        self.post_message(self.Reflow(follow_tail))

    DEFAULT_CSS = f"""
    TranscriptView {{
        width: 100%;
        height: 1fr;
        overflow-y: scroll;
        overflow-x: hidden;
        scrollbar-size-vertical: 1;
        scrollbar-size-horizontal: 0;
        scrollbar-color: {MUTED};
        scrollbar-color-hover: {ACCENT};
        scrollbar-color-active: {ACCENT};
        scrollbar-background: transparent;
        scrollbar-background-hover: transparent;
        scrollbar-background-active: transparent;
        scrollbar-gutter: auto;
    }}
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(wrap=True, markup=False, highlight=False, **kwargs)
        self._viewport_height = 0

    @property
    def transcript_content_width(self) -> int:
        """Width available to transcript rows and the native scrollbar."""
        content_width = self.content_region.width or self.size.width
        return max(1, content_width - self.scrollbar_size_vertical)

    @contextmanager
    def preserve_viewport(self) -> Iterator[None]:
        """Follow the tail only there; anchor history across aggregate rewrites."""
        auto_scroll = self.auto_scroll
        follow_tail = auto_scroll and self.is_vertical_scroll_end
        offset = self.scroll_offset
        old_count = len(self.lines)
        old_first = self.lines[0] if self.lines else None
        anchors: list[tuple[int, str, int]] = []
        reading_anchor: tuple[int, str, int] | None = None
        if not follow_tail:
            texts = [line.text for line in self.lines]
            for index in range(offset.y, min(len(texts), offset.y + self.size.height)):
                if texts[index].strip():
                    anchors.append((index - offset.y, texts[index], texts[:index].count(texts[index])))
                    if reading_anchor is None:
                        # Locate text across new wrap boundaries, including a
                        # viewport starting in the middle of a long paragraph.
                        needle = "".join(texts[index].split())[:32]
                        preceding = "".join("".join(text.split()) for text in texts[:index])
                        reading_anchor = (index - offset.y, needle, preceding.count(needle))
        # Batch writes must not schedule a scroll for every rendered line.
        self.auto_scroll = False
        try:
            yield
        finally:
            self.auto_scroll = auto_scroll
            changed = (old_count != len(self.lines) or
                       (bool(self.lines) and self.lines[0] is not old_first))
            if changed:
                if follow_tail:
                    self.scroll_end(animate=False, immediate=True, x_axis=False)
                    # The live Assistant widget may change the viewport height
                    # during the same dispatch. Follow its final layout as well.
                    self.scroll_end(animate=False, immediate=False, x_axis=False)
                else:
                    top = offset.y
                    for delta, text, occurrence in anchors:
                        matches = [index for index, line in enumerate(self.lines) if line.text == text]
                        if occurrence < len(matches):
                            top = matches[occurrence] - delta
                            break
                    if reading_anchor is not None:
                        delta, needle, occurrence = reading_anchor
                        compact = ["".join(line.text.split()) for line in self.lines]
                        joined = "".join(compact)
                        position = -1
                        for _ in range(occurrence + 1):
                            position = joined.find(needle, position + 1)
                            if position < 0:
                                break
                        if position >= 0:
                            ends: list[int] = []
                            total = 0
                            for text in compact:
                                total += len(text)
                                ends.append(total)
                            top = bisect_right(ends, position) - delta
                    self.scroll_to(x=offset.x, y=max(0, top), animate=False, immediate=True, force=True)

    def render_line(self, y: int):
        scroll_x, scroll_y = self.scroll_offset
        line = super().render_line(y)
        selection = self.text_selection
        if selection is not None:
            span = selection.get_span(scroll_y + y)
            if span is not None:
                start, end = span
                if end == -1:
                    end = scroll_x + line.cell_length
                start = max(0, start - scroll_x)
                end = min(line.cell_length, end - scroll_x)
                if start < end:
                    selected = line.crop(start, end)
                    line = Strip.join(
                        (
                            line.crop(0, start),
                            Strip(
                                Segment.apply_style(
                                    selected,
                                    post_style=self.selection_style,
                                ),
                                selected.cell_length,
                            ),
                            line.crop(end, line.cell_length),
                        )
                    )
        return line.apply_offsets(scroll_x, scroll_y + y)

    def get_selection(self, selection: Selection) -> tuple[str, str] | None:
        if not self.lines:
            return None

        line_count = len(self.lines)
        start = selection.start
        end = selection.end

        # Textual retains selections while an attached widget's content changes.
        # Validate against the current RichLog lines. Textual's Selection.extract
        # also drops trailing blank lines via splitlines(), so extract directly
        # from this list after normalizing the offsets.
        if start is not None:
            if start.y >= line_count:
                return None
            if start.y < 0:
                start = Offset(0, 0)
            else:
                start = Offset(max(0, min(start.x, len(self.lines[start.y].text))), start.y)

        if end is not None:
            if end.y < 0:
                return None
            if end.y >= line_count:
                last_line = self.lines[-1].text
                end = Offset(len(last_line), line_count - 1)
            else:
                end = Offset(max(0, min(end.x, len(self.lines[end.y].text))), end.y)

        start = start or Offset(0, 0)
        end = end or Offset(len(self.lines[-1].text), line_count - 1)
        if end.transpose < start.transpose:
            return None

        if start.y == end.y:
            selected = self.lines[start.y].text[start.x : end.x]
        else:
            selected_lines = [self.lines[start.y].text[start.x :]]
            selected_lines.extend(
                line.text for line in self.lines[start.y + 1 : end.y]
            )
            selected_lines.append(self.lines[end.y].text[: end.x])
            selected = "\n".join(selected_lines)
        return selected, "\n"
