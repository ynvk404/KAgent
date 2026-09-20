from __future__ import annotations

from rich.segment import Segment
from rich.text import Text
from textual.geometry import Offset
from textual.selection import Selection
from textual.strip import Strip
from textual.widgets import RichLog

from src.ui.core.state import TranscriptEntry
from src.ui.widgets.transcript import entry_view


class TranscriptView(RichLog):

    DEFAULT_CSS = """
    TranscriptView {
        width: 100%;
        height: 1fr;
        overflow-y: scroll;
        overflow-x: hidden;
        scrollbar-size-vertical: 1;
        scrollbar-size-horizontal: 0;
        scrollbar-color: #7E8A9A;
        scrollbar-color-hover: #38BDF8;
        scrollbar-color-active: #38BDF8;
        scrollbar-background: transparent;
        scrollbar-background-hover: transparent;
        scrollbar-background-active: transparent;
        scrollbar-gutter: auto;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(wrap=True, markup=False, highlight=False, **kwargs)
        self._printed_count = 0
        self._last_generation: object | None = None

    def sync(
        self,
        committed: list[TranscriptEntry],
        generation: object,
    ) -> None:
        if generation != self._last_generation:
            self.clear()
            self._printed_count = 0
            self._last_generation = generation

        new_entries = committed[self._printed_count :]
        for entry in new_entries:
            self._write_entry(entry)

        self._printed_count = len(committed)

    def _write_entry(self, entry: TranscriptEntry) -> None:
        width = self.transcript_content_width
        for line in entry_view(entry, width=width):
            self.write(
                Text.from_ansi(line.text, style=line.color or ""),
                width=width,
            )

    @property
    def transcript_content_width(self) -> int:
        """Width available to transcript rows and the native scrollbar."""
        content_width = self.content_region.width or self.size.width
        return max(1, content_width - self.scrollbar_size_vertical)

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
