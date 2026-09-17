from __future__ import annotations

from rich.segment import Segment
from rich.text import Text
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
        for line in entry_view(entry):
            self.write(Text(line.text, style=line.color or ""))

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
        return selection.extract("\n".join(line.text for line in self.lines)), "\n"
