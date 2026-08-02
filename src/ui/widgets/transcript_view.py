from __future__ import annotations

from rich.text import Text
from textual.widgets import RichLog

from src.ui.core.state import TranscriptEntry
from src.ui.widgets.transcript import entry_view


class TranscriptView(RichLog):
    """
    Widget Textual thật cho phần "committed log" — tương đương JSX:

        <Transcript committed={filteredCommitted} bannerData={...}
                    generation={`${state.clearGen}:${state.transcriptFilter}`} />

    LƯU Ý: đây là lớp MỚI, không phải port 1:1 từ TS (JSX component
    không map thẳng sang 1 class Python cụ thể) — viết theo Hướng B
    (widget-tree thật của Textual) đã thống nhất. Logic "chỉ in các
    entry mới kể từ lần trước" giữ đúng ý tưởng từ src/ui/widgets/
    transcript.py (Transcript.flush) nhưng đích ghi là RichLog thay vì
    sys.stdout.
    """

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