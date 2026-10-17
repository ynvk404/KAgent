from __future__ import annotations

import sys
import weakref
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from typing import IO, Callable, Literal

from src.ui.core.state import TranscriptEntry
from src.ui.core.terminal_size import get_terminal_size
from src.ui.render.markdown import render_markdown
from src.ui.render.help import render_help
from src.ui.render.sanitize import sanitize_text
from src.ui.widgets.banner import Banner, BannerData
from src.ui.theme import ACCENT, BOLD_ACCENT, BOLD_ERROR, MUTED, PRIMARY, WARNING, BOLD_SUCCESS
from src.ui.theme import DARK_UI, UIPalette

EntryKind = Literal[
    "user",
    "assistant",
    "system",
    "error",
    "finding",
    "info",
    "warning",
    "validation",
]


@dataclass(frozen=True, slots=True)
class RoleStyle:
    color: str
    prefix: str


ROLE_STYLES: dict[EntryKind, RoleStyle] = {
    "user": RoleStyle(color=ACCENT, prefix="› "),
    "assistant": RoleStyle(color=PRIMARY, prefix="  "),
    "system": RoleStyle(color=MUTED, prefix="  "),
    "error": RoleStyle(color=BOLD_ERROR, prefix="! "),
    "finding": RoleStyle(color=BOLD_SUCCESS, prefix="◆ "),
    "info": RoleStyle(color=BOLD_ACCENT, prefix="◆ "),
    "warning": RoleStyle(color=WARNING, prefix="! "),
    "validation": RoleStyle(color=BOLD_SUCCESS, prefix="◆ "),
}

CONTINUATION_INDENT = "  "

MARKDOWN_KINDS: set[EntryKind] = {"assistant"}


@dataclass(frozen=True, slots=True)
class Row:
    kind: EntryKind
    text: str
    is_first: bool


@dataclass(frozen=True, slots=True)
class RenderedLine:

    text: str
    color: str
    # Only entry_view sets this after sanitizing untrusted input and applying
    # application-owned Markdown formatting. Plain writer input is untrusted.
    trusted_ansi: bool = False


_row_cache: dict[
    int,
    tuple["weakref.ReferenceType[TranscriptEntry]", int | None, UIPalette, list[Row]],
] = {}


def rows_for_entry(entry: TranscriptEntry, width: int | None = None, ui: UIPalette = DARK_UI) -> list[Row]:
    key = id(entry)
    cached = _row_cache.get(key)
    if cached is not None:
        ref, cached_width, cached_ui, rows = cached
        if ref() is entry and cached_width == width and cached_ui == ui:
            return rows

    entry_text = _display_text(entry)
    text = render_help(entry.help_document, width) if entry.help_document is not None else (
        render_markdown(entry_text, width=width, ui=ui)
        if entry.kind in MARKDOWN_KINDS
        else entry_text
    )
    lines = text.split("\n")
    out = [Row(kind=entry.kind, text=line, is_first=(j == 0)) for j, line in enumerate(lines)]
    out.append(Row(kind=entry.kind, text="", is_first=False))

    def _on_collected(_ref: object, key: int = key) -> None:
        _row_cache.pop(key, None)

    _row_cache[key] = (weakref.ref(entry, _on_collected), width, ui, out)
    return out


def plain_rows_for_entry(entry: TranscriptEntry) -> list[Row]:
    lines = _display_text(entry).split("\n")
    out = [Row(kind=entry.kind, text=line, is_first=(j == 0)) for j, line in enumerate(lines)]
    out.append(Row(kind=entry.kind, text="", is_first=False))
    return out


def _display_text(entry: TranscriptEntry) -> str:
    # Keep field boundaries: redacting one field must not consume another.
    text = sanitize_text(entry.text)
    for detail in entry.details:
        text += "\n  " + sanitize_text(detail)
    return text


def entry_view(
    entry: TranscriptEntry,
    streaming: bool = False,
    width: int | None = None,
    ui: UIPalette = DARK_UI,
) -> list[RenderedLine]:
    style = ROLE_STYLES[entry.kind]
    rows = plain_rows_for_entry(entry) if streaming else rows_for_entry(entry, width, ui)

    lines: list[RenderedLine] = []
    for row in rows:
        indent = style.prefix if row.is_first else CONTINUATION_INDENT
        text = f"{indent}{row.text}" if row.text else ""
        color = (MUTED if entry.kind not in {"assistant", "user", "error", "warning"}
                 and not row.is_first and (entry.kind in {"finding", "validation"}
                 or row.text.startswith("  ")) else style.color)
        if (entry.kind in {"validation", "info"} and entry.text.startswith("Validation ")
                and not row.is_first and row.text.lstrip().startswith("Observed impact · ")):
            color = PRIMARY
        if color == PRIMARY:
            color = ui.text
        elif entry.kind == "user":
            color = ui.accent
        # Other role colors, including system notices and recovery, are statuses.
        lines.append(RenderedLine(text=text, color=color,
            trusted_ansi=entry.kind in MARKDOWN_KINDS and not streaming))
    return lines


class Transcript:

    def __init__(
        self,
        out: IO[str] | None = None,
        width: Callable[[], int] | None = None,
        clear: Callable[[], object] | None = None,
        write_banner: Callable[[BannerData], None] | None = None,
        preserve_viewport: Callable[[], AbstractContextManager[None]] | None = None,
        write_line: Callable[[RenderedLine], None] | None = None,
        ui: UIPalette = DARK_UI,
        line_count: Callable[[], int] | None = None,
        replace_lines: Callable[[int, int, list[RenderedLine]], int] | None = None,
    ) -> None:
        self._out: IO[str] = out if out is not None else sys.stdout
        self._width = width
        self._clear = clear
        self._write_banner_panel = write_banner
        self._preserve_viewport = preserve_viewport
        self._write_line = write_line
        self._ui = ui
        self._line_count = line_count
        self._replace_lines = replace_lines
        self._entries: list[TranscriptEntry] = []
        self._ranges: list[tuple[int, int]] = []
        self._printed_count = 0
        self._last_generation: object | None = None
        self._banner_printed = False
        self._last_banner_data: BannerData | None = None
        self._last_width: int | None = None

    def flush(
        self,
        committed: list[TranscriptEntry],
        banner_data: BannerData,
        generation: object,
        clear_message: str | None = None,
    ) -> None:
        width = self._width() if self._width is not None else None
        # RichLog stores rendered strips, so a resize must redraw source entries.
        if width != self._last_width and self._clear is not None:
            self._last_generation = None
        self._last_width = width
        changed = (generation != self._last_generation or len(committed) != self._printed_count
                   or any(left is not right and left != right for left, right in zip(committed, self._entries)))
        with self._preserve_viewport() if changed and self._preserve_viewport else nullcontext():
            self._flush(committed, banner_data, generation, clear_message)

    def _flush(
        self,
        committed: list[TranscriptEntry],
        banner_data: BannerData,
        generation: object,
        clear_message: str | None,
    ) -> None:
        if generation != self._last_generation:
            if self._clear is not None:
                self._clear()
            self._printed_count = 0
            self._banner_printed = False
            self._last_generation = generation
            self._entries = []
            self._ranges = []

        if (self._replace_lines is not None and self._line_count is not None
                and len(committed) >= self._printed_count and len(self._ranges) == self._printed_count):
            heights = [end - start for start, end in self._ranges]
            for index in range(self._printed_count - 1, -1, -1):
                if committed[index] is not self._entries[index] and committed[index] != self._entries[index]:
                    start, end = self._ranges[index]
                    width = self._width() if self._width is not None else None
                    heights[index] = self._replace_lines(start, end, entry_view(committed[index], width=width, ui=self._ui))
            if self._ranges:
                position = self._ranges[0][0]
                self._ranges = []
                for height in heights:
                    self._ranges.append((position, position + height))
                    position += height
        elif self._printed_count and (len(committed) < self._printed_count or any(
                a is not b and a != b for a, b in zip(committed, self._entries))):
            if self._clear is not None:
                self._clear()
            self._printed_count = 0
            self._banner_printed = False
            self._ranges = []

        if not self._banner_printed:
            if clear_message is not None:
                self._write_entry(TranscriptEntry(kind="system", text=clear_message))
            columns, _rows = get_terminal_size()
            self._write_banner(banner_data, columns)
            self._banner_printed = True
            self._last_banner_data = banner_data
        elif (
            self._write_banner_panel is not None
            and banner_data != self._last_banner_data
        ):
            # The TUI supplies a replaceable Overview widget here. Updating it
            # leaves the RichLog and its scrollback untouched.
            columns, _rows = get_terminal_size()
            self._write_banner(banner_data, columns)
            self._last_banner_data = banner_data

        new_entries = committed[self._printed_count :]
        for entry in new_entries:
            start = self._line_count() if self._line_count is not None else 0
            self._write_entry(entry)
            if self._line_count is not None:
                self._ranges.append((start, self._line_count()))

        self._printed_count = len(committed)
        self._entries = list(committed)

    def _write_banner(self, banner_data: BannerData, columns: int) -> None:
        if self._write_banner_panel is not None:
            self._write_banner_panel(banner_data)
            return
        for line in Banner(banner_data, width=columns).render():
            self._out.write(line.text + "\n")
        self._out.write("\n")

    def _write_entry(self, entry: TranscriptEntry) -> None:
        width = self._width() if self._width is not None else None
        for line in entry_view(entry, width=width, ui=self._ui):
            if self._write_line:
                self._write_line(line)
            else:
                self._out.write(line.text + "\n")
