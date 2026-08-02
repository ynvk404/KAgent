from __future__ import annotations

import sys
import weakref
from dataclasses import dataclass
from typing import IO, Literal

from src.ui.core.state import TranscriptEntry
from src.ui.core.terminal_size import get_terminal_size
from src.ui.render.markdown import render_markdown
from src.ui.widgets.banner import Banner, BannerData

EntryKind = Literal[
    "user",
    "assistant",
    "tool-call",
    "tool-result",
    "system",
    "error",
    "finding",
    "decision",
]


@dataclass(frozen=True, slots=True)
class RoleStyle:
    color: str
    prefix: str


ROLE_STYLES: dict[EntryKind, RoleStyle] = {
    "user": RoleStyle(color="cyan", prefix="› "),
    "assistant": RoleStyle(color="white", prefix="  "),
    "tool-call": RoleStyle(color="magenta", prefix="⚙ "),
    "tool-result": RoleStyle(color="gray", prefix="↳ "),
    "system": RoleStyle(color="gray", prefix="· "),
    "error": RoleStyle(color="red", prefix="! "),
    "finding": RoleStyle(color="yellow", prefix="★ "),
    "decision": RoleStyle(color="cyan", prefix="· "),
}

CONTINUATION_INDENT = "  "

MARKDOWN_KINDS: set[EntryKind] = {"assistant", "finding"}


@dataclass(frozen=True, slots=True)
class Row:
    kind: EntryKind
    text: str
    is_first: bool


@dataclass(frozen=True, slots=True)
class RenderedLine:

    text: str
    color: str


_row_cache: dict[int, tuple["weakref.ReferenceType[TranscriptEntry]", list[Row]]] = {}


def rows_for_entry(entry: TranscriptEntry) -> list[Row]:
    key = id(entry)
    cached = _row_cache.get(key)
    if cached is not None:
        ref, rows = cached
        if ref() is entry:
            return rows

    text = render_markdown(entry.text) if entry.kind in MARKDOWN_KINDS else entry.text
    lines = text.split("\n")
    out = [Row(kind=entry.kind, text=line, is_first=(j == 0)) for j, line in enumerate(lines)]
    out.append(Row(kind=entry.kind, text="", is_first=False))

    def _on_collected(_ref: object, key: int = key) -> None:
        _row_cache.pop(key, None)

    _row_cache[key] = (weakref.ref(entry, _on_collected), out)
    return out


def plain_rows_for_entry(entry: TranscriptEntry) -> list[Row]:
    lines = entry.text.split("\n")
    out = [Row(kind=entry.kind, text=line, is_first=(j == 0)) for j, line in enumerate(lines)]
    out.append(Row(kind=entry.kind, text="", is_first=False))
    return out


def entry_view(entry: TranscriptEntry, streaming: bool = False) -> list[RenderedLine]:
    style = ROLE_STYLES[entry.kind]
    rows = plain_rows_for_entry(entry) if streaming else rows_for_entry(entry)

    lines: list[RenderedLine] = []
    for row in rows:
        indent = (getattr(entry, "prefix", None) or style.prefix) if row.is_first else CONTINUATION_INDENT
        text = f"{indent}{row.text}" if row.text else ""
        color = getattr(entry, "color", None) or style.color
        lines.append(RenderedLine(text=text, color=color))
    return lines


class Transcript:

    def __init__(self, out: IO[str] | None = None) -> None:
        self._out: IO[str] = out if out is not None else sys.stdout
        self._printed_count = 0
        self._last_generation: object | None = None
        self._banner_printed = False

    def flush(
        self,
        committed: list[TranscriptEntry],
        banner_data: BannerData,
        generation: object,
    ) -> None:
        if generation != self._last_generation:
            self._printed_count = 0
            self._banner_printed = False
            self._last_generation = generation

        if not self._banner_printed:
            columns, _rows = get_terminal_size()
            self._write_banner(banner_data, columns)
            self._banner_printed = True

        new_entries = committed[self._printed_count :]
        for entry in new_entries:
            self._write_entry(entry)

        self._printed_count = len(committed)

    def _write_banner(self, banner_data: BannerData, columns: int) -> None:
        for line in Banner(banner_data, width=columns).render():
            self._out.write(line.text + "\n")
        self._out.write("\n")

    def _write_entry(self, entry: TranscriptEntry) -> None:
        for line in entry_view(entry):
            self._out.write(line.text + "\n")