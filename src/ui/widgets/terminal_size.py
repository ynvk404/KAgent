from __future__ import annotations

from dataclasses import dataclass
import shutil


@dataclass(frozen=True, slots=True)
class TerminalSize:
    columns: int
    rows: int

DEFAULT_SIZE = TerminalSize(columns=100, rows=30)


def read_terminal_size() -> TerminalSize:
    size = shutil.get_terminal_size(
        fallback=(DEFAULT_SIZE.columns, DEFAULT_SIZE.rows)
    )
    return TerminalSize(
        columns=size.columns,
        rows=size.lines,
    )