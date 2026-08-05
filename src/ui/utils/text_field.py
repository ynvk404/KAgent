from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional
import re


@dataclass(frozen=True)
class TextFieldState:
    value: str
    cursor: int


def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def position_of(value: str, offset: int) -> tuple[int, int]:
    line = 0
    col = 0
    cap = clamp(offset, 0, len(value))
    for i in range(cap):
        if value[i] == "\n":
            line += 1
            col = 0
        else:
            col += 1
    return line, col


def offset_at(value: str, line: int, col: int) -> int:
    lines = value.split("\n")
    target_line = clamp(line, 0, len(lines) - 1)
    off = 0
    for i in range(target_line):
        off += len(lines[i]) + 1
    line_len = len(lines[target_line])
    return off + clamp(col, 0, line_len)


class TextField:

    def __init__(self, initial: str = "") -> None:
        self._state = TextFieldState(value=initial, cursor=len(initial))

    @property
    def value(self) -> str:
        return self._state.value

    @property
    def cursor(self) -> int:
        return self._state.cursor

    def insert_text(self, text: str) -> None:
        s = self._state
        value = s.value[: s.cursor] + text + s.value[s.cursor :]
        self._state = TextFieldState(value=value, cursor=s.cursor + len(text))

    def backspace(self) -> None:
        s = self._state
        if s.cursor == 0:
            return
        value = s.value[: s.cursor - 1] + s.value[s.cursor :]
        self._state = TextFieldState(value=value, cursor=s.cursor - 1)

    def delete_forward(self) -> None:
        s = self._state
        if s.cursor >= len(s.value):
            return
        value = s.value[: s.cursor] + s.value[s.cursor + 1 :]
        self._state = TextFieldState(value=value, cursor=s.cursor)

    def move_left(self) -> None:
        self._move(-1)

    def move_right(self) -> None:
        self._move(1)

    def _move(self, delta: int) -> None:
        s = self._state
        self._state = TextFieldState(
            value=s.value, cursor=clamp(s.cursor + delta, 0, len(s.value))
        )

    def move_up(self) -> None:
        s = self._state
        line, col = position_of(s.value, s.cursor)
        if line == 0:
            self._state = TextFieldState(value=s.value, cursor=0)
            return
        self._state = TextFieldState(
            value=s.value, cursor=offset_at(s.value, line - 1, col)
        )

    def move_down(self) -> None:
        s = self._state
        line, col = position_of(s.value, s.cursor)
        lines = s.value.split("\n")
        if line >= len(lines) - 1:
            self._state = TextFieldState(value=s.value, cursor=len(s.value))
            return
        self._state = TextFieldState(
            value=s.value, cursor=offset_at(s.value, line + 1, col)
        )

    def move_line_start(self) -> None:
        s = self._state
        line, _ = position_of(s.value, s.cursor)
        self._state = TextFieldState(
            value=s.value, cursor=offset_at(s.value, line, 0)
        )

    def move_line_end(self) -> None:
        s = self._state
        line, _ = position_of(s.value, s.cursor)
        lines = s.value.split("\n")
        line_text = lines[line] if 0 <= line < len(lines) else ""
        self._state = TextFieldState(
            value=s.value, cursor=offset_at(s.value, line, len(line_text))
        )

    def set_value(self, v: str, cursor: Optional[int] = None) -> None:
        c = cursor if cursor is not None else len(v)
        self._state = TextFieldState(value=v, cursor=clamp(c, 0, len(v)))

    def clear(self) -> None:
        self._state = TextFieldState(value="", cursor=0)


def looks_like_paste(input_text: str, key_return: bool = False) -> bool:
    if not input_text:
        return False
    if len(input_text) > 1:
        return True
    if "\n" in input_text and not key_return:
        return True
    return False


PASTE_START = "\x1b[200~"
PASTE_END = "\x1b[201~"


def strip_paste_markers(s: str) -> str:
    """Loại bỏ các ký tự điều khiển bracketed-paste bị rò rỉ từ terminal."""
    return s.replace(PASTE_START, "").replace(PASTE_END, "")


def normalize_pasted_text(s: str) -> str:
    return s.replace("\r\n", "\n").replace("\r", "\n")


def should_collapse_paste(s: str) -> bool:
    return "\n" in normalize_pasted_text(s)


def pasted_text_marker(id_: int, text: str) -> str:
    normalized = normalize_pasted_text(text)
    line_count = len(normalized.split("\n"))
    return f"[Pasted text #{id_} +{line_count} lines, {len(normalized)} chars]"


PASTED_TEXT_MARKER_RE = re.compile(
    r"\[Pasted text #(\d+) \+\d+ lines(?:, \d+ chars)?\]"
)


def expand_pasted_text_markers(
    value: str, pasted_text_by_id: Mapping[int, str]
) -> str:
    def _replace(m: re.Match[str]) -> str:
        pasted = pasted_text_by_id.get(int(m.group(1)))
        return pasted if pasted is not None else m.group(0)

    return PASTED_TEXT_MARKER_RE.sub(_replace, value)

def cursor_is_on_first_line(value: str, cursor: int) -> bool:
    return value.rfind("\n", 0, cursor) == -1


def cursor_is_on_last_line(value: str, cursor: int) -> bool:
    return value.find("\n", cursor) == -1