from __future__ import annotations

import re
from typing import List

from .color_level import color_level

_ESC = "\x1b"
_RESET = f"{_ESC}[0m"

_CODES = {
    "bold": "1",
    "dim": "2",
    "italic": "3",
    "underline": "4",
    "gray": "90",
    "magenta": "35",
    "cyan": "36",
    "blue": "34",
}


def _style(name: str, text: str) -> str:
    if not text:
        return text
    if color_level() == 0:
        return text
    code = _CODES[name]
    return f"{_ESC}[{code}m{text}{_RESET}"


def _bold(text: str) -> str:
    return _style("bold", text)


def _dim(text: str) -> str:
    return _style("dim", text)


def _italic(text: str) -> str:
    return _style("italic", text)


def _gray(text: str) -> str:
    return _style("gray", text)


def _magenta(text: str) -> str:
    return _style("magenta", text)


def _cyan(text: str) -> str:
    return _style("cyan", text)


def _blue_underline(text: str) -> str:
    if not text or color_level() == 0:
        return text
    return f"{_ESC}[34m{_ESC}[4m{text}{_RESET}"


def render_markdown(s: str) -> str:
    if not s:
        return s

    lines = _strip_proposed_plan_wrapper(s).split("\n")
    out: List[str] = []
    in_fence = False
    fence_lang = ""
    fence_buf: List[str] = []

    i = 0
    while i < len(lines):
        raw = lines[i] if i < len(lines) else ""
        fence_match = re.match(r"^[ \t]{0,3}```\s*(\S*)", raw)
        if fence_match:
            if in_fence:
                out.append(_render_fenced_block(fence_buf, fence_lang))
                in_fence = False
                fence_lang = ""
                fence_buf = []
            else:
                in_fence = True
                fence_lang = fence_match.group(1) or ""
            i += 1
            continue

        if in_fence:
            fence_buf.append(raw)
            i += 1
            continue

        next_line = lines[i + 1] if i + 1 < len(lines) else ""
        if _is_table_row(raw) and _is_table_separator(next_line):
            block = [raw]
            j = i + 2
            while j < len(lines) and _is_table_row(lines[j]):
                block.append(lines[j])
                j += 1
            out.append(_render_table(block))
            i = j
            continue

        out.append(_render_line(raw))
        i += 1

    if in_fence and fence_buf:
        out.append(_render_fenced_block(fence_buf, fence_lang))

    return "\n".join(out)


def _strip_proposed_plan_wrapper(s: str) -> str:
    lines = [
        line
        for line in s.split("\n")
        if line.strip() not in ("<proposed_plan>", "</proposed_plan>")
    ]
    return "\n".join(_trim_outer_blank_lines(lines))


def _trim_outer_blank_lines(lines: List[str]) -> List[str]:
    start = 0
    end = len(lines)
    while start < end and lines[start].strip() == "":
        start += 1
    while end > start and lines[end - 1].strip() == "":
        end -= 1
    return lines[start:end]


def _render_fenced_block(lines: List[str], lang: str) -> str:
    if not lines:
        return ""

    highlighted = _highlight_lines(lines, lang)

    gutter_width = len(str(len(highlighted)))
    out = []
    for idx, row in enumerate(highlighted):
        num = str(idx + 1).rjust(gutter_width, " ")
        out.append(f"{_dim(f'{num}\u2502')} {row}")
    return "\n".join(out)


def _highlight_lines(lines: List[str], lang: str) -> List[str]:
    if lang and _supports_language(lang):
        try:
            from pygments import highlight
            from pygments.lexers import get_lexer_by_name
            from pygments.formatters import Terminal256Formatter

            if color_level() == 0:
                return [line for line in lines]

            lexer = get_lexer_by_name(lang, stripnl=False)
            formatter = Terminal256Formatter()
            body = highlight("\n".join(lines), lexer, formatter)
            return body.rstrip("\n").split("\n")
        except Exception:
            return [_dim(line) for line in lines]
    return [_dim(line) for line in lines]


def _supports_language(lang: str) -> bool:
    try:
        from pygments.lexers import get_lexer_by_name

        get_lexer_by_name(lang)
        return True
    except Exception:
        return False


_HEADING_RE = re.compile(r"^(\s*)(#{1,6})\s+(.*)$")
_BULLET_RE = re.compile(r"^(\s*)([-*])\s+(.*)$")
_QUOTE_RE = re.compile(r"^(\s*)>\s?(.*)$")


def _render_line(line: str) -> str:
    heading = _HEADING_RE.match(line)
    if heading:
        indent, hashes, text = heading.group(1), heading.group(2), heading.group(3)
        level = len(hashes)
        rendered_text = _render_inline(text)
        if level == 1:
            return f"{indent}{_bold(_magenta(rendered_text))}"
        if level == 2:
            return f"{indent}{_bold(_cyan(rendered_text))}"
        return f"{indent}{_bold(rendered_text)}"

    bullet = _BULLET_RE.match(line)
    if bullet:
        indent, _, text = bullet.group(1), bullet.group(2), bullet.group(3)
        return f"{indent}{_gray('\u2022')} {_render_inline(text)}"

    quote = _QUOTE_RE.match(line)
    if quote:
        indent, text = quote.group(1), quote.group(2)
        return f"{indent}{_gray('\u2502 ')}{_dim(_render_inline(text))}"

    return _render_inline(line)


_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_CODE_RE = re.compile(r"`([^`]+)`")
_BOLD_STAR_RE = re.compile(r"\*\*([^*\n]+)\*\*")
_BOLD_UNDER_RE = re.compile(r"__([^_\n]+)__")
_ITALIC_STAR_RE = re.compile(r"(?<![\w*])\*([^*\n]+)\*(?!\w)")
_ITALIC_UNDER_RE = re.compile(r"(?<![\w_])_([^_\n]+)_(?!\w)")


def _render_inline(s: str) -> str:
    if not s:
        return s

    def _link_sub(m: re.Match) -> str:
        label, url = m.group(1), m.group(2)
        if label == url:
            return _blue_underline(url)
        return f"{_blue_underline(label)} {_dim(f'({url})')}"

    s = _LINK_RE.sub(_link_sub, s)
    s = _CODE_RE.sub(lambda m: _cyan(m.group(1)), s)
    s = _BOLD_STAR_RE.sub(lambda m: _bold(m.group(1)), s)
    s = _BOLD_UNDER_RE.sub(lambda m: _bold(m.group(1)), s)
    s = _ITALIC_STAR_RE.sub(lambda m: _italic(m.group(1)), s)
    s = _ITALIC_UNDER_RE.sub(lambda m: _italic(m.group(1)), s)
    return s


_ANSI_RE = re.compile(rf"{_ESC}\[[0-9;]*m")


def _visible_width(s: str) -> int:
    return len(_ANSI_RE.sub("", s))


def _is_table_row(line: str) -> bool:
    return "|" in line and line.strip() != ""


_TABLE_SEP_RE = re.compile(r"^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?$")


def _is_table_separator(line: str) -> bool:
    t = line.strip()
    if "-" not in t or "|" not in t:
        return False
    return bool(_TABLE_SEP_RE.match(t))


def _split_table_row(line: str) -> List[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    cells = re.split(r"(?<!\\)\|", s)
    return [c.replace("\\|", "|").strip() for c in cells]


def _render_table(block: List[str]) -> str:
    header = _split_table_row(block[0]) if block else []
    body_rows = [_split_table_row(row) for row in block[1:]]
    cols = max(len(header), max((len(r) for r in body_rows), default=0), 1)

    def cell(cells: List[str], c: int) -> str:
        return _render_inline(cells[c] if c < len(cells) else "")

    widths = []
    for c in range(cols):
        w = _visible_width(cell(header, c))
        for row in body_rows:
            w = max(w, _visible_width(cell(row, c)))
        widths.append(w)

    def pad(text: str, width: int) -> str:
        return text + " " * max(0, width - _visible_width(text))

    def render_row(cells: List[str], bold: bool) -> str:
        parts = []
        for c in range(cols):
            styled = _bold(cell(cells, c)) if bold else cell(cells, c)
            parts.append(pad(styled, widths[c]))
        return _dim(" \u2502 ").join(parts)

    rule = _dim("\u2500\u253c\u2500").join("\u2500" * w for w in widths)
    out = [render_row(header, True), rule]
    for row in body_rows:
        out.append(render_row(row, False))
    return "\n".join(out)