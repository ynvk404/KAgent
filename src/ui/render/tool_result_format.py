from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable, Optional

from .color_level import color_level

_LEVEL = color_level()

_CODES = {
    "dim": "2",
    "bold": "1",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "cyan": "36",
}


def _style(code: str, s: str) -> str:
    if _LEVEL <= 0 or not s:
        return s
    return f"\x1b[{code}m{s}\x1b[0m"


class _Chalk:
    def dim(self, s: str) -> str:
        return _style(_CODES["dim"], s)

    def bold(self, s: str) -> str:
        return _style(_CODES["bold"], s)

    def red(self, s: str) -> str:
        return _style(_CODES["red"], s)

    def green(self, s: str) -> str:
        return _style(_CODES["green"], s)

    def yellow(self, s: str) -> str:
        return _style(_CODES["yellow"], s)

    def cyan(self, s: str) -> str:
        return _style(_CODES["cyan"], s)


chalk = _Chalk()

EXIT_RE = re.compile(r"^exit:\s*(-?\d+|timeout[^\n]*)")
STDOUT_LABEL = "stdout:"
STDERR_LABEL = "stderr:"


@dataclass
class ShellResultParts:
    exit: str
    stdout: str
    stderr: str
    rest: str


def colorize_shell_result(body: str) -> str:
    if not body:
        return body
    lines = body.split("\n")
    section = "pre"
    out_lines: list[str] = []
    for line in lines:
        exit_match = EXIT_RE.match(line)
        if exit_match:
            tail = line[exit_match.end():]
            code = exit_match.group(1) or ""
            is_success = code == "0"
            is_timeout = code.startswith("timeout")
            if is_success:
                styled_code = chalk.green(code)
            elif is_timeout:
                styled_code = chalk.yellow(code)
            else:
                styled_code = chalk.red(code)
            out_lines.append(f"{chalk.dim('exit:')} {styled_code}{tail}")
            continue
        if line == STDOUT_LABEL:
            section = "stdout"
            out_lines.append(chalk.dim(STDOUT_LABEL))
            continue
        if line == STDERR_LABEL:
            section = "stderr"
            out_lines.append(chalk.dim(STDERR_LABEL))
            continue
        if section == "stderr" and line:
            out_lines.append(chalk.red(line))
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def looks_like_shell_result(body: str) -> bool:
    return bool(EXIT_RE.search(body)) or body.startswith(STDOUT_LABEL) or "\nstdout:" in body


def _parse_shell_result(body: str) -> Optional[ShellResultParts]:
    lines = [line.rstrip("\r") for line in body.split("\n")]
    first = lines[0] if lines else ""
    exit_match = EXIT_RE.match(first)
    if not exit_match:
        return None

    stdout_idx = -1
    for idx, line in enumerate(lines):
        if idx > 0 and line.strip() == STDOUT_LABEL:
            stdout_idx = idx
            break
    if stdout_idx == -1:
        return None

    stderr_idx = -1
    for idx, line in enumerate(lines):
        if idx > stdout_idx and line.strip() == STDERR_LABEL:
            stderr_idx = idx
            break

    if stderr_idx == -1:
        stdout_lines = lines[stdout_idx + 1:]
    else:
        stdout_lines = lines[stdout_idx + 1:stderr_idx]
    stderr_lines = [] if stderr_idx == -1 else lines[stderr_idx + 1:]

    return ShellResultParts(
        exit=exit_match.group(1) or "",
        stdout="\n".join(_trim_trailing_blank_lines(stdout_lines)),
        stderr="\n".join(_trim_trailing_blank_lines(stderr_lines)),
        rest="\n".join(lines[1:stdout_idx]),
    )


def _trim_trailing_blank_lines(lines: list[str]) -> list[str]:
    out = list(lines)
    while out and out[-1] == "":
        out.pop()
    return out


def _compact_shell_result_for_transcript(body: str) -> str:
    parsed = _parse_shell_result(body)
    if parsed and parsed.exit != "0" and not parsed.stderr and not parsed.rest and not parsed.stdout:
        return f"exit: {parsed.exit}\n(no output)"
    if parsed and parsed.exit != "0" and parsed.stderr and not parsed.rest and not parsed.stdout:
        return f"exit: {parsed.exit}\nstderr:\n{parsed.stderr}"
    if (
        not parsed
        or parsed.exit != "0"
        or parsed.stderr
        or parsed.rest
        or not parsed.stdout
        or "\n[... truncated " in parsed.stdout
    ):
        return body
    return parsed.stdout


def shell_result_exit_status(body: str) -> Optional[str]:
    parsed = _parse_shell_result(body)
    return parsed.exit if parsed else None


HTTP_STATUS_RE = re.compile(r"^(HTTP/[\d.]+)\s+(\d{3})\s*(.*)$")


def looks_like_http_result(body: str) -> bool:
    first_line = body.split("\n", 1)[0]
    return bool(HTTP_STATUS_RE.match(first_line))


def _status_color(code: int) -> Callable[[str], str]:
    if 200 <= code < 300:
        return chalk.green
    if 300 <= code < 400:
        return chalk.cyan
    if 400 <= code < 500:
        return chalk.yellow
    if code >= 500:
        return chalk.red
    return lambda s: s


def _colorize_header_line(line: str) -> str:
    idx = line.find(":")
    if idx <= 0:
        return line
    return f"{chalk.dim(line[:idx + 1])}{line[idx + 1:]}"


def _maybe_highlight_json(body_text: str) -> str:
    trimmed = body_text.lstrip()
    if not trimmed.startswith("{") and not trimmed.startswith("["):
        return body_text
    if _LEVEL <= 0:
        return body_text
    try:
        from pygments import highlight
        from pygments.lexers import JsonLexer
        from pygments.formatters import TerminalFormatter

        json.loads(body_text)
        return highlight(body_text, JsonLexer(), TerminalFormatter()).rstrip("\n")
    except Exception:
        return body_text


def colorize_http_result(body: str) -> str:
    lines = body.split("\n")
    status_match = HTTP_STATUS_RE.match(lines[0]) if lines else None
    if not status_match:
        return body

    code = int(status_match.group(2) or 0)
    color = _status_color(code)
    status_text = f"{status_match.group(2)} {status_match.group(3) or ''}".rstrip()
    status_line = f"{chalk.dim(status_match.group(1) or '')} {color(chalk.bold(status_text))}"

    try:
        blank_idx = lines.index("", 1)
    except ValueError:
        blank_idx = -1
    header_end = len(lines) if blank_idx == -1 else blank_idx
    out = [status_line, *[_colorize_header_line(line) for line in lines[1:header_end]]]
    if blank_idx != -1:
        out.append("")
        out.append(_maybe_highlight_json("\n".join(lines[blank_idx + 1:])))
    return "\n".join(out)


GENERIC_PREVIEW_LINES = 5
PREVIEW_LINE_CHAR_CAP = 220
HTTP_BODY_PREVIEW_LINES = 3
COLLAPSE_LINE_THRESHOLD = 16
COLLAPSE_CHAR_THRESHOLD = 1200
HTTP_PREVIEW_HEADERS = frozenset({"content-type", "content-length", "location"})
HTTP_BODY_TRUNCATION_MARKER = "[response body truncated"


@dataclass
class ToolResultView:
    full: str
    preview: str
    collapsible: bool


def extract_text_content(raw: str) -> str:
    head = raw.lstrip()
    if not head.startswith("[") and not head.startswith("{"):
        return raw
    try:
        parsed = json.loads(raw)
        blocks = parsed if isinstance(parsed, list) else [parsed]
        if blocks and all(
            isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
            for b in blocks
        ):
            return "\n".join(b["text"] for b in blocks)
    except (json.JSONDecodeError, TypeError):
        pass
    return raw


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def _clamp_preview_line(line: str) -> tuple[str, bool]:
    if len(line) <= PREVIEW_LINE_CHAR_CAP:
        return line, False
    return f"{line[:PREVIEW_LINE_CHAR_CAP]}… <{len(line)} chars>", True


def _collapsed_notice(content: str, hidden_lines: int, shortened_lines: int) -> str:
    if hidden_lines > 0:
        what = f"{hidden_lines} more line{'' if hidden_lines == 1 else 's'}"
    elif shortened_lines > 0:
        what = f"{shortened_lines} shortened line{'' if shortened_lines == 1 else 's'}"
    else:
        what = "more output"
    return chalk.dim(
        f"… {what} · {_format_bytes(len(content))} — Ctrl-K latest · Ctrl-O all"
    )


def _http_preview(content: str) -> tuple[str, int, int] | None:
    """Build a short HTTP preview; return None when the response shape is malformed."""
    lines = content.splitlines()
    status_match = HTTP_STATUS_RE.match(lines[0]) if lines else None
    if status_match is None:
        return None

    separator = next(
        (index for index, line in enumerate(lines[1:], start=1) if not line.strip()),
        None,
    )
    if separator is None:
        return None

    status_code = int(status_match.group(2))
    is_redirect = 300 <= status_code < 400
    wanted_headers = set(HTTP_PREVIEW_HEADERS)
    if not is_redirect:
        wanted_headers.discard("location")

    selected_headers: list[str] = []
    selected_names: set[str] = set()
    for line in lines[1:separator]:
        if not line:
            continue
        name, delimiter, _value = line.partition(":")
        if not delimiter or not name.strip():
            return None
        normalized_name = name.strip().lower()
        if normalized_name in wanted_headers and normalized_name not in selected_names:
            selected_headers.append(line)
            selected_names.add(normalized_name)

    body = [
        (index, line)
        for index, line in enumerate(lines[separator + 1 :], start=separator + 1)
    ]
    while body and not body[0][1].strip():
        body.pop(0)

    body_indices = [index for index, _line in body[:HTTP_BODY_PREVIEW_LINES]]
    truncation_index = next(
        (
            index
            for index, line in body
            if HTTP_BODY_TRUNCATION_MARKER in line.lower()
        ),
        None,
    )
    if (
        truncation_index is not None
        and truncation_index not in body_indices
        and body_indices
    ):
        body_indices[-1] = truncation_index

    body_by_index = dict(body)
    preview_lines = [lines[0], *selected_headers]
    if body_indices:
        preview_lines.append("")
        preview_lines.extend(body_by_index[index] for index in body_indices)

    shortened = 0
    clamped_lines: list[str] = []
    for line in preview_lines:
        clamped, was_shortened = _clamp_preview_line(line)
        clamped_lines.append(clamped)
        shortened += int(was_shortened)

    visible_source_lines = 1 + len(selected_headers) + len(body_indices)
    source_lines = len(lines) - 1  # The header/body separator is structural.
    hidden_lines = max(0, source_lines - visible_source_lines)
    return "\n".join(clamped_lines), hidden_lines, shortened


def build_tool_result_view(raw: str) -> ToolResultView:
    content = _compact_shell_result_for_transcript(extract_text_content(raw))
    is_http = looks_like_http_result(content)
    if looks_like_shell_result(content):
        colorize: Callable[[str], str] = colorize_shell_result
    elif is_http:
        colorize = colorize_http_result
    else:
        colorize = lambda s: s  # noqa: E731

    full = colorize(content)
    lines = content.splitlines()
    collapsible = len(lines) > COLLAPSE_LINE_THRESHOLD or len(content) > COLLAPSE_CHAR_THRESHOLD
    if not collapsible:
        return ToolResultView(full=full, preview=full, collapsible=False)

    if is_http:
        http_preview = _http_preview(content)
        if http_preview is not None:
            preview_text, hidden_lines, shortened_lines = http_preview
            notice = _collapsed_notice(content, hidden_lines, shortened_lines)
            return ToolResultView(
                full=full,
                preview=f"{colorize(preview_text)}\n{notice}",
                collapsible=True,
            )

    preview_lines = lines[:GENERIC_PREVIEW_LINES]
    clamped_lines: list[str] = []
    shortened_lines = 0
    for line in preview_lines:
        clamped, was_shortened = _clamp_preview_line(line)
        clamped_lines.append(clamped)
        shortened_lines += int(was_shortened)
    hidden_lines = max(0, len(lines) - len(preview_lines))
    notice = _collapsed_notice(content, hidden_lines, shortened_lines)
    preview_text = "\n".join(clamped_lines)
    return ToolResultView(
        full=full,
        preview=f"{colorize(preview_text)}\n{notice}",
        collapsible=True,
    )
