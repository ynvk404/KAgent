"""Parse exit and stderr metadata for actionable Shell presentation."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

EXIT_RE = re.compile(r"^exit:\s*(-?\d+|timeout[^\n]*)")
STDOUT_LABEL = "stdout:"
STDERR_LABEL = "stderr:"


@dataclass
class ShellResultParts:
    exit: str
    stdout: str
    stderr: str
    rest: str


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


