"""Structured Shell diagnostics; legacy text parsing is only a best-effort view."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from src.tools.common.runtime_metadata import RuntimeMetadata, process_diagnostic

EXIT_RE = re.compile(r"^exit:\s*(-?\d+|timeout[^\n]*)")
STDOUT_LABEL = "stdout:"
STDERR_LABEL = "stderr:"


def shell_issues(metadata: RuntimeMetadata | None, *, status: str, error_kind: str | None,
                 reported_error: bool, search: bool = False) -> list[str]:
    """No output/err text enters diagnostics, including for ambiguous history."""
    if type(metadata) is not RuntimeMetadata:
        if status in {"error", "cancelled", "pending"} or error_kind or reported_error:
            reason = ("cancelled" if status == "cancelled" else "operation pending" if status == "pending"
                      else {"permission_denied": "permission denied", "scope_denied": "scope denied",
                            "policy_block": "blocked by execution policy", "invalid_args": "invalid arguments",
                            "timeout": "timeout", "network": "network error"}.get(error_kind or "", "execution error"))
            return [f"Shell {reason}; process/stream metadata unavailable. See sanitized output."]
        return []

    no_matches = (search and metadata.process == "exit" and metadata.exit_code == 1
                  and metadata.stdout is not None and metadata.stdout.complete and metadata.stdout.observed_bytes == 0
                  and metadata.stderr is not None and metadata.stderr.complete and metadata.stderr.observed_bytes == 0
                  and status in {"success", "error"} and error_kind in {None, "tool_exception"})
    issues = []
    process = process_diagnostic(metadata)
    if process and not no_matches:
        issues.append(process)
    elif not no_matches and (status in {"error", "cancelled", "pending"} or error_kind
                            or (reported_error and metadata.process == "unknown")):
        issues.append("Shell operation pending" if status == "pending" else
                      "Shell cancelled" if status == "cancelled" else "Shell tool execution error")
    if metadata.stderr is not None and metadata.stderr.observed_bytes:
        stream = metadata.stderr
        issues.append(f"Shell stderr: {stream.observed_bytes} bytes observed ({stream.retained_bytes} retained); "
                      "see sanitized output.")
    return issues


@dataclass
class ShellResultParts:
    exit: str
    stdout: str
    stderr: str
    rest: str


def _parse_shell_result(body: str) -> Optional[ShellResultParts]:
    """Archival display helper. Delimiters cannot establish exit/stream facts."""
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


