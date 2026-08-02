from __future__ import annotations
import asyncio
import os
import re
from pathlib import Path
from typing import Any
from .types import (
    Tool,
    arg_bool,
    arg_number,
    arg_string,
)
from .file import gate_sensitive_path

# ==========================================================
# Constants
# ==========================================================
GREP_FILE_BYTE_CAP = 5 * 1024 * 1024
GREP_CONCURRENCY = 8
SKIP_DIR_NAMES = {
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "dist",
    "build",
    ".next",
    ".cache",
    "coverage",
    "vendor",
    "__pycache__",
}

# ==========================================================
# GlobTool
# ==========================================================
class GlobTool(Tool):
    def name(self) -> str:
        return "GlobTool"
    def description(self) -> str:
        return (
            "Find files by glob pattern. "
            "Supports *, ?, ** recursive matching."
        )
    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description":
                        'Glob pattern e.g "**/*.py"',
                },
                "path": {
                    "type": "string",
                    "description":
                        "Optional base directory",
                },
                "limit": {
                    "type": "integer",
                    "description":
                        "Maximum matches",
                },
            },
            "required": [
                "pattern"
            ],
        }
    def requires_permission(self) -> bool:
        return False
    async def run(
        self,
        args: dict[str, Any],
        signal,
        p,
    ) -> str:
        pattern = arg_string(
            args,
            "pattern"
        )
        if not pattern:
            raise ValueError(
                "pattern is required"
            )
        base = (
            arg_string(args, "path")
            or "."
        )
        raw_limit = arg_number(
            args,
            "limit"
        )
        limit = max(
            1,
            int(
                raw_limit
                if raw_limit is not None
                else 200
            )
        )
        await gate_search_inputs(
            p,
            base,
            pattern,
            signal
        )
        matches = await glob_files(
            base,
            pattern,
            limit,
            signal
        )
        for file in matches:
            await gate_sensitive_path(
                p,
                file,
                "search",
                signal
            )
        if not matches:
            return "no matches"
        return "\n".join(matches)

# ==========================================================
# GrepTool
# ==========================================================
class GrepTool(Tool):
    def name(self) -> str:
        return "GrepTool"
    def description(self) -> str:
        return (
            "Search file contents using regex. "
            "Returns path:line:match."
        )
    def schema(self):
        return {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description":
                        "Regular expression",
                },
                "path": {
                    "type": "string",
                },
                "glob": {
                    "type": "string",
                },
                "ignore_case": {
                    "type": "boolean",
                },
                "limit": {
                    "type": "integer",
                },
            },
            "required": [
                "pattern"
            ],
        }
    def requires_permission(self):
        return False
    async def run(
        self,
        args,
        signal,
        p,
    ):
        raw_pattern = arg_string(
            args,
            "pattern"
        )
        if not raw_pattern:
            raise ValueError(
                "pattern is required"
            )
        flags = (
            re.IGNORECASE
            if arg_bool(
                args,
                "ignore_case"
            )
            else 0
        )
        try:
            regex = re.compile(
                raw_pattern,
                flags
            )
        except Exception as e:
            raise ValueError(
                f"invalid regex: {e}"
            )
        base = (
            arg_string(args, "path")
            or "."
        )
        glob_pattern = (
            arg_string(args, "glob")
            or "**/*"
        )
        raw_limit = arg_number(
            args,
            "limit"
        )
        limit = max(
            1,
            int(
                raw_limit
                if raw_limit is not None
                else 200
            )
        )
        await gate_search_inputs(
            p,
            base,
            glob_pattern,
            signal
        )
        entries = await glob_entries(
            base,
            glob_pattern,
            10000,
            signal
        )
        output = await grep_entries(
            entries,
            regex,
            limit,
            signal,
            p,
        )
        if not output:
            return "no matches"
        if len(output) >= limit:
            output = output[:limit]
            output.append(
                f"[... limited to {limit} matches ...]"
            )
        return "\n".join(output)

# ==========================================================
# Glob implementation
# ==========================================================
async def glob_files(
    base: str,
    pattern: str,
    limit: int,
    signal,
):
    root = Path(base).resolve()
    if root.is_file():
        parent = root.parent
        for file in walk_files(parent):
            rel = file.relative_to(parent)
            if glob_match(
                str(rel),
                pattern
            ):
                return [
                    str(root)
                ]
        return []
    results = []
    for file in walk_files(root):
        if _is_aborted(signal):
            raise RuntimeError("aborted")
        rel = str(
            file.relative_to(root)
        )
        if glob_match(
            rel,
            pattern
        ):
            results.append(
                str(file)
            )
            if len(results) >= limit:
                break
    return sorted(results)

async def glob_entries(
    base,
    pattern,
    limit,
    signal,
):
    files = await glob_files(
        base,
        pattern,
        limit,
        signal
    )
    result = []
    for f in files:
        try:
            size = os.path.getsize(f)
        except OSError:
            size = 0
        result.append(
            {
                "path": f,
                "size": size
            }
        )
    return sorted(
        result,
        key=lambda x: x["path"]
    )

# ==========================================================
# Grep implementation
# ==========================================================
async def grep_entries(
    entries,
    regex,
    limit,
    signal,
    p,
):
    results = [
        []
        for _ in entries
    ]
    counter = 0
    lock = asyncio.Lock()
    async def worker(index, entry):
        nonlocal counter
        if (
            entry["size"] >
            GREP_FILE_BYTE_CAP
        ):
            return
        async with lock:
            if counter >= limit:
                return
        await gate_sensitive_path(
            p,
            entry["path"],
            "search",
            signal
        )
        remaining = max(
            0,
            limit - counter
        )
        matches = await grep_file(
            entry["path"],
            regex,
            remaining,
            signal
        )
        results[index] = matches
        async with lock:
            counter += len(matches)
    tasks = []
    sem = asyncio.Semaphore(
        GREP_CONCURRENCY
    )
    async def run_worker(i, e):
        async with sem:
            await worker(i, e)
    for i, e in enumerate(entries):
        tasks.append(
            run_worker(i, e)
        )
    await asyncio.gather(
        *tasks
    )
    return [
        item
        for group in results
        for item in group
    ]

async def grep_file(
    path,
    regex,
    remaining,
    signal,
):
    if remaining <= 0:
        return []
    output = []
    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:
            for line_no, line in enumerate(f, start=1):
                if _is_aborted(signal):
                    break
                if regex.search(line):
                    output.append(
                        f"{path}:{line_no}:{line.rstrip()}"
                    )
                    if len(output) >= remaining:
                        break
    except Exception:
        pass
    return output

# ==========================================================
# Security helpers
# ==========================================================
async def gate_search_inputs(
    p,
    base,
    pattern,
    signal,
):
    await gate_sensitive_path(
        p,
        str(Path(base).resolve()),
        "search",
        signal
    )
    prefix = absolute_literal_prefix(
        pattern
    )
    if prefix:
        await gate_sensitive_path(
            p,
            prefix,
            "search",
            signal
        )

def absolute_literal_prefix(
    pattern: str
):
    if not os.path.isabs(pattern):
        return ""
    match = re.search(
        r"[*?\[\]{}()!]",
        pattern
    )
    prefix = (
        pattern[:match.start()]
        if match
        else pattern
    )
    return (
        str(Path(prefix).resolve())
        if prefix
        else ""
    )

# ==========================================================
# Filesystem helpers
# ==========================================================
def walk_files(root: Path):
    for entry in root.iterdir():
        if entry.is_symlink():
            continue
        if entry.is_dir():
            if entry.name in SKIP_DIR_NAMES:
                continue
            yield from walk_files(entry)
        elif entry.is_file():
            yield entry

def glob_match(
    path: str,
    pattern: str,
) -> bool:
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")
    return (
        re.fullmatch(
            _translate_glob(pattern),
            path,
        )
        is not None
    )

def _translate_glob(
    pattern: str,
) -> str:
    i = 0
    n = len(pattern)
    result = []
    while i < n:
        c = pattern[i]
        if c == "*":
            # **
            if (
                i + 1 < n
                and pattern[i + 1] == "*"
            ):
                i += 2
                # **/ => zero or more directories
                if (
                    i < n
                    and pattern[i] == "/"
                ):
                    i += 1
                result.append(
                    "(?:.*/)?"
                )
            # *
            else:
                result.append(
                    "[^/]*"
                )
                i += 1
        elif c == "?":
            result.append(
                "[^/]"
            )
            i += 1
        else:
            result.append(
                re.escape(c)
            )
            i += 1
    return "".join(result)

def _is_aborted(signal) -> bool:
    return (
        signal is not None
        and getattr(signal, "aborted", False)
    )