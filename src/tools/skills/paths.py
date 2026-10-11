"""Shared path resolution for tools that read files shipped inside a skill directory."""

from __future__ import annotations

from collections.abc import Collection
from pathlib import Path
import hashlib
import json
import uuid

from src.tools.common.outcome import ToolOutput

from src.skills.registry import Registry as SkillRegistry

MAX_BYTES = 256 * 1024
MAX_PREVIEW_BYTES = 16 * 1024

DEFAULT_LINE_LIMIT = 200
MAX_LINE_LIMIT = 5000


def resolve_skill_dir(
    skills: SkillRegistry,
    skill_name: str,
) -> tuple[Path | None, str | None]:
    """Return the directory of a loaded skill, or an error message for the model."""
    if not skill_name:
        return None, "error: skill is required"

    skill = skills.get(skill_name)
    if not skill:
        return None, f'error: skill "{skill_name}" not loaded'

    return Path(skill.path).parent, None


def contained_in(base: Path, target: Path) -> bool:
    """True when `target` stays inside `base` once both are fully resolved."""
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except (FileNotFoundError, ValueError):
        return False


def clamp_line_limit(limit: float | None) -> int:
    if limit is None:
        limit = DEFAULT_LINE_LIMIT
    return int(max(1, min(MAX_LINE_LIMIT, limit)))


def list_files(
    directory: Path,
    prefix: str = "",
    skip_root_names: Collection[str] = (),
) -> list[str]:
    """Sorted relative paths of readable files under `directory`, skipping oversized ones.

    `skip_root_names` entries are omitted only at the top level of the walk.
    """
    result: list[str] = []

    for entry in sorted(directory.iterdir()):
        # Never enumerate external content or recurse through a directory
        # symlink (including cycles); readers retain their own path checks.
        if not contained_in(directory, entry) or entry.is_symlink() and entry.is_dir():
            continue
        if not prefix and entry.name in skip_root_names:
            continue

        relative = f"{prefix}/{entry.name}" if prefix else entry.name

        if entry.is_dir():
            result.extend(list_files(entry, relative, skip_root_names))
            continue

        if not entry.is_file():
            continue

        if entry.stat().st_size > MAX_BYTES:
            continue

        result.append(relative)

    return sorted(result)


def render_file_preview(
    heading: str,
    raw: str,
    size: int,
    limit: int,
) -> str:
    """Format `raw` as a line-capped, byte-capped preview under a `# heading` line."""
    lines = raw.split("\n")
    total = len(lines)
    body = ''.join(raw.splitlines(keepends=True)[:limit])

    if len(body.encode("utf-8")) > MAX_PREVIEW_BYTES:
        body = body.encode('utf-8')[:MAX_PREVIEW_BYTES].decode('utf-8', errors='ignore') + f"\n...<truncated; {size} bytes on disk>"

    truncated = ""
    if total > limit:
        truncated = f"\n...<truncated at {limit} of {total} lines>"

    return f"# {heading} — {total} line(s), {size} bytes\n{body}{truncated}"


class SkillFilePages:
    """Producer-owned continuations, bound to one adapter and immutable source.

    These are auxiliary-file identifiers, never retained-result/evidence IDs.
    A fresh read still resolves its path through the adapter's skill boundary.
    """
    def __init__(self):
        self.sources: dict[str, tuple[str, str, str]] = {}

    def preview(self, path: Path, heading: str, args: dict, limit: int) -> ToolOutput:
        start = args.get('start_char', 0)
        ref = args.get('source_ref')
        if type(start) is not int or start < 0:
            return ToolOutput('error: start_char must be a non-negative Unicode character offset',
                              status='error', error_kind='invalid_args')
        if (start and not ref) or (ref is not None and not isinstance(ref, str)):
            return ToolOutput('error: continuation requires the source_ref published by this reader',
                              status='error', error_kind='invalid_args')
        with path.open('rb') as source:
            data = source.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            return ToolOutput('error: auxiliary file exceeds the 256 KiB source limit',
                              status='error', error_kind='invalid_args')
        identity = (str(path.resolve()), heading, hashlib.sha256(data).hexdigest())
        if ref is not None and self.sources.get(ref) != identity:
            return ToolOutput('error: auxiliary source_ref unavailable or source changed; request a fresh first page',
                              status='error', error_kind='reference_unavailable')
        raw = data.decode('utf-8')
        if start > len(raw):
            return ToolOutput('error: start_char exceeds this source', status='error', error_kind='invalid_args')
        # Keep complete line separators in the character range so successive
        # pages reconstruct the exact source, including long single lines.
        selected = ''.join(raw[start:].splitlines(keepends=True)[:limit])
        body = selected.encode('utf-8')[:MAX_PREVIEW_BYTES].decode('utf-8', errors='ignore')
        end = start + len(body)
        clipped = end < len(raw)
        result = render_file_preview(heading, raw[start:], len(data), limit)
        # render_file_preview preserves the legacy first-page appearance;
        # range metadata accounts for the exact content before its notices.
        if clipped or ref is not None:
            if ref is None:
                ref = 'sf_' + uuid.uuid4().hex
                if len(self.sources) >= 256:
                    del self.sources[next(iter(self.sources))]
                self.sources[ref] = identity
            result += '\nContinuation: ' + json.dumps({
                'source_ref': ref, 'sha256': identity[2], 'offset_unit': 'unicode_characters',
                'start_char': start, 'end_char': end, 'next_start_char': end if clipped else None, 'source_chars': len(raw),
                'source_bytes': len(data), 'preview_bytes': len(body.encode('utf-8')),
                'instruction': 'Use this same reader, skill and file/path with source_ref and start_char. Do not pass sf_ references to read_tool_result.',
            })
        return ToolOutput(result, truncated=clipped)
