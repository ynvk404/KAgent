"""Shared path resolution for tools that read files shipped inside a skill directory."""

from __future__ import annotations

from collections.abc import Collection
from pathlib import Path

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
    body = "\n".join(lines[:limit])

    if len(body.encode("utf-8")) > MAX_PREVIEW_BYTES:
        body = body[:MAX_PREVIEW_BYTES] + f"\n...<truncated; {size} bytes on disk>"

    truncated = ""
    if total > limit:
        truncated = f"\n...<truncated at {limit} of {total} lines>"

    return f"# {heading} — {total} line(s), {size} bytes\n{body}{truncated}"
