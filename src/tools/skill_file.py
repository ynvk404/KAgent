from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from src.permission.permission import Prompter
from .types import (
    Tool,
    arg_number,
    arg_string,
)
from src.skills.registry import Registry as SkillRegistry

MAX_BYTES = 256 * 1024
MAX_PREVIEW_BYTES = 16 * 1024

class ReadSkillFileTool:
    def __init__(
        self,
        skills: SkillRegistry,
    ):
        self.skills = skills

    def name(self) -> str:
        return "read_skill_file"

    def description(self) -> str:
        return (
            "Read or list any auxiliary file shipped with a skill. "
            "Skills carry their own directory; this tool resolves paths "
            "relative to that directory and reads them safely.\n\n"
            "Use after loading a skill — skill bodies reference "
            "${SKILL_DIR} for absolute paths; this tool is the "
            "skill-name-relative way to fetch the same file.\n\n"
            "Examples:\n"
            '  read_skill_file(skill="takeover", action="list")\n'
            '  read_skill_file(skill="takeover", path="payloads/fingerprints.json")\n'
            '  read_skill_file(skill="ssti", path="payloads/jinja2.txt", limit=50)'
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "skill": {
                    "type": "string",
                    "description": "Skill name whose directory to read from.",
                },
                "action": {
                    "type": "string",
                    "enum": [
                        "list",
                        "read",
                    ],
                    "description": (
                        "'list' returns filenames under the skill directory "
                        "(excluding SKILL.md). 'read' returns one file's "
                        "contents. Default: read when path is given, "
                        "list when not."
                    ),
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Relative path within the skill directory "
                        '(example: "payloads/jwt.txt").'
                    ),
                },
                "limit": {
                    "type": "number",
                    "description": (
                        "Cap number of lines returned "
                        "(default 200, max 5000)."
                    ),
                },
            },
            "required": [
                "skill"
            ],
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str:
        skill_name = arg_string(
            args,
            "skill",
        )

        if not skill_name:
            return "error: skill is required"

        skill = self.skills.get(
            skill_name
        )

        if not skill:
            return (
                f'error: skill "{skill_name}" not loaded'
            )

        skill_dir = Path(skill.path).parent

        path = arg_string(
            args,
            "path",
        )

        action = arg_string(
            args,
            "action",
        )

        if not action:
            action = "read" if path else "list"

        if action == "list":
            return json.dumps(
                list_files(skill_dir),
                indent=2,
            )

        if action != "read":
            return (
                f'error: unknown action "{action}"'
            )

        if not path:
            return (
                "error: path is required for action=read"
            )

        resolved = (skill_dir / path).resolve()

        if not contained_in(
            skill_dir,
            resolved,
        ):
            return (
                f'error: path "{path}" escapes the skill directory'
            )

        rel = resolved.relative_to(
            skill_dir.resolve()
        ).as_posix()

        if rel == "SKILL.md":
            return (
                "error: SKILL.md is loaded via load_skill, not this tool"
            )

        if not resolved.exists() or not resolved.is_file():
            return (
                f"error: not a file: {path}"
            )

        if not contained_in(
            skill_dir,
            resolved,
        ):
            return (
                f'error: path "{path}" escapes the skill directory via a symlink'
            )

        size = resolved.stat().st_size

        limit_value = arg_number(
            args,
            "limit",
        )

        limit = int(
            max(
                1,
                min(
                    5000,
                    limit_value if limit_value is not None else 200,
                ),
            )
        )

        raw = resolved.read_text(
            encoding="utf-8"
        )

        lines = raw.split("\n")

        total = len(lines)

        body = "\n".join(
            lines[:limit]
        )

        if len(body.encode("utf-8")) > MAX_PREVIEW_BYTES:
            body = (
                body[:MAX_PREVIEW_BYTES]
                + f"\n...<truncated; {size} bytes on disk>"
            )

        truncated = ""

        if total > limit:
            truncated = (
                f"\n...<truncated at {limit} of {total} lines>"
            )

        return (
            f"# {skill_name}/{rel} — "
            f"{total} line(s), {size} bytes\n"
            f"{body}"
            f"{truncated}"
        )

def contained_in(
    base: Path,
    target: Path,
) -> bool:
    try:
        real_base = base.resolve()
        real_target = target.resolve()

        real_target.relative_to(
            real_base
        )

        return True

    except (
        FileNotFoundError,
        ValueError,
    ):
        return False

def list_files(
    directory: Path,
    prefix: str = "",
) -> list[str]:
    result: list[str] = []

    for entry in directory.iterdir():
        if entry.name == "SKILL.md" and not prefix:
            continue

        if entry.is_dir():
            result.extend(
                list_files(
                    entry,
                    f"{prefix}/{entry.name}"
                    if prefix
                    else entry.name,
                )
            )
            continue

        if not entry.is_file():
            continue

        if entry.stat().st_size > MAX_BYTES:
            continue

        result.append(
            f"{prefix}/{entry.name}"
            if prefix
            else entry.name
        )

    return sorted(result)