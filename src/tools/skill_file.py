from __future__ import annotations

import json
from typing import Any

from src.permission.permission import Prompter
from .skill_paths import (
    MAX_BYTES,
    MAX_PREVIEW_BYTES,
    clamp_line_limit,
    contained_in,
    list_files,
    render_file_preview,
    resolve_skill_dir,
)
from .types import (
    Tool,
    arg_number,
    arg_string,
)
from src.skills.registry import Registry as SkillRegistry

__all__ = ["MAX_BYTES", "MAX_PREVIEW_BYTES", "ReadSkillFileTool"]


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
            '  read_skill_file(skill="sql-injection", action="list")\n'
            '  read_skill_file(skill="sql-injection", path="payloads.txt", limit=50)\n'
            '  read_skill_file(skill="recon", action="list")'
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
                        '(example: "payloads.txt").'
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

        skill_dir, error = resolve_skill_dir(
            self.skills,
            skill_name,
        )

        if skill_dir is None:
            return error or "error: skill is required"

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
                list_files(skill_dir, skip_root_names=("SKILL.md",)),
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

        return render_file_preview(
            f"{skill_name}/{rel}",
            resolved.read_text(encoding="utf-8"),
            resolved.stat().st_size,
            clamp_line_limit(
                arg_number(
                    args,
                    "limit",
                )
            ),
        )
