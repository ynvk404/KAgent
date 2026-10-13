from __future__ import annotations

import json
from typing import Any

from src.permission.permission import Prompter
from src.tools.skills.paths import (
    MAX_BYTES,
    MAX_PREVIEW_BYTES,
    clamp_line_limit,
    contained_in,
    list_files,
    render_file_preview,
    resolve_skill_dir,
    SkillFilePages,
)
from src.tools.common.types import (
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
        self.pages = SkillFilePages()

    def name(self) -> str:
        return "read_skill_file"

    def description(self) -> str:
        return 'Read/list loaded skill files, excluding SKILL.md. Clipped: copy the Next page call exactly; never guess source_ref or offsets. Fresh read: omit source_ref and start_char. Source <=256KiB, body <=16KiB. sf_ IDs are not read_tool_result refs.'

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                'start_char': {'type': 'integer', 'minimum': 0, 'description': 'Unicode offset; source_ref required after 0.'},
                'source_ref': {'type': 'string', 'description': 'Published sf_ source identity.'},
                "skill": {
                    "type": "string",
                    "description": "Loaded skill name.",
                },
                "action": {
                    "type": "string",
                    "enum": [
                        "list",
                        "read",
                    ],
                    "description": (
                        "'list' returns auxiliary filenames "
                        "(excludes SKILL.md). 'read' returns "
                        "content. Default: read with path, "
                        "list when not."
                    ),
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Auxiliary path within skill "
                        ''
                    ),
                },
                "limit": {
                    "type": "number",
                    "description": (
                        "Line cap "
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

    def context_reduction_policy(self):
        return "preserve"

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

        return self.pages.preview(
            resolved, f"{skill_name}/{rel}", args,
            clamp_line_limit(
                arg_number(
                    args,
                    "limit",
                )
            ),
            reader=self.name(),
            source_args={"skill": skill_name, "path": path},
        )
