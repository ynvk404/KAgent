from __future__ import annotations

import json
from typing import Any

from src.permission.permission import Prompter
from src.skills.registry import Registry as SkillRegistry

from .skill_paths import (
    MAX_BYTES,
    MAX_PREVIEW_BYTES,
    clamp_line_limit,
    contained_in,
    list_files,
    render_file_preview,
    resolve_skill_dir,
)
from .types import Tool, arg_number, arg_string

__all__ = ["MAX_BYTES", "MAX_PREVIEW_BYTES", "ReadPayloadsTool"]


class ReadPayloadsTool(Tool):

    def __init__(
        self,
        skills: SkillRegistry,
    ):
        self.skills = skills

    def name(self) -> str:
        return "read_payloads"

    def description(self) -> str:
        return "\n".join(
            [
                (
                    "Read a curated payload list shipped with a skill. "
                    "Each skill can carry a payloads/ directory."
                ),
                "",
                (
                    "Use after loading a skill. "
                    "Avoid inventing payloads from memory when "
                    "the skill provides curated payload files."
                ),
                "",
                "Examples:",
                '  read_payloads(skill="ssti", action="list")',
                '  read_payloads(skill="jwt", file="alg-confusion.txt")',
                '  read_payloads(skill="ssti", file="jinja2.txt", limit=50)',
            ]
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "skill": {
                    "type": "string",
                    "description": (
                        "Skill name whose payloads directory to read."
                    ),
                },
                "action": {
                    "type": "string",
                    "enum": [
                        "list",
                        "read",
                    ],
                    "description": (
                        "'list' returns available payload files. "
                        "'read' returns file content."
                    ),
                },
                "file": {
                    "type": "string",
                    "description": (
                        "Relative path inside skill/payloads."
                    ),
                },
                "limit": {
                    "type": "number",
                    "description": (
                        "Maximum lines returned. "
                        "Default 200, max 5000."
                    ),
                },
            },
            "required": [
                "skill",
            ],
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        _signal,
        _prompter: Prompter,
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

        payloads_dir = skill_dir / "payloads"

        if not payloads_dir.exists():
            return (
                f'skill "{skill_name}" has no payloads/ directory '
                f"at {payloads_dir}"
            )

        file = arg_string(
            args,
            "file",
        )

        action = (
            arg_string(
                args,
                "action",
            )
            or ("read" if file else "list")
        )

        if action == "list":
            return json.dumps(
                list_files(
                    payloads_dir
                ),
                indent=2,
            )

        if action != "read":
            return (
                f'error: unknown action "{action}"'
            )

        if not file:
            return (
                "error: file is required for action=read"
            )

        resolved = (
            payloads_dir /
            file
        ).resolve(
            strict=False
        )

        if not contained_in(
            payloads_dir,
            resolved,
        ):
            return (
                f'error: path "{file}" escapes '
                "<skill>/payloads/"
            )

        if (
            not resolved.exists()
            or not resolved.is_file()
        ):
            return (
                f"error: not a file: {file}"
            )

        relative_path = resolved.relative_to(
            payloads_dir.resolve()
        )

        return render_file_preview(
            f"{skill_name}/{relative_path}",
            resolved.read_text(encoding="utf-8"),
            resolved.stat().st_size,
            clamp_line_limit(
                arg_number(
                    args,
                    "limit",
                )
            ),
        )