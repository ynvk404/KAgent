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
                    "A skill can carry a payloads/ directory or a "
                    "top-level payloads.txt file."
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
                '  read_payloads(skill="ssti", file="payloads.txt", limit=50)',
                '  read_payloads(skill="sql-injection", file="payloads.txt")',
            ]
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "skill": {
                    "type": "string",
                    "description": (
                        "Skill name whose bundled payload source to read."
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
                        "Relative path inside skill/payloads, or payloads.txt "
                        "for a skill's top-level compatibility file."
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
        signal,
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

        payloads_dir = skill_dir / "payloads"
        top_level_payloads = skill_dir / "payloads.txt"
        has_payloads_dir = payloads_dir.is_dir()
        has_top_level_payloads = (
            top_level_payloads.is_file()
            and contained_in(skill_dir, top_level_payloads)
        )

        if not has_payloads_dir and not has_top_level_payloads:
            return (
                f'skill "{skill_name}" has no payload sources; '
                "expected payloads/ directory or payloads.txt file"
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
            files = list_files(payloads_dir) if has_payloads_dir else []

            if (
                has_top_level_payloads
                and top_level_payloads.stat().st_size <= MAX_BYTES
            ):
                files.append("payloads.txt")

            return json.dumps(
                sorted(set(files)),
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

        directory_candidate = (
            payloads_dir /
            file
        ).resolve(
            strict=False
        )

        if not contained_in(
            payloads_dir,
            directory_candidate,
        ):
            return (
                f'error: path "{file}" escapes '
                "<skill>/payloads/"
            )

        if directory_candidate.is_file():
            resolved = directory_candidate
            relative_path = resolved.relative_to(payloads_dir.resolve())
        elif file == "payloads.txt" and has_top_level_payloads:
            resolved = top_level_payloads.resolve()
            relative_path = resolved.relative_to(skill_dir.resolve())
        else:
            return (
                f"error: not a file: {file}"
            )

        if (
            not resolved.exists()
            or not resolved.is_file()
        ):
            return (
                f"error: not a file: {file}"
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
