from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.permission.permission import Prompter
from src.skills.registry import Registry as SkillRegistry

from .types import Tool, arg_number, arg_string

MAX_BYTES = 256 * 1024
MAX_PREVIEW_BYTES = 16 * 1024

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

        if not skill_name:
            return "error: skill is required"

        skill = self.skills.get(
            skill_name
        )

        if not skill:
            return (
                f'error: skill "{skill_name}" not loaded'
            )

        skill_dir = Path(
            skill.path
        ).parent

        payloads_dir = (
            skill_dir /
            "payloads"
        )

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

        size = (
            resolved.stat()
            .st_size
        )

        limit = arg_number(
            args,
            "limit",
        )

        if limit is None:
            limit = 200

        limit = max(
            1,
            min(
                5000,
                int(limit),
            ),
        )

        raw = resolved.read_text(
            encoding="utf-8"
        )

        lines = raw.split("\n")

        total = len(lines)

        body = "\n".join(
            lines[:limit]
        )

        if len(body) > MAX_PREVIEW_BYTES:
            body = (
                body[:MAX_PREVIEW_BYTES]
                +
                f"\n...<truncated; {size} bytes on disk>"
            )

        truncated = ""

        if total > limit:
            truncated = (
                f"\n...<truncated at {limit} "
                f"of {total} lines>"
            )

        relative_path = resolved.relative_to(
            payloads_dir.resolve()
        )

        return (
            f"# {skill_name}/{relative_path} "
            f"— {total} line(s), {size} bytes\n"
            f"{body}"
            f"{truncated}"
        )

def contained_in(
    base: Path,
    target: Path,
) -> bool:
    try:
        target.relative_to(
            base.resolve()
        )
        return True
    except ValueError:
        return False

def list_files(
    directory: Path,
    prefix: str = "",
) -> list[str]:
    result: list[str] = []

    for entry in directory.iterdir():
        path = directory / entry.name

        if path.is_dir():
            result.extend(
                list_files(
                    path,
                    (
                        f"{prefix}/{entry.name}"
                        if prefix
                        else entry.name
                    ),
                )
            )
            continue

        if not path.is_file():
            continue

        if path.stat().st_size > MAX_BYTES:
            continue

        result.append(
            (
                f"{prefix}/{entry.name}"
                if prefix
                else entry.name
            )
        )

    return sorted(result)