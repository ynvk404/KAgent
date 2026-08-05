from __future__ import annotations

from typing import Any

from .registry import (
    Registry,
    materialize_skill_body,
)

class LoadSkillTool:
    def __init__(
        self,
        registry: Registry
    ):
        self.reg = registry

    def name(self) -> str:
        return "load_skill"

    def description(self) -> str:
        return (
            "Load the full body of a named skill. "
            "Skills are pre-authored playbooks for "
            "specific pentesting workflows "
            "(recon, web vuln hunting, etc.). "
            "Call this when one of the listed skills "
            "matches the user's task \u2014 the body contains "
            "step-by-step guidance, recommended tools, "
            "and example commands."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": (
                        "Skill name (matches the "
                        "'name' field listed in the "
                        "system prompt)."
                    ),
                }
            },
            "required": [
                "name"
            ],
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        signal=None,
        prompter=None
    ) -> str:
        name = args.get("name", "")

        if not isinstance(name, str) or not name:
            raise ValueError("name is required")

        skill = self.reg.get(name)

        if skill is None:
            names = ", ".join(
                s.name
                for s in self.reg.list_enabled()
                if not s.disable_model_invocation
            )
            raise ValueError(
                f'unknown skill "{name}". '
                f"Available: {names}"
            )

        if self.reg.is_disabled(name):
            raise ValueError(
                f'skill "{name}" is disabled. '
                f"The user must enable it via "
                f"/skills enable {name} before it "
                f"can be loaded."
            )

        if skill.disable_model_invocation:
            raise ValueError(
                f'skill "{name}" is marked '
                f"disable-model-invocation: true. "
                f"Only the user can load it via /{name}."
            )

        return materialize_skill_body(skill)