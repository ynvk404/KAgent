from __future__ import annotations

"""
Load Skill Tool

Chức năng:
- Cung cấp tool load_skill cho Agent
- Lấy nội dung đầy đủ của một skill
- Kiểm tra skill tồn tại
- Kiểm tra skill bị disable
- Trả playbook Markdown cho LLM
"""

from typing import Any

from .registry import (
    Registry,
    materialize_skill_body,
)


class LoadSkillTool:
    """
    Tool cho phép Agent load nội dung skill.

    Ví dụ:

    Agent gọi:

    load_skill({
        "name": "webvuln"
    })

    Kết quả:
        trả về nội dung SKILL.md
    """

    def __init__(
        self,
        registry: Registry
    ):
        self.reg = registry


    # --------------------------------------------------
    # Tool metadata
    # --------------------------------------------------

    def name(self) -> str:
        """
        Tên tool.
        """
        return "load_skill"


    def description(self) -> str:
        return (
            "Load the full body of a named skill. "
            "Skills are pre-authored playbooks for "
            "specific pentesting workflows "
            "(recon, web vuln hunting, etc.). "
            "Call this when one of the listed skills "
            "matches the user's task."
        )


    def schema(self) -> dict[str, Any]:
        """
        JSON schema cho LLM function calling.
        """

        return {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": (
                        "Skill name "
                        "(matches the name listed "
                        "in system prompt)"
                    ),
                }
            },
            "required": [
                "name"
            ],
        }


    def requires_permission(self) -> bool:
        """
        Load skill chỉ đọc file markdown,
        không cần permission.
        """

        return False


    # --------------------------------------------------
    # Execute
    # --------------------------------------------------

    async def run(
        self,
        args: dict[str, Any],
        signal=None,
        prompter=None
    ) -> str:
        """
        Load skill body.

        args:
        {
            "name": "webvuln"
        }
        """

        name = args.get("name", "")


        if not isinstance(name, str) or not name:
            raise ValueError(
                "name is required"
            )


        skill = self.reg.get(name)


        # Không tồn tại
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


        # Skill bị disable
        if self.reg.is_disabled(name):

            raise ValueError(
                f'skill "{name}" is disabled. '
                f"The user must enable it before loading."
            )


        # Skill chỉ user được gọi
        if skill.disable_model_invocation:

            raise ValueError(
                f'skill "{name}" has '
                "disable-model-invocation=true. "
                "Only user can load it."
            )


        return materialize_skill_body(skill)