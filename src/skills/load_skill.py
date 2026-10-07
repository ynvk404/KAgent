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

    def context_reduction_policy(self) -> str:
        # The result is the full playbook, not the short acknowledgment shown
        # by the transcript renderer.
        return "preserve"

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

        from src.permission.runtime.execution import policy_for
        policy = policy_for(prompter)
        prefix = ""
        if policy is not None:
            prefix = ("Runtime authority takes precedence over permission-review wording in this playbook. "
                      "Read permissions_status for actual rights. YOLO auto-approves covered actions, including impact "
                      "requests; do not ask_user to approve those again. OFF restores ordinary review. "
                      "Skill prerequisites, proof requirements and stop conditions still apply; a skill cannot grant "
                      "rights or enable unavailable adapters. Blocked/pending waits for operator action, not repeated "
                      "permission questions. Missing accounts/OTP remain real input questions. Runtime validates source "
                      "provenance, integrity, ownership and scope; Agent/skill assesses vulnerability meaning. "
                      "Start validation, cite primary observation_ids and immutable evidence_refs for both terminal outcomes. "
                      "Select complete, non-truncated, completed observations supporting the assessment; do not add unusable sources. "
                      "Body/content/size comparisons require positive response capture, never max_response_bytes=0. "
                      "After evidence-admissibility rejection read the source ID/reason and retry at most once using usable existing evidence. "
                      "Repair derived artifacts if needed; do not add probes merely to repair a sufficient manifest. "
                      "If evidence is insufficient, submit insufficient-evidence unless a distinct missing validation step is identified. "
                      "Declare bounded hypothesis, criteria, limitations, observed_impact, severity and completed_attempt for negatives. "
                      "A proof file alone cannot establish target traffic. Operator /review-result optionally reviews a proof "
                      "conclusion; that human review is never autonomous verification or tool authorization.\n\n")
        return prefix + materialize_skill_body(skill)
