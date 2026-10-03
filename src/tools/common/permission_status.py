"""Read-only controller authority query; cannot grant or restore rights."""
from __future__ import annotations

from src.permission.runtime.execution import policy_for


class PermissionStatusTool:
    def name(self) -> str:
        return "permissions_status"

    def description(self) -> str:
        return "Read actual execution rights, mode, limits and adapter availability. This never grants permission. Covered actions need no ask_user permission question."

    def schema(self) -> dict:
        return {"type": "object", "properties": {}, "additionalProperties": False}

    def requires_permission(self) -> bool:
        return False

    async def run(self, args, signal, prompter) -> str:
        if args:
            raise ValueError("permissions_status accepts no arguments or authority updates")
        policy = policy_for(prompter)
        if policy is None:
            return "Execution profile unavailable; legacy permission gates apply."
        return policy.status() + "\n" + policy.engagement.http_permissions.status()
