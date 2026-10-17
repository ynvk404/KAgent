"""Compact permission state for the operator, separate from runtime diagnostics."""
from __future__ import annotations

from typing import TYPE_CHECKING

from src.permission.runtime.execution import ExecutionBlocked

if TYPE_CHECKING:
    from src.permission.network.grants import HTTPPermissions
    from src.permission.runtime.execution import ExecutionPolicy
    from src.tools.mcp.browser_local import BrowserLocalBinding


def permissions_summary(rights: HTTPPermissions, policy: ExecutionPolicy | None) -> str:
    rows = ["Permissions", rights.summary()]
    if policy is not None:
        quota = (f"{policy.used}/{policy.max_calls} used" if policy.max_calls is not None
                 else f"{policy.used} used; no session quota")
        rows.append(f"Tool calls: {quota}; {policy.active}/{policy.concurrency} running")
        rows.append("Revoked tools: " + (", ".join(sorted(policy.revoked)) or "none"))
        if policy.browser_local is not None:
            rows.extend(_browser_summary(policy.browser_local))
    return "\n".join(rows)


def _browser_summary(binding: BrowserLocalBinding) -> list[str]:
    grant = binding.grant
    if grant is None:
        return ["Browser grant: none"]
    try:
        binding.check_grant((grant.id, grant.revision))
        state = "active"
    except ExecutionBlocked:
        state = "expired/exhausted/stale"
    quota = f"{grant.remaining} calls left" if grant.remaining is not None else "no call quota"
    lifetime = (f"{max(0, grant.expires - binding.policy.clock()):.0f}s left"
                if grant.expires is not None else "session lifetime")
    return [f"Browser grant: {state}; {grant.group}; {grant.origin}",
            f"  {quota}; {lifetime}"]
