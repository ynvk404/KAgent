"""Operator permission summaries and execution reference without runtime probes."""
from __future__ import annotations

from typing import TYPE_CHECKING

from src.permission.network.grants import HTTPLimits
from src.permission.runtime.execution import ExecutionBlocked

if TYPE_CHECKING:
    from src.permission.network.grants import HTTPPermissions
    from src.permission.runtime.execution import ExecutionPolicy


def yolo_target_summary(
    target: str, enabled: bool, rights: HTTPPermissions | None = None,
    policy: ExecutionPolicy | None = None,
) -> str:
    """Present mode and target without probing adapters or changing rights."""
    rows = [f"YOLO {'ON' if enabled else 'OFF'} · Target: {target or '(not set)'}"]
    rows.append(
        "Auto-approve supported actions within declared scope." if enabled else
        "Normal permission review; existing explicit HTTP grants are retained."
    )
    if not target:
        rows.append("Set /target <url> before target testing.")
    if rights is not None:
        scope = rights.engagement
        if len(scope.allowed_origins) > 1 or scope.allowed_tcp:
            rows.append(f"Scope: HTTP origins {len(scope.allowed_origins)} · "
                        f"TCP entries {len(scope.allowed_tcp)}. See /scope.")
        if rights.denied:
            rows.append("Blocked: HTTP denied for this session. See /permissions.")
        elif rights.revoked_origins:
            rows.append("Blocked: HTTP origins revoked. See /permissions.")
    if policy is not None:
        if policy.revoked:
            rows.append("Blocked: tools revoked. See /permissions.")
    if enabled:
        rows.append("Warning: actions may change/delete data; deny/revoke and limits remain enforced.")
    rows.append("Permissions: /permissions show")
    return "\n".join(rows)


def permissions_summary(rights: HTTPPermissions, policy: ExecutionPolicy | None) -> str:
    rows = ["Permissions", rights.summary()]
    if policy is not None:
        quota = (f"{policy.used}/{policy.max_calls} used" if policy.max_calls is not None
                 else f"{policy.used} used · no session quota")
        rows.append(f"Tool calls: {quota} · {policy.active}/{policy.concurrency} running")
        rows.append("Revoked tools: " + (", ".join(sorted(policy.revoked)) or "none"))
    return "\n".join(rows)


def permissions_details(rights: HTTPPermissions, policy: ExecutionPolicy | None) -> str:
    """Explain supported execution paths using existing state; never probe them."""
    rows = [
        permissions_summary(rights, policy), "", "Execution details",
        "YOLO ON: auto-approve supported actions within declared scope; deny/revoke and limits remain enforced.",
        "YOLO OFF: normal permission review; explicit autonomous HTTP grants still apply. Confirm-each resumes.",
        "Native HTTP/S: use the http tool for HTTP or HTTPS.",
        "Native Service/Content Discovery: bounded TCP/HTTP on the active target under existing permission gates.",
        "Shell: direct subprocess in project cwd, with account filesystem/network rights; no OS isolation.",
        "Worker-dependent plugins/MCP are unavailable; no automatic host fallback.",
    ]
    rows.append("Default YOLO HTTP limits per origin: " + HTTPLimits.session().display())
    for origin, grant in sorted(rights.grants.items()):
        rows.append(f"Configured HTTP limits {origin.as_url()}: {grant.limits.display()}")
    rows.append("Set HTTP limits with /permissions grant <spec>.")
    return "\n".join(rows)
