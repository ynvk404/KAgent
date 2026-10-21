"""Operator permission summaries and execution reference without runtime probes."""
from __future__ import annotations

from typing import TYPE_CHECKING

from src.permission.network.grants import HTTPLimits
from src.permission.runtime.execution import ExecutionBlocked

if TYPE_CHECKING:
    from src.permission.network.grants import HTTPPermissions
    from src.permission.runtime.execution import ExecutionPolicy
    from src.tools.mcp.browser_local import BrowserLocalBinding


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
        if enabled and policy.browser_local is not None:
            rows.append("Browser auto-approval requires a current scoped grant. See /permissions browser.")
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
        if policy.browser_local is not None:
            rows.extend(_browser_summary(policy.browser_local))
    return "\n".join(rows)


def permissions_details(rights: HTTPPermissions, policy: ExecutionPolicy | None) -> str:
    """Explain supported execution paths using existing state; never probe them."""
    rows = [
        permissions_summary(rights, policy), "", "Execution details",
        "YOLO ON: auto-approve supported actions within declared scope; deny/revoke and limits remain enforced.",
        "YOLO OFF: normal permission review; explicit autonomous HTTP grants still apply. Confirm-each resumes.",
        "Native HTTP/S: use the http tool for HTTP or HTTPS.",
        "Typed Nmap/ffuf: require a separate ready scanner adapter. ON auto-approves eligible jobs; "
        "OFF reviews each job. HTTP quotas do not govern scanner traffic.",
        "Shell/local stdio MCP: require a compatible isolated worker. Scoped plaintext HTTP uses the broker; "
        "direct target sockets and CONNECT tunnels are unavailable in both modes.",
        "Remote MCP: direct HTTP/SSE transport is unavailable in both modes.",
        "Trusted-local Browser: auto-approval requires a separate scoped grant. See /permissions browser.",
    ]
    if policy is not None:
        rows.append("Worker: " + ("available" if policy.worker is not None else "unavailable"))
    rows.append("Default YOLO HTTP limits per origin: " + HTTPLimits.session().display())
    for origin, grant in sorted(rights.grants.items()):
        rows.append(f"Configured HTTP limits {origin.as_url()}: {grant.limits.display()}")
    rows.append("Set HTTP limits with /permissions grant <spec>.")
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
    return [f"Browser grant: {state} · {grant.group}\nOrigin: {grant.origin}",
            f"  {quota} · {lifetime}"]
