"""Presentation admission. No traffic retention, execution or persistence."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from src.agent.events import Invocation, SkillActiveEvent, ToolCallEvent, ToolResultEvent, ToolStartedEvent
from src.ui.render.sanitize import sanitize_text
from src.ui.render.shell_outcome import shell_issues


@dataclass(frozen=True, slots=True)
class PendingCall:
    id: str
    name: str
    operation: str
    identity: str
    search: bool = False
    candidate_id: str = ""
    activity: str = ""
    recovery_identity: str = ""
    scope: str = ""
    skill: str = ""
    attempt_id: str = ""
    invocation: Invocation | None = None
    retired: bool = False
    resolved: bool = False
    scanner: str = ''
    scanner_job: str = ''
    started_monotonic: float | None = None
    http_redirects: bool = False


def invocation_call(calls: tuple[PendingCall, ...],
                    event: ToolCallEvent | ToolResultEvent | ToolStartedEvent | SkillActiveEvent) -> PendingCall | None:
    identifier = event.call_id if isinstance(event, SkillActiveEvent) else event.id
    name = 'load_skill' if isinstance(event, SkillActiveEvent) else event.name
    return next((call for call in calls if identifier and call.id == identifier and call.name == name
                 and call.invocation == event.invocation), None)


def call_metadata(ev: ToolCallEvent) -> PendingCall:
    args = ev.args
    if not args and ev.args_json:
        try:
            parsed = json.loads(ev.args_json)
            args = parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            args = {}
    command = args.get("command", "")
    # Exit 1 means no matches only for a simple search, never a pipeline.
    search = (ev.name in {"shell", "bash", "BashTool"} and isinstance(command, str)
              and bool(re.match(r"^\s*(?:rg|grep)\s", command))
              and not any(token in command for token in ("|", ";", "&&", "\n")))
    operation = args.get("action", "") if ev.name == "workflow" else ""
    candidate_id = args.get("candidate_id", "")
    identity_args = args
    if ev.name == "http":
        try:
            url = urlsplit(str(args.get("url", "")))
            headers = args.get("headers", {})
            auth = {str(key).lower(): value for key, value in headers.items()
                    if str(key).lower() in {"authorization", "cookie"}} if isinstance(headers, dict) else {}
            query = parse_qsl(url.query, keep_blank_values=True)
            auth_query = [(key, value) for key, value in query
                          if key.lower() in {"token", "api_key", "password", "session", "auth"}]
            identity_args = {"method": str(args.get("method", "GET")).upper(),
                "endpoint": (url.scheme, url.hostname, url.port, url.path),
                "parameters": sorted(key for key, _ in query), "parameter": args.get("parameter"),
                "candidate_id": candidate_id, "attempt_id": args.get("attempt_id"),
                "auth": (auth, auth_query, url.username, url.password, args.get("auth_context_ref"))}
        except ValueError:
            pass
    elif ev.name in {"workflow", "confirm_finding"}:
        identity_args = {key: args.get(key) for key in
                         ("action", "candidate_id", "result_id", "attempt_id", "skill_name", "phase",
                          "target", "endpoint", "method", "parameter", "input_id", "goal_id", "artifact_ref", "force")}
    identity = hashlib.sha256(json.dumps(identity_args, sort_keys=True, default=str).encode()).hexdigest()
    recovery_identity = hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()
    if ev.name == "workflow" and operation == "record_result":
        recovery_identity = identity
    activity = ""
    if (ev.name == "http" and args.get("url")) or args.get("endpoint"):
        endpoint = str(args.get("url") or args.get("endpoint") or "")
        method = str(args.get('method') or '').upper()
        # Presentation only: coverage endpoints may already use METHOD /path.
        prefixed = re.match(r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S.*)$", endpoint, re.I)
        if prefixed:
            method = method or prefixed.group(1).upper()
            endpoint = prefixed.group(2)
        try:
            path = urlsplit(endpoint).path or "/"
        except ValueError:
            path = "[invalid endpoint]"
        parameter = args.get("parameter")
        activity = sanitize_text(f"{method or 'GET'} {path}" +
                                 (f" · input {parameter}" if parameter else ""))
    elif operation:
        activity = sanitize_text(operation.replace("_", " "))
    scanner = args.get('scanner', '') if ev.name == 'shell' else ''
    scanner = scanner if isinstance(scanner, str) else ''
    if scanner in {'nmap', 'ffuf'}:
        activity = sanitize_text(f"preparing/reviewing {scanner} job · " +
            (str(args.get('target', '')) + ' ports ' + str(args.get('ports', '')) if scanner == 'nmap'
             else str(args.get('url', '')) + ' · wordlist ' + str(args.get('wordlist_id', ''))))
    skill = args.get("name") if ev.name == "load_skill" else args.get("skill_name")
    attempt_id = args.get("attempt_id")
    return PendingCall(ev.id, ev.name, operation[:80] if isinstance(operation, str) else "", identity, search,
                       candidate_id[:80] if isinstance(candidate_id, str) else "", activity, recovery_identity,
                       skill=skill if isinstance(skill, str) else "",
                       attempt_id=attempt_id if isinstance(attempt_id, str) else "",
                       invocation=ev.invocation, scanner=scanner if scanner in {'nmap', 'ffuf'} else '',
                       http_redirects=(ev.name == 'http' and type(args.get('max_redirects')) is int
                                       and 0 < args['max_redirects'] <= 5))


def http_activity(ev: ToolResultEvent, call: PendingCall | None, context: str) -> str:
    """Last-response metadata cannot identify the destination of a redirect."""
    label = "http" + (" · initial request" if call and call.http_redirects else "")
    if context:
        label += " · " + context
    if ev.http_status is not None:
        label += " · " + ("Last response " if call is None or call.http_redirects else "") + str(ev.http_status)
    return sanitize_text(label)


def issue_category(text: str, ev: ToolResultEvent) -> str:
    if "compact report export failed" in text:
        return "export"
    if text.startswith(("Validation ", "Cleanup ", "Coverage synchronization")):
        return "incomplete"
    if text.startswith(("WARNING:", "Warning:", "Shell stderr:", "Tool output truncated", "MCP output truncated",
                        "Response body truncated", "Last response body truncated")):
        return "diagnostic"
    if ev.status == "cancelled":
        return "cancelled"
    if ev.name in {"shell", "bash", "BashTool"} and text.startswith("Shell cancelled"):
        return "cancelled"
    if ev.status == 'pending' or ev.error_kind in {'permission_pending', 'permission_timeout', 'permission_stale'}:
        return 'pending'
    if ev.error_kind == "network":
        return "network"
    if ev.error_kind in {"permission", "permission_denied", "refusal", "authorization"} or "permission denied" in text.lower():
        return "denial"
    return "failure"


def result_issues(ev: ToolResultEvent, call: PendingCall | None) -> list[str]:
    """Use explicit failures and known receipt warnings, never success guesses."""
    issues: list[str] = []
    shell = ev.name in {"shell", "bash", "BashTool"}
    if shell and ev.scanner_summary is None:
        issues.extend(shell_issues(ev.runtime_metadata, status=ev.status, error_kind=ev.error_kind,
                                   reported_error=bool(ev.err), search=bool(call and call.search)))
    elif ev.err:
        issues.append(ev.err.split("(raw:", 1)[0].rstrip() if ev.error_kind == "invalid_args" else ev.err)
    elif ev.status in {"error", "cancelled", "pending"} or ev.error_kind:
        issues.append(ev.error_kind or ev.status)
        if ev.result.lower().startswith(("error:", "permission denied", "scope denied")):
            issues[0] = ev.result.splitlines()[0]
    if ev.name == "workflow":
        if ev.result.startswith("error:") and not ev.err:
            issues = [ev.result.removeprefix("error:").strip()]
        else:
            try:
                receipt = json.loads(ev.result)
            except (ValueError, TypeError):
                receipt = None
            if isinstance(receipt, dict):
                if receipt.get("ok") is False:
                    issues.append(str(receipt.get("error") or "Workflow operation rejected"))
                if receipt.get("coverage_sync") == "pending":
                    issues.append("Coverage synchronization pending" +
                                  (": " + str(receipt["coverage_error"]) if receipt.get("coverage_error") else ""))
                result = receipt.get("result")
                if isinstance(result, dict):
                    outcome = result.get("outcome")
                    if isinstance(outcome, str) and outcome in {"blocked", "insufficient-evidence", "deferred", "browser-required", "authorization-required"}:
                        issues.append("Validation " + outcome +
                                      (": " + str(result["deferred_reason"]) if result.get("deferred_reason") else ""))
                    cleanup = result.get("cleanup_state")
                    if isinstance(cleanup, str) and cleanup in {"pending", "failed", "requires-user-action"}:
                        issues.append("Cleanup " + cleanup)
    if ev.name == "confirm_finding" and "Finding persisted; compact report export failed." in ev.result:
        issues.append("Finding persisted; compact report export failed. Retry confirm_finding with the same candidate_id to regenerate the report.")
    if not shell and not issues and ev.result.lower().startswith("error:"):
        issues.append(ev.result.splitlines()[0].partition(":")[2].strip())
    if ev.name not in {"http", "shell", "bash", "BashTool"}:
        notice_text = ev.result
        if ev.name.startswith("mcp_"):
            try:
                content, _ = json.JSONDecoder().raw_decode(ev.result.lstrip())
            except (ValueError, TypeError):
                pass
            else:
                from src.tools.mcp.integration import extract_mcp_text
                notice_text = extract_mcp_text(content)
            if re.search(r"\[\.\.\. truncated \d+ chars \.\.\.\]", ev.result):
                issues.append("MCP output truncated. Omitted output may limit validation.")
            issues.extend(line for line in notice_text.splitlines() if line.startswith("ERROR:"))
        issues.extend(line for line in notice_text.splitlines()
                      if line.startswith(("WARNING:", "Warning:")) and line not in issues)
    if ev.truncated:
        if ev.name == "http":
            subject = "Last response body" if call is None or call.http_redirects else "Response body"
            issues.append(subject + " truncated; validation may be limited.")
        else:
            issues.append("Tool output truncated. Omitted output may limit validation.")
    if ev.status not in {"success", "observation", "error", "cancelled", "pending"}:
        issues.append("Unrecognized tool outcome. Review the operation.")
    return list(dict.fromkeys(re.sub(r"\b(?:cand(?:idate)?|result|attempt|ev|goal)_[0-9a-f]{12,}\b",
                                    "[reference]", sanitize_text(issue)) for issue in issues))
